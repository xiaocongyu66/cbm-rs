//! extract_channels.rs — 1:1 rewrite of `internal/cbm/extract_channels.c`:
//! the pub/sub channel participation extractor.
//!
//! Detects event-driven communication across languages:
//!   JS/TS/TSX/ArkTS: Socket.IO, EventEmitter, raw WebSocket, Kafka, RabbitMQ
//!   Python:          python-socketio, Django Channels, FastAPI WebSocket, kafka-python
//!   Go:              gorilla/nhooyr websocket (WriteMessage/ReadMessage)
//!   Java/Kotlin:     JSR 356 WebSocket, Spring STOMP/WebSocket
//!   C#:              SignalR (Clients.All.SendAsync / Hub.On)
//!   Ruby:            ActionCable (broadcast / stream_from)
//!   Elixir:          Phoenix.PubSub, Phoenix.Channel
//!   Rust:            tokio-tungstenite (sink.send / stream.next)
//!
//! Transport is stored on the record so later detectors share the schema.
//! String-constant resolution: a bare-identifier channel argument is
//! resolved through a single-pass module scan of `const X = "…"` (JS) /
//! `X = "…"` (Python) bindings; template literals stay unresolved.
//! The constant table is flat (no scope boundaries) — sufficient for the
//! common Socket.IO pattern, exactly like the C.

use crate::extract_env_accesses::ExtractCtx;
use crate::fqn::node_text;
use crate::types::{Channel, ChannelDirection};
use crate::Language;
use std::collections::HashMap;
use tree_sitter::Node;

/// C CHAN_CONST_CAP — the flat table caps tracked identifiers per file.
const CHAN_CONST_CAP: usize = 256;
/// C CHAN_DIR_UNKNOWN.
const CHAN_DIR_UNKNOWN: i32 = -1;

// ── String literal helpers ──────────────────────────────────────

/// Strip one pair of matching quotes (C unquote_string). None unless the
/// text is a quoted literal.
fn unquote_string(s: &str) -> Option<&str> {
    let b = s.as_bytes();
    if b.len() < 2 {
        return None;
    }
    let first = b[0];
    let last = b[b.len() - 1];
    if (first == b'"' && last == b'"')
        || (first == b'\'' && last == b'\'')
        || (first == b'`' && last == b'`')
    {
        Some(&s[1..s.len() - 1])
    } else {
        None
    }
}

/// Literal channel name from an argument node (C literal_from_arg). Only
/// plain string-literal node kinds qualify.
fn literal_from_arg<'s>(arg: Node<'_>, source: &'s str) -> Option<&'s str> {
    const KINDS: &[&str] = &[
        "string",
        "string_literal",
        "interpreted_string_literal",
        "raw_string_literal",
        "string_content",
    ];
    if !KINDS.contains(&arg.kind()) {
        return None;
    }
    unquote_string(node_text(arg, source))
}

/// Literal from the first named child that yields one
/// (C literal_from_first_child).
fn literal_from_first_child<'s>(node: Node<'_>, source: &'s str) -> Option<&'s str> {
    (0..node.named_child_count())
        .filter_map(|i| node.named_child(i))
        .find_map(|child| literal_from_arg(child, source))
}

// ── Constant resolution table ───────────────────────────────────

/// `const X = "…"` / `X = "…"` bindings (C chan_const_table_t, flat).
type ConstTable = HashMap<String, String>;

/// Collect JS `const IDENT = "value"` bindings (C scan_string_consts_js).
fn scan_string_consts_js(root: Node<'_>, source: &str) -> ConstTable {
    let mut tbl = ConstTable::new();
    let mut stack = vec![root];
    while let Some(node) = stack.pop() {
        if tbl.len() >= CHAN_CONST_CAP {
            break;
        }
        if node.kind() == "variable_declarator" {
            let name = node.child_by_field_name("name");
            let value = node.child_by_field_name("value");
            if let (Some(name), Some(value)) = (name, value) {
                if name.kind() == "identifier"
                    && (value.kind() == "string" || value.kind() == "string_literal")
                {
                    if let Some(unq) = unquote_string(node_text(value, source)) {
                        tbl.insert(node_text(name, source).to_string(), unq.to_string());
                    }
                }
            }
        }
        for i in (0..node.child_count()).rev() {
            if let Some(c) = node.child(i) {
                stack.push(c);
            }
        }
    }
    tbl
}

/// Collect Python `NAME = "value"` assignments (C scan_string_consts_python).
fn scan_string_consts_python(root: Node<'_>, source: &str) -> ConstTable {
    let mut tbl = ConstTable::new();
    let mut stack = vec![root];
    while let Some(node) = stack.pop() {
        if tbl.len() >= CHAN_CONST_CAP {
            break;
        }
        if node.kind() == "assignment" {
            let left = node.child_by_field_name("left");
            let right = node.child_by_field_name("right");
            if let (Some(left), Some(right)) = (left, right) {
                if left.kind() == "identifier" && right.kind() == "string" {
                    let val = literal_from_arg(right, source)
                        .or_else(|| literal_from_first_child(right, source));
                    if let Some(val) = val {
                        tbl.insert(node_text(left, source).to_string(), val.to_string());
                    }
                }
            }
        }
        for i in (0..node.child_count()).rev() {
            if let Some(c) = node.child(i) {
                stack.push(c);
            }
        }
    }
    tbl
}

// ── Enclosing function detection ────────────────────────────────

const FUNC_KINDS: &[&str] = &[
    "function_declaration",
    "method_definition",
    "arrow_function",
    "function_expression",
    "function",
    "method_signature",
    "function_definition",
    "method_declaration",
    "function_item",
    "def",
];

/// Name of the nearest enclosing function-like node (C
/// enclosing_function_qn); empty string when anonymous/absent.
fn enclosing_function_qn(node: Node<'_>, source: &str) -> String {
    let mut cur = node;
    while let Some(parent) = cur.parent() {
        if FUNC_KINDS.contains(&parent.kind()) {
            if let Some(name) = parent.child_by_field_name("name") {
                let text = node_text(name, source);
                if !text.is_empty() {
                    return text.to_string();
                }
            }
            return String::new();
        }
        cur = parent;
    }
    String::new()
}

// ── Channel name extraction from arguments ──────────────────────

/// Channel name from the first argument of a call: literal first, then
/// identifier resolution via the constant table (C extract_channel_name).
fn extract_channel_name(
    args: Node<'_>,
    consts: Option<&ConstTable>,
    source: &str,
) -> Option<String> {
    let first = args.named_child(0)?;
    let name = literal_from_arg(first, source)
        .or_else(|| literal_from_first_child(first, source))
        .map(|s| s.to_string())
        .or_else(|| {
            if first.kind() == "identifier" {
                let ident = node_text(first, source);
                consts.and_then(|t| t.get(ident).cloned())
            } else {
                None
            }
        })?;
    if name.is_empty() {
        None
    } else {
        Some(name)
    }
}

// ── Emit helper ─────────────────────────────────────────────────

fn push_channel(
    ctx: &mut ExtractCtx<'_>,
    channel_name: &str,
    transport: &str,
    direction: ChannelDirection,
    call: Node<'_>,
) {
    ctx.result.channels.push(Channel {
        channel_name: channel_name.to_string(),
        transport: transport.to_string(),
        enclosing_func_qn: enclosing_function_qn(call, ctx.source),
        direction,
    });
}

/// Rightmost dot-tail of a receiver expression (shared classifier tail).
fn receiver_tail(text: &str) -> &str {
    match text.rfind('.') {
        Some(dot) => &text[dot + 1..],
        None => text,
    }
}

// ═══ JS/TS/TSX/ArkTS ════════════════════════════════════════════

/// Classify receiver for Socket.IO / EventEmitter / WebSocket / Kafka /
/// RabbitMQ (C js_classify_receiver).
fn js_classify_receiver(object_text: &str) -> Option<&'static str> {
    let tail = receiver_tail(object_text);
    // Socket.IO
    if matches!(tail, "socket" | "io" | "ws" | "client" | "server") {
        return Some("socketio");
    }
    // Node.js EventEmitter
    if matches!(
        tail,
        "emitter" | "eventEmitter" | "events" | "bus" | "eventBus" | "pubsub"
    ) {
        return Some("event_emitter");
    }
    // Kafka
    if tail == "producer" || tail == "consumer" {
        return Some("kafka");
    }
    // RabbitMQ / AMQP: `channel` but NOT the bare word (C's !strcmp(text,
    // "channel") guard means the FULL text must not be "channel").
    if tail == "channel" && object_text != "channel" {
        return Some("rabbitmq");
    }
    None
}

fn js_process_call(ctx: &mut ExtractCtx<'_>, call: Node<'_>, consts: &ConstTable) {
    let Some(func) = call.child_by_field_name("function") else {
        return;
    };
    if func.kind() != "member_expression" {
        return;
    }
    let (Some(object), Some(property)) = (
        func.child_by_field_name("object"),
        func.child_by_field_name("property"),
    ) else {
        return;
    };
    let method = node_text(property, ctx.source);
    let Some(transport) = js_classify_receiver(node_text(object, ctx.source)) else {
        return;
    };

    let direction = match transport {
        "kafka" => match method {
            "send" | "sendBatch" => ChannelDirection::Emit,
            "subscribe" | "run" => ChannelDirection::Listen,
            _ => return,
        },
        "rabbitmq" => match method {
            "publish" | "sendToQueue" => ChannelDirection::Emit,
            "consume" | "assertQueue" => ChannelDirection::Listen,
            _ => return,
        },
        // socketio / event_emitter
        "socketio" | "event_emitter" => {
            if method == "emit" {
                ChannelDirection::Emit
            } else if matches!(method, "on" | "addListener" | "once") {
                ChannelDirection::Listen
            } else {
                return;
            }
        }
        _ => return,
    };

    let Some(args) = call.child_by_field_name("arguments") else {
        return;
    };
    let Some(channel_name) = extract_channel_name(args, Some(consts), ctx.source) else {
        return;
    };
    push_channel(ctx, &channel_name, transport, direction, call);
}

fn extract_channels_js(ctx: &mut ExtractCtx<'_>) {
    let consts = scan_string_consts_js(ctx.root, ctx.source);
    let mut stack = vec![ctx.root];
    while let Some(node) = stack.pop() {
        if node.kind() == "call_expression" {
            js_process_call(ctx, node, &consts);
        }
        for i in (0..node.child_count()).rev() {
            if let Some(c) = node.child(i) {
                stack.push(c);
            }
        }
    }
}

// ═══ Python ═════════════════════════════════════════════════════

/// Classify receiver (C py_classify_receiver).
fn py_classify_receiver(object_text: &str) -> Option<&'static str> {
    let tail = receiver_tail(object_text);
    // python-socketio
    if matches!(tail, "sio" | "socketio" | "socket") {
        return Some("socketio");
    }
    // Django Channels
    if tail == "channel_layer" {
        return Some("django_channels");
    }
    // FastAPI/Starlette WebSocket
    if tail == "websocket" || tail == "ws" {
        return Some("websocket");
    }
    // kafka-python
    if tail == "producer" || tail == "consumer" {
        return Some("kafka");
    }
    None
}

/// Table-driven Python method→direction (C py_method_table). None
/// transport = wildcard (socketio fallback).
const PY_METHOD_TABLE: &[(Option<&str>, &str, i32)] = &[
    (Some("kafka"), "send", 1),
    (Some("kafka"), "produce", 1),
    (Some("kafka"), "subscribe", 2),
    (Some("kafka"), "poll", 2),
    (Some("django_channels"), "send", 1),
    (Some("django_channels"), "group_send", 1),
    (Some("django_channels"), "receive", 2),
    (Some("django_channels"), "group_add", 2),
    (Some("websocket"), "send", 1),
    (Some("websocket"), "send_text", 1),
    (Some("websocket"), "send_json", 1),
    (Some("websocket"), "send_bytes", 1),
    (Some("websocket"), "receive", 2),
    (Some("websocket"), "receive_text", 2),
    (Some("websocket"), "receive_json", 2),
    (Some("websocket"), "receive_bytes", 2),
    (None, "emit", 1),
    (None, "send", 1),
    (None, "on", 2),
];

/// 1 = emit, 2 = listen (matching the C's encoding of CBM_CHANNEL_*).
fn py_classify_direction(transport: &str, method: &str) -> i32 {
    for (t, m, dir) in PY_METHOD_TABLE {
        if let Some(t) = t {
            if *t != transport {
                continue;
            }
        }
        if *m == method {
            return *dir;
        }
    }
    CHAN_DIR_UNKNOWN
}

fn py_process_call(ctx: &mut ExtractCtx<'_>, call: Node<'_>, consts: &ConstTable) {
    // Python call: attribute { object, attribute }, argument_list.
    let Some(func) = call.child_by_field_name("function") else {
        return;
    };
    if func.kind() != "attribute" {
        return;
    }
    let (Some(object), Some(attr)) = (
        func.child_by_field_name("object"),
        func.child_by_field_name("attribute"),
    ) else {
        return;
    };
    let method = node_text(attr, ctx.source);
    let Some(transport) = py_classify_receiver(node_text(object, ctx.source)) else {
        return;
    };
    let dir = py_classify_direction(transport, method);
    if dir == CHAN_DIR_UNKNOWN {
        return;
    }
    let direction = if dir == 1 {
        ChannelDirection::Emit
    } else {
        ChannelDirection::Listen
    };
    let Some(args) = call.child_by_field_name("arguments") else {
        return;
    };
    let Some(channel_name) = extract_channel_name(args, Some(consts), ctx.source) else {
        return;
    };
    push_channel(ctx, &channel_name, transport, direction, call);
}

/// Decorator-based listeners: @sio.on("event") (C py_process_decorator).
fn py_process_decorator(ctx: &mut ExtractCtx<'_>, decorator: Node<'_>, consts: &ConstTable) {
    let Some(expr) = decorator.named_child(0) else {
        return;
    };
    if expr.kind() != "call" {
        return;
    }
    let Some(func) = expr.child_by_field_name("function") else {
        return;
    };
    if func.kind() != "attribute" {
        return;
    }
    let (Some(object), Some(attr)) = (
        func.child_by_field_name("object"),
        func.child_by_field_name("attribute"),
    ) else {
        return;
    };
    if node_text(attr, ctx.source) != "on" {
        return;
    }
    let Some(transport) = py_classify_receiver(node_text(object, ctx.source)) else {
        return;
    };
    let Some(args) = expr.child_by_field_name("arguments") else {
        return;
    };
    let Some(channel_name) = extract_channel_name(args, Some(consts), ctx.source) else {
        return;
    };
    push_channel(
        ctx,
        &channel_name,
        transport,
        ChannelDirection::Listen,
        decorator,
    );
}

fn extract_channels_python(ctx: &mut ExtractCtx<'_>) {
    let consts = scan_string_consts_python(ctx.root, ctx.source);
    let mut stack = vec![ctx.root];
    while let Some(node) = stack.pop() {
        match node.kind() {
            "call" => py_process_call(ctx, node, &consts),
            "decorator" => py_process_decorator(ctx, node, &consts),
            _ => {}
        }
        for i in (0..node.child_count()).rev() {
            if let Some(c) = node.child(i) {
                stack.push(c);
            }
        }
    }
}

// ═══ Go ═════════════════════════════════════════════════════════

fn go_process_call(ctx: &mut ExtractCtx<'_>, call: Node<'_>) {
    let Some(func) = call.child_by_field_name("function") else {
        return;
    };
    if func.kind() != "selector_expression" {
        return;
    }
    let (Some(field), Some(operand)) = (
        func.child_by_field_name("field"),
        func.child_by_field_name("operand"),
    ) else {
        return;
    };
    let direction = match node_text(field, ctx.source) {
        "WriteMessage" | "WriteJSON" | "Write" => ChannelDirection::Emit,
        "ReadMessage" | "ReadJSON" | "Read" => ChannelDirection::Listen,
        _ => return,
    };
    // Verify receiver looks like a websocket connection.
    let tail = receiver_tail(node_text(operand, ctx.source));
    if !matches!(tail, "conn" | "wsConn" | "ws" | "c" | "Conn" | "connection") {
        return;
    }
    // Go WebSocket is connection-level: the enclosing function name is the
    // pseudo-channel for cross-repo matching.
    let func_name = enclosing_function_qn(call, ctx.source);
    let channel_name = if func_name.is_empty() {
        "(websocket)"
    } else {
        &func_name
    };
    push_channel(ctx, channel_name, "websocket", direction, call);
}

fn extract_channels_go(ctx: &mut ExtractCtx<'_>) {
    let mut stack = vec![ctx.root];
    while let Some(node) = stack.pop() {
        if node.kind() == "call_expression" {
            go_process_call(ctx, node);
        }
        for i in (0..node.child_count()).rev() {
            if let Some(c) = node.child(i) {
                stack.push(c);
            }
        }
    }
}

// ═══ Java / Kotlin ══════════════════════════════════════════════

fn java_process_call(ctx: &mut ExtractCtx<'_>, call: Node<'_>) {
    let Some(func) = call.child_by_field_name("name") else {
        return;
    };
    let method = node_text(func, ctx.source);
    // Spring STOMP: template.convertAndSend("/topic/...", msg).
    if method == "convertAndSend" || method == "convertAndSendToUser" {
        if let Some(args) = call.child_by_field_name("arguments") {
            if let Some(channel_name) = extract_channel_name(args, None, ctx.source) {
                push_channel(
                    ctx,
                    &channel_name,
                    "spring_websocket",
                    ChannelDirection::Emit,
                    call,
                );
            }
        }
        return;
    }
    // JSR 356: session.getBasicRemote().sendText(msg).
    if matches!(method, "sendText" | "sendObject" | "sendBinary") {
        let func_name = enclosing_function_qn(call, ctx.source);
        let channel_name = if func_name.is_empty() {
            "(websocket)"
        } else {
            &func_name
        };
        push_channel(ctx, channel_name, "websocket", ChannelDirection::Emit, call);
    }
}

/// Annotation-based listeners: @OnMessage / @MessageMapping / @ServerEndpoint
/// (C java_process_annotation).
fn java_process_annotation(ctx: &mut ExtractCtx<'_>, annotation: Node<'_>) {
    let Some(name_node) = annotation.child_by_field_name("name") else {
        return;
    };
    let name = node_text(name_node, ctx.source);
    if matches!(name, "OnMessage" | "OnOpen" | "OnClose") {
        let func_name = enclosing_function_qn(annotation, ctx.source);
        let channel_name = if func_name.is_empty() {
            "(websocket)"
        } else {
            &func_name
        };
        push_channel(
            ctx,
            channel_name,
            "websocket",
            ChannelDirection::Listen,
            annotation,
        );
    } else if name == "MessageMapping" {
        // @MessageMapping("/path") — extract the path.
        if let Some(args) = annotation.child_by_field_name("arguments") {
            if let Some(path) = extract_channel_name(args, None, ctx.source) {
                push_channel(
                    ctx,
                    &path,
                    "spring_websocket",
                    ChannelDirection::Listen,
                    annotation,
                );
                return;
            }
        }
        push_channel(
            ctx,
            "(spring_ws)",
            "spring_websocket",
            ChannelDirection::Listen,
            annotation,
        );
    } else if name == "ServerEndpoint" {
        if let Some(args) = annotation.child_by_field_name("arguments") {
            if let Some(path) = extract_channel_name(args, None, ctx.source) {
                push_channel(
                    ctx,
                    &path,
                    "websocket",
                    ChannelDirection::Listen,
                    annotation,
                );
            }
        }
    }
}

fn extract_channels_java(ctx: &mut ExtractCtx<'_>) {
    let mut stack = vec![ctx.root];
    while let Some(node) = stack.pop() {
        match node.kind() {
            "method_invocation" => java_process_call(ctx, node),
            "marker_annotation" | "annotation" => java_process_annotation(ctx, node),
            _ => {}
        }
        for i in (0..node.child_count()).rev() {
            if let Some(c) = node.child(i) {
                stack.push(c);
            }
        }
    }
}

// ═══ C# ═════════════════════════════════════════════════════════

fn csharp_process_call(ctx: &mut ExtractCtx<'_>, call: Node<'_>) {
    let Some(func) = call.child_by_field_name("function") else {
        return;
    };
    if func.kind() != "member_access_expression" {
        return;
    }
    let Some(name_node) = func.child_by_field_name("name") else {
        return;
    };
    let method = node_text(name_node, ctx.source);
    // SignalR: Clients.All.SendAsync("method", data).
    if method == "SendAsync" || method == "SendCoreAsync" {
        let full = node_text(func, ctx.source);
        if full.contains("Clients") || full.contains("clients") {
            if let Some(args) = call.child_by_field_name("arguments") {
                if let Some(channel_name) = extract_channel_name(args, None, ctx.source) {
                    push_channel(ctx, &channel_name, "signalr", ChannelDirection::Emit, call);
                }
            }
        }
        return;
    }
    // SignalR: connection.On<T>("method", handler).
    if method == "On" {
        if let Some(args) = call.child_by_field_name("arguments") {
            if let Some(channel_name) = extract_channel_name(args, None, ctx.source) {
                push_channel(
                    ctx,
                    &channel_name,
                    "signalr",
                    ChannelDirection::Listen,
                    call,
                );
            }
        }
    }
}

fn extract_channels_csharp(ctx: &mut ExtractCtx<'_>) {
    let mut stack = vec![ctx.root];
    while let Some(node) = stack.pop() {
        if node.kind() == "invocation_expression" {
            csharp_process_call(ctx, node);
        }
        for i in (0..node.child_count()).rev() {
            if let Some(c) = node.child(i) {
                stack.push(c);
            }
        }
    }
}

// ═══ Ruby ═══════════════════════════════════════════════════════

fn ruby_process_call(ctx: &mut ExtractCtx<'_>, call: Node<'_>) {
    if call.kind() != "call" {
        return;
    }
    let Some(method_node) = call.child_by_field_name("method") else {
        return;
    };
    let method = node_text(method_node, ctx.source);
    // ActionCable.server.broadcast("channel", data).
    if method == "broadcast" {
        if let Some(args) = call.child_by_field_name("arguments") {
            if let Some(channel_name) = extract_channel_name(args, None, ctx.source) {
                push_channel(
                    ctx,
                    &channel_name,
                    "actioncable",
                    ChannelDirection::Emit,
                    call,
                );
            }
        }
        return;
    }
    // stream_from "channel" — listener registration.
    if method == "stream_from" || method == "stream_for" {
        if let Some(args) = call.child_by_field_name("arguments") {
            if let Some(channel_name) = extract_channel_name(args, None, ctx.source) {
                push_channel(
                    ctx,
                    &channel_name,
                    "actioncable",
                    ChannelDirection::Listen,
                    call,
                );
            }
        }
    }
}

fn extract_channels_ruby(ctx: &mut ExtractCtx<'_>) {
    let mut stack = vec![ctx.root];
    while let Some(node) = stack.pop() {
        if node.kind() == "call" {
            ruby_process_call(ctx, node);
        }
        for i in (0..node.child_count()).rev() {
            if let Some(c) = node.child(i) {
                stack.push(c);
            }
        }
    }
}

// ═══ Elixir ═════════════════════════════════════════════════════

/// Literal from the Nth named child of an args node (C
/// elixir_nth_arg_literal).
fn elixir_nth_arg_literal<'s>(args: Node<'_>, index: usize, source: &'s str) -> Option<&'s str> {
    let arg = args.named_child(index)?;
    literal_from_arg(arg, source).or_else(|| literal_from_first_child(arg, source))
}

/// Emit a channel from the second argument of an Elixir call (C
/// elixir_emit_second_arg).
fn elixir_emit_second_arg(
    ctx: &mut ExtractCtx<'_>,
    call: Node<'_>,
    args: Option<Node<'_>>,
    transport: &str,
    direction: ChannelDirection,
) {
    let Some(args) = args else { return };
    if let Some(val) = elixir_nth_arg_literal(args, 1, ctx.source) {
        push_channel(ctx, val, transport, direction, call);
    }
}

fn elixir_process_call(ctx: &mut ExtractCtx<'_>, call: Node<'_>) {
    let Some(target) = call.child_by_field_name("target") else {
        return;
    };
    let target_text = node_text(target, ctx.source);
    let args = call.child_by_field_name("arguments");

    if target_text.contains("PubSub.broadcast") || target_text.contains("PubSub.local_broadcast") {
        elixir_emit_second_arg(ctx, call, args, "phoenix_pubsub", ChannelDirection::Emit);
    } else if target_text.contains("PubSub.subscribe") {
        elixir_emit_second_arg(ctx, call, args, "phoenix_pubsub", ChannelDirection::Listen);
    } else if matches!(target_text, "push" | "broadcast" | "broadcast!") {
        elixir_emit_second_arg(ctx, call, args, "phoenix_channel", ChannelDirection::Emit);
    }
}

/// handle_in("event", payload, socket) — Phoenix Channel listener (C
/// elixir_process_function_def).
fn elixir_process_function_def(ctx: &mut ExtractCtx<'_>, func_def: Node<'_>) {
    let Some(name_node) = func_def.child_by_field_name("name") else {
        return;
    };
    if node_text(name_node, ctx.source) != "handle_in" {
        return;
    }
    // First parameter is the event name pattern.
    let Some(params) = func_def.child_by_field_name("parameters") else {
        return;
    };
    let Some(first_param) = params.named_child(0) else {
        return;
    };
    if let Some(val) = literal_from_arg(first_param, ctx.source)
        .or_else(|| literal_from_first_child(first_param, ctx.source))
    {
        push_channel(
            ctx,
            val,
            "phoenix_channel",
            ChannelDirection::Listen,
            func_def,
        );
    }
}

fn extract_channels_elixir(ctx: &mut ExtractCtx<'_>) {
    let mut stack = vec![ctx.root];
    while let Some(node) = stack.pop() {
        match node.kind() {
            "call" => elixir_process_call(ctx, node),
            "def" => elixir_process_function_def(ctx, node),
            _ => {}
        }
        for i in (0..node.child_count()).rev() {
            if let Some(c) = node.child(i) {
                stack.push(c);
            }
        }
    }
}

// ═══ Rust ═══════════════════════════════════════════════════════

fn rust_process_call(ctx: &mut ExtractCtx<'_>, call: Node<'_>) {
    let Some(func) = call.child_by_field_name("function") else {
        return;
    };
    if func.kind() != "field_expression" {
        return;
    }
    let (Some(field), Some(value)) = (
        func.child_by_field_name("field"),
        func.child_by_field_name("value"),
    ) else {
        return;
    };
    let direction = match node_text(field, ctx.source) {
        "send" | "send_all" | "feed" => ChannelDirection::Emit,
        "next" | "try_next" => ChannelDirection::Listen,
        _ => return,
    };
    // Verify receiver looks like a websocket sink/stream.
    let tail = receiver_tail(node_text(value, ctx.source));
    if !matches!(
        tail,
        "sink"
            | "ws_sender"
            | "writer"
            | "write"
            | "stream"
            | "ws_receiver"
            | "reader"
            | "read"
            | "ws_stream"
            | "ws"
    ) {
        return;
    }
    let func_name = enclosing_function_qn(call, ctx.source);
    let channel_name = if func_name.is_empty() {
        "(websocket)"
    } else {
        &func_name
    };
    push_channel(ctx, channel_name, "websocket", direction, call);
}

fn extract_channels_rust(ctx: &mut ExtractCtx<'_>) {
    let mut stack = vec![ctx.root];
    while let Some(node) = stack.pop() {
        if node.kind() == "call_expression" {
            rust_process_call(ctx, node);
        }
        for i in (0..node.child_count()).rev() {
            if let Some(c) = node.child(i) {
                stack.push(c);
            }
        }
    }
}

// ═══ Entry point — language dispatch ════════════════════════════

/// Public entry (C cbm_extract_channels).
pub fn extract_channels(ctx: &mut ExtractCtx<'_>) {
    match ctx.language {
        Language::JAVASCRIPT | Language::TYPESCRIPT | Language::TSX | Language::ARKTS => {
            extract_channels_js(ctx)
        }
        Language::PYTHON => extract_channels_python(ctx),
        Language::GO => extract_channels_go(ctx),
        Language::JAVA | Language::KOTLIN => extract_channels_java(ctx),
        Language::CSHARP => extract_channels_csharp(ctx),
        Language::RUBY => extract_channels_ruby(ctx),
        Language::ELIXIR => extract_channels_elixir(ctx),
        Language::RUST => extract_channels_rust(ctx),
        _ => {} // no channel detection for this language
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    type ChanSummary = (String, String, String, u8); // name, transport, enclosing, 0=emit 1=listen

    fn run(lang: Language, source: &str) -> Vec<ChanSummary> {
        let Some(tree) = crate::ts::parse(lang, source) else {
            return Vec::new(); // grammar not compiled in → nothing extracted
        };
        let mut ctx = ExtractCtx {
            source,
            root: tree.root_node(),
            language: lang,
            project: "proj",
            rel_path: "f",
            module_qn: "proj.f".to_string(),
            ef_cache: Default::default(),
            result: Default::default(),
            constants: Vec::new(),
        };
        extract_channels(&mut ctx);
        ctx.result
            .channels
            .iter()
            .map(|c| {
                (
                    c.channel_name.clone(),
                    c.transport.clone(),
                    c.enclosing_func_qn.clone(),
                    match c.direction {
                        ChannelDirection::Emit => 0,
                        ChannelDirection::Listen => 1,
                    },
                )
            })
            .collect()
    }

    #[test]
    fn js_socketio_emit_and_listen() {
        let src = r#"
io.on("connection", (socket) => {
  socket.emit("user.created", data);
  socket.on("chat.message", handler);
});
"#;
        let chans = run(Language::JAVASCRIPT, src);
        // io.on("connection", cb) is itself a socketio listen (C behavior).
        assert_eq!(chans.len(), 3, "{chans:?}");
        assert_eq!(
            chans[0],
            ("connection".into(), "socketio".into(), String::new(), 1)
        );
        assert_eq!(
            chans[1],
            ("user.created".into(), "socketio".into(), String::new(), 0)
        );
        assert_eq!(
            chans[2],
            ("chat.message".into(), "socketio".into(), String::new(), 1)
        );
    }

    #[test]
    fn js_event_emitter_in_function() {
        let src = r#"
function setup(bus) {
  bus.emit("order.placed", order);
}
const e = new events.EventEmitter();
e.addListener("tick", onTick);
"#;
        let chans = run(Language::JAVASCRIPT, src);
        // `e.addListener(...)` has an identifier callee — the C only walks
        // member_expression calls, so it is NOT recorded.
        assert_eq!(chans.len(), 1, "{chans:?}");
        assert_eq!(chans[0].0, "order.placed");
        assert_eq!(chans[0].1, "event_emitter");
        assert_eq!(chans[0].2, "setup");
    }

    #[test]
    fn js_const_table_resolution() {
        let src = r#"
const EVENT_NAME = "user.signup";
emitter.emit(EVENT_NAME, data);
"#;
        let chans = run(Language::JAVASCRIPT, src);
        assert_eq!(chans.len(), 1);
        assert_eq!(chans[0].0, "user.signup");
    }

    #[test]
    fn js_kafka_and_rabbitmq() {
        // Object-literal arguments carry no string literal, so only the
        // string-arg calls below produce channels (C parity).
        let src = r#"
producer.send("events");
consumer.subscribe("events");
conn.channel.publish("amq.direct", "key", buf);
conn.channel.consume("queue", handler);
socket.emit("x");
"#;
        let chans = run(Language::JAVASCRIPT, src);
        assert_eq!(chans.len(), 5, "{chans:?}");
        assert_eq!(&chans[0].1, "kafka");
        assert_eq!(chans[0].3, 0);
        assert_eq!(&chans[1].1, "kafka");
        assert_eq!(chans[1].3, 1);
        assert_eq!(&chans[2].1, "rabbitmq");
        assert_eq!(&chans[3].1, "rabbitmq");
        assert_eq!(&chans[4].0, "x");
    }

    #[test]
    fn python_calls_and_decorators() {
        let src = r#"
@sio.on("connect")
def on_connect():
    pass

await sio.emit("update", data)
channel_layer.group_send("room1", msg)
ws.receive_text()
EVENT = "const_event"
sio.on(EVENT)
"#;
        let chans = run(Language::PYTHON, src);
        // The decorator's inner call node is visited by BOTH the decorator
        // path and the generic call path — the C's walk records it twice
        // (upstream quirk, kept 1:1). ws.receive_text() has no arguments →
        // no channel.
        assert_eq!(chans.len(), 5, "{chans:?}");
        assert_eq!(&chans[0].0, "connect");
        assert_eq!(&chans[0].1, "socketio");
        assert_eq!(&chans[1].0, "connect");
        assert_eq!(&chans[2].0, "update");
        assert_eq!(&chans[3].0, "room1");
        assert_eq!(&chans[3].1, "django_channels");
        assert_eq!(&chans[4].0, "const_event", "const table must resolve");
    }

    #[test]
    fn go_websocket_conn() {
        let src = r#"
func pump(conn *ws.Conn) {
    conn.WriteMessage(1, data)
    msg, _ := conn.ReadMessage()
}
"#;
        let chans = run(Language::GO, src);
        assert_eq!(chans.len(), 2, "{chans:?}");
        assert_eq!(chans[0].0, "pump");
        assert_eq!(chans[0].1, "websocket");
        assert_eq!(chans[0].3, 0);
        assert_eq!(chans[1].3, 1);
    }

    #[test]
    fn java_stomp_and_annotations() {
        let src = r#"
import org.springframework.messaging.handler.annotation.MessageMapping;

template.convertAndSend("/topic/updates", payload);

@MessageMapping("/hello")
public void handle() {}

@OnMessage
public void onMessage(Session s) {}
"#;
        let chans = run(Language::JAVA, src);
        assert_eq!(chans.len(), 3, "{chans:?}");
        assert_eq!(&chans[0].0, "/topic/updates");
        assert_eq!(&chans[0].1, "spring_websocket");
        assert_eq!(&chans[1].0, "/hello");
        assert_eq!(&chans[2].1, "websocket");
    }

    #[test]
    fn csharp_signalr() {
        let src = r#"
public async Task Send() {
    await Clients.All.SendAsync("receiveMessage", msg);
}
connection.On("notify", handler);
"#;
        let chans = run(Language::CSHARP, src);
        assert_eq!(chans.len(), 2, "{chans:?}");
        assert_eq!(&chans[0].0, "receiveMessage");
        assert_eq!(&chans[0].1, "signalr");
        assert_eq!(chans[0].3, 0);
        assert_eq!(&chans[1].0, "notify");
        assert_eq!(chans[1].3, 1);
    }

    #[test]
    fn ruby_actioncable() {
        let src = r#"
ActionCable.server.broadcast("room_channel", message: msg)
stream_from "room_channel"
"#;
        let chans = run(Language::RUBY, src);
        assert_eq!(chans.len(), 2, "{chans:?}");
        assert_eq!(&chans[0].0, "room_channel");
        assert_eq!(chans[0].3, 0);
        assert_eq!(chans[1].3, 1);
    }

    #[test]
    fn elixir_pubsub_and_handle_in() {
        let src = r#"
defmodule X do
  def broadcast(topic, msg) do
    Phoenix.PubSub.broadcast(MyApp.PubSub, topic, msg)
  end

  def sub(topic), do: Phoenix.PubSub.subscribe(MyApp.PubSub, topic)

  def handle_in("new_msg", payload, socket) do
    {:ok, socket}
  end
end
"#;
        // Three upstream blind spots, all kept 1:1: (a) neither the
        // vendored nor the crates.io elixir grammar exposes an
        // `arguments` FIELD on call nodes, so every
        // elixir_emit_second_arg bails; (b) `def` is a call node, not a
        // dedicated symbol, in both grammars, so
        // elixir_process_function_def never fires; (c) net effect — the C
        // produces NO channels for elixir, and so does this port.
        let chans = run(Language::ELIXIR, src);
        assert!(chans.is_empty(), "{chans:?}");
    }

    #[test]
    fn rust_tokio_tungstenite() {
        let src = r#"
async fn forward(ws_stream: WebSocketStream) {
    while let Some(msg) = ws_stream.next().await {
        sink.send(msg).await;
    }
}
"#;
        let chans = run(Language::RUST, src);
        assert_eq!(chans.len(), 2, "{chans:?}");
        assert_eq!(chans[0].0, "forward");
        assert_eq!(chans[0].1, "websocket");
        assert_eq!(chans[1].3, 0);
    }

    #[test]
    fn unsupported_language_noop() {
        let chans = run(Language::C, "int main() { return 0; }");
        assert!(chans.is_empty());
    }
}
