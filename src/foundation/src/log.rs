//! log.rs — 1:1 rewrite of `src/foundation/log.{c,h}`.
//!
//! Level-filtered, structured key=value logging to stderr with an optional
//! sink override. Text format `level=X msg=E k=v` and JSON format are both
//! supported; control records bypass level suppression and are always JSON.

use std::fmt::Write as _;
use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub enum Level {
    Debug = 0,
    Info = 1,
    Warn = 2,
    Error = 3,
    None = 4,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    Text,
    Json,
}

impl Level {
    fn as_str(self) -> &'static str {
        match self {
            Level::Debug => "debug",
            Level::Info => "info",
            Level::Warn => "warn",
            Level::Error => "error",
            Level::None => "none",
        }
    }
}

static LOG_LEVEL: AtomicU8 = AtomicU8::new(Level::Info as u8);
static LOG_FORMAT: AtomicU8 = AtomicU8::new(0); // Format::Text
static LOG_SINK_MODE: AtomicU8 = AtomicU8::new(0); // Replace
static LOG_CRASH_DURABLE: AtomicBool = AtomicBool::new(false);

type Sink = std::sync::Arc<dyn Fn(&str) + Send + Sync>;
static SINK: std::sync::RwLock<Option<Sink>> = std::sync::RwLock::new(None);

/// Install a sink. Replace mode: sink output only. Tee mode: sink + stderr.
pub fn set_sink(f: Sink, tee: bool) {
    if let Ok(mut slot) = SINK.write() {
        *slot = Some(f);
    }
    LOG_SINK_MODE.store(if tee { 1 } else { 0 }, Ordering::Relaxed);
}

pub fn set_level(level: Level) {
    LOG_LEVEL.store(level as u8, Ordering::Relaxed);
}

pub fn get_level() -> Level {
    match LOG_LEVEL.load(Ordering::Relaxed) {
        0 => Level::Debug,
        1 => Level::Info,
        2 => Level::Warn,
        3 => Level::Error,
        _ => Level::None,
    }
}

pub fn set_format(format: Format) {
    LOG_FORMAT.store(
        match format {
            Format::Text => 0,
            Format::Json => 1,
        },
        Ordering::Relaxed,
    );
}

pub fn get_format() -> Format {
    if LOG_FORMAT.load(Ordering::Relaxed) == 1 {
        Format::Json
    } else {
        Format::Text
    }
}

/// `CBM_LOG_LEVEL` = debug|info|warn|error|none (or 0-4); invalid → default.
pub fn init_from_env() {
    let Ok(raw) = std::env::var("CBM_LOG_LEVEL") else {
        return;
    };
    let level = match raw.to_ascii_lowercase().as_str() {
        "debug" | "0" => Level::Debug,
        "info" | "1" => Level::Info,
        "warn" | "2" => Level::Warn,
        "error" | "3" => Level::Error,
        "none" | "4" => Level::None,
        _ => return,
    };
    set_level(level);
}

pub fn set_crash_durable(enabled: bool) {
    LOG_CRASH_DURABLE.store(enabled, Ordering::Relaxed);
}

/// Append `s` as a quoted, escaped JSON string (mirrors append_json_string).
fn json_escape_into(out: &mut String, s: &str) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

/// Core entry: `level, event, &[(key, value), ...]`. Fields are stringly
/// typed like the C varargs form.
pub fn log(level: Level, event: &str, fields: &[(&str, &str)]) {
    if (level as u8) < LOG_LEVEL.load(Ordering::Relaxed) {
        return;
    }
    let mut line = String::with_capacity(256);
    if get_format() == Format::Json {
        line.push_str("{\"level\":");
        json_escape_into(&mut line, level.as_str());
        line.push_str(",\"event\":");
        json_escape_into(&mut line, event);
        for (k, v) in fields {
            line.push(',');
            json_escape_into(&mut line, k);
            line.push(':');
            json_escape_into(&mut line, v);
        }
        line.push('}');
    } else {
        line.push_str("level=");
        line.push_str(level.as_str());
        line.push_str(" msg=");
        line.push_str(event);
        for (k, v) in fields {
            line.push(' ');
            line.push_str(k);
            line.push('=');
            line.push_str(v);
        }
    }
    emit_line(&line);
}

/// Always-JSON control record; bypasses level suppression by design.
pub fn control_record(event: &str, fields: &[(&str, &str)]) {
    let mut line = String::with_capacity(256);
    line.push_str("{\"level\":\"control\",\"event\":");
    json_escape_into(&mut line, event);
    for (k, v) in fields {
        line.push(',');
        json_escape_into(&mut line, k);
        line.push(':');
        json_escape_into(&mut line, v);
    }
    line.push('}');
    emit_line(&line);
}

fn emit_line(line: &str) {
    let sink_called = SINK
        .read()
        .ok()
        .and_then(|guard| guard.clone())
        .map(|f| {
            f(line);
            true
        })
        .unwrap_or(false);
    if sink_called && LOG_SINK_MODE.load(Ordering::Relaxed) == 0 {
        return; // replace mode
    }
    eprintln!("{line}");
}

pub fn debug(event: &str, fields: &[(&str, &str)]) {
    log(Level::Debug, event, fields);
}
pub fn info(event: &str, fields: &[(&str, &str)]) {
    log(Level::Info, event, fields);
}
pub fn warn(event: &str, fields: &[(&str, &str)]) {
    log(Level::Warn, event, fields);
}
pub fn error(event: &str, fields: &[(&str, &str)]) {
    log(Level::Error, event, fields);
}

pub fn log_int(level: Level, event: &str, key: &str, value: i64) {
    log(level, event, &[(key, &value.to_string())]);
}

/// MCP request lifecycle line (warns on error, infos otherwise).
pub fn mcp_request(method: &str, tool_name: &str, is_error: bool, duration_us: i64) {
    let level = if is_error { Level::Warn } else { Level::Info };
    let duration_ms = (duration_us / 1000).to_string();
    let status = if is_error { "error" } else { "ok" };
    if !tool_name.is_empty() {
        log(
            level,
            "mcp.request",
            &[
                ("protocol", "jsonrpc"),
                ("method", method),
                ("tool", tool_name),
                ("status", status),
                ("duration_ms", &duration_ms),
            ],
        );
    } else {
        log(
            level,
            "mcp.request",
            &[
                ("protocol", "jsonrpc"),
                ("method", method),
                ("status", status),
                ("duration_ms", &duration_ms),
            ],
        );
    }
}

/// HTTP request line; path is stripped of query/fragment. Level from status.
pub fn http_request(
    component: &str,
    method: &str,
    path: &str,
    status: i32,
    duration_ms: i64,
    request_bytes: usize,
    response_bytes: usize,
) {
    let safe_path: String = path.chars().take_while(|&c| c != '?' && c != '#').collect();
    let level = if status >= 500 {
        Level::Error
    } else if status >= 400 {
        Level::Warn
    } else {
        Level::Info
    };
    log(
        level,
        "http.request",
        &[
            ("component", component),
            ("method", method),
            ("path", &safe_path),
            ("status", &status.to_string()),
            ("duration_ms", &duration_ms.to_string()),
            ("request_bytes", &request_bytes.to_string()),
            ("response_bytes", &response_bytes.to_string()),
        ],
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Log state (level/format/sink) is process-global; serialize tests.
    static STATE_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn install(g2: std::sync::Arc<std::sync::Mutex<String>>, tee: bool) {
        set_sink(
            std::sync::Arc::new(move |line: &str| *g2.lock().unwrap() = line.to_string()),
            tee,
        );
    }

    #[test]
    fn level_filtering_and_text_format() {
        let _g = STATE_LOCK.lock().unwrap();
        set_level(Level::Warn);
        set_format(Format::Text);
        let got = std::sync::Arc::new(std::sync::Mutex::new(String::new()));
        let g2 = got.clone();
        install(g2, false);
        info("filtered.out", &[("k", "v")]); // below level — must not hit sink
        warn("kept.msg", &[("a", "1"), ("b", "2")]);
        assert_eq!(
            got.lock().unwrap().as_str(),
            "level=warn msg=kept.msg a=1 b=2"
        );
        set_level(Level::Info);
    }

    #[test]
    fn json_format_and_control_bypass() {
        let _g = STATE_LOCK.lock().unwrap();
        set_level(Level::None); // suppress everything
        set_format(Format::Json);
        let got = std::sync::Arc::new(std::sync::Mutex::new(String::new()));
        let g2 = got.clone();
        install(g2, false);
        error("suppressed", &[]); // level None — not emitted
        control_record("ctrl", &[("k", "va\"l")]);
        assert_eq!(
            got.lock().unwrap().as_str(),
            "{\"level\":\"control\",\"event\":\"ctrl\",\"k\":\"va\\\"l\"}"
        );
        set_level(Level::Info);
        set_format(Format::Text);
    }

    #[test]
    fn tee_mode_also_writes_stderr_sink() {
        let _g = STATE_LOCK.lock().unwrap();
        set_level(Level::Info);
        let got = std::sync::Arc::new(std::sync::Mutex::new(String::new()));
        let g2 = got.clone();
        install(g2, true); // tee
        info("teed", &[("x", "y")]);
        assert_eq!(got.lock().unwrap().as_str(), "level=info msg=teed x=y");
    }

    #[test]
    fn mcp_request_shape() {
        let _g = STATE_LOCK.lock().unwrap();
        set_level(Level::Info);
        set_format(Format::Text);
        let got = std::sync::Arc::new(std::sync::Mutex::new(String::new()));
        let g2 = got.clone();
        install(g2, false);
        mcp_request("tools/call", "search_graph", false, 1500);
        assert_eq!(
            got.lock().unwrap().as_str(),
            "level=info msg=mcp.request protocol=jsonrpc method=tools/call tool=search_graph status=ok duration_ms=1"
        );
    }

    #[test]
    fn http_request_level_by_status() {
        let _g = STATE_LOCK.lock().unwrap();
        set_level(Level::Debug);
        set_format(Format::Text);
        let got = std::sync::Arc::new(std::sync::Mutex::new(String::new()));
        let g2 = got.clone();
        install(g2, false);
        http_request("ui", "GET", "/api/graph?x=1#frag", 404, 3, 10, 20);
        let line = got.lock().unwrap().clone();
        assert!(line.starts_with("level=warn msg=http.request"));
        assert!(line.contains("path=/api/graph")); // query/fragment stripped
        assert!(line.contains("status=404"));
    }

    #[test]
    fn init_from_env_parses_names_and_numbers() {
        let _g = STATE_LOCK.lock().unwrap();
        for (raw, want) in [
            ("debug", Level::Debug),
            ("WARN", Level::Warn),
            ("3", Level::Error),
            ("none", Level::None),
        ] {
            std::env::set_var("CBM_LOG_LEVEL", raw);
            init_from_env();
            assert_eq!(get_level(), want);
        }
        std::env::set_var("CBM_LOG_LEVEL", "bogus");
        init_from_env(); // invalid → unchanged (None from loop above)
        std::env::remove_var("CBM_LOG_LEVEL");
        set_level(Level::Info);
    }
}
