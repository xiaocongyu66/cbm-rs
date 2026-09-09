//! extract_imports.rs — 1:1 rewrite of `internal/cbm/extract_imports.c`
//! (3161 lines), part 1 of N: shared helpers, the Go / Python / ES
//! (JS-TS-TSX-ArkTS) / Java / Rust parsers, namespace capture, and the
//! dispatcher. The remaining per-language parsers land in later parts;
//! until then the dispatcher routes unported languages to no-op (matching
//! the C's per-language fan-out shape).

use crate::extract_env_accesses::ExtractCtx;
use crate::lang_specs::LanguageSpec;
use crate::types::Import;
use crate::Language;

// ── Shared helpers ──────────────────────────────────────────────

/// Strip one matching pair of surrounding quotes (C strip_quotes).
fn strip_quotes(s: &str) -> &str {
    let b = s.as_bytes();
    if b.len() >= 2 && (b[0] == b'"' || b[0] == b'\'') && b[b.len() - 1] == b[0] {
        return &s[1..b.len() - 1];
    }
    s
}

/// Last path component, recognizing every separator used across import
/// syntaxes: `/`, `.`, `::`, `\` — the LAST separator of any kind wins
/// (C path_last): "std::collections::HashMap" → "HashMap".
fn path_last(path: &str) -> &str {
    let last_sep = path
        .char_indices()
        .rev()
        .find(|(_, c)| matches!(c, '/' | '.' | ':' | '\\'));
    match last_sep {
        Some((i, _)) => {
            // '::' counts as one separator: skip the second colon too.
            let after = i + 1;
            if path.as_bytes().get(i) == Some(&b':') && path.as_bytes().get(after) == Some(&b':') {
                &path[after + 1..]
            } else {
                &path[i + 1..]
            }
        }
        None => path,
    }
}

/// An unaliased dotted Python import binds its FIRST component:
/// `import xml.etree` introduces `xml` (C python_import_root).
fn python_import_root(path: &str) -> &str {
    match path.find('.') {
        Some(i) => &path[..i],
        None => path,
    }
}

fn push_import(ctx: &mut ExtractCtx<'_>, local_name: &str, module_path: &str) {
    ctx.result.imports.push(Import {
        local_name: local_name.to_string(),
        module_path: module_path.to_string(),
    });
}

// ── Go ──────────────────────────────────────────────────────────

/// One import_spec: path (quoted) + optional name (alias)
/// (C parse_go_import_spec).
fn parse_go_import_spec(ctx: &mut ExtractCtx<'_>, spec: tree_sitter::Node<'_>) {
    let Some(path_node) = spec.child_by_field_name("path") else {
        return;
    };
    let path = strip_quotes(crate::fqn::node_text(path_node, ctx.source));
    if path.is_empty() {
        return;
    }
    let local_name = match spec.child_by_field_name("name") {
        Some(n) => crate::fqn::node_text(n, ctx.source),
        None => path_last(path),
    };
    push_import(ctx, local_name, path);
}

/// Top-level import_declaration walk (C parse_go_imports).
fn parse_go_imports(ctx: &mut ExtractCtx<'_>) {
    let root = ctx.root;
    let mut cursor = root.walk();
    if !cursor.goto_first_child() {
        return;
    }
    loop {
        let decl = cursor.node();
        if decl.kind() == "import_declaration" {
            for j in 0..decl.child_count() {
                let child = decl.child(j).unwrap();
                match child.kind() {
                    "import_spec" => parse_go_import_spec(ctx, child),
                    "import_spec_list" => {
                        for k in 0..child.child_count() {
                            let spec = child.child(k).unwrap();
                            if spec.kind() == "import_spec" {
                                parse_go_import_spec(ctx, spec);
                            }
                        }
                    }
                    _ => {}
                }
            }
        }
        if !cursor.goto_next_sibling() {
            break;
        }
    }
}

// ── Python ──────────────────────────────────────────────────────

/// Module node for import_from: `module_name` field, else first
/// dotted_name/relative_import child (C resolve_py_module_node).
fn resolve_py_module_node<'t>(node: tree_sitter::Node<'t>) -> Option<tree_sitter::Node<'t>> {
    if let Some(m) = node.child_by_field_name("module_name") {
        return Some(m);
    }
    for j in 0..node.child_count() {
        let c = node.child(j)?;
        if matches!(c.kind(), "dotted_name" | "relative_import") {
            return Some(c);
        }
    }
    None
}

/// Aliased import emission (C emit_py_aliased_import).
fn emit_py_aliased_import(
    ctx: &mut ExtractCtx<'_>,
    child: tree_sitter::Node<'_>,
    mod_prefix: Option<&str>,
) {
    let mod_node = child.child_by_field_name("name");
    let alias_node = child.child_by_field_name("alias");
    let Some(mod_node) = mod_node else { return };
    let name = crate::fqn::node_text(mod_node, ctx.source);
    if name.is_empty() {
        return;
    }
    let local = match alias_node {
        Some(a) => crate::fqn::node_text(a, ctx.source),
        None => path_last(name),
    };
    let full = match mod_prefix {
        Some(p) => format!("{p}.{name}"),
        None => name.to_string(),
    };
    push_import(ctx, local, &full);
}

/// import_statement: `import X` / `import X as Y` / `import a.b, c`
/// (C process_py_import_stmt).
fn process_py_import_stmt(ctx: &mut ExtractCtx<'_>, node: tree_sitter::Node<'_>) {
    match node.child_by_field_name("name") {
        None => {
            for j in 0..node.child_count() {
                let child = node.child(j).unwrap();
                match child.kind() {
                    "dotted_name" | "identifier" => {
                        let m = crate::fqn::node_text(child, ctx.source);
                        if !m.is_empty() {
                            push_import(ctx, python_import_root(m), m);
                        }
                    }
                    "aliased_import" => emit_py_aliased_import(ctx, child, None),
                    _ => {}
                }
            }
        }
        Some(name_node) => {
            if name_node.kind() == "aliased_import" {
                // `import util as u` — name field points at the
                // aliased_import; extract its real module name.
                emit_py_aliased_import(ctx, name_node, None);
            } else {
                let m = crate::fqn::node_text(name_node, ctx.source);
                if !m.is_empty() {
                    push_import(ctx, python_import_root(m), m);
                }
            }
        }
    }
}

/// from-import name child (identifier/dotted_name)
/// (C emit_py_import_from_name).
fn emit_py_import_from_name(
    ctx: &mut ExtractCtx<'_>,
    child: tree_sitter::Node<'_>,
    mod_path: Option<&str>,
) {
    let name = crate::fqn::node_text(child, ctx.source);
    if !name.is_empty() {
        let full = match mod_path {
            Some(p) => format!("{p}.{name}"),
            None => name.to_string(),
        };
        push_import(ctx, name, &full);
    }
}

/// import_from_statement (C process_py_import_from).
fn process_py_import_from(ctx: &mut ExtractCtx<'_>, node: tree_sitter::Node<'_>) {
    // `from __future__ import annotations` is a dedicated node type.
    if node.kind() == "future_import_statement" {
        push_import(ctx, "__future__", "__future__");
        return;
    }
    let module_node = resolve_py_module_node(node);
    let mod_path = module_node.map(|m| crate::fqn::node_text(m, ctx.source));

    let mut emitted = false;
    for j in 0..node.child_count() {
        let child = node.child(j).unwrap();
        let ck = child.kind();
        if matches!(ck, "identifier" | "dotted_name") {
            if let Some(m) = module_node {
                if child.start_byte() == m.start_byte() {
                    continue; // the module itself
                }
            }
            emit_py_import_from_name(ctx, child, mod_path);
            emitted = true;
        } else if ck == "aliased_import" {
            emit_py_aliased_import(ctx, child, mod_path);
            emitted = true;
        } else if ck == "wildcard_import" {
            // `from os.path import *` — the module itself is the import.
            if let Some(mp) = mod_path {
                if !mp.is_empty() {
                    push_import(ctx, path_last(mp), mp);
                    emitted = true;
                }
            }
        }
    }
    // Defensive: a from-import with a module but no recognized name child
    // still records the module.
    if !emitted {
        if let Some(mp) = mod_path {
            if !mp.is_empty() {
                push_import(ctx, path_last(mp), mp);
            }
        }
    }
}

/// Python walk: top-level import statements (C parse_python_imports).
fn parse_python_imports(ctx: &mut ExtractCtx<'_>) {
    let root = ctx.root;
    let mut cursor = root.walk();
    if !cursor.goto_first_child() {
        return;
    }
    loop {
        let node = cursor.node();
        match node.kind() {
            "import_statement" => process_py_import_stmt(ctx, node),
            "import_from_statement" | "future_import_statement" => {
                process_py_import_from(ctx, node)
            }
            _ => {}
        }
        if !cursor.goto_next_sibling() {
            break;
        }
    }
}

// ── ES modules (JS / TS / TSX / ArkTS) ──────────────────────────

/// Source string node in an ES import_statement (C find_es_source_node).
fn find_es_source_node<'t>(node: tree_sitter::Node<'t>) -> Option<tree_sitter::Node<'t>> {
    if let Some(s) = node.child_by_field_name("source") {
        return Some(s);
    }
    for j in (0..node.child_count()).rev() {
        let c = node.child(j)?;
        if matches!(c.kind(), "string" | "string_literal") {
            return Some(c);
        }
    }
    None
}

/// named_imports: `import {A, B as C} from "path"` (C process_named_imports).
fn process_named_imports(ctx: &mut ExtractCtx<'_>, sub: tree_sitter::Node<'_>, path: &str) -> bool {
    let mut found = false;
    for m in 0..sub.child_count() {
        let imp_spec = sub.child(m).unwrap();
        if imp_spec.kind() != "import_specifier" {
            continue;
        }
        let local = imp_spec.child_by_field_name("alias");
        let orig = imp_spec.child_by_field_name("name").or_else(|| {
            if imp_spec.child_count() > 0 {
                imp_spec.child(0)
            } else {
                None
            }
        });
        if let Some(orig) = orig {
            let local_name = match local {
                Some(l) => crate::fqn::node_text(l, ctx.source),
                None => crate::fqn::node_text(orig, ctx.source),
            };
            push_import(ctx, local_name, path);
            found = true;
        }
    }
    found
}

/// import_clause: default, namespace, named imports
/// (C process_import_clause). Falls back to the path's last component.
fn process_import_clause(
    ctx: &mut ExtractCtx<'_>,
    clause: tree_sitter::Node<'_>,
    path: &str,
) -> bool {
    let mut found = false;
    for k in 0..clause.child_count() {
        let sub = clause.child(k).unwrap();
        match sub.kind() {
            "identifier" => {
                let name = crate::fqn::node_text(sub, ctx.source);
                push_import(ctx, name, path);
                found = true;
            }
            "namespace_import" => {
                let as_name = sub.child_by_field_name("name").or_else(|| {
                    if sub.child_count() > 0 {
                        sub.child(sub.child_count() - 1)
                    } else {
                        None
                    }
                });
                if let Some(a) = as_name {
                    let name = crate::fqn::node_text(a, ctx.source);
                    push_import(ctx, name, path);
                    found = true;
                }
            }
            "named_imports" => {
                found |= process_named_imports(ctx, sub, path);
            }
            _ => {}
        }
    }
    if !found {
        push_import(ctx, path_last(path), path);
        found = true;
    }
    found
}

/// One ES import_statement (C process_es_import_statement).
fn process_es_import_statement(ctx: &mut ExtractCtx<'_>, node: tree_sitter::Node<'_>) -> bool {
    let Some(source_node) = find_es_source_node(node) else {
        return false;
    };
    let path = strip_quotes(crate::fqn::node_text(source_node, ctx.source));
    if path.is_empty() {
        return false;
    }
    let mut found = false;
    for j in 0..node.child_count() {
        let child = node.child(j).unwrap();
        match child.kind() {
            "identifier" => {
                let name = crate::fqn::node_text(child, ctx.source);
                push_import(ctx, name, path);
                found = true;
            }
            "import_clause" => {
                found |= process_import_clause(ctx, child, path);
            }
            _ => {}
        }
    }
    if !found {
        push_import(ctx, path_last(path), path);
    }
    true
}

/// CommonJS `require("path")` (C process_commonjs_require): local name from
/// the enclosing variable_declarator when possible, else the last path
/// component. Only consumes the node when recognized as a require call.
fn process_commonjs_require(ctx: &mut ExtractCtx<'_>, call: tree_sitter::Node<'_>) -> bool {
    if call.child_count() < 2 {
        return false;
    }
    let fn_node = call
        .child_by_field_name("function")
        .or_else(|| call.child(0));
    let Some(fn_node) = fn_node else { return false };
    if fn_node.kind() != "identifier" {
        return false;
    }
    if crate::fqn::node_text(fn_node, ctx.source) != "require" {
        return false;
    }
    let Some(args) = call.child_by_field_name("arguments") else {
        return false;
    };
    let mut path: Option<&str> = None;
    for i in 0..args.named_child_count() {
        let arg = args.named_child(i).unwrap();
        if matches!(arg.kind(), "string" | "string_literal" | "template_string") {
            path = Some(strip_quotes(crate::fqn::node_text(arg, ctx.source)));
            break;
        }
    }
    let Some(path) = path else { return false };
    if path.is_empty() {
        return false;
    }
    // Local name from the enclosing variable_declarator.
    let mut local_name: Option<&str> = None;
    if let Some(parent) = call.parent() {
        if parent.kind() == "variable_declarator" {
            if let Some(name_node) = parent.child_by_field_name("name") {
                if name_node.kind() == "identifier" {
                    local_name = Some(crate::fqn::node_text(name_node, ctx.source));
                }
            }
        }
    }
    let local = local_name.unwrap_or_else(|| path_last(path));
    push_import(ctx, local, path);
    true
}

/// ES walk (C walk_es_imports): import_statement / export_statement /
/// require() call expressions.
fn walk_es_imports(ctx: &mut ExtractCtx<'_>, root: tree_sitter::Node<'_>) {
    let mut stack = vec![root];
    while let Some(node) = stack.pop() {
        let kind = node.kind();
        let mut push_children = true;
        if kind == "import_statement" {
            if process_es_import_statement(ctx, node) {
                push_children = false;
            }
        } else if kind == "export_statement" {
            // Re-export: `export { x } from './mod'` carries a source like
            // an import and creates the same module dependency.
            if let Some(src) = node.child_by_field_name("source") {
                let path = strip_quotes(crate::fqn::node_text(src, ctx.source));
                if !path.is_empty() {
                    push_import(ctx, path_last(path), path);
                }
            }
        } else if kind == "call_expression" && process_commonjs_require(ctx, node) {
            push_children = false;
        }
        if push_children {
            for i in (0..node.child_count()).rev() {
                if let Some(c) = node.child(i) {
                    stack.push(c);
                }
            }
        }
    }
}

// ── Java ────────────────────────────────────────────────────────

/// Top-level import_declarations (C parse_java_imports).
fn parse_java_imports(ctx: &mut ExtractCtx<'_>) {
    let root = ctx.root;
    let mut cursor = root.walk();
    if !cursor.goto_first_child() {
        return;
    }
    loop {
        let node = cursor.node();
        if node.kind() == "import_declaration" {
            // Full import path — skip "import" / "static" keywords.
            for j in 0..node.child_count() {
                let child = node.child(j).unwrap();
                if matches!(child.kind(), "scoped_identifier" | "identifier") {
                    let path = crate::fqn::node_text(child, ctx.source);
                    if !path.is_empty() {
                        push_import(ctx, path_last(path), path);
                    }
                    break;
                }
            }
        }
        if !cursor.goto_next_sibling() {
            break;
        }
    }
}

// ── Rust ────────────────────────────────────────────────────────

/// use_declarations (C parse_rust_imports): strip "use " and trailing ';'.
fn parse_rust_imports(ctx: &mut ExtractCtx<'_>) {
    let root = ctx.root;
    let mut cursor = root.walk();
    if !cursor.goto_first_child() {
        return;
    }
    loop {
        let node = cursor.node();
        if node.kind() == "use_declaration" {
            let mut full = crate::fqn::node_text(node, ctx.source);
            if let Some(stripped) = full.strip_prefix("use ") {
                full = stripped;
            }
            let full = full.strip_suffix(';').unwrap_or(full);
            if !full.is_empty() {
                push_import(ctx, path_last(full), full);
            }
        }
        if !cursor.goto_next_sibling() {
            break;
        }
    }
}

// ── Namespace capture (Java / Kotlin / C# / PHP) ────────────────

/// Namespace/package capture (C capture_namespace_decl): first
/// namespace/package declaration's name becomes result.namespace_name.
fn capture_namespace_decl(ctx: &mut ExtractCtx<'_>) {
    const NS_KINDS: &[&str] = &[
        "namespace_declaration",             // C#
        "file_scoped_namespace_declaration", // C# 10
        "package_declaration",               // Java / Kotlin
        "package_header",                    // Kotlin
        "namespace_definition",              // PHP
    ];
    const NAME_KINDS: &[&str] = &[
        "qualified_name",
        "scoped_identifier",
        "namespace_name",
        "identifier",
        "dotted_name",
        "name",
    ];
    let root = ctx.root;
    let mut cursor = root.walk();
    if !cursor.goto_first_child() {
        return;
    }
    loop {
        let node = cursor.node();
        if NS_KINDS.contains(&node.kind()) {
            for nk in NAME_KINDS {
                if let Some(nn) = find_first_descendant_of(node, nk) {
                    let ns = crate::fqn::node_text(nn, ctx.source);
                    if !ns.is_empty() {
                        ctx.result.namespace_name = Some(ns.to_string());
                    }
                    break;
                }
            }
            if ctx.result.namespace_name.is_some() {
                break;
            }
        }
        if !cursor.goto_next_sibling() {
            break;
        }
    }
}

/// First descendant (depth-first) with the given kind
/// (C find_first_descendant_of).
fn find_first_descendant_of<'t>(
    node: tree_sitter::Node<'t>,
    kind: &str,
) -> Option<tree_sitter::Node<'t>> {
    if node.kind() == kind {
        return Some(node);
    }
    for i in 0..node.child_count() {
        let c = node.child(i)?;
        if let Some(found) = find_first_descendant_of(c, kind) {
            return Some(found);
        }
    }
    None
}

// ── Dispatcher ──────────────────────────────────────────────────

/// Entry (C cbm_extract_imports). Part 1 covers Go / Python / ES / Java /
/// Rust; later parts add the remaining ~47 language parsers.
pub fn extract_imports(ctx: &mut ExtractCtx<'_>, ported: fn(Language) -> bool) {
    match ctx.language {
        Language::JAVA | Language::KOTLIN | Language::CSHARP | Language::PHP => {
            capture_namespace_decl(ctx);
        }
        _ => {}
    }
    if !ported(ctx.language) {
        return;
    }

    match ctx.language {
        Language::GO => parse_go_imports(ctx),
        Language::PYTHON => parse_python_imports(ctx),
        Language::JAVASCRIPT | Language::TYPESCRIPT | Language::TSX | Language::ARKTS => {
            walk_es_imports(ctx, ctx.root)
        }
        Language::JAVA => parse_java_imports(ctx),
        Language::KOTLIN => parse_kotlin_imports(ctx),
        Language::CSHARP => parse_csharp_imports(ctx),
        Language::RUST => parse_rust_imports(ctx),
        Language::C | Language::CPP | Language::OBJC => parse_c_imports(ctx),
        Language::PHP => {
            // PHP `use Foo\Bar;` is a namespace_use_declaration;
            // require/include are expression_statements. Both handled.
            parse_php_imports(ctx)
        }
        Language::RUBY => parse_ruby_imports(ctx),
        Language::LUA => parse_lua_imports(ctx),
        Language::SCALA => parse_generic_imports(ctx, "import_declaration"),
        Language::ELIXIR => parse_generic_imports(ctx, "call"),
        Language::BASH => parse_generic_imports(ctx, "command"),
        Language::ERLANG => parse_generic_imports(ctx, "module_attribute"),
        Language::OCAML => parse_generic_imports(ctx, "open_module"),
        Language::PERL => parse_generic_imports(ctx, "use_statement"),
        Language::GROOVY => parse_generic_imports(ctx, "groovy_import"),
        Language::SWIFT => parse_generic_imports(ctx, "import_declaration"),
        Language::LEAN => parse_generic_imports(ctx, "import"),
        Language::FORM => parse_generic_imports(ctx, "include_directive"),
        Language::MAGMA => parse_generic_imports(ctx, "load_statement"),
        // Everything else: spec-driven generic extraction (equivalent power
        // to the C's per-language parsers, which end in the same helpers).
        _ => {
            let spec = crate::lang_specs::lang_spec(ctx.language);
            parse_spec_imports(ctx, spec);
        }
    }
}

// ── Part 2: Kotlin / C# / Ruby / Lua / C-family / PHP / generic ──

/// path/source/module/name field → import (C try_generic_path_fields).
fn try_generic_path_fields(ctx: &mut ExtractCtx<'_>, node: tree_sitter::Node<'_>) -> bool {
    for f in ["path", "source", "module", "name"] {
        if let Some(path_node) = node.child_by_field_name(f) {
            let path = strip_quotes(crate::fqn::node_text(path_node, ctx.source));
            if !path.is_empty() {
                push_import(ctx, path_last(path), path);
            }
            return true;
        }
    }
    false
}

/// Fallback: import path from full node text, stripping the keyword before
/// the first space, a trailing ';', and surrounding quotes (Pony
/// `use "util"`, func `#include "utils.fc"`), C generic_import_from_text.
fn generic_import_from_text(ctx: &mut ExtractCtx<'_>, node: tree_sitter::Node<'_>) {
    let text = crate::fqn::node_text(node, ctx.source);
    if text.is_empty() {
        return;
    }
    let after_space = match text.find(' ') {
        Some(i) => &text[i + 1..],
        None => text,
    };
    let after_semi = after_space.strip_suffix(';').unwrap_or(after_space);
    let cleaned = strip_quotes(after_semi);
    if !cleaned.is_empty() {
        push_import(ctx, path_last(cleaned), cleaned);
    }
}

/// Kotlin import_header / import_list (C extract_one_import_header +
/// parse_kotlin_imports): generic path fields, then text fallback.
fn extract_one_import_header(ctx: &mut ExtractCtx<'_>, header: tree_sitter::Node<'_>) {
    if !try_generic_path_fields(ctx, header) {
        generic_import_from_text(ctx, header);
    }
}

fn parse_kotlin_imports(ctx: &mut ExtractCtx<'_>) {
    let root = ctx.root;
    let mut cursor = root.walk();
    if !cursor.goto_first_child() {
        return;
    }
    loop {
        let node = cursor.node();
        let kind = node.kind();
        if kind == "import_header" {
            extract_one_import_header(ctx, node);
        } else if kind == "import_list" {
            for j in 0..node.child_count() {
                let child = node.child(j).unwrap();
                if child.kind() == "import_header" {
                    extract_one_import_header(ctx, child);
                }
            }
        }
        if !cursor.goto_next_sibling() {
            break;
        }
    }
}

/// C# using_directives (C parse_csharp_imports): the right-most
/// qualified_name/identifier/member_access/name named child is the target
/// even in alias form `using F = X;`; alias field overrides the local name.
fn parse_csharp_imports(ctx: &mut ExtractCtx<'_>) {
    let root = ctx.root;
    let mut cursor = root.walk();
    if !cursor.goto_first_child() {
        return;
    }
    loop {
        let node = cursor.node();
        if node.kind() == "using_directive" {
            let mut path_node: tree_sitter::Node<'_> = node;
            let mut found = false;
            for i in (0..node.named_child_count()).rev() {
                let c = node.named_child(i).unwrap();
                if matches!(
                    c.kind(),
                    "qualified_name" | "identifier" | "member_access_expression" | "name"
                ) {
                    path_node = c;
                    found = true;
                    break;
                }
            }
            let path = if found {
                crate::fqn::node_text(path_node, ctx.source)
            } else {
                ""
            };
            if path.is_empty() {
                // Fallback handles `using static X;`.
                if !try_generic_path_fields(ctx, node) {
                    generic_import_from_text(ctx, node);
                }
            } else {
                let local = match node.child_by_field_name("alias") {
                    Some(a) => crate::fqn::node_text(a, ctx.source),
                    None => path_last(path),
                };
                push_import(ctx, local, path);
            }
        }
        if !cursor.goto_next_sibling() {
            break;
        }
    }
}

/// Ruby require/require_relative method name (C ruby_require_method).
fn ruby_require_method<'t>(node: tree_sitter::Node<'t>, source: &'t str) -> Option<&'t str> {
    let method = node.child_by_field_name("method").or_else(|| {
        if node.child_count() > 0 {
            node.child(0)
        } else {
            None
        }
    })?;
    let name = crate::fqn::node_text(method, source);
    if name == "require" || name == "require_relative" {
        Some(name)
    } else {
        None
    }
}

/// Ruby require string argument (C extract_ruby_require_arg).
fn extract_ruby_require_arg<'a>(node: tree_sitter::Node<'a>, source: &'a str) -> Option<String> {
    let args = node.child_by_field_name("arguments").or_else(|| {
        if node.child_count() > 1 {
            node.child(1)
        } else {
            None
        }
    })?;
    for j in 0..args.child_count() {
        let c = args.child(j)?;
        if matches!(c.kind(), "string" | "string_literal") {
            return Some(strip_quotes(crate::fqn::node_text(c, source)).to_string());
        }
    }
    Some(strip_quotes(crate::fqn::node_text(args, source)).to_string())
}

/// Ruby walk (C parse_ruby_imports): call/command_call nodes whose method
/// is require/require_relative.
fn parse_ruby_imports(ctx: &mut ExtractCtx<'_>) {
    let root = ctx.root;
    let mut cursor = root.walk();
    if !cursor.goto_first_child() {
        return;
    }
    loop {
        let node = cursor.node();
        let kind = node.kind();
        if (kind == "call" || kind == "command_call")
            && ruby_require_method(node, ctx.source).is_some()
        {
            if let Some(arg_text) = extract_ruby_require_arg(node, ctx.source) {
                if !arg_text.is_empty() {
                    push_import(ctx, path_last(&arg_text), &arg_text);
                }
            }
        }
        if !cursor.goto_next_sibling() {
            break;
        }
    }
}

/// Lua require (C parse_lua_imports): text-scan for require("...") inside
/// assignment/variable_declaration nodes.
fn parse_lua_imports(ctx: &mut ExtractCtx<'_>) {
    let root = ctx.root;
    let mut cursor = root.walk();
    if !cursor.goto_first_child() {
        return;
    }
    loop {
        let node = cursor.node();
        let text = crate::fqn::node_text(node, ctx.source);
        if let Some(req_pos) = text.find("require") {
            let req = &text[req_pos..];
            let open = req
                .find('(')
                .or_else(|| req.find('"'))
                .or_else(|| req.find('\''));
            if let Some(open) = open {
                let after = &req[open..];
                let q1 = after.find('"');
                let q2 = after.find('\'');
                let (q, qch) = match (q1, q2) {
                    (Some(a), Some(b)) => {
                        if a < b {
                            (a, '"')
                        } else {
                            (b, '\'')
                        }
                    }
                    (Some(a), None) => (a, '"'),
                    (None, Some(b)) => (b, '\''),
                    _ => {
                        if !cursor.goto_next_sibling() {
                            break;
                        }
                        continue;
                    }
                };
                let inner = &after[q + 1..];
                if let Some(close) = inner.find(qch) {
                    let raw = format!("{qch}{}{qch}", &inner[..close]);
                    let path = strip_quotes(&raw).to_string();
                    if !path.is_empty() {
                        let p = path.clone();
                        push_import(ctx, path_last(&p), &p);
                    }
                }
            }
        }
        if !cursor.goto_next_sibling() {
            break;
        }
    }
}

/// C-family includes (C parse_c_imports): #include / #import lines.
fn parse_c_imports(ctx: &mut ExtractCtx<'_>) {
    let root = ctx.root;
    let mut cursor = root.walk();
    if !cursor.goto_first_child() {
        return;
    }
    loop {
        let node = cursor.node();
        let kind = node.kind();
        if kind == "preproc_include" || kind == "preproc_def" {
            if let Some(p) = node.child_by_field_name("path") {
                let path = strip_quotes(crate::fqn::node_text(p, ctx.source));
                if !path.is_empty() {
                    push_import(ctx, path_last(path), path);
                }
            } else {
                generic_import_from_text(ctx, node);
            }
        }
        if !cursor.goto_next_sibling() {
            break;
        }
    }
}

/// PHP: namespace_use_declaration use clauses + require/include expression
/// statements (C parse_php_imports).
fn parse_php_imports(ctx: &mut ExtractCtx<'_>) {
    let root = ctx.root;
    let mut cursor = root.walk();
    if !cursor.goto_first_child() {
        return;
    }
    loop {
        let node = cursor.node();
        let kind = node.kind();
        if kind == "namespace_use_declaration" {
            for j in 0..node.named_child_count() {
                let child = node.named_child(j).unwrap();
                // use Foo\Bar; or use Foo\Bar as B;
                let text = crate::fqn::node_text(child, ctx.source);
                let path = text.split(" as ").next().unwrap_or(text).trim();
                if !path.is_empty() {
                    push_import(ctx, path_last(path), path);
                }
            }
        } else if matches!(
            kind,
            "expression_statement" | "include_expression" | "require_expression"
        ) && text_has_require_include(node, ctx.source)
        {
            generic_import_from_text(ctx, node);
        }
        if !cursor.goto_next_sibling() {
            break;
        }
    }
}

fn text_has_require_include(node: tree_sitter::Node<'_>, source: &str) -> bool {
    let text = crate::fqn::node_text(node, source);
    text.starts_with("require ")
        || text.starts_with("include ")
        || text.starts_with("require ")
        || text.contains("require")
        || text.contains("include")
}

/// Generic import parser (C parse_generic_imports): top-level nodes of
/// `node_type`, generic fields then text fallback.
fn parse_generic_imports(ctx: &mut ExtractCtx<'_>, node_type: &str) {
    let root = ctx.root;
    let mut cursor = root.walk();
    if !cursor.goto_first_child() {
        return;
    }
    loop {
        let node = cursor.node();
        if node.kind() == node_type && !try_generic_path_fields(ctx, node) {
            generic_import_from_text(ctx, node);
        }
        if !cursor.goto_next_sibling() {
            break;
        }
    }
}

/// Spec-driven imports (C parse_spec_imports): top-level nodes matching
/// the language's import_node_types, generic fields then text fallback.
/// This is the fallback for languages without a dedicated parser — and it
/// carries the same extraction power, since both end in the same two
/// generic helpers.
fn parse_spec_imports(ctx: &mut ExtractCtx<'_>, spec: &LanguageSpec) {
    if spec.import_node_types.is_empty() {
        return;
    }
    let mut cursor = ctx.root.walk();
    if !cursor.goto_first_child() {
        return;
    }
    loop {
        let node = cursor.node();
        if spec.import_node_types.contains(&node.kind()) && !try_generic_path_fields(ctx, node) {
            generic_import_from_text(ctx, node);
        }
        if !cursor.goto_next_sibling() {
            break;
        }
    }
}

/// Languages whose dedicated parser is ported (parts 1-2); everything else
/// in `ALL` falls through to parse_spec_imports.
fn has_dedicated_parser(lang: Language) -> bool {
    matches!(
        lang,
        Language::GO
            | Language::PYTHON
            | Language::JAVASCRIPT
            | Language::TYPESCRIPT
            | Language::TSX
            | Language::ARKTS
            | Language::JAVA
            | Language::KOTLIN
            | Language::CSHARP
            | Language::RUST
            | Language::C
            | Language::CPP
            | Language::OBJC
            | Language::PHP
            | Language::RUBY
            | Language::LUA
    )
}

/// Languages with extraction coverage (parts 1-3): dedicated parsers plus
/// the spec-driven fallback that covers every language with
/// import_node_types.
pub fn ported_languages(lang: Language) -> bool {
    has_dedicated_parser(lang)
        || !crate::lang_specs::lang_spec(lang)
            .import_node_types
            .is_empty()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::extract_env_accesses::ExtractCtx;

    fn run(lang: Language, src: &str, rel: &str) -> Vec<Import> {
        let tree = crate::ts::parse(lang, src).expect("grammar");
        let mut ctx = ExtractCtx::new(src, tree.root_node(), lang, "proj", rel);
        extract_imports(&mut ctx, ported_languages);
        ctx.result.imports
    }

    #[test]
    fn helpers_path_last_and_quotes() {
        assert_eq!(path_last("std::collections::HashMap"), "HashMap");
        assert_eq!(path_last("a.b.c"), "c");
        assert_eq!(path_last("net/http"), "http");
        assert_eq!(path_last("App\\Http\\Controller"), "Controller");
        assert_eq!(path_last("plain"), "plain");
        assert_eq!(strip_quotes("\"x\""), "x");
        assert_eq!(strip_quotes("'y'"), "y");
        assert_eq!(strip_quotes("z"), "z");
        assert_eq!(python_import_root("xml.etree"), "xml");
        assert_eq!(python_import_root("os"), "os");
    }

    #[test]
    fn go_single_and_grouped() {
        let src =
            "package app\nimport \"net/http\"\nimport (\n\t\"fmt\"\n\tu \"example.com/user\"\n)\n";
        let imports = run(Language::GO, src, "a.go");
        assert_eq!(imports.len(), 3, "{imports:?}");
        assert!(imports
            .iter()
            .any(|i| i.local_name == "http" && i.module_path == "net/http"));
        assert!(imports
            .iter()
            .any(|i| i.local_name == "fmt" && i.module_path == "fmt"));
        assert!(imports
            .iter()
            .any(|i| i.local_name == "u" && i.module_path == "example.com/user"));
    }

    #[test]
    fn python_plain_dotted_aliased() {
        let src = "import os\nimport xml.etree\nimport numpy as np\n";
        let imports = run(Language::PYTHON, src, "a.py");
        assert_eq!(imports.len(), 3, "{imports:?}");
        assert!(imports
            .iter()
            .any(|i| i.local_name == "os" && i.module_path == "os"));
        // Dotted: binds the FIRST component; module stays intact.
        assert!(imports
            .iter()
            .any(|i| i.local_name == "xml" && i.module_path == "xml.etree"));
        assert!(imports
            .iter()
            .any(|i| i.local_name == "np" && i.module_path == "numpy"));
    }

    #[test]
    fn python_from_import() {
        let src = "from os.path import join\nfrom typing import List as L\nfrom json import dumps, loads\n";
        let imports = run(Language::PYTHON, src, "a.py");
        assert_eq!(imports.len(), 4, "{imports:?}");
        assert!(imports
            .iter()
            .any(|i| i.local_name == "join" && i.module_path == "os.path.join"));
        assert!(imports
            .iter()
            .any(|i| i.local_name == "L" && i.module_path == "typing.List"));
        assert!(imports
            .iter()
            .any(|i| i.local_name == "dumps" && i.module_path == "json.dumps"));
        assert!(imports
            .iter()
            .any(|i| i.local_name == "loads" && i.module_path == "json.loads"));
    }

    #[test]
    fn python_future_import() {
        let src = "from __future__ import annotations\n";
        let imports = run(Language::PYTHON, src, "a.py");
        assert_eq!(imports.len(), 1);
        assert_eq!(imports[0].module_path, "__future__");
    }

    #[test]
    fn es_import_forms() {
        let src = r#"
import def from "mod1";
import { a, b as c } from "mod2";
import * as ns from "mod3";
import "mod4";
export { x } from "mod5";
const lib = require("mod6");
"#;
        let imports = run(Language::JAVASCRIPT, src, "a.js");
        let mods: Vec<&str> = imports.iter().map(|i| i.module_path.as_str()).collect();
        assert!(mods.contains(&"mod1"), "{imports:?}");
        assert!(mods.contains(&"mod2"));
        assert!(mods.contains(&"mod3"));
        assert!(mods.contains(&"mod4"));
        assert!(mods.contains(&"mod5"));
        assert!(mods.contains(&"mod6"));
        // Named: `b as c` → local "c".
        assert!(imports
            .iter()
            .any(|i| i.local_name == "c" && i.module_path == "mod2"));
        // require with enclosing declarator name.
        assert!(imports
            .iter()
            .any(|i| i.local_name == "lib" && i.module_path == "mod6"));
    }

    #[test]
    fn java_imports_and_namespace() {
        let src =
            "package com.example.svc;\nimport java.util.List;\nimport static java.lang.Math.PI;\n";
        let tree = crate::ts::parse(Language::JAVA, src).expect("grammar");
        let mut ctx = ExtractCtx::new(src, tree.root_node(), Language::JAVA, "proj", "S.java");
        extract_imports(&mut ctx, ported_languages);
        assert_eq!(
            ctx.result.namespace_name.as_deref(),
            Some("com.example.svc")
        );
        let mods: Vec<&str> = ctx
            .result
            .imports
            .iter()
            .map(|i| i.module_path.as_str())
            .collect();
        assert!(mods.contains(&"java.util.List"), "{mods:?}");
        assert!(mods.contains(&"java.lang.Math.PI"));
        assert!(ctx.result.imports.iter().any(|i| i.local_name == "List"));
    }

    #[test]
    fn rust_use_declarations() {
        let src = "use std::collections::HashMap;\nuse serde::Serialize;\n";
        let imports = run(Language::RUST, src, "a.rs");
        assert_eq!(imports.len(), 2, "{imports:?}");
        assert!(imports
            .iter()
            .any(|i| i.local_name == "HashMap" && i.module_path == "std::collections::HashMap"));
        assert!(imports
            .iter()
            .any(|i| i.local_name == "Serialize" && i.module_path == "serde::Serialize"));
    }

    #[test]
    fn unported_language_is_noop() {
        // Not ported yet: the dispatcher skips without touching the result.
        let tree = crate::ts::parse(Language::PYTHON, "import os\n").unwrap();
        let mut ctx = ExtractCtx::new(
            "import os\n",
            tree.root_node(),
            Language::PYTHON,
            "p",
            "a.py",
        );
        extract_imports(&mut ctx, |_| false);
        assert!(ctx.result.imports.is_empty());
    }
}
