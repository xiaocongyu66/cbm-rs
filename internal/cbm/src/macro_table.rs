//! macro_table.rs — 1:1 rewrite of `internal/cbm/macro_table.c`: the
//! ObjectScript `$$$macro` table. System macros ship as a static table;
//! `.inc` files contribute `#define NAME(params) expansion` entries; the
//! call extractor resolves `$$$NAME` references through
//! [`macro_table_find`] and [`macro_extract_callee`].
//!
//! The C stores strings in a per-table arena; the Rust version owns them
//! as `String`s (same lifetime shape: the table outlives every extraction
//! pass that borrows it).

/// C CBM_MACRO_MAX_PARAMS.
pub const MACRO_MAX_PARAMS: usize = 4;
/// C CBM_MACRO_TABLE_CAP.
pub const MACRO_TABLE_CAP: usize = 4096;

/// One macro entry (C CBMMacroEntry). `param_count = -1` means variadic
/// (LISTBUILD); `None` expansion means a system macro with only a
/// resolved callee.
#[derive(Debug, Clone)]
pub struct MacroEntry {
    pub name: String,
    /// -1 = variadic, 0 = nullary.
    pub param_count: i32,
    pub param_names: [Option<String>; MACRO_MAX_PARAMS],
    pub expansion: Option<String>,
    pub resolved_callee: Option<String>,
}

/// ObjectScript macro table (C CBMMacroTable).
#[derive(Debug, Clone, Default)]
pub struct MacroTable {
    pub entries: Vec<MacroEntry>,
}

/// Case-insensitive ASCII equality (C strcasecmp on macro names).
fn eq_ignore_case(a: &str, b: &str) -> bool {
    a.eq_ignore_ascii_case(b)
}

/// Case-insensitive prefix test (C strncasecmp).
fn starts_with_ignore_case(haystack: &[u8], prefix: &str) -> bool {
    haystack.len() >= prefix.len()
        && haystack[..prefix.len()].eq_ignore_ascii_case(prefix.as_bytes())
}

// ── System macro table (C SYSTEM_MACROS) ────────────────────────

const SYSTEM_MACROS: &[(&str, i32, Option<&str>)] = &[
    ("OK", 0, None),
    ("ISERR", 1, Some("%SYSTEM.Status.IsError")),
    ("ISOK", 1, Some("%SYSTEM.Status.IsOK")),
    ("GETERRORTEXT", 1, Some("%SYSTEM.Status.GetErrorText")),
    ("ADDSC", 2, Some("%SYSTEM.Status.AppendStatus")),
    ("ThrowStatus", 1, Some("%SYSTEM.Status.ThrowStatus")),
    ("ThrowOnError", 1, Some("%SYSTEM.Status.ThrowStatus")),
    ("ERROR", 2, Some("%SYSTEM.Status.Error")),
    ("NULLOREF", 0, None),
    ("LISTBUILD", -1, None),
    ("LISTGET", 2, None),
    ("LISTNEXT", 3, None),
    ("LISTLENGTH", 1, None),
    ("SORTBEGIN", 1, None),
    ("SORTEND", 0, None),
    ("AUDITSTART", 3, Some("%SYSTEM.Audit.Event")),
    ("logoutput", 1, None),
    ("objExists", 1, None),
    ("traceStatus", 1, None),
];

/// Seed the table with the system macros (C cbm_macro_table_init_system).
pub fn macro_table_init_system(t: &mut MacroTable) {
    t.entries.clear();
    for (name, param_count, callee) in SYSTEM_MACROS {
        if t.entries.len() >= MACRO_TABLE_CAP {
            break;
        }
        t.entries.push(MacroEntry {
            name: (*name).to_string(),
            param_count: *param_count,
            param_names: Default::default(),
            expansion: None,
            resolved_callee: callee.map(|s| s.to_string()),
        });
    }
}

/// Add a macro; silently ignores duplicates (case-insensitive) and full
/// tables (C cbm_macro_table_add).
pub fn macro_table_add(
    t: &mut MacroTable,
    name: &str,
    param_count: i32,
    param_names: &[&str],
    expansion: Option<&str>,
    resolved_callee: Option<&str>,
) {
    if t.entries.len() >= MACRO_TABLE_CAP || name.is_empty() {
        return;
    }
    if t.entries.iter().any(|e| eq_ignore_case(&e.name, name)) {
        return;
    }
    let mut names: [Option<String>; MACRO_MAX_PARAMS] = Default::default();
    for (i, pn) in param_names.iter().enumerate().take(MACRO_MAX_PARAMS) {
        names[i] = Some((*pn).to_string());
    }
    t.entries.push(MacroEntry {
        name: name.to_string(),
        param_count,
        param_names: names,
        expansion: expansion.map(|s| s.to_string()),
        resolved_callee: resolved_callee.map(|s| s.to_string()),
    });
}

/// Case-insensitive lookup (C cbm_macro_table_find).
pub fn macro_table_find<'a>(t: &'a MacroTable, name: &str) -> Option<&'a MacroEntry> {
    t.entries.iter().find(|e| eq_ignore_case(&e.name, name))
}

/// Parse `.inc` content for `#define` lines (C cbm_parse_inc_file).
/// Handles `#define NAME`, `#define NAME(a, b) body` with any spacing.
pub fn parse_inc_file(t: &mut MacroTable, content: &str) {
    for line in content.lines() {
        let p = line.trim_start_matches([' ', '\t']);
        let Some(after) = p.strip_prefix("#define") else {
            continue;
        };
        if !after.starts_with([' ', '\t']) {
            continue;
        }
        let p = after.trim_start_matches([' ', '\t']);

        // Macro name: up to '(' or whitespace.
        let name_end = p.find(['(', ' ', '\t']).unwrap_or(p.len());
        if name_end == 0 {
            continue;
        }
        let name = &p[..name_end];
        let mut rest = &p[name_end..];

        let mut param_count: i32 = -1;
        let mut param_names: Vec<&str> = Vec::new();

        if let Some(after_paren) = rest.strip_prefix('(') {
            param_count = 0;
            rest = after_paren;
            let mut segs = Vec::new();
            let mut depth_done = false;
            for seg in rest.split_inclusive([',', ')']) {
                let seg_trim = seg.trim_end_matches([',', ')']);
                let seg_trim = seg_trim.trim();
                if !seg_trim.is_empty() && param_count < MACRO_MAX_PARAMS as i32 {
                    segs.push(seg_trim);
                    param_count += 1;
                }
                if seg.ends_with(')') {
                    depth_done = true;
                    break;
                }
            }
            if !depth_done {
                // No closing paren on this line — the C leaves param_count
                // at whatever it gathered; keep parsing the rest of line.
            }
            // Advance rest past the closing paren.
            if let Some(close) = rest.find(')') {
                rest = &rest[close + 1..];
            }
            param_names = segs;
        }

        let expansion = rest.trim_matches([' ', '\t']);
        let expansion = expansion.trim_end_matches(['\r', ' ', '\t']);
        let expansion = if expansion.is_empty() {
            None
        } else {
            Some(expansion)
        };

        macro_table_add(t, name, param_count, &param_names, expansion, None);
    }
}

/// Expand a macro template against arguments (C cbm_macro_expand): `%`
/// followed by a parameter name substitutes the argument (case-insensitive
/// match); a lone `%` passes through. The C's 1024-byte stack buffer
/// truncation is not reproduced — Rust strings grow.
pub fn macro_expand(entry: &MacroEntry, args: &[&str]) -> Option<String> {
    let tmpl = entry.expansion.as_ref()?;
    let mut out = String::with_capacity(tmpl.len());
    let bytes = tmpl.as_bytes();
    let mut i = 0usize;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            let mut matched = false;
            for (pi, pn) in entry.param_names.iter().enumerate() {
                let Some(pn) = pn else { continue };
                if starts_with_ignore_case(&bytes[i + 1..], pn) {
                    // C: args[i] when available, else "".
                    let arg = args.get(pi).copied().unwrap_or("");
                    out.push_str(arg);
                    i += 1 + pn.len();
                    matched = true;
                    break;
                }
            }
            if !matched {
                out.push('%');
                i += 1;
            }
        } else {
            // Multi-byte UTF-8 chars are copied byte-wise like the C's
            // char loop; pushing each byte as a char would mangle them, so
            // copy the full char.
            let ch_len = utf8_len(bytes[i]);
            out.push_str(&tmpl[i..i + ch_len]);
            i += ch_len;
        }
    }
    Some(out)
}

/// UTF-8 sequence length for a lead byte (1 for ASCII).
fn utf8_len(b: u8) -> usize {
    match b {
        0x00..=0x7F => 1,
        0xC0..=0xDF => 2,
        0xE0..=0xEF => 3,
        _ => 4,
    }
}

/// Extract a resolved callee from a macro expansion body
/// (C cbm_macro_extract_callee): `##class(Pkg.Class).Method(...)` →
/// `Pkg.Class.Method`, or `$$tag^routine` → `tag^routine`.
pub fn macro_extract_callee(expansion: &str) -> Option<String> {
    if let Some(pos) = expansion.find("##class(") {
        let p = &expansion[pos + 8..];
        let cls_end = p.find(')')?;
        let cls = &p[..cls_end];
        let dot = p.get(cls_end + 1..)?;
        let dot = dot.strip_prefix('.')?;
        let method_end = dot.find(['(', ' ']).unwrap_or(dot.len());
        let method = &dot[..method_end];
        if cls.is_empty() || method.is_empty() {
            return None;
        }
        return Some(format!("{cls}.{method}"));
    }

    if let Some(pos) = expansion.find("$$") {
        let p = &expansion[pos + 2..];
        if p.starts_with("$$") {
            return None; // C checks p[2] != '$'
        }
        let tag_end = p.find(['^', '(', ' ']).unwrap_or(p.len());
        let tag = &p[..tag_end];
        if let Some(rtn_part) = p[tag_end..].strip_prefix('^') {
            let rtn_end = rtn_part.find(['(', ' ']).unwrap_or(rtn_part.len());
            let rtn = &rtn_part[..rtn_end];
            if !tag.is_empty() && !rtn.is_empty() {
                return Some(format!("{tag}^{rtn}"));
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn table() -> MacroTable {
        let mut t = MacroTable::default();
        macro_table_init_system(&mut t);
        t
    }

    #[test]
    fn system_macros_seeded() {
        let t = table();
        assert_eq!(t.entries.len(), SYSTEM_MACROS.len());
        let e = macro_table_find(&t, "ISOK").unwrap();
        assert_eq!(e.resolved_callee.as_deref(), Some("%SYSTEM.Status.IsOK"));
        assert!(e.expansion.is_none());
        // Case-insensitive.
        assert!(macro_table_find(&t, "isok").is_some());
        assert!(macro_table_find(&t, "MISSING").is_none());
    }

    #[test]
    fn add_dedupes_case_insensitive() {
        let mut t = table();
        let before = t.entries.len();
        macro_table_add(&mut t, "isok", 1, &["x"], Some("body"), None);
        assert_eq!(t.entries.len(), before, "duplicate must be ignored");
        macro_table_add(&mut t, "MYMACRO", 2, &["a", "b"], Some("a+b"), None);
        assert_eq!(t.entries.len(), before + 1);
        let e = macro_table_find(&t, "mymacro").unwrap();
        assert_eq!(e.param_names[0].as_deref(), Some("a"));
    }

    #[test]
    fn parse_inc_defines() {
        let mut t = table();
        let src = "\n#define FOO(x, y) do(x, y)\n\
                   #define   BAR   simple body   \n\
                   #define variadic(...) stuff\n\
                   #notdefine\n\
                   #define EMPTY()\n";
        parse_inc_file(&mut t, src);
        let foo = macro_table_find(&t, "FOO").unwrap();
        assert_eq!(foo.param_count, 2);
        assert_eq!(foo.param_names[0].as_deref(), Some("x"));
        assert_eq!(foo.expansion.as_deref(), Some("do(x, y)"));
        let bar = macro_table_find(&t, "BAR").unwrap();
        assert_eq!(bar.param_count, -1, "no parens = -1");
        assert_eq!(bar.expansion.as_deref(), Some("simple body"));
        assert!(macro_table_find(&t, "EMPTY").unwrap().expansion.is_none());
    }

    #[test]
    fn expand_substitutes_params() {
        let mut t = table();
        // Expansion syntax: %param substitutes (case-insensitive), bare %
        // passes through.
        macro_table_add(&mut t, "ADD", 2, &["a", "b"], Some("(%a + %b)"), None);
        let e = macro_table_find(&t, "ADD").unwrap();
        let out = macro_expand(e, &["1", "2"]).unwrap();
        assert_eq!(out, "(1 + 2)");
        // Missing args → empty string (C behavior).
        let out2 = macro_expand(e, &["1"]).unwrap();
        assert_eq!(out2, "(1 + )");
        // Case-insensitive param match; each bare % passes through.
        macro_table_add(&mut t, "MIX", 1, &["Arg"], Some("%arg%%"), None);
        let e2 = macro_table_find(&t, "MIX").unwrap();
        assert_eq!(macro_expand(e2, &["X"]).unwrap(), "X%%");
    }

    #[test]
    fn extract_callee_class_and_routine() {
        assert_eq!(
            macro_extract_callee("##class(%SYSTEM.Status).IsError(x)"),
            Some("%SYSTEM.Status.IsError".to_string())
        );
        assert_eq!(
            macro_extract_callee("do $$TAG^MYROUT(1)"),
            Some("TAG^MYROUT".to_string())
        );
        assert_eq!(macro_extract_callee("plain text"), None);
        assert_eq!(macro_extract_callee("##class(Broken"), None);
    }
}
