//! str_util.rs — 1:1 rewrite of `src/foundation/str_util.{c,h}`.
//!
//! Safe string operations. C originals are arena-allocated; Rust returns
//! owned `String`/`&str`, which subsumes the arena-lifetime concern.

/// Join `base` and `name` with a single `/`. Exact C semantics:
/// empty `base` → `name` verbatim; empty `name` → `base` verbatim;
/// otherwise trailing `/` on base and leading `/` on name are stripped
/// (all of them), then joined. A lone slash between separators collapses.
pub fn path_join(base: &str, name: &str) -> String {
    if base.is_empty() {
        return name.to_string();
    }
    if name.is_empty() {
        return base.to_string();
    }
    let b = base.trim_end_matches('/');
    let n = name.trim_start_matches('/');
    if b.is_empty() {
        return n.to_string();
    }
    if n.is_empty() {
        return b.to_string();
    }
    format!("{b}/{n}")
}

/// Join `parts` left-to-right with [`path_join`]; empty slice → "".
pub fn path_join_n(parts: &[&str]) -> String {
    match parts {
        [] => String::new(),
        [first] => (*first).to_string(),
        [first, rest @ ..] => {
            let mut acc = (*first).to_string();
            for p in rest {
                acc = path_join(&acc, p);
            }
            acc
        }
    }
}

/// Extension after the last `.`, if that dot is in the basename.
pub fn path_ext(path: &str) -> &str {
    let dot = match path.rfind('.') {
        Some(d) => d,
        None => return "",
    };
    let slash = path.rfind('/');
    match slash {
        Some(s) if s > dot => "",
        _ => {
            // dot at start of basename → no ext
            let base_start = slash.map_or(0, |s| s + 1);
            if dot == base_start {
                ""
            } else {
                &path[dot + 1..]
            }
        }
    }
}

/// Basename after the last `/`.
pub fn path_base(path: &str) -> &str {
    match path.rfind('/') {
        Some(s) => &path[s + 1..],
        None => path,
    }
}

/// Directory portion before the last `/`; `"."` when no slash.
pub fn path_dir(path: &str) -> String {
    match path.rfind('/') {
        Some(0) => "/".to_string(),
        Some(s) => path[..s].to_string(),
        None => ".".to_string(),
    }
}

pub fn starts_with(s: &str, prefix: &str) -> bool {
    s.starts_with(prefix)
}

pub fn ends_with(s: &str, suffix: &str) -> bool {
    s.ends_with(suffix)
}

pub fn contains(s: &str, sub: &str) -> bool {
    s.contains(sub)
}

/// ASCII lowercase (C `tolower` per byte — non-ASCII bytes pass through).
pub fn tolower(s: &str) -> String {
    s.chars().map(|c| c.to_ascii_lowercase()).collect()
}

/// Replace every occurrence of byte `from` with byte `to`.
pub fn replace_char(s: &str, from: char, to: char) -> String {
    s.chars().map(|c| if c == from { to } else { c }).collect()
}

/// Strip the extension (same rule as [`path_ext`]); unchanged when no ext.
pub fn strip_ext(path: &str) -> String {
    let dot = match path.rfind('.') {
        Some(d) => d,
        None => return path.to_string(),
    };
    let slash = path.rfind('/');
    if matches!(slash, Some(s) if s > dot) {
        return path.to_string();
    }
    let base_start = slash.map_or(0, |s| s + 1);
    if dot == base_start {
        return path.to_string();
    }
    path[..dot].to_string()
}

/// Split on `delim`, keeping empty parts (`"a::b"` → 3 parts).
pub fn split(s: &str, delim: char) -> Vec<String> {
    s.split(delim).map(str::to_string).collect()
}

/// Reject shell metacharacters in a subprocess argument (POSIX + Windows).
pub fn validate_shell_arg(s: &str) -> bool {
    !s.chars().any(|c| {
        matches!(
            c,
            '\'' | '"' | ';' | '|' | '&' | '$' | '`' | '<' | '>' | '\n' | '\r' | '\\'
        )
    })
}

/// [`validate_shell_arg`] plus Windows cmd.exe metacharacters (`%`, `!`, `^`)
/// that double-quoting cannot neutralize.
pub fn validate_shell_path_arg(path: &str) -> bool {
    if !validate_shell_arg(path) {
        return false;
    }
    // The C gate is `#ifdef _WIN32`; this build targets POSIX, so the
    // %/!/^ check is omitted — same as the compiled C on Linux.
    true
}

/// Project names: non-empty, no `..`/separators/leading dot, and only
/// `[A-Za-z0-9._-]`.
pub fn validate_project_name(name: &str) -> bool {
    if name.is_empty() {
        return false;
    }
    if name == ".." || name.contains("..") {
        return false;
    }
    if name.contains('/') || name.contains('\\') {
        return false;
    }
    if name.starts_with('.') {
        return false;
    }
    name.chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.')
}

/// JSON-escape `src` into `buf`, C-style: returns bytes written, stops at
/// capacity. Control chars become `\u00XX`; `"`,`\`,`\n`,`\r`,`\t` get the
/// short forms. Prefer [`json_escape_string`] for owned output.
pub fn json_escape(buf: &mut [u8], src: &str) -> usize {
    const CTRL_LIMIT: u8 = 0x20;
    let mut pos = 0usize;
    if buf.is_empty() {
        return 0;
    }
    let cap = buf.len() - 1; // reserve for NUL semantics (caller sets buf[pos])
    let bytes = src.as_bytes();
    let mut i = 0;
    while i < bytes.len() && pos < cap {
        let c = bytes[i];
        let esc: &[u8] = match c {
            b'"' | b'\\' => &[b'\\', c],
            b'\n' => b"\\n",
            b'\r' => b"\\r",
            b'\t' => b"\\t",
            _ if c < CTRL_LIMIT => {
                let hex = format!("\\u{:04x}", c);
                if pos + hex.len() > buf.len() - 1 {
                    break;
                }
                buf[pos..pos + hex.len()].copy_from_slice(hex.as_bytes());
                pos += hex.len();
                i += 1;
                continue;
            }
            _ => {
                buf[pos] = c;
                pos += 1;
                i += 1;
                continue;
            }
        };
        if pos + esc.len() > buf.len() - 1 {
            break;
        }
        buf[pos..pos + esc.len()].copy_from_slice(esc);
        pos += esc.len();
        i += 1;
    }
    pos
}

/// Owned variant of [`json_escape`] (no fixed buffer).
pub fn json_escape_string(src: &str) -> String {
    let mut buf = vec![0u8; src.len() * 6 + 1];
    let n = json_escape(&mut buf, src);
    buf.truncate(n + 1);
    String::from_utf8_lossy(&buf[..n]).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn path_join_basics() {
        assert_eq!(path_join("a/b", "c.txt"), "a/b/c.txt");
        assert_eq!(path_join("a/b/", "c.txt"), "a/b/c.txt"); // trailing slash trimmed
        assert_eq!(path_join("a/b", "/c.txt"), "a/b/c.txt"); // leading slash trimmed
        assert_eq!(path_join("", "x"), "x");
        assert_eq!(path_join("x", ""), "x");
        assert_eq!(path_join("", ""), "");
        assert_eq!(path_join("a//", "//b"), "a/b");
    }

    #[test]
    fn path_join_n_variants() {
        assert_eq!(path_join_n(&[]), "");
        assert_eq!(path_join_n(&["only"]), "only");
        assert_eq!(path_join_n(&["a", "b", "c"]), "a/b/c");
        assert_eq!(path_join_n(&["a/", "/b/"]), "a/b/"); // C: name's trailing slash survives
    }

    #[test]
    fn path_ext_cases() {
        assert_eq!(path_ext("a/b.txt"), "txt");
        assert_eq!(path_ext("a.tar.gz"), "gz");
        assert_eq!(path_ext("noext"), "");
        assert_eq!(path_ext("a.b/c"), ""); // dot before last slash
        assert_eq!(path_ext(".hidden"), ""); // dot at basename start
        assert_eq!(path_ext("dir/.hidden"), "");
        assert_eq!(path_ext(".hidden.ext"), "ext");
    }

    #[test]
    fn path_base_and_dir() {
        assert_eq!(path_base("a/b/c.txt"), "c.txt");
        assert_eq!(path_base("plain"), "plain");
        assert_eq!(path_base("a/"), "");
        assert_eq!(path_dir("a/b/c.txt"), "a/b");
        assert_eq!(path_dir("plain"), ".");
        assert_eq!(path_dir("/abs"), "/");
    }

    #[test]
    fn str_predicates() {
        assert!(starts_with("hello", "he"));
        assert!(!starts_with("hello", "lo"));
        assert!(ends_with("hello", "lo"));
        assert!(!ends_with("hello", "he"));
        assert!(contains("hello", "ell"));
        assert!(contains("hello", ""));
    }

    #[test]
    fn tolower_and_replace() {
        assert_eq!(tolower("HeLLo"), "hello");
        assert_eq!(replace_char("a/b/c", '/', '-'), "a-b-c");
        assert_eq!(replace_char("same", 'z', 'y'), "same");
    }

    #[test]
    fn strip_ext_cases() {
        assert_eq!(strip_ext("a/b.txt"), "a/b");
        assert_eq!(strip_ext("a.tar.gz"), "a.tar");
        assert_eq!(strip_ext("noext"), "noext");
        assert_eq!(strip_ext("a.b/c"), "a.b/c"); // dot before slash → unchanged
        assert_eq!(strip_ext(".hidden"), ".hidden");
        assert_eq!(strip_ext(".hidden.ext"), ".hidden");
    }

    #[test]
    fn split_keeps_empty_parts() {
        assert_eq!(split("a,b,c", ','), vec!["a", "b", "c"]);
        assert_eq!(split("a::b", ':'), vec!["a", "", "b"]);
        assert_eq!(split("", ','), vec![""]);
        assert_eq!(split("x", ','), vec!["x"]);
    }

    #[test]
    fn shell_validation() {
        assert!(validate_shell_arg("plain-file.txt"));
        assert!(validate_shell_arg("a b"));
        assert!(!validate_shell_arg("a;rm"));
        assert!(!validate_shell_arg("a|b"));
        assert!(!validate_shell_arg("$(cmd)"));
        assert!(!validate_shell_arg("back`tick"));
        assert!(!validate_shell_arg("a\nb"));
        assert!(!validate_shell_arg("back\\slash"));

        assert!(validate_shell_path_arg("/safe/path.txt"));
    }

    #[test]
    fn project_name_validation() {
        assert!(validate_project_name("my-project_1.0"));
        assert!(!validate_project_name(""));
        assert!(!validate_project_name(".."));
        assert!(!validate_project_name("a..b"));
        assert!(!validate_project_name("a/b"));
        assert!(!validate_project_name("a\\b"));
        assert!(!validate_project_name(".hidden"));
        assert!(!validate_project_name("has space"));
    }

    #[test]
    fn json_escape_full() {
        assert_eq!(json_escape_string("plain"), "plain");
        assert_eq!(json_escape_string("q\"uote"), "q\\\"uote");
        assert_eq!(json_escape_string("back\\slash"), "back\\\\slash");
        assert_eq!(json_escape_string("nl\n"), "nl\\n");
        assert_eq!(json_escape_string("cr\r"), "cr\\r");
        assert_eq!(json_escape_string("tab\t"), "tab\\t");
        assert_eq!(json_escape_string("\u{1}\u{1f}"), "\\u0001\\u001f");
        assert_eq!(json_escape_string("中文"), "中文");
    }

    #[test]
    fn json_escape_respects_buffer_cap() {
        let mut buf = [0u8; 8];
        let n = json_escape(&mut buf, "abcdefghij");
        assert_eq!(n, 7); // 8 - 1 reserved
        assert_eq!(&buf[..n], b"abcdefg");
        let mut tiny = [0u8; 1];
        assert_eq!(json_escape(&mut tiny, "abc"), 0);
    }
}
