//! helpers.rs — rewrite of `internal/cbm/helpers.{c,h}` (part 1: pure
//! name/path classification helpers; the AST-traversal half lands with
//! extract_defs.rs, which shares its ctx type).
//!
//! Every list here is verbatim from the C — keyword sets, credential
//! shapes, and label sets are load-bearing for graph parity.

use crate::types::StringRefKind;
use crate::Language;

// ── Constants (C helpers.c enum) ────────────────────────────────

const MIN_ROUTE_LEN: usize = 3;
const MIN_SYS_PATH_LEN: usize = 4;
const MAX_ROUTE_SCAN: usize = 20;
const MAX_HEX_NAME_LEN: usize = 64;

// ── Keyword sets (verbatim) ─────────────────────────────────────

const GO_KEYWORDS: &[&str] = &[
    "break",
    "case",
    "chan",
    "const",
    "continue",
    "default",
    "defer",
    "else",
    "fallthrough",
    "for",
    "func",
    "go",
    "goto",
    "if",
    "import",
    "interface",
    "map",
    "package",
    "range",
    "return",
    "select",
    "struct",
    "switch",
    "type",
    "var",
    "true",
    "false",
    "nil",
    "iota",
    "append",
    "cap",
    "close",
    "complex",
    "copy",
    "delete",
    "imag",
    "len",
    "make",
    "new",
    "panic",
    "print",
    "println",
    "real",
    "recover",
];

const PYTHON_KEYWORDS: &[&str] = &[
    "False",
    "None",
    "True",
    "and",
    "as",
    "assert",
    "async",
    "await",
    "break",
    "class",
    "continue",
    "def",
    "del",
    "elif",
    "else",
    "except",
    "finally",
    "for",
    "from",
    "global",
    "if",
    "import",
    "in",
    "is",
    "lambda",
    "nonlocal",
    "not",
    "or",
    "pass",
    "raise",
    "return",
    "try",
    "while",
    "with",
    "yield",
    "self",
    "cls",
    "__init__",
    "__name__",
    "__main__",
    "super",
    "print",
    "len",
    "range",
    "enumerate",
    "zip",
    "map",
    "filter",
    "type",
    "int",
    "str",
    "float",
    "bool",
    "list",
    "dict",
    "set",
    "tuple",
    "bytes",
];

const JS_KEYWORDS: &[&str] = &[
    "break",
    "case",
    "catch",
    "class",
    "const",
    "continue",
    "debugger",
    "default",
    "delete",
    "do",
    "else",
    "export",
    "extends",
    "false",
    "finally",
    "for",
    "function",
    "if",
    "import",
    "in",
    "instanceof",
    "let",
    "new",
    "null",
    "return",
    "super",
    "switch",
    "this",
    "throw",
    "true",
    "try",
    "typeof",
    "undefined",
    "var",
    "void",
    "while",
    "with",
    "yield",
    "async",
    "await",
    "of",
    "static",
    "get",
    "set",
    "from",
    "as",
    "constructor",
    "prototype",
    "console",
    "window",
    "document",
    "process",
    "module",
    "exports",
    "require",
    "Array",
    "Object",
    "String",
    "Number",
    "Boolean",
    "Symbol",
    "Map",
    "Set",
    "Promise",
    "Error",
    "RegExp",
    "Date",
    "Math",
    "JSON",
    "parseInt",
    "parseFloat",
    "setTimeout",
    "setInterval",
    "clearTimeout",
    "clearInterval",
];

const RUST_KEYWORDS: &[&str] = &[
    "as",
    "async",
    "await",
    "break",
    "const",
    "continue",
    "crate",
    "dyn",
    "else",
    "enum",
    "extern",
    "false",
    "fn",
    "for",
    "if",
    "impl",
    "in",
    "let",
    "loop",
    "match",
    "mod",
    "move",
    "mut",
    "pub",
    "ref",
    "return",
    "self",
    "Self",
    "static",
    "struct",
    "super",
    "trait",
    "true",
    "type",
    "unsafe",
    "use",
    "where",
    "while",
    "abstract",
    "become",
    "box",
    "do",
    "final",
    "macro",
    "override",
    "priv",
    "try",
    "typeof",
    "unsized",
    "virtual",
    "yield",
    "Some",
    "None",
    "Ok",
    "Err",
    "Vec",
    "String",
    "Box",
    "Rc",
    "Arc",
    "Option",
    "Result",
    "println",
    "eprintln",
    "format",
    "write",
    "writeln",
    "print",
    "eprint",
    "panic",
    "assert",
    "assert_eq",
    "assert_ne",
    "debug_assert",
    "todo",
    "unimplemented",
    "cfg",
    "derive",
    "test",
    "allow",
    "deny",
    "warn",
    "forbid",
    "deprecated",
];

const JAVA_KEYWORDS: &[&str] = &[
    "abstract",
    "assert",
    "boolean",
    "break",
    "byte",
    "case",
    "catch",
    "char",
    "class",
    "const",
    "continue",
    "default",
    "do",
    "double",
    "else",
    "enum",
    "extends",
    "false",
    "final",
    "finally",
    "float",
    "for",
    "goto",
    "if",
    "implements",
    "import",
    "instanceof",
    "int",
    "interface",
    "long",
    "native",
    "new",
    "null",
    "package",
    "private",
    "protected",
    "public",
    "return",
    "short",
    "static",
    "strictfp",
    "super",
    "switch",
    "synchronized",
    "this",
    "throw",
    "throws",
    "transient",
    "true",
    "try",
    "void",
    "volatile",
    "while",
    "var",
    "record",
    "sealed",
    "permits",
    "yield",
    "System",
    "String",
    "Integer",
    "Long",
    "Double",
    "Float",
    "Boolean",
    "Object",
    "List",
    "Map",
    "Set",
    "Optional",
    "Stream",
    "Arrays",
    "Collections",
];

/// Kotlin hard keywords only. Kotlin does NOT reserve primitive type names
/// (`fun double()` is legal); soft/modifier keywords are usable as
/// identifiers and intentionally omitted.
const KOTLIN_KEYWORDS: &[&str] = &[
    "as",
    "break",
    "class",
    "continue",
    "do",
    "else",
    "false",
    "for",
    "fun",
    "if",
    "in",
    "interface",
    "is",
    "null",
    "object",
    "package",
    "return",
    "super",
    "this",
    "throw",
    "true",
    "try",
    "typealias",
    "typeof",
    "val",
    "var",
    "when",
    "while",
];

const GENERIC_KEYWORDS: &[&str] = &[
    "true",
    "false",
    "null",
    "nil",
    "None",
    "undefined",
    "void",
    "if",
    "else",
    "for",
    "while",
    "do",
    "switch",
    "case",
    "default",
    "break",
    "continue",
    "return",
    "throw",
    "try",
    "catch",
    "finally",
    "class",
    "struct",
    "enum",
    "interface",
    "trait",
    "impl",
    "import",
    "export",
    "package",
    "module",
    "use",
    "require",
    "include",
    "new",
    "delete",
    "this",
    "self",
    "super",
    "public",
    "private",
    "protected",
    "static",
    "const",
    "var",
    "let",
    "function",
    "def",
    "fn",
    "func",
    "fun",
    "proc",
    "sub",
    "method",
    "async",
    "await",
    "yield",
];

/// Puppet reserves control-flow words but NOT include/require/contain
/// (ordinary built-in functions invoked as calls) — a generic list would
/// wrongly drop those call edges.
const PUPPET_KEYWORDS: &[&str] = &[
    "true", "false", "undef", "if", "elsif", "else", "unless", "case", "and", "or", "in", "node",
    "class", "define", "inherits", "default", "return",
];

/// Builtins with a real graph node (MUST stay in sync with kPyBuiltinNodes
/// in lsp/py_builtins.c): suppressed as bare usages, but a CALL to them is
/// still extracted because the LSP resolves it to "builtins.<name>".
const PYTHON_RESOLVABLE_BUILTINS: &[&str] =
    &["len", "print", "str", "int", "list", "dict", "range"];

/// Ancestor-walk bound for lisp_node_in_quote: a quote nest deeper than
/// this is pathological input, not Chialisp (C CBM_LISP_QUOTE_ANCESTOR_MAX).
const LISP_QUOTE_ANCESTOR_MAX: usize = 256;

/// True when any ancestor list of `node` is headed by a quote symbol
/// (`q`/`quote`/`qq`) — its contents are DATA, not code, so no def and no
/// call may be minted from them (C cbm_lisp_node_in_quote).
pub fn lisp_node_in_quote(node: tree_sitter::Node<'_>, source: &str) -> bool {
    let mut cur = node.parent();
    for _ in 0..LISP_QUOTE_ANCESTOR_MAX {
        let Some(cur_node) = cur else { return false };
        let ck = cur_node.kind();
        if (ck == "list" || ck == "list_lit") && cur_node.named_child_count() > 0 {
            if let Some(h) = cur_node.named_child(0) {
                let hk = h.kind();
                if hk == "symbol" || hk == "sym_lit" {
                    let ht = crate::fqn::node_text(h, source);
                    if ht == "q" || ht == "quote" || ht == "qq" {
                        return true;
                    }
                }
            }
        }
        cur = cur_node.parent();
    }
    false
}

/// The `want`-th named child of `node`, skipping `comment` nodes. Comments
/// are named in the s-expression grammars and so occupy named-child
/// indices: a comment between a def head and its name shifts every later
/// index by one. Definition extraction and call-scope attribution MUST use
/// this same skipping rule or they desynchronise on exactly the files that
/// carry doc comments (C cbm_lisp_named_child_skip_comments).
pub fn lisp_named_child_skip_comments<'t>(
    node: tree_sitter::Node<'t>,
    want: usize,
) -> Option<tree_sitter::Node<'t>> {
    let mut seen = 0usize;
    for i in 0..node.named_child_count() {
        let c = node.named_child(i)?;
        if c.kind() == "comment" {
            continue;
        }
        if seen == want {
            return Some(c);
        }
        seen += 1;
    }
    None
}

/// Chialisp definition-form heads (C cbm_chialisp_is_def_head).
/// `export` and `namespace` are absent ON PURPOSE: `(export foo)` re-exports
/// a function `(defun foo ...)` already defined in the same file, so
/// admitting it here mints a SECOND node for the same symbol.
pub fn chialisp_is_def_head(t: &str) -> bool {
    matches!(
        t,
        "mod"
            | "defun"
            | "defun-inline"
            | "defmacro"
            | "defmac"
            | "defconstant"
            | "defconst"
            | "embed-file"
            | "compile-file"
    )
}

/// Is this a language keyword (skip as callee/usage)?
pub fn is_keyword(name: &str, lang: Language) -> bool {
    if name.is_empty() {
        return true;
    }
    let keywords: &[&str] = match lang {
        Language::GO => GO_KEYWORDS,
        Language::PYTHON => PYTHON_KEYWORDS,
        Language::JAVASCRIPT | Language::TYPESCRIPT | Language::TSX | Language::ARKTS => {
            JS_KEYWORDS
        }
        Language::RUST => RUST_KEYWORDS,
        Language::JAVA | Language::SCALA => JAVA_KEYWORDS,
        Language::KOTLIN => KOTLIN_KEYWORDS,
        Language::PUPPET => PUPPET_KEYWORDS,
        _ => GENERIC_KEYWORDS,
    };
    keywords.contains(&name)
}

pub fn is_resolvable_builtin(name: &str, lang: Language) -> bool {
    if name.is_empty() || lang != Language::PYTHON {
        return false;
    }
    PYTHON_RESOLVABLE_BUILTINS.contains(&name)
}

// ── Label classification (single source of truth) ───────────────

/// Type-like container labels. Adding one here updates the SQL mirror in
/// cbm-foundation::constants, the registry, IMPLEMENTS and LSP consumers.
pub fn label_is_type_like(label: &str) -> bool {
    matches!(
        label,
        "Class" | "Struct" | "Interface" | "Enum" | "Type" | "Trait"
    )
}

/// Data relation: SQL CREATE TABLE/VIEW and a dbt Model.
pub fn label_is_relation(label: &str) -> bool {
    matches!(label, "Table" | "View" | "Model")
}

/// Labels admitted to the cross-file name registry: full, parallel and
/// incremental pipelines MUST agree or incremental re-resolve diverges
/// from a clean reindex. "Constant" is deliberately NOT type-like — a
/// constant must never satisfy an inheritance/impl/semantic-type lookup.
pub fn label_is_registry_symbol(label: &str) -> bool {
    matches!(
        label,
        "Function" | "Method" | "Variable" | "Constant" | "Field"
    ) || label_is_type_like(label)
        || label_is_relation(label)
}

// ── Export / test-file classification ───────────────────────────

/// Exported per language convention.
pub fn is_exported(name: &str, lang: Language) -> bool {
    if name.is_empty() {
        return false;
    }
    let first = name.as_bytes()[0];
    match lang {
        Language::GO => first.is_ascii_uppercase(),
        Language::PYTHON => first != b'_',
        Language::JAVA | Language::CSHARP | Language::KOTLIN => first.is_ascii_uppercase(),
        _ => true,
    }
}

fn has_suffix(s: &str, suffix: &str) -> bool {
    s.ends_with(suffix)
}

/// Test-file detection: directory rules are language-agnostic (a file
/// under a conventional test directory is a test file regardless of
/// basename, mirroring cbm_is_test_path in pass_tests.c, #1294); then
/// per-language basename rules.
pub fn is_test_file(rel_path: &str, lang: Language) -> bool {
    // Directory-based, language-agnostic.
    if rel_path.contains("__tests__/")
        || rel_path.contains("/tests/")
        || rel_path.contains("/test/")
        || rel_path.contains("/spec/")
        || rel_path.starts_with("tests/")
        || rel_path.starts_with("test/")
        || rel_path.starts_with("spec/")
        || rel_path.starts_with("__tests__/")
    {
        return true;
    }
    let base = rel_path.rsplit('/').next().unwrap_or(rel_path);
    match lang {
        Language::GO => has_suffix(base, "_test.go"),
        Language::PYTHON => base.starts_with("test_") || has_suffix(base, "_test.py"),
        Language::JAVASCRIPT | Language::TYPESCRIPT | Language::TSX | Language::ARKTS => {
            let noext = base.rsplit_once('.').map(|(stem, _)| stem).unwrap_or(base);
            has_suffix(noext, ".test")
                || has_suffix(noext, ".spec")
                || has_suffix(noext, "_test")
                || has_suffix(noext, "_spec")
                || base.starts_with("test_")
        }
        Language::JAVA | Language::KOTLIN | Language::SCALA => {
            has_suffix(base, "Test.java")
                || has_suffix(base, "Tests.java")
                || has_suffix(base, "Spec.java")
                || has_suffix(base, "Test.kt")
                || has_suffix(base, "Spec.kt")
                || has_suffix(base, "Test.scala")
                || has_suffix(base, "Spec.scala")
        }
        Language::RUST => has_suffix(base, "_test.rs") || base.starts_with("test_"),
        Language::RUBY => {
            has_suffix(base, "_test.rb")
                || has_suffix(base, "_spec.rb")
                || base.starts_with("test_")
        }
        Language::PHP => has_suffix(base, "Test.php"),
        Language::CSHARP => has_suffix(base, "Tests.cs") || has_suffix(base, "Test.cs"),
        Language::CPP | Language::C => {
            has_suffix(base, "_test.c")
                || has_suffix(base, "_test.cc")
                || has_suffix(base, "_test.cpp")
                || base.starts_with("test_")
        }
        Language::MATLAB => base.starts_with("test_") || base.starts_with("Test"),
        _ => false,
    }
}

// ── String literal classifier ───────────────────────────────────

/// Slash-prefixed strings that are filesystem paths, not REST routes.
fn is_filesystem_path(s: &str) -> bool {
    if s.len() <= MIN_SYS_PATH_LEN {
        return false;
    }
    [
        "/usr/", "/bin/", "/etc/", "/var/", "/tmp/", "/opt/", "/home/", "/dev/", "/sys/", "/proc/",
    ]
    .iter()
    .any(|p| s.starts_with(p))
}

/// Slash-prefixed strings that look like REST API paths.
fn is_rest_path(s: &str) -> bool {
    if is_filesystem_path(s) {
        return false;
    }
    if s.len() > 1 && s.ends_with('/') {
        return false; // regex pattern
    }
    if s.as_bytes().get(1) == Some(&b'^') {
        return false; // regex
    }
    if s.len() == 1 || (s.len() == 2 && s.as_bytes()[1] == b'/') {
        return false; // bare / or //
    }
    if s.as_bytes().get(1) == Some(&b'.') {
        return false; // relative path
    }
    s[1..s.len().min(MAX_ROUTE_SCAN)]
        .chars()
        .any(|c| c.is_ascii_alphanumeric())
}

fn is_url_like(s: &str) -> bool {
    if s.len() < MIN_ROUTE_LEN {
        return false;
    }
    if s.contains("://") {
        return true;
    }
    if s.starts_with('/') {
        return is_rest_path(s);
    }
    false
}

fn has_config_extension(s: &str) -> bool {
    [
        ".toml",
        ".yaml",
        ".yml",
        ".json",
        ".ini",
        ".env",
        ".cfg",
        ".conf",
        ".properties",
    ]
    .iter()
    .any(|ext| s.len() > ext.len() && s.ends_with(ext))
}

/// SCREAMING_SNAKE_CASE within the length window (env-var key shape).
fn is_env_var_pattern(s: &str) -> bool {
    if s.len() < MIN_ROUTE_LEN || s.len() > MAX_HEX_NAME_LEN {
        return false;
    }
    let mut has_upper = false;
    let mut has_underscore = false;
    for c in s.chars() {
        if c.is_ascii_uppercase() {
            has_upper = true;
        } else if c == '_' {
            has_underscore = true;
        } else if c.is_ascii_digit() {
            // digits ok
        } else {
            return false;
        }
    }
    has_upper && has_underscore
}

/// Classify a string literal: URL, CONFIG, or None (C cbm_classify_string).
pub fn classify_string(s: &str) -> Option<StringRefKind> {
    if s.len() < 2 {
        return None;
    }
    if is_url_like(s) {
        return Some(StringRefKind::Url);
    }
    if has_config_extension(s) {
        return Some(StringRefKind::Config);
    }
    if is_env_var_pattern(s) {
        return Some(StringRefKind::Config);
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keyword_sets_by_language() {
        assert!(is_keyword("func", Language::GO));
        assert!(is_keyword("defer", Language::GO));
        assert!(!is_keyword("Func", Language::GO));
        assert!(is_keyword("def", Language::PYTHON));
        assert!(is_keyword("self", Language::PYTHON)); // added to the set
        assert!(!is_keyword("self", Language::GO));
        assert!(is_keyword("fn", Language::RUST));
        assert!(is_keyword("let", Language::RUST));
        // Kotlin does NOT reserve primitive names.
        assert!(!is_keyword("double", Language::KOTLIN));
        assert!(is_keyword("when", Language::KOTLIN));
        // Puppet keeps include/require as callable builtins.
        assert!(!is_keyword("include", Language::PUPPET));
        assert!(is_keyword("unless", Language::PUPPET));
        // Java/Scala share a set.
        assert!(is_keyword("synchronized", Language::JAVA));
        assert!(is_keyword("synchronized", Language::SCALA));
        // Fallback set for everything else.
        assert!(is_keyword("sub", Language::PERL));
        assert!(!is_keyword("some_function", Language::PERL));
        // Empty names are keywords (skip everything).
        assert!(is_keyword("", Language::PYTHON));
    }

    #[test]
    fn resolvable_builtins_python_only() {
        for b in ["len", "print", "str", "int", "list", "dict", "range"] {
            assert!(is_resolvable_builtin(b, Language::PYTHON), "{b}");
        }
        assert!(!is_resolvable_builtin("len", Language::GO));
        assert!(!is_resolvable_builtin("not_a_builtin", Language::PYTHON));
        assert!(!is_resolvable_builtin("", Language::PYTHON));
    }

    #[test]
    fn label_classifiers() {
        for l in ["Class", "Struct", "Interface", "Enum", "Type", "Trait"] {
            assert!(label_is_type_like(l), "{l}");
        }
        assert!(!label_is_type_like("Function"));
        for l in ["Table", "View", "Model"] {
            assert!(label_is_relation(l), "{l}");
        }
        for l in ["Function", "Method", "Variable", "Constant", "Field"] {
            assert!(label_is_registry_symbol(l), "{l}");
        }
        assert!(label_is_registry_symbol("Class"));
        assert!(label_is_registry_symbol("Table"));
        assert!(!label_is_registry_symbol("Module"));
        assert!(!label_is_registry_symbol("File"));
    }

    #[test]
    fn export_conventions() {
        assert!(is_exported("Handler", Language::GO));
        assert!(!is_exported("handler", Language::GO));
        assert!(is_exported("public_fn", Language::PYTHON));
        assert!(!is_exported("_private_fn", Language::PYTHON));
        assert!(is_exported("UserService", Language::JAVA));
        assert!(!is_exported("userService", Language::JAVA));
        assert!(is_exported("anything", Language::RUST)); // default true
        assert!(!is_exported("", Language::GO));
    }

    #[test]
    fn test_file_directory_rules() {
        assert!(is_test_file("tests/helpers/fixtures.c", Language::C));
        assert!(is_test_file("src/__tests__/foo.ts", Language::JAVASCRIPT));
        assert!(is_test_file("test/x.py", Language::PYTHON));
        assert!(is_test_file("spec/user_spec.rb", Language::RUBY));
        assert!(!is_test_file("src/main.rs", Language::RUST));
    }

    #[test]
    fn test_file_language_rules() {
        assert!(is_test_file("main_test.go", Language::GO));
        assert!(!is_test_file("main.go", Language::GO));
        assert!(is_test_file("test_user.py", Language::PYTHON));
        assert!(is_test_file("user_test.py", Language::PYTHON));
        assert!(!is_test_file("user.py", Language::PYTHON));
        assert!(is_test_file("app.test.tsx", Language::TSX));
        assert!(is_test_file("app.spec.ts", Language::TYPESCRIPT));
        assert!(is_test_file("UserTest.java", Language::JAVA));
        assert!(is_test_file("UserServiceTest.kt", Language::KOTLIN));
        assert!(is_test_file("lib_test.rs", Language::RUST));
        assert!(is_test_file("FooTest.php", Language::PHP));
        assert!(is_test_file("foo_test.cpp", Language::CPP));
        assert!(!is_test_file("foo.cpp", Language::CPP));
    }

    #[test]
    fn classify_urls() {
        assert_eq!(
            classify_string("https://api.example.com/v1"),
            Some(StringRefKind::Url)
        );
        assert_eq!(classify_string("grpc://svc:9090"), Some(StringRefKind::Url));
        assert_eq!(classify_string("/api/users/{id}"), Some(StringRefKind::Url));
        assert_eq!(classify_string("/webhooks/gh"), Some(StringRefKind::Url));
    }

    #[test]
    fn classify_rest_path_exclusions() {
        // filesystem paths are not REST (but /etc/config.yaml still carries
        // a config extension, so the C classifier returns CONFIG for it).
        assert_eq!(classify_string("/usr/local/bin"), None);
        assert_eq!(
            classify_string("/etc/config.yaml"),
            Some(StringRefKind::Config)
        );
        // regex patterns
        assert_eq!(classify_string("/^ab+$/"), None);
        assert_eq!(classify_string("/*/"), None);
        // bare / or //, relative
        assert_eq!(classify_string("/"), None);
        assert_eq!(classify_string("//"), None);
        assert_eq!(classify_string("/./x"), None);
    }

    #[test]
    fn classify_config_and_env() {
        assert_eq!(
            classify_string("settings.toml"),
            Some(StringRefKind::Config)
        );
        assert_eq!(
            classify_string("config/app.yml"),
            Some(StringRefKind::Config)
        );
        assert_eq!(classify_string(".env"), None); // ext must be a suffix of something longer
        assert_eq!(classify_string("DATABASE_URL"), Some(StringRefKind::Config));
        assert_eq!(classify_string("MY_KEY_2"), Some(StringRefKind::Config));
        // lowercase-only / no underscore → not an env var
        assert_eq!(classify_string("lower_case"), None);
        assert_eq!(classify_string("UPPERCASE"), None);
        assert_eq!(classify_string("plain text"), None);
        assert_eq!(classify_string(""), None);
        assert_eq!(classify_string("a"), None);
    }
}
