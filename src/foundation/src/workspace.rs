//! workspace.rs — 1:1 rewrite of `src/foundation/workspace.{c,h}` (POSIX
//! surface; the Windows volume/UNC branches degrade to their POSIX
//! minimums here).
//!
//! Root classification and the grant store. The breadth policy is ALWAYS
//! enforced ("…/", "/etc", "$HOME", "~/.ssh" and friends refuse with no
//! configuration); containment applies only once the grant store is
//! non-empty or a root is configured — declaring the first root turns on
//! confinement and never silently loosens it.

use std::io::Write;
use std::path::PathBuf;

pub const WS_MANIFEST_NAME: &str = ".cbmpathwhitelist";
#[allow(dead_code)] // consumed by the manifest reader (task: src/discover)
const WS_MANIFEST_MAX_ENTRIES: usize = 64;
const WS_MIN_DEPTH_POSIX: i32 = 2;
const WS_MIN_DEPTH_WINDOWS: i32 = 1;
const WS_LINE_MAX: usize = 4096;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WsVerdict {
    Allow,
    /// Fewer path components than the platform minimum — "/etc", "/home".
    DenyTooShallow,
    /// A filesystem root, or a path that is/contains the cache dir. Never
    /// overridable.
    DenyAbsolute,
    /// The home directory itself, or a credential/system directory.
    /// Overridable only by an explicit human action.
    DenySensitive,
}

pub fn verdict_reason(verdict: WsVerdict) -> &'static str {
    match verdict {
        WsVerdict::Allow => "allowed",
        WsVerdict::DenyTooShallow => {
            "path is too broad to index as one root; name a project directory below it"
        }
        WsVerdict::DenyAbsolute => {
            "path is a volume root or holds the codebase-memory cache; it cannot be indexed"
        }
        WsVerdict::DenySensitive => {
            "path is a home, credential, system, or application-install directory"
        }
    }
}

pub fn verdict_is_overridable(verdict: WsVerdict) -> bool {
    verdict == WsVerdict::DenySensitive
}

/// Directory/file names carrying credentials — matched against EVERY
/// component, so both "…/.ssh" and "…/.ssh/sub" refuse. Additive by
/// design: appending a name needs no design authority.
const WS_CREDENTIAL_NAMES: &[&str] = &[
    ".ssh",
    ".aws",
    ".gnupg",
    ".gpg",
    ".kube",
    ".docker",
    ".netrc",
    "_netrc",
    ".git-credentials",
    ".azure",
    ".gcloud",
    "Keychains",
    ".password-store",
    ".authinfo",
];

/// Windows system trees — first component below the drive only. "Users"
/// is deliberately absent (it would refuse every ordinary Windows
/// project path); it is handled as a tree root, mirroring "/Users" on
/// POSIX.
const WS_WINDOWS_SYSTEM_TREES: &[&str] = &[
    "Windows",
    "ProgramData",
    "Program Files",
    "Program Files (x86)",
];
const WS_WINDOWS_USER_TREE: &str = "Users";

fn is_sep(c: char) -> bool {
    c == '/' || c == '\\'
}

/// Volume prefix length: POSIX absolute ("/") or Windows style
/// ("C:/", "//srv/share/"). Returns 0 for relative paths (not usable).
fn volume_prefix_len(path: &str) -> usize {
    let b = path.as_bytes();
    if b.is_empty() {
        return 0;
    }
    if b[0] == b'/' {
        return 1;
    }
    // Windows drive: "X:/"
    if b.len() >= 3 && b[0].is_ascii_alphabetic() && b[1] == b':' && (b[2] == b'/' || b[2] == b'\\')
    {
        return 3;
    }
    // UNC: "//srv/share"
    if b.len() >= 2 && b[0] == b'\\' && b[1] == b'\\' {
        let mut seps = 0;
        for (i, &c) in b.iter().enumerate() {
            if c == b'\\' {
                seps += 1;
                if seps == 4 {
                    return i;
                }
            }
        }
        return b.len();
    }
    0
}

fn is_windows_style(path: &str) -> bool {
    let b = path.as_bytes();
    (b.len() >= 3 && b[1] == b':')
        || (b.len() >= 2 && b[0] == b'\\' && b[1] == b'\\')
        || b.contains(&b'\\')
}

/// Component count below the volume prefix. macOS firmlinks make "/etc"
/// canonicalize to "/private/etc"; a leading "private" is treated as
/// transparent so depth reflects the tree the user named.
pub fn path_depth(canonical_path: &str) -> i32 {
    let prefix = volume_prefix_len(canonical_path);
    if prefix == 0 {
        return 0;
    }
    let mut rest = &canonical_path[prefix..];
    if let Some(stripped) = rest.strip_prefix("private") {
        if stripped.is_empty() || is_sep(stripped.chars().next().unwrap()) {
            rest = stripped;
        }
    }
    rest.split(is_sep).filter(|c| !c.is_empty()).count() as i32
}

fn component_matches(comp: &str, name: &str, fold_case: bool) -> bool {
    if comp.len() != name.len() {
        return false;
    }
    if fold_case {
        comp.eq_ignore_ascii_case(name)
    } else {
        comp == name
    }
}

fn any_component_matches(path: &str, names: &[&str], fold_case: bool) -> bool {
    let prefix = volume_prefix_len(path);
    path[prefix.min(path.len())..]
        .split(is_sep)
        .any(|c| names.iter().any(|n| component_matches(c, n, fold_case)))
}

fn first_component_matches(path: &str, names: &[&str], fold_case: bool) -> bool {
    let prefix = volume_prefix_len(path);
    let first = path[prefix.min(path.len())..]
        .split(is_sep)
        .find(|c| !c.is_empty());
    first
        .map(|c| names.iter().any(|n| component_matches(c, n, fold_case)))
        .unwrap_or(false)
}

/// `a` equals `b` or is an ancestor of it (component-boundary aware).
fn is_ancestor_or_equal(a: &str, b: &str) -> bool {
    if a.is_empty() || b.is_empty() {
        return false;
    }
    let a = a.trim_end_matches(is_sep);
    let a_norm = if a.is_empty() { "/" } else { a };
    if !b.starts_with(a_norm) {
        return false;
    }
    let rest = &b[a_norm.len()..];
    rest.is_empty() || rest.starts_with(is_sep)
}

fn paths_equal(a: &str, b: &str) -> bool {
    is_ancestor_or_equal(a, b) && is_ancestor_or_equal(b, a)
}

/// Is `abs_path` inside `root_path` (C cbm_path_within_root)?
pub fn path_within_root(root_path: &str, abs_path: &str) -> bool {
    is_ancestor_or_equal(root_path, abs_path)
}

/// Classify a canonical root (C cbm_workspace_classify_root).
pub fn classify_root(
    canonical_path: &str,
    home_dir: Option<&str>,
    cache_dir: Option<&str>,
) -> WsVerdict {
    if canonical_path.is_empty() || volume_prefix_len(canonical_path) == 0 {
        // A relative path is not a usable root; refuse like a volume root.
        return WsVerdict::DenyAbsolute;
    }
    let windows_style = is_windows_style(canonical_path);
    let depth = path_depth(canonical_path);
    if depth == 0 {
        return WsVerdict::DenyAbsolute;
    }
    // Home before cache: the home normally CONTAINS the cache, so testing
    // the cache first would report every $HOME as "holds the cache".
    if let Some(h) = home_dir {
        if !h.is_empty() && paths_equal(canonical_path, h) {
            return WsVerdict::DenySensitive;
        }
    }
    let min_depth = if windows_style {
        WS_MIN_DEPTH_WINDOWS
    } else {
        WS_MIN_DEPTH_POSIX
    };
    if depth < min_depth {
        return WsVerdict::DenyTooShallow;
    }
    // No rule for "this root contains the cache dir" (see the C comment:
    // the indexer never extracts a binary SQLite graph; the cache is
    // excluded from discovery separately).
    let _ = cache_dir;
    if any_component_matches(canonical_path, WS_CREDENTIAL_NAMES, windows_style) {
        return WsVerdict::DenySensitive;
    }
    if windows_style {
        if first_component_matches(canonical_path, WS_WINDOWS_SYSTEM_TREES, true)
            || (first_component_matches(canonical_path, &[WS_WINDOWS_USER_TREE], true)
                && depth == 1)
        {
            return WsVerdict::DenySensitive;
        }
    } else {
        // POSIX: "/Users" style breadth refusals are covered by depth; a
        // "Users" first component is ordinary user space.
        let _ = WS_WINDOWS_USER_TREE;
    }
    WsVerdict::Allow
}

// ── Grant store ─────────────────────────────────────────────────

/// A line may carry a leading '!' — "a person explicitly approved this
/// sensitive root". Stored rather than inferred so re-classifying later
/// cannot silently upgrade an ordinary grant into a sensitive one.
const WS_SENSITIVE_MARK: char = '!';

/// Grant store path: `<cache_dir>/allowed_roots`.
pub fn grant_path(cache_dir: &str) -> Option<PathBuf> {
    if cache_dir.is_empty() {
        return None;
    }
    let p = format!("{cache_dir}/allowed_roots");
    if p.len() >= WS_LINE_MAX {
        return None;
    }
    Some(PathBuf::from(p))
}

/// Walk the grant file, visiting each entry. Returns entries seen.
fn grant_walk(cache_dir: &str, mut visit: impl FnMut(&str, bool) -> bool) -> usize {
    let Some(store) = grant_path(cache_dir) else {
        return 0;
    };
    let Ok(text) = std::fs::read_to_string(store) else {
        return 0;
    };
    let mut seen = 0usize;
    for line in text.lines() {
        let line = line.trim_end_matches(['\n', '\r']);
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let (sensitive, root) = match line.strip_prefix(WS_SENSITIVE_MARK) {
            Some(r) => (true, r),
            None => (false, line),
        };
        if root.is_empty() {
            continue;
        }
        seen += 1;
        if visit(root, sensitive) {
            break;
        }
    }
    seen
}

#[derive(Default)]
struct Match {
    candidate: String,
    contained: bool,
    exact_sensitive: bool,
}

fn match_visit(root: &str, sensitive: bool, m: &mut Match) {
    if path_within_root(root, &m.candidate) {
        m.contained = true;
        if sensitive && paths_equal(root, &m.candidate) {
            m.exact_sensitive = true;
        }
    }
}

/// List the grant store as human-readable lines.
pub fn grant_list(cache_dir: &str) -> Option<String> {
    let mut out = String::new();
    grant_walk(cache_dir, |root, sensitive| {
        out.push_str(if sensitive { "(approved) " } else { "" });
        out.push_str(root);
        out.push('\n');
        false // visit every entry
    });
    Some(out)
}

/// Grant a root (C cbm_workspace_grant_add). Sensitive verdicts require
/// `approve_sensitive` — refuse by default and name the flag rather than
/// asking a question whose answer we cannot authenticate.
pub fn grant_add(
    cache_dir: &str,
    home_dir: Option<&str>,
    canonical_path: &str,
    approve_sensitive: bool,
) -> Result<bool, String> {
    let verdict = classify_root(canonical_path, home_dir, Some(cache_dir));
    if verdict != WsVerdict::Allow {
        if !verdict_is_overridable(verdict) {
            return Err(verdict_reason(verdict).to_string());
        }
        if !approve_sensitive {
            return Err(format!(
                "{}; re-run with --approve-sensitive if that is intended",
                verdict_reason(verdict)
            ));
        }
    }
    let sensitive = verdict == WsVerdict::DenySensitive;
    // Already present is success, not a duplicate error. A sensitive
    // approval is narrower: an old ordinary grant establishes containment
    // but does not record the exact human-approved exception — append that
    // exact marked entry once.
    let mut existing = Match {
        candidate: canonical_path.to_string(),
        ..Match::default()
    };
    grant_walk(cache_dir, |root, sensitive| {
        match_visit(root, sensitive, &mut existing);
        false
    });
    if existing.contained && (!sensitive || existing.exact_sensitive) {
        return Ok(true);
    }
    let Some(store) = grant_path(cache_dir) else {
        return Err("cache path too long".to_string());
    };
    let mut f = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&store)
        .map_err(|_| format!("cannot write {}", store.display()))?;
    if writeln!(f, "{}{}", if sensitive { "!" } else { "" }, canonical_path).is_err() {
        return Err(format!("cannot write {}", store.display()));
    }
    Ok(true)
}

/// Enforcement (C cbm_workspace_root_allowed): grants + configured root +
/// breadth policy + the sensitive-approval lift.
pub fn root_allowed(
    canonical_path: &str,
    home_dir: Option<&str>,
    cache_dir: &str,
    configured_root: Option<&str>,
) -> Result<(), String> {
    if canonical_path.is_empty() {
        return Err("no repository path given".to_string());
    }
    let mut m = Match {
        candidate: canonical_path.to_string(),
        ..Match::default()
    };
    let grants = grant_walk(cache_dir, |root, sensitive| {
        match_visit(root, sensitive, &mut m);
        false
    });
    // A configured root behaves as an additional grant so existing
    // CBM_ALLOWED_ROOT deployments keep working unchanged.
    let configured = configured_root.map(|r| !r.is_empty()).unwrap_or(false);
    let configured_contains = configured
        .then(|| configured_root.unwrap())
        .map(|r| path_within_root(r, canonical_path))
        .unwrap_or(false);
    let boundary_declared = grants > 0 || configured;
    if boundary_declared && !m.contained && !configured_contains {
        return Err(format!(
            "{canonical_path} is outside the allowed root. To allow it, run: \
             codebase-memory-mcp allow-root {canonical_path}"
        ));
    }
    let verdict = classify_root(canonical_path, home_dir, Some(cache_dir));
    if verdict == WsVerdict::Allow {
        return Ok(());
    }
    // An explicit human approval recorded for exactly this path is the only
    // thing that lifts a sensitive refusal. Absolute and shallow refusals
    // cannot be lifted at all.
    if verdict == WsVerdict::DenySensitive && m.exact_sensitive {
        return Ok(());
    }
    Err(verdict_reason(verdict).to_string())
}

pub fn home_dir() -> Option<String> {
    for var in ["HOME", "USERPROFILE"] {
        if let Ok(v) = std::env::var(var) {
            if !v.is_empty() {
                return Some(v);
            }
        }
    }
    None
}

pub fn cache_dir() -> Option<String> {
    crate::platform::resolve_cache_dir()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn depth_counts_components() {
        assert_eq!(path_depth("/"), 0);
        assert_eq!(path_depth("/etc"), 1);
        assert_eq!(path_depth("/etc/passwd"), 2);
        assert_eq!(path_depth("/home/user/proj"), 3);
        assert_eq!(path_depth(""), 0);
        assert_eq!(path_depth("relative/path"), 0); // no volume prefix
                                                    // firmlink transparency
        assert_eq!(path_depth("/private/etc"), 1);
        assert_eq!(path_depth("/private/tmp/proj"), 2);
    }

    #[test]
    fn classify_breadth() {
        let home = "/home/dev";
        assert_eq!(
            classify_root("/", Some(home), None),
            WsVerdict::DenyAbsolute
        );
        assert_eq!(classify_root("", Some(home), None), WsVerdict::DenyAbsolute);
        assert_eq!(
            classify_root("relative", Some(home), None),
            WsVerdict::DenyAbsolute
        );
        assert_eq!(
            classify_root("/etc", Some(home), None),
            WsVerdict::DenyTooShallow
        );
        assert_eq!(
            classify_root("/home", Some(home), None),
            WsVerdict::DenyTooShallow
        );
        assert_eq!(
            classify_root(home, Some(home), None),
            WsVerdict::DenySensitive
        );
        assert_eq!(
            classify_root("/home/dev", Some(home), None),
            WsVerdict::DenySensitive
        );
        assert_eq!(
            classify_root("/home/dev/proj", Some(home), None),
            WsVerdict::Allow
        );
    }

    #[test]
    fn classify_credential_dirs() {
        for name in [
            ".ssh",
            ".aws",
            ".gnupg",
            ".kube",
            ".docker",
            ".git-credentials",
        ] {
            let p = format!("/home/dev/{name}");
            assert_eq!(
                classify_root(&p, Some("/home/dev"), None),
                WsVerdict::DenySensitive,
                "{p}"
            );
            // Nested too (matched against every component).
            let nested = format!("/home/dev/proj/{name}/sub");
            assert_eq!(
                classify_root(&nested, Some("/home/dev"), None),
                WsVerdict::DenySensitive,
                "{nested}"
            );
        }
        // Ordinary dir under the same home is fine.
        assert_eq!(
            classify_root("/home/dev/proj/.gitignore", Some("/home/dev"), None),
            WsVerdict::Allow
        );
    }

    #[test]
    fn verdict_metadata() {
        assert_eq!(verdict_reason(WsVerdict::Allow), "allowed");
        assert!(verdict_is_overridable(WsVerdict::DenySensitive));
        assert!(!verdict_is_overridable(WsVerdict::DenyAbsolute));
        assert!(!verdict_is_overridable(WsVerdict::DenyTooShallow));
    }

    #[test]
    fn within_root_component_boundary() {
        assert!(path_within_root("/home/dev", "/home/dev/proj"));
        assert!(path_within_root("/home/dev", "/home/dev"));
        assert!(!path_within_root("/home/dev", "/home/developer"));
        assert!(!path_within_root("/home/dev", "/etc/passwd"));
    }

    #[test]
    fn grant_add_list_and_enforce() {
        let cache = std::env::temp_dir().join(format!("cbm-ws-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&cache);
        std::fs::create_dir_all(&cache).unwrap();
        let cache_s = cache.to_str().unwrap();
        let home = "/home/dev";

        // Empty store: no boundary declared → breadth-only.
        assert!(root_allowed("/home/dev/proj", Some(home), cache_s, None).is_ok());
        assert!(root_allowed("/etc", Some(home), cache_s, None).is_err()); // breadth (depth 1)

        // Grant a project.
        assert!(grant_add(cache_s, Some(home), "/home/dev/proj", false).unwrap_or(false));
        // List shows it.
        let list = grant_list(cache_s).unwrap();
        assert!(list.contains("/home/dev/proj"));

        // First root declared → confinement ON: another root is refused.
        let err = root_allowed("/home/dev/other", Some(home), cache_s, None).unwrap_err();
        assert!(err.contains("outside the allowed root"));

        // Still-breadth refusals hold inside the boundary too.
        assert!(root_allowed("/etc", Some(home), cache_s, None).is_err());

        // Sensitive refusal requires explicit approval.
        let err = grant_add(cache_s, Some(home), "/home/dev/.ssh", false).unwrap_err();
        assert!(err.contains("--approve-sensitive"));
        assert!(grant_add(cache_s, Some(home), "/home/dev/.ssh", true).is_ok());
        // Now allowed only via the exact sensitive grant.
        assert!(root_allowed("/home/dev/.ssh", Some(home), cache_s, None).is_ok());
        // Absolute refusal is not liftable even with approval.
        let e = grant_add(cache_s, Some(home), "/", false).unwrap_err();
        assert!(e.contains("volume root"));
        std::fs::remove_dir_all(&cache).ok();
    }

    #[test]
    fn configured_root_acts_as_grant() {
        let cache = std::env::temp_dir().join(format!("cbm-ws-cfg-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&cache);
        std::fs::create_dir_all(&cache).unwrap();
        let cache_s = cache.to_str().unwrap();
        // No grants, but a configured root contains the candidate.
        assert!(root_allowed("/srv/proj", None, cache_s, Some("/srv")).is_ok());
        // Outside it → refused with the exact wording.
        let err = root_allowed("/home/dev", None, cache_s, Some("/srv")).unwrap_err();
        assert!(err.contains("outside the allowed root"));
        std::fs::remove_dir_all(&cache).ok();
    }

    #[test]
    fn windows_style_paths() {
        assert_eq!(classify_root("C:/", None, None), WsVerdict::DenyAbsolute);
        assert_eq!(
            classify_root("C:/Windows", None, None),
            WsVerdict::DenySensitive
        );
        assert_eq!(
            classify_root("C:/Program Files/App", None, None),
            WsVerdict::DenySensitive
        );
        assert_eq!(
            classify_root("C:/Users", None, None),
            WsVerdict::DenySensitive
        ); // tree root
        assert_eq!(classify_root("D:/repos/proj", None, None), WsVerdict::Allow); // depth 2 OK for windows
                                                                                  // Case-folded credential match on Windows style.
        assert_eq!(
            classify_root("D:/repos/.SSH", None, None),
            WsVerdict::DenySensitive
        );
    }

    #[test]
    fn home_and_cache_dir_helpers() {
        let _ = home_dir();
        let _ = cache_dir();
    }

    #[test]
    fn manifest_name_const() {
        assert_eq!(WS_MANIFEST_NAME, ".cbmpathwhitelist");
        assert_eq!(WS_MANIFEST_NAME, ".cbmpathwhitelist");
        assert!(WS_MANIFEST_NAME.starts_with('.'));
    }
}
