//! yaml.rs — 1:1 rewrite of `src/foundation/yaml.{c,h}`.
//!
//! Minimal YAML parser for config files: line-by-line with indentation
//! tracking. Handles maps, lists ("- value"), scalars, comments (#), and
//! dot-separated path lookups. No anchors, multi-line scalars, or flow
//! style — same scope as the C original.

use std::collections::BTreeMap;

#[derive(Debug, Clone, PartialEq)]
pub enum Node {
    Map(BTreeMap<String, Node>),
    List(Vec<Node>),
    Scalar(String),
}

// ── Parsing ─────────────────────────────────────────────────────

/// Trim leading/trailing whitespace (C trim_dup).
fn trim(s: &str) -> &str {
    s.trim_matches(|c: char| c.is_ascii_whitespace())
}

fn leading_spaces(line: &str) -> usize {
    line.bytes().take_while(|&b| b == b' ').count()
}

/// Strip inline comments from a value string (not inside quotes).
fn strip_inline_comment(after: &str) -> &str {
    if after.starts_with('"') || after.starts_with('\'') {
        return after;
    }
    match after.find(" #") {
        Some(i) => &after[..i],
        None => after,
    }
}

/// Peek ahead: is the next content line a list item?
fn peek_is_list(rest: &[&str]) -> bool {
    for line in rest {
        let indent = leading_spaces(line);
        let content = line[indent.min(line.len())..].trim_end_matches('\r');
        if content.is_empty() || content.starts_with('#') {
            continue;
        }
        return content.starts_with('-');
    }
    false
}

/// Parse a whole config text into a map node.
pub fn parse(text: &str) -> Node {
    if text.is_empty() {
        return Node::Map(BTreeMap::new());
    }

    let mut root: BTreeMap<String, Node> = BTreeMap::new();
    // Stack of (path keys, indent) to track nesting.
    let mut stack: Vec<(Vec<String>, usize)> = vec![(Vec::new(), usize::MAX)];
    let lines: Vec<&str> = text.lines().collect();

    for (li, line) in lines.iter().enumerate() {
        let indent = leading_spaces(line);
        let content = line[indent.min(line.len())..]
            .trim_end_matches('\r')
            .trim_end();
        if content.is_empty() || content.starts_with('#') {
            continue;
        }

        // Pop to the parent at the correct indentation.
        while stack.len() > 1 && stack.last().unwrap().1 >= indent {
            stack.pop();
        }
        let parent_path = stack.last().unwrap().0.clone();

        if let Some(item) = content.strip_prefix("- ") {
            // List item → append to the list named by the current path.
            let item = trim(item);
            // Resolve the parent map + the list key (last path segment).
            if let Some(items) = find_list(&mut root, &parent_path) {
                items.push(Node::Scalar(item.to_string()));
            }
            continue;
        }

        // "key: value" or "key:"
        let Some(colon) = content.find(':') else {
            continue;
        };
        let key = trim(&content[..colon]).to_string();
        let after = strip_inline_comment(trim(&content[colon + 1..]));

        let mut path = parent_path.clone();
        path.push(key.clone());

        if after.is_empty() {
            // "key:" — map or list, decided by the next content line.
            let is_list = peek_is_list(&lines[li + 1..]);
            let node = if is_list {
                Node::List(Vec::new())
            } else {
                Node::Map(BTreeMap::new())
            };
            insert_at(&mut root, &path, node);
            stack.push((path, indent));
        } else {
            insert_at(&mut root, &path, Node::Scalar(after.to_string()));
        }
    }
    Node::Map(root)
}

/// Navigate to the list at `path` (mutable).
fn find_list<'a>(
    map: &'a mut BTreeMap<String, Node>,
    path: &[String],
) -> Option<&'a mut Vec<Node>> {
    match path.split_first() {
        None => None,
        Some((last, [])) => match map.get_mut(last) {
            Some(Node::List(items)) => Some(items),
            _ => None,
        },
        Some((first, rest)) => match map.get_mut(first) {
            Some(Node::Map(m)) => find_list(m, rest),
            _ => None,
        },
    }
}

fn insert_at(root: &mut BTreeMap<String, Node>, path: &[String], node: Node) {
    if let Some((first, rest)) = path.split_first() {
        if rest.is_empty() {
            root.insert(first.clone(), node);
        } else {
            let child = root
                .entry(first.clone())
                .or_insert_with(|| Node::Map(BTreeMap::new()));
            if let Node::Map(m) = child {
                insert_at(m, rest, node);
            }
        }
    }
}

// ── Query helpers ───────────────────────────────────────────────

/// Navigate a dot-separated path.
fn navigate<'a>(root: &'a Node, path: &str) -> Option<&'a Node> {
    let mut cur = root;
    for seg in path.split('.') {
        match cur {
            Node::Map(m) => {
                cur = m.get(seg)?;
            }
            _ => return None,
        }
    }
    Some(cur)
}

/// Get a scalar string value at `path`; None when absent or not scalar.
pub fn get_str<'a>(root: &'a Node, path: &str) -> Option<&'a str> {
    match navigate(root, path) {
        Some(Node::Scalar(v)) => Some(v),
        _ => None,
    }
}

/// Get a float at `path`; `default` when absent/unparseable (strtod prefix
/// parse is mirrored by Rust's f64 parse on trimmed input; partial parses
/// like "3.5x" fall back like the C's full-consumption check).
pub fn get_float(root: &Node, path: &str, default: f64) -> f64 {
    match get_str(root, path) {
        Some(s) => s.trim().parse::<f64>().unwrap_or(default),
        None => default,
    }
}

/// Get a bool at `path`: true/yes/on/1; false/no/off/0; else `default`.
pub fn get_bool(root: &Node, path: &str, default: bool) -> bool {
    match get_str(root, path) {
        Some(s) => match s.to_ascii_lowercase().as_str() {
            "true" | "yes" | "on" | "1" => true,
            "false" | "no" | "off" | "0" => false,
            _ => default,
        },
        None => default,
    }
}

/// Get a list of strings at `path` (max `max_out` entries).
pub fn get_str_list(root: &Node, path: &str, max_out: usize) -> Vec<String> {
    match navigate(root, path) {
        Some(Node::List(items)) => items
            .iter()
            .filter_map(|n| match n {
                Node::Scalar(v) => Some(v.clone()),
                _ => None,
            })
            .take(max_out)
            .collect(),
        _ => Vec::new(),
    }
}

pub fn has(root: &Node, path: &str) -> bool {
    navigate(root, path).is_some()
}

#[cfg(test)]
mod tests {
    use super::*;

    const CFG: &str = r#"# top comment
name: my-project
port: 8080
rate: 0.75
enabled: yes
disabled: false
count: 1
# nested map
server:
  host: 0.0.0.0
  ports:
    - 80
    - 443
  tls:
    on: true
# list of strings
exclude:
  - node_modules
  - .git
    "#;

    fn parsed() -> Node {
        parse(CFG)
    }

    #[test]
    fn scalars() {
        let y = parsed();
        assert_eq!(get_str(&y, "name"), Some("my-project"));
        assert_eq!(get_str(&y, "port"), Some("8080"));
        assert_eq!(get_float(&y, "rate", 0.0), 0.75);
        assert!(get_bool(&y, "enabled", false));
        assert!(!get_bool(&y, "disabled", true));
        assert_eq!(get_float(&y, "count", 0.0), 1.0);
    }

    #[test]
    fn nested_map() {
        let y = parsed();
        assert_eq!(get_str(&y, "server.host"), Some("0.0.0.0"));
        assert!(get_bool(&y, "server.tls.on", false));
        assert!(!has(&y, "server.tls.off"));
        assert_eq!(get_str(&y, "server.tls"), None); // map, not scalar
    }

    #[test]
    fn lists() {
        let y = parsed();
        let ports = get_str_list(&y, "server.ports", 10);
        assert_eq!(ports, vec!["80", "443"]);
        let ex = get_str_list(&y, "exclude", 10);
        assert_eq!(ex, vec!["node_modules", ".git"]);
        assert!(get_str_list(&y, "name", 10).is_empty()); // scalar, not list
    }

    #[test]
    fn defaults_and_absent() {
        let y = parsed();
        assert_eq!(get_float(&y, "nope", 1.5), 1.5);
        assert!(get_bool(&y, "nope", true));
        assert_eq!(get_str(&y, "a.b.c"), None);
        assert!(!has(&y, "nope"));
    }

    #[test]
    fn inline_comments_stripped() {
        // C semantics: " #" (space-hash) strips; a hash at value start does
        // NOT (i>0 guard), so `j: # x` keeps "# x" as a scalar.
        let y = parse("k: value # trailing comment\nj: # still a map\nsub:\n  a: 1 # c\n");
        assert_eq!(get_str(&y, "k"), Some("value"));
        assert_eq!(get_str(&y, "j"), Some("# still a map"));
        assert_eq!(get_float(&y, "sub.a", 0.0), 1.0);
        let y2 = parse("m:\n  a: 1 # c\n");
        assert!(has(&y2, "m.a"));
    }

    #[test]
    fn quoted_values() {
        let y = parse("a: \"x # y\"\nb: 'single'\n");
        assert_eq!(get_str(&y, "a"), Some("\"x # y\""));
        assert_eq!(get_str(&y, "b"), Some("'single'"));
    }

    #[test]
    fn empty_input() {
        let y = parse("");
        assert_eq!(y, Node::Map(BTreeMap::new()));
        let y2 = parse("# only a comment\n\n");
        assert_eq!(y2, Node::Map(BTreeMap::new()));
    }
}
