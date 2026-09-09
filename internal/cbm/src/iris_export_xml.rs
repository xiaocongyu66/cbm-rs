//! iris_export_xml.rs — 1:1 rewrite of `internal/cbm/iris_export_xml.c`:
//! the IRIS Studio Export XML transcoder.
//!
//! Converts `<Export generator="Cache">` XML files to equivalent UDL text
//! so they can be fed to the ObjectScript UDL extraction pipeline. The
//! XML-to-UDL mapping is 1:1; no new extraction logic is needed.
//!
//! One Export file may contain multiple `<Class>` blocks; each produces a
//! separate UDL string. This is a hand-rolled tag scanner, NOT a general
//! XML parser — exactly like the C (which scans for `<Method `,
//! `</Method>`, attribute `name=`, CDATA bodies, and self-closing tags).
//!
//! The C's fixed buffers (64KB output cap, 256-byte names, 32KB
//! implementations) are preserved: overflowing content is silently
//! truncated, matching upstream behavior.

use self::foundation_buf::{UdlBuf, BUF_CAP, MAX_NAME};

/// C EXPORT_MARKER — a file without this is not an Export file.
const EXPORT_MARKER: &str = "<Export generator=";
/// C MAX_PARAMS.
const MAX_PARAMS: usize = 32;
/// C MAX_CLASSES.
const MAX_CLASSES: usize = 64;

// ── Byte-slice helpers (C skip_ws / sw / find_s / skip_tag / …) ────

fn skip_ws(p: &[u8], start: usize, end: usize) -> usize {
    let mut i = start;
    while i < end && (p[i] == b' ' || p[i] == b'\t' || p[i] == b'\r' || p[i] == b'\n') {
        i += 1;
    }
    i
}

/// First occurrence of `needle` in `p[start..end]` (C find_s). Returns the
/// absolute index.
fn find_s(p: &[u8], start: usize, end: usize, needle: &str) -> Option<usize> {
    let n = needle.as_bytes();
    if start + n.len() > end {
        return None;
    }
    (start..=end - n.len()).find(|&i| &p[i..i + n.len()] == n)
}

/// Index after the next '>' (C skip_tag).
fn skip_tag(p: &[u8], start: usize, end: usize) -> usize {
    match find_s(p, start, end, ">") {
        Some(gt) => gt + 1,
        None => end,
    }
}

/// Is the tag ending at `gt` self-closing (`/` before the `>`)? (C
/// is_self_closing)
fn is_self_closing(p: &[u8], start: usize, gt: usize) -> bool {
    // gt is the '>' position; the C starts at gt-1 and walks back over
    // whitespace.
    let mut i = gt - 1;
    while i > start && (p[i] == b' ' || p[i] == b'\t') {
        i -= 1;
    }
    p[i] == b'/'
}

/// Attribute value extraction from a tag body `ts..te` (C extract_attr).
/// Only quoted forms are accepted.
fn extract_attr(p: &[u8], ts: usize, te: usize, attr: &str) -> Option<String> {
    let a = attr.as_bytes();
    let mut i = ts;
    while i + a.len() < te {
        if &p[i..i + a.len()] == a && p[i + a.len()] == b'=' {
            let mut j = i + a.len() + 1;
            let q = p[j];
            if q != b'"' && q != b'\'' {
                return None;
            }
            j += 1;
            let v = j;
            while j < te && p[j] != q {
                j += 1;
            }
            let vl = j - v;
            let cap = MAX_NAME - 1;
            let take = vl.min(cap);
            return Some(String::from_utf8_lossy(&p[v..v + take]).into_owned());
        }
        i += 1;
    }
    None
}

/// Element content extraction (C elem_content): finds `<tag`, handles
/// self-closing tags (returns the index after them with empty content),
/// CDATA bodies, and normal `</tag>` bodies.
fn elem_content(p: &[u8], start: usize, end: usize, tag: &str) -> Option<(String, usize)> {
    let open = format!("<{tag}");
    let s = find_s(p, start, end, &open)?;
    let gt = find_s(p, s, end, ">")?;
    if is_self_closing(p, s, gt) {
        return Some((String::new(), gt + 1));
    }
    let cs = gt + 1;
    if cs + 9 <= end && &p[cs..cs + 9] == b"<![CDATA[" {
        let body = cs + 9;
        let ce = find_s(p, body, end, "]]>")?;
        let l = (ce - body).min(BUF_CAP - 1);
        return Some((
            String::from_utf8_lossy(&p[body..body + l]).into_owned(),
            ce + 3,
        ));
    }
    let close = format!("</{tag}>");
    let cl = find_s(p, cs, end, &close)?;
    let l = (cl - cs).min(BUF_CAP - 1);
    Some((
        String::from_utf8_lossy(&p[cs..cs + l]).into_owned(),
        cl + close.len(),
    ))
}

/// The content of `<tag>1</tag>` (C tag_is_one).
fn tag_is_one(p: &[u8], start: usize, end: usize, tag: &str) -> bool {
    matches!(elem_content(p, start, end, tag), Some((c, _)) if c == "1")
}

// ── Emitters (C emit_header / emit_method / …) ─────────────────

/// `Class Name [ Extends ... ]` header (C emit_header).
fn emit_header(b: &mut UdlBuf, p: &[u8], cs: usize, ce: usize) {
    let Some(name) = extract_attr(p, cs, ce, "name") else {
        return;
    };
    if name.is_empty() {
        return;
    }
    b.app("Class ");
    b.app(&name);
    if let Some((sup, _)) = elem_content(p, cs, ce, "Super") {
        if sup.contains(',') {
            b.app(" Extends (");
            b.app(&sup);
            b.app(")");
        } else {
            b.app(" Extends ");
            b.app(&sup);
        }
    }
    let mut pragma = String::new();
    if tag_is_one(p, cs, ce, "Abstract") {
        pragma.push_str("Abstract,");
    }
    if tag_is_one(p, cs, ce, "Final") {
        pragma.push_str("Final,");
    }
    if !pragma.is_empty() {
        pragma.pop(); // trailing comma
        b.app(" [ ");
        b.app(&pragma);
        b.app(" ]");
    }
    b.app("\n{\n\n");
}

/// `///docs Method name(formal) As Ret { impl }` (C emit_method).
fn emit_method(b: &mut UdlBuf, p: &[u8], ms: usize, me: usize) {
    let Some(mn) = extract_attr(p, ms, me, "name") else {
        return;
    };
    if mn.is_empty() {
        return;
    }
    let cm = tag_is_one(p, ms, me, "ClassMethod");
    let formal = elem_content(p, ms, me, "FormalSpec")
        .map(|(c, _)| c)
        .unwrap_or_default();
    let ret = elem_content(p, ms, me, "ReturnType")
        .map(|(c, _)| c)
        .unwrap_or_default();
    let desc = elem_content(p, ms, me, "Description")
        .map(|(c, _)| c)
        .unwrap_or_default();
    if !desc.is_empty() {
        b.app("/// ");
        for line in desc.split('\n') {
            b.app(line);
            b.app("\n/// ");
        }
        b.app("\n");
    }
    b.app(if cm { "ClassMethod " } else { "Method " });
    b.app(&mn);
    b.app("(");
    b.app(&formal);
    b.app(")");
    if !ret.is_empty() {
        b.app(" As ");
        b.app(&ret);
    }
    b.app("\n{\n");
    // C: 32KB implementation cap.
    let impl_cap = 1024 * 32;
    if let Some((impl_text, _)) = elem_content(p, ms, me, "Implementation") {
        let take = impl_text.len().min(impl_cap);
        b.app(&impl_text[..take]);
    }
    b.app("}\n\n");
}

/// `Property name As Type(PARAMS);` (C emit_property).
fn emit_property(b: &mut UdlBuf, p: &[u8], ps: usize, pe: usize) {
    let Some(pn) = extract_attr(p, ps, pe, "name") else {
        return;
    };
    if pn.is_empty() {
        return;
    }
    let pt = elem_content(p, ps, pe, "Type")
        .map(|(c, _)| c)
        .unwrap_or_default();
    let mut params: Vec<(String, String)> = Vec::with_capacity(MAX_PARAMS);
    let mut pp = ps;
    while pp < pe && params.len() < MAX_PARAMS {
        let Some(po) = find_s(p, pp, pe, "<Parameter ") else {
            break;
        };
        let Some(pg) = find_s(p, po, pe, ">") else {
            break;
        };
        let name = extract_attr(p, po, pg, "name").unwrap_or_default();
        let mut value = extract_attr(p, po, pg, "value").unwrap_or_default();
        if value.is_empty() {
            if let Some((db, _)) = elem_content(p, po, pe, "Parameter") {
                if !db.is_empty() {
                    value = db.chars().take(MAX_NAME - 1).collect();
                }
            }
        }
        if !name.is_empty() {
            params.push((name, value));
        }
        pp = pg + 1;
    }
    b.app("Property ");
    b.app(&pn);
    if !pt.is_empty() {
        b.app(" As ");
        b.app(&pt);
    }
    if !params.is_empty() {
        b.app("(");
        for (i, (name, value)) in params.iter().enumerate() {
            if i > 0 {
                b.app(", ");
            }
            b.app(name);
            if !value.is_empty() {
                b.app(" = ");
                b.app(value);
            }
        }
        b.app(")");
    }
    b.app(";\n\n");
}

/// `Parameter name = "default";` (C emit_parameter).
fn emit_parameter(b: &mut UdlBuf, p: &[u8], ps: usize, pe: usize) {
    let Some(pn) = extract_attr(p, ps, pe, "name") else {
        return;
    };
    if pn.is_empty() {
        return;
    }
    let dv = elem_content(p, ps, pe, "Default")
        .map(|(c, _)| c)
        .unwrap_or_default();
    b.app("Parameter ");
    b.app(&pn);
    if !dv.is_empty() {
        b.app(" = \"");
        b.app(&dv);
        b.app("\"");
    }
    b.app(";\n\n");
}

/// `Index name On props [ flags ];` (C emit_index).
fn emit_index(b: &mut UdlBuf, p: &[u8], is_: usize, ie: usize) {
    let Some(in_) = extract_attr(p, is_, ie, "name") else {
        return;
    };
    if in_.is_empty() {
        return;
    }
    let props = elem_content(p, is_, ie, "Properties")
        .map(|(c, _)| c)
        .unwrap_or_default();
    let uniq = tag_is_one(p, is_, ie, "Unique");
    let pkey = tag_is_one(p, is_, ie, "PrimaryKey");
    b.app("Index ");
    b.app(&in_);
    if !props.is_empty() {
        b.app(" On ");
        b.app(&props);
    }
    if uniq || pkey {
        b.app(" [ ");
        if pkey {
            b.app("PrimaryKey, ");
        }
        if uniq {
            b.app("Unique");
        }
        b.app(" ]");
    }
    b.app(";\n\n");
}

/// `XData name { data }` (C emit_xdata).
fn emit_xdata(b: &mut UdlBuf, p: &[u8], xs: usize, xe: usize) {
    let Some(xn) = extract_attr(p, xs, xe, "name") else {
        return;
    };
    if xn.is_empty() {
        return;
    }
    // C: 32KB data cap.
    let data_cap = 1024 * 32;
    let data = elem_content(p, xs, xe, "Data")
        .map(|(c, _)| c)
        .unwrap_or_default();
    b.app("XData ");
    b.app(&xn);
    b.app("\n{\n");
    let take = data.len().min(data_cap);
    b.app(&data[..take]);
    b.app("\n}\n\n");
}

/// Transcode one `<Class ...>...</Class>` body to UDL (C transcode_class).
fn transcode_class(p: &[u8], cs: usize, ce: usize) -> String {
    let mut b = UdlBuf::new();
    emit_header(&mut b, p, cs, ce);
    let mut pos = cs;
    while pos < ce {
        pos = skip_ws(p, pos, ce);
        if pos >= ce || p[pos] != b'<' {
            if pos < ce {
                pos += 1;
            }
            continue;
        }
        if starts_tag(p, pos, ce, "<Method ") || starts_tag(p, pos, ce, "<Method>") {
            let Some(gt) = find_s(p, pos, ce, ">") else {
                break;
            };
            let Some(me) = find_s(p, gt + 1, ce, "</Method>") else {
                pos = gt + 1;
                continue;
            };
            emit_method(&mut b, p, pos, me + 9);
            pos = me + 9;
            continue;
        }
        if starts_tag(p, pos, ce, "<Property ") {
            let Some(gt) = find_s(p, pos, ce, ">") else {
                break;
            };
            let Some(pe) = find_s(p, gt + 1, ce, "</Property>") else {
                pos = gt + 1;
                continue;
            };
            emit_property(&mut b, p, pos, pe + 11);
            pos = pe + 11;
            continue;
        }
        if starts_tag(p, pos, ce, "<Parameter ") {
            let Some(gt) = find_s(p, pos, ce, ">") else {
                break;
            };
            if is_self_closing(p, pos, gt) {
                pos = gt + 1;
                continue;
            }
            let Some(pe) = find_s(p, gt + 1, ce, "</Parameter>") else {
                pos = gt + 1;
                continue;
            };
            emit_parameter(&mut b, p, pos, pe + 12);
            pos = pe + 12;
            continue;
        }
        if starts_tag(p, pos, ce, "<Index ") || starts_tag(p, pos, ce, "<Index>") {
            let Some(gt) = find_s(p, pos, ce, ">") else {
                break;
            };
            let Some(ie) = find_s(p, gt + 1, ce, "</Index>") else {
                pos = gt + 1;
                continue;
            };
            emit_index(&mut b, p, pos, ie + 8);
            pos = ie + 8;
            continue;
        }
        if starts_tag(p, pos, ce, "<XData ") || starts_tag(p, pos, ce, "<XData>") {
            let Some(gt) = find_s(p, pos, ce, ">") else {
                break;
            };
            let Some(xe) = find_s(p, gt + 1, ce, "</XData>") else {
                pos = gt + 1;
                continue;
            };
            emit_xdata(&mut b, p, pos, xe + 8);
            pos = xe + 8;
            continue;
        }
        pos = skip_tag(p, pos, ce);
    }
    b.app("}\n");
    b.into_string()
}

/// Tag-prefix test with the C's sw() index semantics.
fn starts_tag(p: &[u8], pos: usize, end: usize, tag: &str) -> bool {
    let n = tag.len();
    pos + n <= end && &p[pos..pos + n] == tag.as_bytes()
}

/// Transcode an Export XML document into UDL strings (C
/// cbm_iris_export_to_udl). Returns an empty Vec when the input is not an
/// Export file or no classes parse.
pub fn iris_export_to_udl(xml: &str) -> Vec<String> {
    let p = xml.as_bytes();
    let end = p.len();
    if find_s(p, 0, end, EXPORT_MARKER).is_none() {
        return Vec::new();
    }
    let mut results: Vec<String> = Vec::with_capacity(MAX_CLASSES);
    let mut pos = 0usize;
    while pos < end && results.len() < MAX_CLASSES {
        let Some(co) = find_s(p, pos, end, "<Class ") else {
            break;
        };
        let Some(gt) = find_s(p, co, end, ">") else {
            break;
        };
        let Some(cc) = find_s(p, gt + 1, end, "</Class>") else {
            break;
        };
        let udl = transcode_class(p, co, cc);
        if !udl.is_empty() {
            results.push(udl);
        }
        pos = cc + 8;
    }
    results
}

// Small local buffer module to keep the C's UdlBuf cap semantics.
mod foundation_buf {
    /// C BUF_CAP (64KB output buffer).
    pub const BUF_CAP: usize = 1024 * 64;
    /// C MAX_NAME (256-byte name fields).
    pub const MAX_NAME: usize = 256;

    /// C UdlBuf: append-only buffer that silently drops once full.
    pub struct UdlBuf {
        buf: String,
        cap: usize,
    }

    impl UdlBuf {
        pub fn new() -> UdlBuf {
            UdlBuf {
                buf: String::with_capacity(BUF_CAP),
                cap: BUF_CAP,
            }
        }

        /// C ub_app: silent drop at capacity.
        pub fn app(&mut self, s: &str) {
            if self.buf.len() + s.len() + 1 >= self.cap {
                return;
            }
            self.buf.push_str(s);
        }

        pub fn into_string(self) -> String {
            self.buf
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<Export generator="Cache" version="25">
<Class name="MyApp.User">
<Description>
Base user class
second line</Description>
<Super>%Persistent,User.Base</Super>
<Abstract>1</Abstract>
<Property name="UserName" asis="1">
<Type>%String</Type>
<Parameter name="MAXLEN" value="200"/>
</Property>
<Property name="Roles">
<Type>%String</Type>
</Property>
<Parameter name="VERSION" value="1.2"/>
<Index name="UserNameIdx">
<Properties>UserName</Properties>
<Unique>1</Unique>
</Index>
<Method name="GetFullName">
<ClassMethod>1</ClassMethod>
<Description>
Gets the name.
More.</Description>
<FormalSpec>id:%Integer</FormalSpec>
<ReturnType>%String</ReturnType>
<Implementation><![CDATA[
    QUIT ..Name(id)
]]></Implementation>
</Method>
<XData name="View">
<Data>
<Pane/>
</Data>
</XData>
</Class>
</Export>
"#;

    #[test]
    fn transcodes_class_to_udl() {
        let out = iris_export_to_udl(SAMPLE);
        assert_eq!(out.len(), 1);
        let udl = &out[0];
        assert!(udl.starts_with("Class MyApp.User"), "got: {udl}");
        assert!(udl.contains(" Extends (%Persistent,User.Base)"));
        assert!(udl.contains(" [ Abstract ]"));
        // Method doc comments: the C appends "\n/// " after every
        // description line (including the leading newline token), so the
        // block opens with an empty "/// " line.
        assert!(udl.contains("/// \n/// Gets the name.\n/// More.\n/// \n"));
        // ClassMethod detection.
        assert!(udl.contains("ClassMethod GetFullName(id:%Integer) As %String"));
        assert!(udl.contains("QUIT ..Name(id)"));
        // Properties with parameters.
        assert!(udl.contains("Property UserName As %String(MAXLEN = 200)"));
        // Class-level <Parameter> tags are NOT transcoded (the C loop only
        // handles Method/Property/Parameter-inside-Property/Index/XData).
        assert!(!udl.contains("Parameter VERSION"));
        // Index with flags.
        assert!(udl.contains("Index UserNameIdx On UserName [ Unique ]"));
        // XData.
        assert!(udl.contains("XData View"));
        assert!(udl.trim_end().ends_with("}"));
    }

    #[test]
    fn non_export_file_rejected() {
        assert!(iris_export_to_udl("<html><body>hi</body></html>").is_empty());
        assert!(iris_export_to_udl("").is_empty());
    }

    #[test]
    fn multiple_classes_each_get_udl() {
        let src = r#"<Export generator="Cache" version="25">
<Class name="A"><Method name="M"><Implementation>x</Implementation></Method></Class>
<Class name="B"><Super>C</Super></Class>
"#;
        let out = iris_export_to_udl(src);
        assert_eq!(out.len(), 2);
        assert!(out[0].starts_with("Class A"));
        assert!(out[0].contains("Method M"));
        assert!(out[1].starts_with("Class B"));
        assert!(out[1].contains(" Extends C"));
    }

    #[test]
    fn self_closing_parameter_skipped() {
        let src = r#"<Export generator="Cache"><Class name="S"><Parameter name="X" value="1"/><Property name="P"><Type>%Int</Type></Property></Class>"#;
        let out = iris_export_to_udl(src);
        assert_eq!(out.len(), 1);
        assert!(
            !out[0].contains("Parameter X"),
            "self-closing Parameter is skipped"
        );
        assert!(out[0].contains("Property P As %Int"));
    }

    #[test]
    fn final_class_pragma() {
        let src = r#"<Export generator="Cache"><Class name="F"><Final>1</Final></Class>"#;
        let out = iris_export_to_udl(src);
        assert!(out[0].contains(" [ Final ]"));
    }
}
