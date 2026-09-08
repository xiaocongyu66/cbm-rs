//! compat_regex.rs — 1:1 rewrite of `src/foundation/compat_regex.{c,h}`.
//!
//! POSIX: direct wrappers around `<regex.h>` — exactly the C original.
//! (The C version additionally vendors TRE on Windows; not a build target
//! here.) The opaque 256-byte buffer contract is preserved with the same
//! `_Static_assert`-backed size bound.

use std::ffi::CString;

pub const REG_EXTENDED: i32 = 1;
pub const REG_ICASE: i32 = 2;
pub const REG_NOSUB: i32 = 4;
pub const REG_NEWLINE: i32 = 8;
pub const REG_NOTBOL: i32 = libc::REG_NOTBOL;
pub const REG_OK: i32 = 0;
pub const REG_NOMATCH: i32 = -1;

/// Opaque regex storage — C keeps `char opaque[256]` with a static assert
/// that regex_t fits. The 8-byte align mirrors regex_t's alignment (the C
/// char array gets away with it only because malloc results are aligned;
/// an unaligned cast here would be UB).
#[repr(C, align(8))]
pub struct Opaque([u8; 256]);

pub struct Regex {
    buf: Opaque,
    nmatch_caps: usize,
}

// POSIX regex_t is not cross-thread on re-entry for the same object.
unsafe impl Send for Regex {}

pub struct Regmatch {
    /// Byte offset of match start, -1 if no match (C rm_so).
    pub rm_so: i32,
    /// Byte offset past match end (C rm_eo).
    pub rm_eo: i32,
}

fn as_regex_t(buf: &Opaque) -> *const libc::regex_t {
    // SAFETY: 256 >= size_of::<regex_t>() on all supported platforms
    // (glibc 64B, musl 68B), asserted by a build-time check below, and
    // Opaque carries align(8) >= regex_t's alignment.
    unsafe { &*buf.0.as_ptr() as *const u8 as *const libc::regex_t }
}

fn as_regex_t_mut(buf: &mut Opaque) -> *mut libc::regex_t {
    buf.0.as_mut_ptr() as *mut libc::regex_t
}

const _: () = assert!(std::mem::size_of::<libc::regex_t>() <= 256);

impl Regex {
    /// Compile `pattern` with POSIX flags (EXTENDED/ICASE/NOSUB/NEWLINE).
    /// Returns Err(message) with the regcomp error string on failure.
    pub fn compile(pattern: &str, flags: i32) -> Result<Regex, String> {
        let c_pat = CString::new(pattern).map_err(|_| "embedded NUL in pattern".to_string())?;
        let mut re = Regex {
            buf: Opaque([0u8; 256]),
            nmatch_caps: if flags & REG_NOSUB != 0 { 0 } else { 16 },
        };
        let rc = unsafe { libc::regcomp(as_regex_t_mut(&mut re.buf), c_pat.as_ptr(), flags) };
        if rc != 0 {
            let mut errbuf = [0u8; 256];
            unsafe {
                libc::regerror(
                    rc,
                    as_regex_t(&re.buf),
                    errbuf.as_mut_ptr().cast(),
                    errbuf.len(),
                );
            }
            let end = errbuf.iter().position(|&c| c == 0).unwrap_or(errbuf.len());
            return Err(String::from_utf8_lossy(&errbuf[..end]).into_owned());
        }
        Ok(re)
    }

    /// Execute. With a non-empty `matches` slice, slot 0 gets the whole
    /// match and slots 1.. get capture groups (rm_so=-1 when a group did
    /// not participate). `eflags` supports REG_NOTBOL.
    pub fn exec(&self, s: &str, matches: &mut [Regmatch], eflags: i32) -> i32 {
        let c_s = match CString::new(s) {
            Ok(s) => s,
            Err(_) => return REG_NOMATCH,
        };
        let mut pmatch: [libc::regmatch_t; 16] = unsafe { std::mem::zeroed() };
        let n = self.nmatch_caps.min(matches.len());
        let rc = unsafe {
            libc::regexec(
                as_regex_t(&self.buf),
                c_s.as_ptr(),
                n,
                pmatch.as_mut_ptr(),
                eflags,
            )
        };
        if rc != 0 {
            return REG_NOMATCH;
        }
        for (i, slot) in matches.iter_mut().take(n).enumerate() {
            *slot = Regmatch {
                // regoff_t is i32 on glibc, i64 on musl — normalize.
                rm_so: pmatch[i].rm_so as i32,
                rm_eo: pmatch[i].rm_eo as i32,
            };
        }
        REG_OK
    }
}

impl Drop for Regex {
    fn drop(&mut self) {
        unsafe {
            libc::regfree(as_regex_t_mut(&mut self.buf));
        }
    }
}

/// One-shot convenience: does `pattern` match anywhere in `s`?
pub fn is_match(pattern: &str, icase: bool, s: &str) -> bool {
    let flags = REG_EXTENDED | if icase { REG_ICASE } else { 0 } | REG_NOSUB;
    match Regex::compile(pattern, flags) {
        Ok(re) => re.exec(s, &mut [], 0) == REG_OK,
        Err(_) => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compile_exec_basic() {
        let re = Regex::compile("ab+c", REG_EXTENDED).unwrap();
        let mut m = [Regmatch { rm_so: 0, rm_eo: 0 }];
        assert_eq!(re.exec("xxabbbcyy", &mut m, 0), REG_OK);
        assert_eq!((m[0].rm_so, m[0].rm_eo), (2, 7));
    }

    #[test]
    fn nomatch_and_bad_pattern() {
        let re = Regex::compile("z+", REG_EXTENDED).unwrap();
        let mut m = [Regmatch { rm_so: 0, rm_eo: 0 }];
        assert_eq!(re.exec("abc", &mut m, 0), REG_NOMATCH);
        assert!(Regex::compile("(unclosed", REG_EXTENDED).is_err());
        assert!(Regex::compile("a{1,x}", REG_EXTENDED).is_err());
    }

    #[test]
    fn icase_flag() {
        let re = Regex::compile("hello", REG_EXTENDED | REG_ICASE).unwrap();
        assert_eq!(re.exec("say HELLO", &mut [], 0), REG_OK);
        let re_cs = Regex::compile("hello", REG_EXTENDED).unwrap();
        assert_eq!(re_cs.exec("say HELLO", &mut [], 0), REG_NOMATCH);
    }

    #[test]
    fn groups_fill_slots() {
        let re = Regex::compile("([a-z]+)=([0-9]+)", REG_EXTENDED).unwrap();
        let mut m = [
            Regmatch { rm_so: 0, rm_eo: 0 },
            Regmatch { rm_so: 0, rm_eo: 0 },
            Regmatch { rm_so: 0, rm_eo: 0 },
        ];
        assert_eq!(re.exec("k=42", &mut m, 0), REG_OK);
        assert_eq!((m[0].rm_so, m[0].rm_eo), (0, 4));
        assert_eq!((m[1].rm_so, m[1].rm_eo), (0, 1));
        assert_eq!((m[2].rm_so, m[2].rm_eo), (2, 4));
    }

    #[test]
    fn notbol_flag() {
        let re = Regex::compile("^b", REG_EXTENDED).unwrap();
        let mut m = [Regmatch { rm_so: 0, rm_eo: 0 }];
        assert_eq!(re.exec("bbc", &mut m, 0), REG_OK);
        // REG_NOTBOL: the string does not begin at bol → ^ fails.
        assert_eq!(re.exec("bbc", &mut m, REG_NOTBOL), REG_NOMATCH);
    }

    #[test]
    fn is_match_convenience() {
        assert!(is_match("[A-Z]{3}", false, "ABC-123"));
        assert!(is_match("abc", true, "ABC"));
        assert!(!is_match("abc", false, "ABC"));
    }
}
