//! fn35-paths: guest iOS path -> host sandbox translation.
//!
//! Faithful port of `FNLoader.translate_path` in scripts/fn35_loader.py:
//! file:// stripping, // collapsing, the fixed root map (bundle, data
//! container, tmp, var/db), the /System|/usr|/Developer|/Library special
//! case, and the final fallthrough into sandbox/System. Also provides
//! the lexical component walker shared with the pakfs resolver.
#![forbid(unsafe_code)]

pub const GUEST_BUNDLE: &str = "/private/var/containers/Bundle/Application/\
6B3F2A11-4C4E-4E22-9A04-7D9E1A55C0FF/FortniteClient.app";
pub const GUEST_DATA: &str = "/var/mobile/Containers/Data/Application/\
8A1D5E77-1234-4E56-9BC0-42DE2C1F9AB7";

/// The sandbox layout. `base` is the sandbox root directory.
pub struct PathTranslator {
    sandbox: String,
}

impl PathTranslator {
    pub fn new(sandbox: &str) -> Self {
        PathTranslator { sandbox: sandbox.to_string() }
    }

    pub fn sandbox(&self) -> &str {
        &self.sandbox
    }

    /// guest path -> host path (mirrors translate_path exactly,
    /// including its quirky fallthrough into sandbox/System).
    pub fn translate(&self, gpath: &str) -> Option<String> {
        if gpath.is_empty() {
            return None;
        }
        // NOTE: python's str.replace("//", "/") is SINGLE-PASS - a
        // "file:///x" URL becomes "file://x" (still file://), strips to
        // the RELATIVE "x", and falls into the System/ fallthrough.
        // The guest relies on this landing spot; keep it byte-exact.
        let mut p = gpath.replace("//", "/");
        if let Some(stripped) = p.strip_prefix("file://") {
            p = stripped.to_string();
        }
        let bundle_host =
            format!("{}/Bundle/FortniteClient.app", self.sandbox);
        let data_host = format!("{}/Data", self.sandbox);
        let tmp_host = format!("{}/tmp", self.sandbox);
        let db_host = format!("{}/Data/db", self.sandbox);
        // note: python checks GUEST_BUNDLE and its /private-stripped
        // twin with the SAME host; order matters (longest first)
        let stripped_bundle = GUEST_BUNDLE
            .replacen("/private/", "/", 1);
        let roots: &[(&str, &str)] = &[
            (GUEST_BUNDLE, &bundle_host),
            (stripped_bundle.as_str(), &bundle_host),
            (GUEST_DATA, &data_host),
            ("/var/mobile", &data_host),
            ("/var/tmp", &tmp_host),
            ("/tmp", &tmp_host),
            ("/private/tmp", &tmp_host),
            ("/var/db", &db_host),
        ];
        for (gp, host) in roots {
            if p == *gp || p.starts_with(&format!("{}/", gp)) {
                let rel = p[gp.len()..].trim_start_matches('/');
                return Some(join_norm(host, rel));
            }
        }
        if p.starts_with("/System") || p.starts_with("/usr")
            || p.starts_with("/Developer")
            || p.starts_with("/Library")
        {
            return Some(format!(
                "{}/System/{}",
                self.sandbox,
                p.trim_start_matches('/')
            ));
        }
        Some(join_norm(
            &format!("{}/System", self.sandbox),
            p.trim_start_matches('/'),
        ))
    }
}

/// join + normalize (no filesystem access; lexical only)
pub fn join_norm(base: &str, rel: &str) -> String {
    let joined = if rel.is_empty() {
        base.to_string()
    } else {
        format!("{}/{}", base, rel)
    };
    norm_path(&joined)
}

/// lexical normpath: resolve . and .. WITHOUT touching the filesystem
pub fn norm_path(p: &str) -> String {
    let absolute = p.starts_with('/');
    let mut out: Vec<&str> = Vec::new();
    for comp in p.split('/') {
        match comp {
            "" | "." => {}
            ".." => {
                if !out.is_empty() && *out.last().unwrap() != ".." {
                    out.pop();
                } else if !absolute {
                    out.push("..");
                }
            }
            c => out.push(c),
        }
    }
    let joined = out.join("/");
    if absolute {
        format!("/{}", joined)
    } else if joined.is_empty() {
        ".".to_string()
    } else {
        joined
    }
}

/// lexical component split collapsing '.' and '..' (mirrors the pakfs
/// resolver walker; shared utility)
pub fn components(gpath: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for c in gpath.split('/') {
        if c == "." || c.is_empty() {
            continue;
        }
        if c == ".." {
            out.pop();
            continue;
        }
        out.push(c.to_string());
    }
    out
}
