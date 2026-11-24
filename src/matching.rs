//! The small pieces under matching: hashing, splitting urls into words, and the
//! glob matcher that handles `*` and `^`.

use crate::{Blocker, HOST, LEFT, RIGHT};

/// FNV-1a over lowercase bytes. Every host and word gets folded into one of these.
pub(crate) fn fnv(b: &[u8]) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for &c in b {
        h ^= c.to_ascii_lowercase() as u64;
        h = h.wrapping_mul(0x100_0000_01b3);
    }
    h
}

pub(crate) fn tok_char(c: u8) -> bool {
    c.is_ascii_alphanumeric() || c == b'%'
}

/// The part of a host one owner controls: "news.bbc.co.uk" gives "bbc.co.uk".
/// It is a guess (the real answer needs the public suffix list) but it is right for
/// the common two-part endings, and it only decides what counts as third-party.
pub fn site(host: &str) -> &str {
    let parts: Vec<&str> = host.rsplitn(4, '.').collect();
    let n = if parts.len() >= 3 && parts[0].len() == 2 && matches!(parts[1], "co" | "com" | "net" | "org" | "gov" | "ac" | "edu" | "ne" | "or") { 3 } else { 2 };
    if parts.len() <= n {
        return host;
    }
    let cut: usize = parts[..n].iter().map(|p| p.len() + 1).sum::<usize>() - 1;
    &host[host.len() - cut..]
}

/// How exact links are keyed: host and path, lowercase, no port, no trailing slash.
pub(crate) fn norm_path(s: &str) -> String {
    let s = s.trim_end_matches('^').trim_end_matches('/');
    let (host, path) = s.split_at(s.find('/').unwrap_or(s.len()));
    let host = host.split(':').next().unwrap_or(host);
    format!("{}{}", host.to_ascii_lowercase(), path.to_ascii_lowercase())
}

pub(crate) fn page_allowed(b: &Blocker, page: &str) -> bool {
    let mut h = page;
    loop {
        if b.page_ok.binary_search(&fnv(h.as_bytes())).is_ok() {
            return true;
        }
        match h.find('.') {
            Some(p) => h = &h[p + 1..],
            None => return false,
        }
    }
}

pub(crate) fn host_span(u: &str) -> (usize, usize) {
    let st = u.find("://").map_or(0, |p| p + 3);
    let rest = &u[st..];
    let end = rest.find(['/', '?', '#', ':']).unwrap_or(rest.len());
    (st, st + end)
}

/// The words of a rule that must show up whole in any url it matches. A word next
/// to a `*` might be cut short, so it does not count.
pub(crate) fn tokens_of(pat: &str, flags: u8) -> Vec<u64> {
    let b = pat.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < b.len() {
        if tok_char(b[i]) {
            let st = i;
            while i < b.len() && tok_char(b[i]) {
                i += 1;
            }
            let left_ok = if st == 0 { flags & (HOST | LEFT) != 0 } else { b[st - 1] != b'*' };
            let right_ok = if i == b.len() { flags & RIGHT != 0 } else { b[i] != b'*' };
            if left_ok && right_ok && i - st >= 2 {
                out.push(fnv(&b[st..i]));
            }
        } else {
            i += 1;
        }
    }
    out
}

pub(crate) fn sep(c: u8) -> bool {
    !(c.is_ascii_alphanumeric() || matches!(c, b'_' | b'-' | b'.' | b'%'))
}

/// Does `p` match `u` starting at `s`? `*` is anything and `^` is a separator or
/// the end. Backtracks to the last `*` on a miss, like a shell glob.
pub(crate) fn glob(p: &[u8], u: &[u8], s: usize, right: bool) -> bool {
    let (mut pi, mut ui) = (0usize, s);
    let mut star: Option<(usize, usize)> = None;
    loop {
        if pi == p.len() {
            if !right || ui == u.len() {
                return true;
            }
        } else {
            match p[pi] {
                b'*' => {
                    star = Some((pi, ui));
                    pi += 1;
                    continue;
                }
                b'^' if ui == u.len() => {
                    pi += 1;
                    continue;
                }
                b'^' if sep(u[ui]) => {
                    pi += 1;
                    ui += 1;
                    continue;
                }
                c if ui < u.len() && u[ui] == c => {
                    pi += 1;
                    ui += 1;
                    continue;
                }
                _ => {}
            }
        }
        match star {
            Some((sp, su)) if su < u.len() => {
                star = Some((sp, su + 1));
                pi = sp + 1;
                ui = su + 1;
            }
            _ => return false,
        }
    }
}

pub(crate) fn matches(p: &[u8], flags: u8, u: &[u8], hs: usize, he: usize) -> bool {
    let right = flags & RIGHT != 0;
    if flags & HOST != 0 {
        // `||` means the start of the host or of any label in it
        let mut s = hs;
        loop {
            if glob(p, u, s, right) {
                return true;
            }
            match u[s..he].iter().position(|&c| c == b'.') {
                Some(d) => s += d + 1,
                None => return false,
            }
        }
    }
    if flags & LEFT != 0 {
        return glob(p, u, 0, right);
    }
    // no anchor: only try where the first literal piece actually appears
    let lit_end = p.iter().position(|&c| c == b'*' || c == b'^').unwrap_or(p.len());
    if lit_end == 0 {
        return (0..=u.len()).any(|s| glob(p, u, s, right));
    }
    let lit = &p[..lit_end];
    let mut from = 0;
    while from + lit.len() <= u.len() {
        match u[from..].windows(lit.len()).position(|w| w == lit) {
            Some(at) => {
                if glob(p, u, from + at, right) {
                    return true;
                }
                from += at + 1;
            }
            None => return false,
        }
    }
    false
}
