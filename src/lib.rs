//! omamori is a content blocker. It reads the filter lists uBlock Origin reads
//! (EasyList, EasyPrivacy, its own badware list, URLhaus, the phishing list) and
//! answers one question for each request a page makes: should this load?
//!
//! I wanted it small enough that a browser can carry it without anyone noticing.
//! With eight lists, about 300,000 rules, it holds 7.3 MB and checks a request in
//! about 4.5 microseconds on my laptop.
//!
//! Most of any list is plain hosts like `||ads.example.com^`. Those become 8-byte
//! hashes in a sorted array. The rest are filed under their rarest word, and a url
//! gets split into words the same way, so it only meets the few rules that share a
//! word with it. uBlock Origin and Brave's engine work the same way.
//!
//! ```
//! use omamori::{Blocker, Kind};
//! let b = Blocker::new(&[("||ads.example.com^\n##.banner-ad\n", false)]);
//! assert!(b.blocks("https://ads.example.com/x.js", "news.com", Kind::Script));
//! assert!(!b.blocks("https://news.com/app.js", "news.com", Kind::Script));
//! ```

use std::collections::HashMap;

mod matching;
mod parse;

pub use matching::site;
use matching::{fnv, host_span, matches, norm_path, page_allowed, tok_char, tokens_of};

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Kind {
    Document,
    Script,
    Image,
    Stylesheet,
    Xhr,
    Subdocument,
    Media,
    Font,
    Websocket,
    Ping,
    Other,
}

impl Kind {
    pub(crate) fn bit(self) -> u16 {
        1 << self as u16
    }
}

pub(crate) const ALL_BUT_DOC: u16 = 0x7FF & !1;

pub(crate) const HOST: u8 = 1;
pub(crate) const LEFT: u8 = 2;
pub(crate) const RIGHT: u8 = 4;
pub(crate) const EXCEPT: u8 = 8;
pub(crate) const IMPORTANT: u8 = 16;
pub(crate) const CASE: u8 = 32;
/// came from a malware or phishing list, so it stops whole pages too
pub(crate) const DANGER: u8 = 64;

/// One rule that is more than a plain host. Its pattern lives in `Blocker::text`.
#[derive(Clone, Copy)]
pub(crate) struct Filter {
    pub(crate) pat: u32,
    pub(crate) len: u16,
    pub(crate) flags: u8,
    /// 0 any, 1 third-party only, -1 first-party only
    pub(crate) party: i8,
    pub(crate) types: u16,
    pub(crate) dom: u32,
    pub(crate) dom_n: u16,
}

/// Everything loaded from the lists. Build one with [`Blocker::new`] and share it;
/// it never changes after that.
#[derive(Default)]
pub struct Blocker {
    pub(crate) hosts: Vec<u64>,
    pub(crate) filters: Vec<Filter>,
    pub(crate) text: String,
    pub(crate) index: HashMap<u64, Vec<u32>>,
    pub(crate) loose: Vec<u32>,
    pub(crate) doms: Vec<(u64, bool)>,
    /// pages where a list turns blocking off (`@@||site^$document`)
    pub(crate) page_ok: Vec<u64>,
    pub(crate) sel_text: String,
    pub(crate) generic: Vec<(u32, u32)>,
    pub(crate) by_host: HashMap<u64, Vec<(u32, u32)>>,
    pub(crate) unhide: HashMap<u64, Vec<(u32, u32)>>,
    /// hosts on malware and phishing lists
    pub(crate) danger_hosts: Vec<u64>,
    /// exact malware links (host + path), as hashes
    pub(crate) danger_paths: Vec<u64>,
    /// how many rules loaded: (network rules, element-hiding rules)
    pub counts: (usize, usize),
    pub danger_count: usize,
}

struct Pending {
    pub(crate) pat: String,
    f: Filter,
}

impl Blocker {
    /// Reads filter lists. Pass each list's text with `true` if it is a malware or
    /// phishing list; pages on those get stopped outright, not only their requests.
    pub fn new(lists: &[(&str, bool)]) -> Blocker {
        let mut b = Blocker::default();
        let mut pending: Vec<Pending> = Vec::new();
        for (list, danger) in lists {
            for line in list.lines() {
                b.line(line.trim(), &mut pending, *danger);
            }
        }
        b.danger_count = b.danger_hosts.len() + pending.iter().filter(|p| p.f.flags & DANGER != 0).count();
        b.danger_count += b.danger_paths.len();
        b.danger_hosts.sort_unstable();
        b.danger_hosts.dedup();
        b.danger_paths.sort_unstable();
        b.danger_paths.dedup();
        // count how often each word shows up across all rules, then file every rule
        // under its rarest one. common words like "com" would make huge buckets
        let mut freq: HashMap<u64, u32> = HashMap::new();
        let toks: Vec<Vec<u64>> = pending.iter().map(|p| tokens_of(&p.pat, p.f.flags)).collect();
        for t in &toks {
            for h in t {
                *freq.entry(*h).or_default() += 1;
            }
        }
        for (p, t) in pending.into_iter().zip(toks) {
            let i = b.filters.len() as u32;
            let mut f = p.f;
            f.pat = b.text.len() as u32;
            f.len = p.pat.len().min(u16::MAX as usize) as u16;
            b.text.push_str(&p.pat);
            b.filters.push(f);
            match t.iter().min_by_key(|h| freq.get(h).copied().unwrap_or(0)) {
                Some(h) => b.index.entry(*h).or_default().push(i),
                None => b.loose.push(i),
            }
        }
        b.hosts.sort_unstable();
        b.hosts.dedup();
        b.page_ok.sort_unstable();
        b.text.shrink_to_fit();
        b.sel_text.shrink_to_fit();
        b.filters.shrink_to_fit();
        b.counts.0 = b.hosts.len() + b.filters.len();
        b
    }

    /// Should this request be stopped? `page` is the host of the page that made it,
    /// which decides third-party rules and `$domain=` options.
    pub fn blocks(&self, url: &str, page: &str, kind: Kind) -> bool {
        if page_allowed(self, page) {
            return false;
        }
        let lower = url.to_ascii_lowercase();
        let (hs, he) = host_span(&lower);
        let host = &lower[hs..he];
        let third = site(host) != site(&page.to_ascii_lowercase());
        let mut hit = false;
        let mut important = false;
        // a host rule covers its subdomains too, so try the host and each parent
        let mut h = host;
        loop {
            if self.hosts.binary_search(&fnv(h.as_bytes())).is_ok() {
                hit = true;
                break;
            }
            match h.find('.') {
                Some(p) => h = &h[p + 1..],
                None => break,
            }
        }
        if !hit && self.danger_path(&lower, hs) {
            hit = true;
        }
        let mut exception = false;
        let mut check = |i: u32| {
            let f = &self.filters[i as usize];
            if f.types & kind.bit() == 0 || (f.party == 1 && !third) || (f.party == -1 && third) {
                return;
            }
            let is_exc = f.flags & EXCEPT != 0;
            if (is_exc && exception) || (!is_exc && hit && f.flags & IMPORTANT == 0) {
                return;
            }
            if f.dom_n > 0 && !self.dom_ok(f, page) {
                return;
            }
            let pat = &self.text.as_bytes()[f.pat as usize..f.pat as usize + f.len as usize];
            let subject = if f.flags & CASE != 0 { url.as_bytes() } else { lower.as_bytes() };
            if matches(pat, f.flags, subject, hs, he) {
                if is_exc {
                    exception = true;
                } else {
                    hit = true;
                    if f.flags & IMPORTANT != 0 {
                        important = true;
                    }
                }
            }
        };
        let b = lower.as_bytes();
        let mut i = 0;
        while i < b.len() {
            if tok_char(b[i]) {
                let st = i;
                while i < b.len() && tok_char(b[i]) {
                    i += 1;
                }
                if let Some(list) = self.index.get(&fnv(&b[st..i])) {
                    for &k in list {
                        check(k);
                    }
                }
            } else {
                i += 1;
            }
        }
        for &k in &self.loose {
            check(k);
        }
        hit && (important || !exception)
    }

    fn danger_path(&self, lower: &str, hs: usize) -> bool {
        if self.danger_paths.is_empty() {
            return false;
        }
        let rest = &lower[hs..];
        let rest = &rest[..rest.find(['?', '#']).unwrap_or(rest.len())];
        let key = norm_path(rest);
        // the link on its host, or on a parent domain of it
        let mut k = key.as_str();
        loop {
            if self.danger_paths.binary_search(&fnv(k.as_bytes())).is_ok() {
                return true;
            }
            let host_end = k.find('/').unwrap_or(k.len());
            match k[..host_end].find('.') {
                Some(p) => k = &k[p + 1..],
                None => return false,
            }
        }
    }

    /// Is this page itself on a malware or phishing list?
    pub fn danger(&self, url: &str) -> bool {
        let lower = url.to_ascii_lowercase();
        let (hs, he) = host_span(&lower);
        if self.danger_path(&lower, hs) {
            return true;
        }
        let mut h = &lower[hs..he];
        loop {
            if self.danger_hosts.binary_search(&fnv(h.as_bytes())).is_ok() {
                return true;
            }
            match h.find('.') {
                Some(p) => h = &h[p + 1..],
                None => break,
            }
        }
        let b = lower.as_bytes();
        let mut i = 0;
        while i < b.len() {
            if tok_char(b[i]) {
                let st = i;
                while i < b.len() && tok_char(b[i]) {
                    i += 1;
                }
                if let Some(list) = self.index.get(&fnv(&b[st..i])) {
                    for &k in list {
                        let f = &self.filters[k as usize];
                        if f.flags & DANGER != 0 && matches(&self.text.as_bytes()[f.pat as usize..f.pat as usize + f.len as usize], f.flags, b, hs, he) {
                            return true;
                        }
                    }
                }
            } else {
                i += 1;
            }
        }
        false
    }

    fn dom_ok(&self, f: &Filter, page: &str) -> bool {
        let list = &self.doms[f.dom as usize..f.dom as usize + f.dom_n as usize];
        let mut any_pos = false;
        let mut pos_hit = false;
        let mut h = page;
        let mut hashes = Vec::new();
        loop {
            hashes.push(fnv(h.as_bytes()));
            match h.find('.') {
                Some(p) => h = &h[p + 1..],
                None => break,
            }
        }
        for (d, neg) in list {
            if *neg {
                if hashes.contains(d) {
                    return false;
                }
            } else {
                any_pos = true;
                if hashes.contains(d) {
                    pos_hit = true;
                }
            }
        }
        !any_pos || pos_hit
    }

    /// CSS that hides ad boxes on a page, as (rules for every site, rules for this one).
    /// The first part is the same everywhere, so a browser can parse it once.
    pub fn hiding(&self, page: &str) -> (String, String) {
        // a selector that starts with an attribute gets tested on every element of every
        // page. the generic set keeps the ones that start with a tag, class or id
        let keyed: Vec<(u32, u32)> = self
            .generic
            .iter()
            .copied()
            .filter(|r| {
                let sel = &self.sel_text[r.0 as usize..(r.0 + r.1) as usize];
                !sel.starts_with('[') && !sel.starts_with(':') && !sel.starts_with('*')
            })
            .collect();
        let generic_css = self.css(&keyed, &[]);
        let mut spec = Vec::new();
        let mut unhide = Vec::new();
        let mut h = page;
        loop {
            let k = fnv(h.as_bytes());
            if let Some(v) = self.by_host.get(&k) {
                spec.extend(v.iter().copied());
            }
            if let Some(v) = self.unhide.get(&k) {
                unhide.extend(v.iter().copied());
            }
            match h.find('.') {
                Some(p) => h = &h[p + 1..],
                None => break,
            }
        }
        (generic_css, self.css(&spec, &unhide))
    }

    fn css(&self, sels: &[(u32, u32)], except: &[(u32, u32)]) -> String {
        let s = |r: &(u32, u32)| &self.sel_text[r.0 as usize..(r.0 + r.1) as usize];
        let skip: Vec<&str> = except.iter().map(s).collect();
        let mut out = String::new();
        // 128 selectors to a rule. a browser that cannot parse one of them should
        // drop just that one, which is what css parsers do with selector lists
        for chunk in sels.chunks(128) {
            let list: Vec<&str> = chunk.iter().map(s).filter(|x| !skip.contains(x)).collect();
            if list.is_empty() {
                continue;
            }
            out.push_str(&list.join(","));
            out.push_str("{display:none!important}\n");
        }
        out
    }

    /// How many network rules became plain host hashes (the cheap kind).
    pub fn host_rules(&self) -> usize {
        self.hosts.len()
    }

    /// Roughly how many heap bytes the blocker holds.
    pub fn bytes(&self) -> usize {
        self.hosts.capacity() * 8
            + self.filters.capacity() * std::mem::size_of::<Filter>()
            + self.text.capacity()
            + self.index.len() * 48
            + self.index.values().map(|v| v.capacity() * 4).sum::<usize>()
            + self.doms.capacity() * 16
            + self.danger_hosts.capacity() * 8
            + self.danger_paths.capacity() * 8
            + self.sel_text.capacity()
            + self.generic.capacity() * 8
            + self.by_host.len() * 48
            + self.by_host.values().map(|v| v.capacity() * 8).sum::<usize>()
    }
}


/// A few rules that work before any list has downloaded.
pub const STARTER: &str = "||doubleclick.net^\n||googlesyndication.com^\n||googleadservices.com^\n||adservice.google.com^\n||google-analytics.com^\n||googletagmanager.com^\n||googletagservices.com^\n||amazon-adsystem.com^\n||adnxs.com^\n||taboola.com^\n||outbrain.com^\n||criteo.com^\n||criteo.net^\n||scorecardresearch.com^\n||hotjar.com^\n||adsrvr.org^\n||rubiconproject.com^\n||pubmatic.com^\n||casalemedia.com^\n||moatads.com^\n||quantserve.com^\n||connect.facebook.net^\n||ads-twitter.com^\n||static.ads-twitter.com^\n||bat.bing.com^\n||chartbeat.com^\n||segment.io^\n||mixpanel.com^\n||sentry-cdn.com^\n##.adsbygoogle\n##ins.adsbygoogle\n##[id^=\"div-gpt-ad\"]\n##.ad-container\n##.advertisement\n";

/// Gets a downloaded list ready to read. uBlock Origin's lists pull in other files
/// with `!#include` and fence off rules for other browsers with `!#if`. This
/// follows includes one level deep through `fetch`, and keeps what applies to a
/// chromium-based browser.
pub fn expand(text: &str, url: &str, fetch: &dyn Fn(&str) -> Option<String>) -> String {
    let base = &url[..url.rfind('/').map_or(url.len(), |p| p + 1)];
    let mut out = String::with_capacity(text.len());
    let mut skip = 0usize;
    for line in text.lines() {
        let l = line.trim();
        if let Some(cond) = l.strip_prefix("!#if ") {
            let keep = cond.contains("env_chromium") || (cond.starts_with('!') && !cond.contains("env_chromium"));
            if skip > 0 || !keep {
                skip += 1;
            }
            continue;
        }
        if l.starts_with("!#endif") {
            skip = skip.saturating_sub(1);
            continue;
        }
        if skip > 0 {
            continue;
        }
        if let Some(inc) = l.strip_prefix("!#include ") {
            let u = format!("{base}{}", inc.trim());
            if let Some(t) = fetch(&u) {
                out.push_str(&t);
                out.push('\n');
            }
            continue;
        }
        out.push_str(line);
        out.push('\n');
    }
    out
}

