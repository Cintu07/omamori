//! Reading list syntax. The format is Adblock Plus's, with the extensions uBlock
//! Origin added. What this understands:
//!
//! - network rules: `||host^`, `|https://start`, `/path/*/part`, `@@` exceptions,
//!   and the options `$script`, `$image` and the other types, `$third-party`,
//!   `$domain=`, `$important`, `$match-case`
//! - element hiding: `##.ad`, `site.com##.promo`, `site.com#@#.ad`
//!
//! What it skips on purpose: regex rules, scriptlets (`##+js(...)`), procedural
//! selectors like `:has()`, and any option it does not know. Skipping a rule only
//! means one ad might get through. Guessing wrong can break a site.

use crate::*;

impl Blocker {
    pub(crate) fn line(&mut self, l: &str, pending: &mut Vec<Pending>, danger: bool) {
        if l.is_empty() || l.starts_with('!') || l.starts_with('[') {
            return;
        }
        // element hiding
        if let Some(p) = l.find("#@#").or_else(|| l.find("##")) {
            let unhide = l[p..].starts_with("#@#");
            let doms = &l[..p];
            let sel = &l[p + if unhide { 3 } else { 2 }..];
            if sel.starts_with('+') || sel.starts_with('^') || doms.contains('#') {
                // scriptlets and html filters need a script engine, not a blocker
                return;
            }
            const PROC: [&str; 12] = [":has(", ":-abp-", ":upward(", ":xpath(", ":matches-css", ":style(", ":remove(", ":has-text(", ":min-text-length(", ":watch-attr(", ":matches-path(", ":others("];
            if PROC.iter().any(|x| sel.contains(x)) || sel.contains('{') {
                return;
            }
            let st = self.sel_text.len() as u32;
            self.sel_text.push_str(sel);
            let r = (st, sel.len() as u32);
            let named: Vec<&str> = doms.split(',').map(|d| d.trim()).filter(|d| !d.is_empty() && !d.starts_with('~')).collect();
            if unhide {
                for d in named {
                    self.unhide.entry(fnv(d.as_bytes())).or_default().push(r);
                }
            } else if named.is_empty() {
                self.generic.push(r);
            } else {
                for d in named {
                    self.by_host.entry(fnv(d.as_bytes())).or_default().push(r);
                }
            }
            self.counts.1 += 1;
            return;
        }
        if l.contains("#$#") || l.contains("#?#") || l.contains("#%#") {
            return;
        }
        // network rules
        let (mut body, except) = match l.strip_prefix("@@") {
            Some(r) => (r, true),
            None => (l, false),
        };
        if body.starts_with('/') && body.len() > 2 && (body.ends_with('/') || body.contains("/$")) {
            // regex rules are rare and slow to run on every request, so they are skipped
            return;
        }
        let mut f = Filter { pat: 0, len: 0, flags: if except { EXCEPT } else { 0 }, party: 0, types: ALL_BUT_DOC, dom: self.doms.len() as u32, dom_n: 0 };
        if let Some(d) = body.rfind('$')
            && !body[d..].contains('/')
        {
            let opts = &body[d + 1..];
            body = &body[..d];
            let mut types_on = 0u16;
            let mut types_off = 0u16;
            for o in opts.split(',') {
                let (neg, name) = match o.strip_prefix('~') {
                    Some(n) => (true, n),
                    None => (false, o),
                };
                let ty = match name {
                    "script" => Some(Kind::Script),
                    "image" => Some(Kind::Image),
                    "stylesheet" | "css" => Some(Kind::Stylesheet),
                    "xmlhttprequest" | "xhr" => Some(Kind::Xhr),
                    "subdocument" | "frame" => Some(Kind::Subdocument),
                    "media" => Some(Kind::Media),
                    "font" => Some(Kind::Font),
                    "websocket" => Some(Kind::Websocket),
                    "ping" | "beacon" => Some(Kind::Ping),
                    "other" | "object" | "object-subrequest" => Some(Kind::Other),
                    "document" | "doc" => Some(Kind::Document),
                    _ => None,
                };
                if let Some(t) = ty {
                    if neg {
                        types_off |= t.bit();
                    } else {
                        types_on |= t.bit();
                    }
                    continue;
                }
                match name {
                    "third-party" | "3p" => f.party = if neg { -1 } else { 1 },
                    "first-party" | "1p" => f.party = if neg { 1 } else { -1 },
                    "important" => f.flags |= IMPORTANT,
                    "match-case" => f.flags |= CASE,
                    "all" => types_on |= 0x7FF,
                    "elemhide" | "generichide" | "ehide" | "ghide" | "specifichide" | "shide" => {}
                    _ if name.starts_with("domain=") || name.starts_with("from=") => {
                        let list = name.split_once('=').map(|x| x.1).unwrap_or("");
                        for d in list.split('|') {
                            let (n, dd) = match d.strip_prefix('~') {
                                Some(x) => (true, x),
                                None => (false, d),
                            };
                            self.doms.push((fnv(dd.as_bytes()), n));
                            f.dom_n += 1;
                        }
                    }
                    // uBO redirects these to harmless stand-ins. we can only block them
                    _ if name.starts_with("redirect") || name.starts_with("csp") => {}
                    // an option we do not understand could change what the rule means, so
                    // the rule is dropped instead of guessed at
                    _ => {
                        self.doms.truncate(f.dom as usize);
                        return;
                    }
                }
            }
            if types_on != 0 {
                f.types = types_on;
            }
            f.types &= !types_off;
            if except && types_on & Kind::Document.bit() != 0 {
                // a whole page allowed
                let h = body.trim_start_matches("||").trim_end_matches('^');
                if !h.is_empty() && h.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'.' || c == b'-') {
                    self.page_ok.push(fnv(h.as_bytes()));
                }
                return;
            }
        }
        if let Some(r) = body.strip_prefix("||") {
            f.flags |= HOST;
            body = r;
        } else if let Some(r) = body.strip_prefix('|') {
            f.flags |= LEFT;
            body = r;
        }
        if let Some(r) = body.strip_suffix('|') {
            f.flags |= RIGHT;
            body = r;
        }
        let body = body.trim_start_matches('*').trim_end_matches('*');
        if body.is_empty() {
            return;
        }
        // most rules in any list are just a host. those become a hash and nothing more
        let plain_host = f.flags & HOST != 0
            && f.flags & (EXCEPT | RIGHT) == 0
            && f.party == 0
            && f.dom_n == 0
            && (f.types == ALL_BUT_DOC || danger)
            && body.strip_suffix('^').unwrap_or(body).bytes().all(|c| c.is_ascii_alphanumeric() || c == b'.' || c == b'-')
            && body.strip_suffix('^').unwrap_or(body).contains('.');
        if plain_host {
            let h = fnv(body.trim_end_matches('^').as_bytes());
            self.hosts.push(h);
            if danger {
                self.danger_hosts.push(h);
            }
            return;
        }
        // URLhaus is mostly exact links to malware files. storing them as text took
        // 16 MB, so each one is a hash of host and path instead
        if danger
            && f.flags & (HOST | EXCEPT) == HOST
            && f.dom_n == 0
            && body.contains('/')
            && !body.contains('*')
            && !body[..body.len() - 1].contains('^')
        {
            self.danger_paths.push(fnv(norm_path(body).as_bytes()));
            return;
        }
        if danger && f.flags & EXCEPT == 0 {
            f.flags |= DANGER;
            f.types |= Kind::Document.bit();
        }
        let pat = if f.flags & CASE != 0 { body.to_string() } else { body.to_ascii_lowercase() };
        pending.push(Pending { pat, f });
    }
}
