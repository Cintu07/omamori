# omamori

omamori is a content blocker written in Rust, with no dependencies. It reads the filter lists uBlock Origin reads and tells you whether a request should load. It is the blocker inside [kamaitachi](https://github.com/Cintu07/kamaitachi), split out so anything else can use it.

I measured it on a Windows laptop in November 2026. EasyList plus EasyPrivacy is 107,004 network rules and another 23,803 that hide elements, and omamori reads all of it in 38 ms into 3.77 MB. kamaitachi loads eight lists, which is about 300,000 rules with 158,036 malware entries among them. That takes 7.26 MB, and a request is checked in about 4.5 microseconds.

The name comes from the small protective charms sold at Japanese shrines.

## use

```rust
use omamori::{Blocker, Kind};

let easylist = std::fs::read_to_string("easylist.txt")?;
let urlhaus = std::fs::read_to_string("urlhaus.txt")?;
// true marks a malware or phishing list: pages on it get stopped, not only requests
let b = Blocker::new(&[(&easylist, false), (&urlhaus, true)]);

b.blocks("https://securepubads.g.doubleclick.net/gampad/ads", "news.com", Kind::Script); // true
b.danger("https://some-phishing-site.example/login"); // true if a list has it
let every_site = b.generic_hiding(); // css that hides ad boxes, the same on every page
let this_site = b.site_hiding("news.com"); // and the rules for one site
```

There is a small tool in `examples/` that loads lists from disk and checks one url.

```sh
cargo run --release --example check -- easylist.txt easyprivacy.txt -- https://ads.example.com/x.js news.com
```

omamori does not download lists. Fetch them however your program already fetches things and hand it the text. If you use uBlock Origin's lists, run them through `omamori::expand` first, which follows their `!#include` lines and drops rules meant for other browsers.

## how it stays small

Most of any list is plain hosts like `||ads.example.com^`. Each one is an 8-byte hash in a sorted array. A request looks up its own host first, then each parent domain, with a binary search every time. Exact malware links, which is most of URLhaus, get the same treatment as a hash of host and path. Storing them as text had cost 16 MB.

Every other rule is filed under its rarest word. A url is split into words the same way, so a request only ever meets the few rules that share a word with it. uBlock Origin and Brave's engine use this idea too.

Element-hiding rules come back as two CSS strings. The part for every site is the same on every page, so a browser can parse it once and share it.

## what it skips

Some things are left out. Regex rules are, along with scriptlets like `##+js(...)`, procedural selectors like `:has()` and any option it does not know. Skipping a rule means an ad might get through. Guessing at one can break a site, so unknown rules are dropped.

`$redirect` rules are treated as plain blocks, because omamori has no stand-in scripts to redirect to.

## tests

```sh
cargo test --release
```

`tests/budget.rs` fails if a list of 140,000 rules goes over 8 MB, or if a request starts scanning more than a handful of rules.

## license

MIT. The filter lists are not in this repo and keep their own licenses. EasyList is under GPLv3 or CC BY-SA 3.0, which matters if you bundle the list with a program instead of downloading it when the program runs.
