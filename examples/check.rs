//! Load some lists and ask about one url.
//!
//!     cargo run --release --example check -- easylist.txt easyprivacy.txt -- https://ads.example.com/x.js news.com

use omamori::{Blocker, Kind};

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let split = args.iter().position(|a| a == "--").unwrap_or(args.len());
    let texts: Vec<String> = args[..split].iter().map(|p| std::fs::read_to_string(p).unwrap_or_else(|e| panic!("{p}: {e}"))).collect();
    let lists: Vec<(&str, bool)> = texts.iter().map(|t| (t.as_str(), false)).collect();
    let t = std::time::Instant::now();
    let b = Blocker::new(&lists);
    println!("{} network rules, {} hiding rules, {:.2} mb, read in {} ms", b.counts.0, b.counts.1, b.bytes() as f64 / 1048576.0, t.elapsed().as_millis());
    if let [url, page] = &args[(split + 1).min(args.len())..] {
        let verdict = if b.blocks(url, page, Kind::Script) { "blocked" } else { "allowed" };
        println!("{url} on {page}: {verdict}");
    }
}
