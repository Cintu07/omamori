//! The rule syntax, one case at a time.

use omamori::{site, Blocker, Kind};

#[test]
fn network_rules() {
    let b = Blocker::new(&[("||ads.example.com^\n/banner/*/img\n||track.io/pixel$image,third-party\n@@||ads.example.com/ok^\n||cdn.x.com/ad.js$script,domain=news.com|~safe.news.com\n|https://evil.\n", false), ("||phish.example^$all\n||bad.test/download/*.exe\n", true)]);
    assert!(b.danger("https://login.phish.example/account"), "danger host and its subdomains");
    assert!(b.danger("https://bad.test/download/setup.exe"));
    assert!(!b.danger("https://bad.test/about"));
    assert!(!b.danger("https://ads.example.com/"), "ads are not danger");
    assert!(b.blocks("https://phish.example/x.js", "site.com", Kind::Script), "danger hosts are blocked as requests too");
    assert!(b.blocks("https://ads.example.com/x.js", "site.com", Kind::Script));
    assert!(b.blocks("https://sub.ads.example.com/x.js", "site.com", Kind::Script), "subdomains of a host rule");
    assert!(!b.blocks("https://notads.example.com/x.js", "site.com", Kind::Script));
    assert!(b.blocks("https://cdn.com/banner/big/img.png", "site.com", Kind::Image));
    assert!(!b.blocks("https://cdn.com/banners/big/img.png", "site.com", Kind::Image));
    assert!(b.blocks("https://track.io/pixel?id=1", "site.com", Kind::Image));
    assert!(!b.blocks("https://track.io/pixel?id=1", "track.io", Kind::Image), "first party");
    assert!(!b.blocks("https://track.io/pixel?id=1", "site.com", Kind::Script), "type");
    assert!(b.blocks("https://cdn.x.com/ad.js", "www.news.com", Kind::Script));
    assert!(!b.blocks("https://cdn.x.com/ad.js", "safe.news.com", Kind::Script));
    assert!(!b.blocks("https://cdn.x.com/ad.js", "other.com", Kind::Script));
    assert!(b.blocks("https://evil.com/", "site.com", Kind::Script));
    assert!(!b.blocks("https://ads.example.com/ok/1", "site.com", Kind::Script), "exception");
}

#[test]
fn hiding_rules() {
    let b = Blocker::new(&[("##.ad\nnews.com##.promo\nnews.com#@#.ad\nexample.com##div:has(.x)\n", false)]);
    let (g, s) = (b.generic_hiding(), b.site_hiding("www.news.com"));
    assert!(g.contains(".ad{display:none!important}"), "{g}");
    assert!(s.contains(".promo"));
    assert_eq!(b.counts.1, 3);
    assert_eq!(site("news.bbc.co.uk"), "bbc.co.uk");
    assert_eq!(site("a.b.example.com"), "example.com");
}
