//! Size limits that fail the build when crossed. The real lists change every day, so
//! these use a made-up list shaped like them: mostly hosts, some paths, some hiding.

use omamori::{Blocker, Kind};

fn fake_list() -> String {
    let mut s = String::new();
    for i in 0..100_000 {
        s.push_str(&format!("||ads{i}.example{}.com^\n", i % 97));
    }
    for i in 0..20_000 {
        s.push_str(&format!("/banner{i}/*/track.js$script,third-party\n"));
    }
    for i in 0..20_000 {
        s.push_str(&format!("##.promo-{i}\n"));
    }
    s
}

#[test]
fn a_big_list_stays_under_eight_megabytes() {
    let list = fake_list();
    let b = Blocker::new(&[(&list, false)]);
    assert_eq!(b.host_rules(), 100_000);
    let mb = b.bytes() as f64 / 1048576.0;
    assert!(mb < 8.0, "{mb:.2} mb for 140k rules");
}

#[test]
fn a_request_meets_only_a_few_rules() {
    let list = fake_list();
    let b = Blocker::new(&[(&list, false)]);
    let t = std::time::Instant::now();
    for i in 0..10_000 {
        let url = format!("https://cdn.site.com/banner{}/x/track.js", i % 20_000);
        assert!(b.blocks(&url, "news.com", Kind::Script));
    }
    let per = t.elapsed().as_secs_f64() * 1e6 / 10_000.0;
    // generous, so a slow CI machine does not fail it; the point is no full scans
    assert!(per < 200.0, "{per:.1} us per request");
}
