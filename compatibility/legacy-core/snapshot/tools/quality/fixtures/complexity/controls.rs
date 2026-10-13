//! Frozen Rust fixture for the locked complexity rule `mccabe-rust-1`.
//!
//! The analyzer is lexical and supports only the subset documented in
//! `docs/quality/complexity-analyzer.md`; keep this fixture inside that
//! subset so the locked raw counts and series remain reproducible.

fn decision(flag: bool, items: &[u8]) -> u32 {
    if flag && items.len() > 0 {
        1
    } else if !flag || items.is_empty() {
        2
    } else {
        0
    }
}

fn classify(value: u8) -> &'static str {
    match value {
        0 if value == 0 => "zero",
        x if x % 2 == 0 => "even",
        _ => "odd",
    }
}

fn loops(mut n: u64) -> u64 {
    while n > 0 {
        n -= 1;
    }
    for i in 0..10 {
        n += i;
    }
    loop {
        n += 1;
        if n == 10 {
            break;
        }
    }
    n
}

fn query(path: Option<&str>) -> Option<String> {
    path?.split('?').next().map(|s: &str| {
        let owned = s.to_string();
        owned
    })
}

fn call_double(value: u32) -> u32 {
    let double = |x: u32| {
        if x > 1 {
            x * 2
        } else {
            x
        }
    };
    let record = |x: u32| {
        x + 1
    };
    double(value) + record(value)
}

fn outer(value: u64) -> u64 {
    fn inner(x: u64) -> u64 {
        if x > 1 {
            x - 1
        } else {
            x
        }
    }
    inner(value)
}

fn with_macros(value: &str) -> usize {
    let formatted = format!("value={value}");
    let _ = formatted;
    assert!(value.len() > 0, "non-empty input required");
    value.len()
}

fn main() {
    let _ = decision(true, &[]);
    let _ = classify(1);
    let _ = loops(0);
    let _ = query(Some("x"));
    let _ = call_double(2);
    let _ = outer(3);
    let _ = with_macros("sample");
}
