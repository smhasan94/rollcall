//! Golden tests for the internal JSON form.
//!
//! The golden files are generated only by `scripts/regen-golden.sh`, which runs this test with
//! `ROLLCALL_BLESS=1`. Never edit them by hand.

mod common;

use std::path::PathBuf;

use common::{base_plus, base_product, dedent, extra_component, last_component, line_diff};
use rollcall_core::model::to_canonical_json;

fn golden_path(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("golden")
        .join(name)
}

fn check_golden(name: &str, actual: &str) {
    let path = golden_path(name);
    if std::env::var("ROLLCALL_BLESS").as_deref() == Ok("1") {
        std::fs::write(&path, actual).unwrap();
        return;
    }
    let expected = std::fs::read_to_string(&path).unwrap_or_else(|e| {
        panic!(
            "cannot read {}: {e}; run scripts/regen-golden.sh",
            path.display()
        )
    });
    assert!(
        expected == actual,
        "{} differs from the model's output; if the change is intended, run \
         scripts/regen-golden.sh and review the diff\n--- expected\n{expected}\n--- actual\n{actual}",
        path.display()
    );
}

#[test]
fn serialising_twice_is_byte_identical() {
    let product = base_product();
    let first = product.to_json().unwrap();
    let second = product.to_json().unwrap();
    assert_eq!(first.as_bytes(), second.as_bytes());
    // An independently built, equal model serialises to the same bytes too.
    assert_eq!(
        first.as_bytes(),
        base_product().to_json().unwrap().as_bytes()
    );
    assert!(first.ends_with("}\n"));
}

#[test]
fn base_product_matches_golden() {
    check_golden("base.json", &base_product().to_json().unwrap());
}

#[test]
fn base_plus_one_matches_golden() {
    check_golden(
        "base_plus_one.json",
        &base_plus(extra_component()).to_json().unwrap(),
    );
}

#[test]
fn adding_one_component_changes_exactly_its_lines() {
    let base = base_product().to_json().unwrap();
    let plus = base_plus(extra_component()).to_json().unwrap();
    let (removed, inserted) = line_diff(&base, &plus);
    assert!(removed.is_empty(), "unexpected removed lines: {removed:#?}");

    let mut block = dedent(&inserted);
    let last = block.pop().unwrap();
    assert_eq!(
        last, "},",
        "inserted block should end with the element separator"
    );
    block.push("}".to_owned());
    let expected = to_canonical_json(&extra_component()).unwrap();
    assert_eq!(block.join("\n"), expected.trim_end_matches('\n'));
}

#[test]
fn adding_last_component_changes_only_its_lines_and_one_separator() {
    let base = base_product().to_json().unwrap();
    let plus = base_plus(last_component()).to_json().unwrap();
    let (removed, inserted) = line_diff(&base, &plus);
    assert!(removed.is_empty(), "unexpected removed lines: {removed:#?}");

    // The previous last sibling's closing `}` gains a comma (the one separator), then the new
    // component follows. Its own closing `}` lines up with the old closing brace, so the diff
    // shows every other line of it as inserted.
    let block = dedent(&inserted);
    let (separator, component) = block.split_first().unwrap();
    assert_eq!(separator, "},");
    let expected = to_canonical_json(&last_component()).unwrap();
    let mut expected_lines: Vec<&str> = expected.lines().collect();
    assert_eq!(expected_lines.pop(), Some("}"));
    assert_eq!(component, expected_lines.as_slice());
}
