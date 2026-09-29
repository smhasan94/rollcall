//! Property tests: deterministic serialisation, order-independent merging, round trips, and
//! a parser that never panics.

mod common;

use common::{arb_entries, arb_evidence, build, shuffled};
use proptest::prelude::*;
use rollcall_core::model::{
    Component, ComponentKind, Cpe, Evidence, EvidenceSet, License, Product, Purl,
};

fn config() -> ProptestConfig {
    ProptestConfig {
        cases: 256,
        // Keep generated regression files out of the repository.
        failure_persistence: None,
        ..ProptestConfig::default()
    }
}

proptest! {
    #![proptest_config(config())]

    #[test]
    fn serialisation_is_independent_of_insertion_order(
        (entries, reordered) in arb_entries()
            .prop_flat_map(|e| (Just(e.clone()), shuffled(e)))
    ) {
        let a = build(&entries);
        let b = build(&reordered);
        prop_assert_eq!(&a, &b);
        prop_assert_eq!(a.to_json().unwrap(), b.to_json().unwrap());
        prop_assert!(a.validate().is_ok());
    }

    #[test]
    fn evidence_merge_is_order_independent(
        (items, shuffled) in proptest::collection::vec(arb_evidence(), 0..=12)
            .prop_flat_map(|e| (Just(e.clone()), Just(e).prop_shuffle()))
    ) {
        let a: EvidenceSet = items.iter().cloned().collect();
        let b: EvidenceSet = shuffled.iter().cloned().collect();
        prop_assert_eq!(&a, &b);
        prop_assert_eq!(serde_json::to_string(&a).unwrap(), serde_json::to_string(&b).unwrap());

        // Merging two components carrying halves of the evidence, either way round, agrees.
        let (left, right) = items.split_at(items.len() / 2);
        let component = |ev: &[Evidence]| {
            let mut c = Component::new(ComponentKind::Library, "x").unwrap();
            c.evidence = ev.iter().cloned().collect();
            c
        };
        let mut lr = component(left);
        lr.merge(component(right)).unwrap();
        let mut rl = component(right);
        rl.merge(component(left)).unwrap();
        prop_assert_eq!(&lr.evidence, &a);
        prop_assert_eq!(&rl.evidence, &a);
    }

    #[test]
    fn json_round_trip_holds_for_random_products(
        entries in arb_entries(),
        edges in proptest::collection::vec((any::<usize>(), any::<usize>()), 0..=4),
    ) {
        let mut product = build(&entries);
        let refs: Vec<_> = product.walk().map(|(_, r, _)| r).collect();
        for (from, to) in edges {
            let (from, to) = (&refs[from % refs.len()], &refs[to % refs.len()]);
            // Self-edges are invalid by design; cycles between distinct nodes are allowed.
            if from != to {
                product.add_dependency(from.clone(), to.clone());
            }
        }
        let json = product.to_json().unwrap();
        let back = Product::from_json(&json).unwrap();
        prop_assert_eq!(&back, &product);
        prop_assert_eq!(back.to_json().unwrap(), json);
    }

    #[test]
    fn random_bytes_never_panic_parser(
        bytes in proptest::collection::vec(any::<u8>(), 0..=512),
        position in any::<usize>(),
        byte in any::<u8>(),
        cut in any::<bool>(),
    ) {
        // Arbitrary bytes.
        let _ = Product::from_json_bytes(&bytes);
        let text = String::from_utf8_lossy(&bytes);
        let _ = Product::from_json(&text);
        let _ = Purl::new(&text);
        let _ = Cpe::new(&text);
        let _ = License::new(&text);

        // A valid document with one byte changed, or cut short.
        let mut base = common::base_product().to_json().unwrap().into_bytes();
        let at = position % base.len();
        if cut {
            base.truncate(at);
        } else {
            base[at] = byte;
        }
        let _ = Product::from_json_bytes(&base);
    }
}
