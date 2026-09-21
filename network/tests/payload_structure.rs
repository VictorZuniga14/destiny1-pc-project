//! M3.2 payload structure unit tests (synthetic observations).

use destiny1_network::bap_session::DecodedBapFrame;
use destiny1_network::crypto::NonceDirection;
use destiny1_network::message_inventory::MessageObservation;
use destiny1_network::payload_structure::{
    analyze_message_id, LengthClass, OffsetStability, StructuralClass,
};

fn obs(capture: &str, idx: u32, id: u16, payload: &[u8]) -> MessageObservation {
    MessageObservation::from_decoded(
        capture,
        idx,
        NonceDirection::ClientToServer,
        &DecodedBapFrame::Clear {
            msg_id: id,
            context: 1,
            payload: payload.to_vec(),
        },
        None,
        None,
    )
    .unwrap()
}

#[test]
fn fixed_payload_all_constant() {
    let all = vec![
        obs("A", 0, 0x19, &[0xaa, 0xbb, 0xcc, 0xdd]),
        obs("B", 0, 0x19, &[0xaa, 0xbb, 0xcc, 0xdd]),
    ];
    let r = analyze_message_id(0x19, &all, "A", "B");
    assert!(r.offsets.iter().all(|o| o.cross_capture == OffsetStability::Constant));
    assert_eq!(r.length_class, LengthClass::CrossCaptureLengthStable);
}

#[test]
fn one_byte_variable() {
    let all = vec![
        obs("A", 0, 0x1a, &[0xaa, 0xbb, 0xcc, 0xdd]),
        obs("B", 0, 0x1a, &[0xaa, 0xbb, 0x99, 0xdd]),
    ];
    let r = analyze_message_id(0x1a, &all, "A", "B");
    assert_eq!(r.offsets[0].cross_capture, OffsetStability::Constant);
    assert_eq!(r.offsets[1].cross_capture, OffsetStability::Constant);
    assert_eq!(r.offsets[2].cross_capture, OffsetStability::Variable);
    assert_eq!(r.offsets[3].cross_capture, OffsetStability::Constant);
}

#[test]
fn different_lengths() {
    let all = vec![
        obs("A", 0, 0x7b, &[1, 2, 3, 4]),
        obs("A", 1, 0x7b, &[1, 2, 3, 4]),
        obs("B", 0, 0x7b, &[1, 2, 3, 4, 5, 6]),
        obs("B", 1, 0x7b, &[1, 2, 3, 4, 5, 6]),
    ];
    let r = analyze_message_id(0x7b, &all, "A", "B");
    assert_eq!(r.length_class, LengthClass::CrossCaptureLengthDivergent);
    assert!(r
        .offsets
        .iter()
        .any(|o| o.cross_capture == OffsetStability::LengthDependent));
}

#[test]
fn u16_be_le_candidate() {
    let all = vec![
        obs("A", 0, 0x12e, &[0x00, 0x01, 0xaa]),
        obs("B", 0, 0x12e, &[0x00, 0x02, 0xaa]),
    ];
    let r = analyze_message_id(0x12e, &all, "A", "B");
    let be = r
        .regions
        .iter()
        .flat_map(|reg| &reg.numeric_candidates)
        .find(|n| n.width == 2 && n.endian == "BE")
        .expect("u16 BE candidate");
    let le = r
        .regions
        .iter()
        .flat_map(|reg| &reg.numeric_candidates)
        .find(|n| n.width == 2 && n.endian == "LE")
        .expect("u16 LE candidate");
    assert!(be.sample_values.contains(&1) && be.sample_values.contains(&2));
    assert_eq!(be.classification, StructuralClass::StructuralHypothesis);
    assert!(!le.sample_values.is_empty());
}

#[test]
fn u32_be_le_candidate() {
    let all = vec![
        obs("A", 0, 0x12f, &[0x00, 0x00, 0x00, 0x01]),
        obs("B", 0, 0x12f, &[0x00, 0x00, 0x00, 0x02]),
    ];
    let r = analyze_message_id(0x12f, &all, "A", "B");
    let be = r
        .regions
        .iter()
        .flat_map(|reg| &reg.numeric_candidates)
        .find(|n| n.width == 4 && n.endian == "BE")
        .expect("u32 BE candidate");
    let le = r
        .regions
        .iter()
        .flat_map(|reg| &reg.numeric_candidates)
        .find(|n| n.width == 4 && n.endian == "LE")
        .expect("u32 LE candidate");
    assert!(be.sample_values.contains(&1) && be.sample_values.contains(&2));
    assert!(le.sample_values.contains(&0x0100_0000) || le.sample_values.contains(&16777216));
    assert_eq!(be.classification, StructuralClass::StructuralHypothesis);
}

#[test]
fn bit_variation() {
    let all = vec![
        obs("A", 0, 0xfa, &[0x00]),
        obs("A", 1, 0xfa, &[0x01]),
        obs("B", 0, 0xfa, &[0x03]),
    ];
    let r = analyze_message_id(0xfa, &all, "A", "B");
    let bit = r.regions[0].bit_variation.as_ref().unwrap();
    assert!(bit.variable_bits.contains(&0));
    assert!(bit.variable_bits.contains(&1));
    assert!(bit.constant_bits.contains(&2));
    assert_eq!(bit.classification, StructuralClass::StructuralHypothesis);
}

#[test]
fn ascii_detection() {
    let all = vec![
        obs("A", 0, 0x10, b"HELLO"),
        obs("B", 0, 0x10, b"HELLO"),
    ];
    let r = analyze_message_id(0x10, &all, "A", "B");
    let text = r.regions.iter().find_map(|reg| reg.text_candidate.as_ref());
    assert!(text.is_some());
    let t = text.unwrap();
    assert!(t.printable_ratio >= 80);
    assert_eq!(t.classification, StructuralClass::StructuralHypothesis);
}

#[test]
fn monotonic_sequence_candidate() {
    let all = vec![
        obs("A", 0, 0x11, &[0x01]),
        obs("A", 1, 0x11, &[0x02]),
        obs("B", 0, 0x11, &[0x03]),
        obs("B", 1, 0x11, &[0x04]),
    ];
    let r = analyze_message_id(0x11, &all, "A", "B");
    let mono = r
        .regions
        .iter()
        .flat_map(|reg| &reg.numeric_candidates)
        .find(|n| n.possible_monotonic)
        .expect("monotonic candidate");
    assert_eq!(mono.semantic_meaning, "UNKNOWN");
    assert_eq!(mono.classification, StructuralClass::StructuralHypothesis);
}

#[test]
fn cross_capture_stable_region() {
    let all = vec![
        obs("A", 0, 0x20, &[0xde, 0xad, 0x01]),
        obs("A", 1, 0x20, &[0xde, 0xad, 0x02]),
        obs("B", 0, 0x20, &[0xde, 0xad, 0x03]),
        obs("B", 1, 0x20, &[0xde, 0xad, 0x04]),
    ];
    let r = analyze_message_id(0x20, &all, "A", "B");
    assert_eq!(r.offsets[0].cross_capture, OffsetStability::Constant);
    assert_eq!(r.offsets[1].cross_capture, OffsetStability::Constant);
    let stable = r
        .regions
        .iter()
        .find(|reg| reg.start == 0 && reg.end == 2)
        .unwrap();
    assert_eq!(stable.structural_status, StructuralClass::StructuralStable);
}

#[test]
fn cross_capture_divergent_region() {
    let all = vec![
        obs("A", 0, 0x21, &[0xaa, 0x00]),
        obs("A", 1, 0x21, &[0xaa, 0x00]),
        obs("B", 0, 0x21, &[0xbb, 0x00]),
        obs("B", 1, 0x21, &[0xbb, 0x00]),
    ];
    let r = analyze_message_id(0x21, &all, "A", "B");
    assert_eq!(r.offsets[0].within_a, OffsetStability::Constant);
    assert_eq!(r.offsets[0].within_b, OffsetStability::Constant);
    assert_eq!(r.offsets[0].cross_capture, OffsetStability::Variable);
    assert_eq!(r.offsets[1].cross_capture, OffsetStability::Constant);
}

#[test]
fn no_semantic_promotion() {
    let all = vec![
        obs("A", 0, 0x2a, &[0x00, 0x00, 0x00, 0x01]),
        obs("B", 0, 0x2a, &[0x00, 0x00, 0x00, 0x02]),
    ];
    let r = analyze_message_id(0x2a, &all, "A", "B");
    for reg in &r.regions {
        for n in &reg.numeric_candidates {
            assert_eq!(n.classification, StructuralClass::StructuralHypothesis);
            assert_eq!(n.semantic_meaning, "UNKNOWN");
            // Must never become a "confirmed" label.
            assert_ne!(n.classification.as_str(), "CONFIRMED_FIELD");
            assert_ne!(n.classification.as_str(), "CONFIRMED_U32");
        }
    }
}
