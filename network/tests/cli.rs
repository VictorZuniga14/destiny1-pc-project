use destiny1_network::cli::{self, CliError};
use destiny1_network::framing;
use destiny1_network::jsonl;
use std::fs;
use std::path::PathBuf;
use std::process::Command;

fn bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_destiny1-network"))
}

fn fixture_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("fixtures/synthetic_session.jsonl")
}

#[test]
fn cli_timeline_valid_fixture() {
    let output = bin()
        .args(["timeline", fixture_path().to_str().unwrap()])
        .output()
        .expect("run cli");
    assert!(
        output.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("[000000ms] C -> S | kind=2 | 0x001e | destiny-service-handshake-request"));
    assert!(stdout.contains("[000052ms] C -> S | kind=2 | 0x0019 | session-login-request"));
    assert!(stdout.contains("[000087ms] S -> C | kind=2 | 0x001a | session-login-response"));
    assert!(stdout.contains("[000103ms] C -> S | kind=1 | encrypted | payload_len="));
    assert!(stdout.contains("0xdead | unknown"));
}

#[test]
fn cli_missing_file_nonzero_exit() {
    let output = bin()
        .args(["timeline", "definitely/missing/evidence.jsonl"])
        .output()
        .expect("run cli");
    assert_eq!(output.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("file not found") || stderr.contains("error:"));
}

#[test]
fn cli_session_crypto_verify_missing_file() {
    let output = bin()
        .args(["session-crypto-verify", "no/such/verify.json"])
        .output()
        .expect("run cli");
    assert!(!output.status.success());
    assert_eq!(output.status.code(), Some(1));
}

#[test]
fn cli_bad_args_nonzero_exit() {
    let output = bin().args(["nope"]).output().expect("run cli");
    assert_eq!(output.status.code(), Some(2));
}

#[test]
fn cli_invalid_frame_hex_nonzero_exit() {
    let dir = tempfile_dir();
    let path = dir.join("bad_frame.jsonl");
    // Valid JSONL schema, but frame_hex is not a valid BAP frame (bad magic).
    fs::write(
        &path,
        r#"{"timestamp_ms":0,"direction":"client_to_server","frame_hex":"000200000000"}
"#,
    )
    .unwrap();
    let output = bin()
        .args(["timeline", path.to_str().unwrap()])
        .output()
        .expect("run cli");
    assert_ne!(output.status.code(), Some(0));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("error:"));
}

#[test]
fn cli_invalid_jsonl_nonzero_exit() {
    let dir = tempfile_dir();
    let path = dir.join("bad.jsonl");
    fs::write(&path, "{not-json\n").unwrap();
    let err = cli::run(&[
        "timeline".into(),
        path.to_str().unwrap().to_string(),
    ])
    .unwrap_err();
    assert!(matches!(err, CliError::Jsonl(_)));
    assert_eq!(err.exit_code(), 1);
}

#[test]
fn lib_pipeline_matches_fixture_without_hardcoded_sequence() {
    // Build expected lines by parsing the same fixture the CLI uses.
    let records = jsonl::parse_jsonl_path(fixture_path()).unwrap();
    let timeline = destiny1_network::Timeline::from_evidence(&records);
    let lines = timeline.format_cli_lines();
    assert_eq!(lines.len(), 7);
    assert!(lines[0].starts_with("[000000ms]"));
    assert!(lines[2].contains("0x0019"));
    assert!(lines[4].contains("encrypted"));
    // Round-trip: serialized clear frame from fixture fields still classifies.
    let frame = framing::clear_frame(0x19, 2, b"\xde\xad");
    let hex = jsonl::encode_hex(&frame.serialize().unwrap());
    let rec = jsonl::parse_jsonl_str(&format!(
        r#"{{"timestamp_ms":1,"direction":"client_to_server","frame_hex":"{hex}"}}"#
    ))
    .unwrap();
    assert_eq!(rec[0].frame.message_id(), Some(0x19));
}

fn external_fixture_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("fixtures/external_schema_synthetic.jsonl")
}

#[test]
fn cli_timeline_external_valid_synthetic_fixture() {
    let output = bin()
        .args([
            "timeline-external",
            external_fixture_path().to_str().unwrap(),
        ])
        .output()
        .expect("run cli");
    assert!(
        output.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("0x001e"));
    assert!(stdout.contains("destiny-service-handshake-request"));
    assert!(stdout.contains("0x0019"));
    assert!(stdout.contains("0x0079"));
    assert!(stdout.contains("0x00fa"));
    // Must not leak sensitive-looking connection metadata from external schema.
    assert!(!stdout.contains("key_sha256"));
    assert!(!stdout.contains("token_source"));
    assert!(!stdout.contains("127.0.0.1"));
    assert!(!stdout.contains("plaintext_hex"));
    assert!(!stdout.contains("payload_hex"));
    // payload bytes from fixture must not appear as hex dumps
    assert!(!stdout.contains("payload_hex"));
    assert!(!stdout.to_lowercase().contains("nonce\":"));
    assert!(!stdout.contains("aaaa"));
}

#[test]
fn cli_timeline_external_missing_file() {
    let output = bin()
        .args(["timeline-external", "definitely/missing/external.jsonl"])
        .output()
        .expect("run cli");
    assert_eq!(output.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("file not found") || stderr.contains("error:"));
}

#[test]
fn cli_timeline_external_invalid_jsonl() {
    let dir = tempfile_dir();
    let path = dir.join("bad_external.jsonl");
    fs::write(&path, "{not-json\n").unwrap();
    let output = bin()
        .args(["timeline-external", path.to_str().unwrap()])
        .output()
        .expect("run cli");
    assert_ne!(output.status.code(), Some(0));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("error:"));
}

#[test]
fn cli_timeline_external_incompatible_direction() {
    let dir = tempfile_dir();
    let path = dir.join("bad_direction.jsonl");
    fs::write(
        &path,
        r#"{"kind":"bap_frame","direction":"sideways","frame_kind":2,"id":25,"context":0,"payload_hex":""}
"#,
    )
    .unwrap();
    let err = cli::run(&[
        "timeline-external".into(),
        path.to_str().unwrap().to_string(),
    ])
    .unwrap_err();
    assert!(matches!(err, CliError::Adapter(_)));
    assert_eq!(err.exit_code(), 1);
}

fn tempfile_dir() -> PathBuf {
    use std::sync::atomic::{AtomicU64, Ordering};
    static N: AtomicU64 = AtomicU64::new(0);
    let n = N.fetch_add(1, Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!(
        "destiny1-network-cli-{}-{}",
        std::process::id(),
        n
    ));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    dir
}
