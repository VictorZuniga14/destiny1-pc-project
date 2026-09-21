# destiny1-network

Analizador **offline** de framing BAP/TCP para investigación del protocolo de Destiny 1.

## Qué es

Un crate Rust + CLI mínima que:

1. parsea / serializa framing BAP documentado en [`docs/networking/framing-bap.md`](../docs/networking/framing-bap.md);
2. clasifica `msg_id` conocidos según [`docs/networking/message-matrix.md`](../docs/networking/message-matrix.md);
3. lee evidencia JSONL con un **schema propio del proyecto**;
4. construye e imprime una timeline ordenada de mensajes;
5. incluye una **primitive AES-GCM offline** (`crypto::aead`) solo para fixtures sintéticos;
6. incluye una **primitive AES-CBC + HMAC-SHA256 offline** (`crypto::cbc_hmac`) para experimentos de session-record (`0x1A`), separada de GCM.

## Qué NO es

- **No** habla con Bungie ni con el cliente Destiny.
- **No** implementa SignOn / OAuth / autenticación real.
- **No** implementa UDP, NAT traversal, gameplay ni physics networking.
- **No** usa secretos / tokens / claves de capturas reales.
- **No** copia código de `kallsyms/d1-re`.
- El servidor local M4.2 es un **harness de compatibilidad** (`SIMULATED_HANDSHAKE`), no un emulador de servidores Bungie.

## AES-GCM offline (sintético)

API genérica en `src/crypto/aead.rs`:

- `encrypt_aes_gcm(key, nonce, plaintext, aad) → { tag, ciphertext }`
- `decrypt_aes_gcm(key, nonce, ciphertext, tag, aad) → plaintext`

Layout alineado con BAP `kind=1`: `[tag:16][ciphertext...]`.

- Key/nonce/AAD los aporta el caller (tests usan material inventado obvio).
- Nonce del servidor, XOR del cliente e incremento por frame **no** están automatizados aquí.
- AAD del protocolo real sigue **UNKNOWN** en la investigación; el parámetro existe para experimentos, no como hecho de Destiny.

La CLI `timeline` sigue tratando `kind=1` como opaco (no descifra).

## AES-CBC + HMAC offline (session-record)

API en `src/crypto/cbc_hmac.rs` (no mezclada con GCM):

- HMAC message kind **explícito**: `HmacMessageKind::LengthIvCiphertext`  
  → `u32_be(record_len) || iv || ciphertext` (hipótesis d1-re).
- `verify_session_record(...)` → reporte seguro (booleanos / longitudes).
- CLI: `cargo run -- session-crypto-verify <ruta-local.json>`

Plantilla (sin secretos): `fixtures/session_crypto_verify.template.json`.  
Material real: copiar a `evidence/local/session_crypto_verify.json` (gitignored) y rellenar hex **manualmente**.

## GCM nonce (first-frame, M2.4b)

API en `src/crypto/gcm_nonce.rs` (no decrypt; no modifica `aead.rs`):

- `XorLastByte(1)` para C→S; `Identity` para S→C (primer frame).
- CLI: `cargo run -- gcm-nonce-reconstruct <ruta-local.json>`

Plantilla: `fixtures/gcm_nonce_reconstruct.template.json`.

## First-frame AES-GCM verify (M2.4c)

CLI: `cargo run -- gcm-first-frame-verify <ruta-local.json>`  
Usa `decrypt_aes_gcm` sin modificar `aead.rs`. Wire real desde PCAP (gitignored).

Plantilla: `fixtures/gcm_first_frame_verify.template.json`.

## GCM sequence verify (M2.4d / M2.5)

CLI: `cargo run -- gcm-sequence-verify <ruta-local.json>`  
Nonces vía `SessionCryptoContext` (bases C→S/S→C + `increment_nonce` por dirección).

Plantilla: `fixtures/gcm_sequence_verify.template.json`.

## BapSession offline (M2.6)

API en `src/bap_session.rs`:

- `BapSession::new(session_key, session_nonce)`
- `decode_frame(direction, raw_frame)` → clear / decrypted / opaque

Clear (`kind=2`) no consume nonce. Encrypted (`kind=1`) usa `SessionCryptoContext` + AES-GCM.
Sin sockets ni transporte.

CLI: `cargo run -- bap-session-verify <ruta-local.json>`  
Plantilla: `fixtures/bap_session_verify.template.json`.  
Material real: `evidence/local/bap_session_verify.json` (gitignored).

## Stream framing incremental (M2.7)

API en `src/stream_framing.rs`:

- `BapStreamDecoder::push(bytes)` → 0..N `RawBapFrame`
- Sin crypto; alimenta `BapSession` con frames completos.

CLI: `cargo run -- bap-stream-verify <ruta-local.json>`  
(mismo JSON de M2.6; chunking artificial offline).

## ByteSource + pipeline (M2.8)

API en `src/byte_source.rs` + `src/bap_pipeline.rs`:

- `ByteSource` / `MockByteSource`
- `BapOfflinePipeline` → decoder + session

CLI: `cargo run -- bap-pipeline-verify <ruta-local.json>`

Futuro documentado (parcialmente implementado en M2.10): `TcpByteSource` read-only.
UDP / write / live endpoints: no.

## TCP ByteSource (M2.10)

API: `src/tcp_byte_source.rs`.

- `TcpEndpoint` + `TcpByteSource` (std::net, **read-only**)
- Implementa `ByteSource` → reutiliza `BapStreamDecoder` / `BapOfflinePipeline`
- Tests solo en `127.0.0.1` (sin Internet / sin Bungie)

## Multi-capture stability (M2.9)

API en `src/multi_capture.rs` + `src/multi_capture_verify.rs`.

CLI: `cargo run -- multi-capture-verify fixtures/multi_capture/manifest.json`

Estado: **VERIFIED_MULTI_CAPTURE** (`20260529-003132` + `20260608-231100`).

## Message inventory (M3.1)

API: `src/message_inventory.rs` + `src/message_inventory_verify.rs`.

CLI: `cargo run -- message-inventory fixtures/multi_capture/manifest.json`  
Export seguro: `fixtures/message_inventory/cross_capture_safe.json`.

## Payload structure (M3.2)

API: `src/payload_structure.rs` + `src/payload_structure_verify.rs`.

CLI: `cargo run -- payload-structure-verify fixtures/multi_capture/manifest.json`  
Export seguro: `fixtures/payload_structure/cross_capture_safe.json` (sin `payload_hex` / keys).

## Message correlation (M3.3)

API: `src/message_correlation.rs` + `src/message_correlation_verify.rs`.

CLI: `cargo run -- message-correlation-verify fixtures/multi_capture/manifest.json`  
Export seguro: `fixtures/message_correlation/cross_capture_safe.json`.

## Protocol state machine (M3.4)

API: `src/state_machine.rs` + `src/state_machine_verify.rs`.

CLI: `cargo run -- state-machine-verify fixtures/multi_capture/manifest.json`  
Export seguro: `fixtures/state_machine/cross_capture_safe.json`.

## Protocol specification (M4.1)

API: `src/protocol_spec.rs` + `src/protocol_spec_verify.rs`.

CLI: `cargo run -- protocol-spec-verify fixtures/multi_capture/manifest.json`  
Export: `fixtures/protocol_spec/protocol_spec_safe.json` → `VERIFIED_PROTOCOL_SPEC`.

## CLI

Desde `network/`:

### Schema propio del proyecto

```bash
cargo run -- timeline fixtures/synthetic_session.jsonl
```

Pipeline:

```text
JSONL reader → BAP parser → message classifier → timeline → formatter
```

### Evidencia externa (`decrypted_bap.jsonl` / schema d1-re)

```bash
cargo run -- timeline-external <path>
```

Pipeline:

```text
JSONL externo → evidence_adapter → EvidenceRecord → classifier → timeline → formatter
```

- Acepta evidencia compatible con [`docs/networking/evidence-jsonl.md`](../docs/networking/evidence-jsonl.md).
- La evidencia **real** debe quedarse en disco local / gitignored (`evidence/local/`, `**/decrypted_bap.jsonl`). **No** commitearla.
- La salida solo muestra timestamp, dirección, kind, message id/name, context y `payload_len`.
- **No** imprime payloads, nonces, key hashes, `token_source` ni metadatos de `bap_connection`.
- Validar contra una captura real es una tarea aparte del operador; este repo solo incluye el fixture sintético `fixtures/external_schema_synthetic.jsonl`.

Ejemplo (sintético, no captura real):

```bash
cargo run -- timeline-external fixtures/external_schema_synthetic.jsonl
```

Salida conceptual (valores del fixture/parser, no hardcodeados):

```text
[000000ms] C -> S | kind=2 | 0x001e | destiny-service-handshake-request | context=1 | payload_len=3
[000031ms] S -> C | kind=2 | 0x001f | destiny-service-handshake-response | context=1 | payload_len=2
[000052ms] C -> S | kind=2 | 0x0019 | session-login-request | context=2 | payload_len=2
[000087ms] S -> C | kind=2 | 0x001a | session-login-response | context=2 | payload_len=2
[000103ms] C -> S | kind=1 | encrypted | payload_len=20
...
```

`timeline` con schema propio: `kind=1` se muestra como `encrypted` (body opaco). No se descifra.

Errores (archivo inexistente, JSONL inválido, schema externo inválido, args incorrectos) → mensaje en stderr y exit code ≠ 0.

## Núcleo documentado (contexto)

```text
SignOn HTTPS → TCP → BAP framing → session → AES-GCM
(offline: BapSession + SessionCryptoContext; no live transport)
```

UDP = UNKNOWN (no asumido aquí).

## Estructura

```text
network/
├── Cargo.toml
├── README.md
├── fixtures/
│   ├── synthetic_session.jsonl           # schema propio
│   └── external_schema_synthetic.jsonl   # schema d1-re (datos inventados)
├── src/
│   ├── main.rs
│   ├── lib.rs
│   ├── cli.rs
│   ├── crypto/
│   ├── evidence_adapter.rs   # decrypted_bap.jsonl → EvidenceRecord
│   ├── framing.rs
│   ├── messages.rs
│   ├── jsonl.rs
│   └── timeline.rs
└── tests/
    ├── framing.rs
    ├── cli.rs
    ├── crypto_aead.rs
    └── evidence_adapter.rs
```

## Schema JSONL (propio del proyecto)

Campos mínimos del schema propio (CLI `timeline`):

| Campo | Obligatorio | Descripción |
| ----- | ----------- | ----------- |
| `timestamp_ms` | sí | Clave de orden |
| `direction` | sí | `client_to_server` / `server_to_client` |
| `frame_hex` o `kind`+campos | sí | Frame BAP |

## Schema JSONL externo (`decrypted_bap.jsonl`)

Documentado en [`docs/networking/evidence-jsonl.md`](../docs/networking/evidence-jsonl.md).

Adaptador:

```rust
use destiny1_network::{adapt_jsonl_path, Timeline};

let records = adapt_jsonl_path("path/to/local/decrypted_bap.jsonl")?; // gitignored
let timeline = Timeline::from_evidence(&records);
```

- Solo mapea campos ya confirmados (`bap_frame` con `id`/`context`/`payload_hex`).
- Ignora `bap_connection` y frames con `error` sin `id`.
- **No** descifra ni deriva claves.
- No commitear JSONL reales; usar `evidence/local/` (gitignored) o el fixture sintético.

## Fixtures

`fixtures/synthetic_session.jsonl` contiene **solo** bytes inventados para tests.  
No hay datos extraídos de capturas reales.

## Uso rápido (API)

```rust
use destiny1_network::jsonl;
use destiny1_network::timeline::Timeline;

let records = jsonl::parse_jsonl_path("fixtures/synthetic_session.jsonl")?;
let timeline = Timeline::from_evidence(&records);
for line in timeline.format_cli_lines() {
    println!("{line}");
}
```

## Local BAP server & replay (M4.2) — DONE

TCP localhost only (`127.0.0.1`, ephemeral port). Reuses `BapStreamDecoder`,
`BapSession`, `SessionCryptoContext`. Synthetic crypto fixtures only.

```bash
cargo run -- local-server
cargo run -- local-replay fixtures/local_server/handshake_replay.json
# → LOCAL_REPLAY: VERIFIED
```

Docs: [`docs/networking/local-server.md`](../docs/networking/local-server.md).

## UDP evidence (M4.3) — DONE

Read-only offline PCAP/UDP analysis. **No UDP send/bind.** Safe exports under
`fixtures/udp_evidence/`.

```bash
cargo run -- udp-evidence-verify fixtures/multi_capture/manifest.json
# → UDP_EVIDENCE_ANALYSIS: VERIFIED
```

Docs: [`docs/networking/udp-evidence.md`](../docs/networking/udp-evidence.md).

## Message codec (M4.4) — DONE

Logical BAP encode/decode + registry + observational dispatcher.

```bash
cargo run -- message-codec-verify
# → MESSAGE_CODEC_VERIFY: VERIFIED
```

Docs: [`docs/networking/message-codec.md`](../docs/networking/message-codec.md).

## Stateful local BAP server (M4.5) — DONE

```bash
cargo run -- stateful-server-verify
```

Expected: `STATEFUL_SERVER_VERIFY: VERIFIED`.

Docs: [`docs/networking/stateful-server.md`](../docs/networking/stateful-server.md).

Local execution `ProtocolState` is separate from M3.4 observational SM. Synthetic crypto only; no external network.

## Compatibility client (M4.6) — DONE

```bash
cargo run -- compatibility-client-verify
```

Expected: `COMPATIBILITY_CLIENT_VERIFY: VERIFIED`.

Docs: [`docs/networking/compatibility-client.md`](../docs/networking/compatibility-client.md).

`BapCompatibilityClient` is distinct from `BapReplayClient`. Localhost TCP only; `SYNTHETIC_TEST_ONLY` material in `test_crypto_material.rs`.

## External client boundary (M4.7) — DONE

```bash
cargo run -- external-boundary-verify
```

Expected: `EXTERNAL_BOUNDARY_VERIFY: VERIFIED`.

Docs: [`docs/networking/external-client-boundary.md`](../docs/networking/external-client-boundary.md).

Localhost-only ingress; reuses `BapStreamDecoder` + `StatefulBapSession`; safe events only.

## Observation harness (M4.8) — DONE

```bash
cargo run -- observation-verify
cargo run -- observation-diff fixtures/observation/startup_expected.json fixtures/observation/divergence_example.json
```

Expected: `OBSERVATION_VERIFY: VERIFIED`.

Docs: [`docs/networking/observation-harness.md`](../docs/networking/observation-harness.md).

Safe metadata traces + structural diff vs local reference scenarios. No external network; no secrets in traces.

## Compatibility matrix (M4.9) — DONE

```bash
cargo run -- compatibility-matrix-verify
cargo run -- compatibility-matrix-report
```

Expected: `COMPATIBILITY_MATRIX: VERIFIED` with `real_client_verified: 0` and `real_server_verified: 0`.

Docs: [`docs/networking/compatibility-matrix.md`](../docs/networking/compatibility-matrix.md).

Machine-readable capability matrix; separate evidence/implementation/verification/scope. Local ≠ real-client.

## SignOn offline analysis (M4.10) — DONE

```bash
cargo run -- signon-verify
cargo run -- signon-report
```

Expected: `SIGNON_ANALYSIS: VERIFIED` with `secret_values_stored: 0`.

Docs: [`docs/networking/signon-analysis.md`](../docs/networking/signon-analysis.md).

Metadata-only SignOn model + `SessionMaterialProvider` boundary. No live HTTP/auth; synthetic material only for BAP tests.

## Tests

```bash
cd network
cargo test
```

## Documentación de protocolo

Ver [`docs/networking/`](../docs/networking/).

## Regla

Evidence first. Fixtures sintéticos. Sin secretos en el repo.
