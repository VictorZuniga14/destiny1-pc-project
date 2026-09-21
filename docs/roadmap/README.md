# Roadmap técnico

## Milestone 1 — Network discovery — DONE

Objetivo: comprender una sesión mínima de Destiny 1 con evidencia primero.

### Núcleo documentado

```text
SignOn HTTPS
     ↓
tokens + endpoints
     ↓
TCP + BAP framing
     ↓
0x1E / 0x1F
     ↓
0x19 / 0x1A
     ↓
session key + nonce
     ↓
AES-GCM
     ↓
0x79 / 0x7A, 0xFA / 0xFB, 0x12D, 0x12E / 0x12F
```

UDP gameplay / physics / peers / NAT de bajo nivel: **UNKNOWN** (no asumir como núcleo).

Plataforma de evidencia actual: **PS3** (`kallsyms/d1-re`). PS4 / Xbox / PC: **UNKNOWN**.

### Estado

```text
DONE — offline networking evidence pipeline validated against real capture.
```

- [x] Documentación en `docs/networking/`.
- [x] Analizador offline (`network/`: framing, classifier, JSONL propio, timeline, AES-GCM sintético).
- [x] Schema externo `decrypted_bap.jsonl` documentado + adaptador.
- [x] CLI `timeline` / `timeline-external`.
- [x] Validación contra captura real PS3 `20260529-003132` (evidencia local gitignored).

Notas de validación: [docs/networking/capture-20260529-003132-notes.md](../networking/capture-20260529-003132-notes.md).

**M1 no incluye:** servidor, UDP/gameplay, crypto de sesión Destiny completa, cliente PC.

## Milestone 2 — Session Reconstruction

**Offline**, sobre evidencia existente.

### M2.1 — 0x1A structure investigation — DONE

Documentación: [session-login-response.md](../networking/session-login-response.md).

- [x] Localizar `0x1A` en captura real `20260529-003132` (metadata segura).
- [x] Documentar longitudes / cabeceras observadas sin publicar secretos.
- [x] Contrastar con interpretación pública de `kallsyms/d1-re`.
- [x] Verificación criptográfica propia (HMAC/AES-CBC) con material real — ver M2.3.
- [ ] Comparación multi-captura (queda abierta dentro de M2).

### M2.2 — Offline cryptographic verification — DONE

Primitive `network/src/crypto/cbc_hmac.rs` + CLI `session-crypto-verify`.

- [x] Primitive offline AES-CBC + HMAC-SHA256 aislada de AES-GCM.
- [x] Hipótesis HMAC explícita: `LengthIvCiphertext` (d1-re).
- [x] Tests sintéticos (HMAC/CBC/padding/tamper).
- [x] CLI offline sobre JSON gitignored (sin imprimir secretos).
- [x] Verificación exitosa con material **real** (M2.3).

### M2.3 — Real verification — DONE

Captura `20260529-003132`: CLI `result: VERIFIED` (HMAC true, AES-CBC success, padding true, plaintext 32→28).

- [x] Validación estricta de longitudes.
- [x] Clasificación `VERIFIED` / `PARTIAL` / `FAILED`.
- [x] Una sola hipótesis HMAC (sin fallback de truncado).
- [x] Keys SignOn en JSON gitignored (manual; no versionadas).
- [x] Corrida real HMAC + AES-CBC + padding + estructura length-compatible.

**M2 sigue abierto.**

### M2.4a — First encrypted frame characterization — DONE

Documentación: [first-encrypted-frame.md](../networking/first-encrypted-frame.md).

- [x] Identificar primer `frame_kind=1` tras `0x1A` en `20260529-003132`.
- [x] Metadata segura (dirección, indices, id/context post-decrypt, deltas).
- [x] Relación observada con `0x79` / `0x7A`.
- [x] Separar wire vs post-decrypt; longitudes wire UNKNOWN en JSONL.
- [x] Listar UNKNOWN (AAD, nonce progression, etc.) sin implementar GCM.

### M2.4b — GCM nonce reconstruction (first `0x79`) — DONE

Documentación: [gcm-nonce.md](../networking/gcm-nonce.md).

- [x] Documentar hipótesis d1-re (S→C Identity, C→S XOR last byte 1).
- [x] Contrastar con JSONL real (igualdades estructurales, sin publicar nonces).
- [x] Primitive + CLI `gcm-nonce-reconstruct` (determinista; no decrypt).
- [x] Confirmar para esta captura: nonce `0x79` = session⊕último_byte(1).

### M2.4c — First real AES-GCM decrypt of `0x79` — DONE

Documentación: [gcm-first-frame.md](../networking/gcm-first-frame.md).

- [x] Localizar wire en `traffic.pcap` (`frame_offset=405`, `body_len=22`).
- [x] tag=16 / ciphertext=6 medidos en PCAP.
- [x] Decrypt con `decrypt_aes_gcm` + key M2.3 + nonce M2.4b + AAD vacío.
- [x] plaintext length 6; coincide con evidencia post-decrypt d1-re.

### M2.4d — Bidirectional GCM + nonce progression — DONE

Documentación: [gcm-channel-validation.md](../networking/gcm-channel-validation.md).

- [x] `0x7A` wire PCAP + decrypt VERIFIED.
- [x] Secuencia de 8 frames GCM (incl. `0x12E`/`0x12F`/`0x0A`/`0x0B`) con AAD vacío.
- [x] Progression CONFIRMED: bases por dirección + `increment_nonce` independiente.
- [x] CLI `gcm-sequence-verify` + tests sintéticos.

### M2.5 — SessionCryptoContext + per-direction nonce — DONE

- [x] `SessionCryptoContext` (`session_key`, `session_nonce`, counters C→S/S→C).
- [x] Bases XOR-last-1 / Identity; `increment_nonce` reutilizado.
- [x] `gcm_sequence` refactorizado para usar solo el contexto.
- [x] Tests unitarios + 8 frames M2.4d VERIFIED vía CLI.

### M2.6 — BapSession offline + mass BAP validation — DONE

Documentación: [bap-session.md](../networking/bap-session.md).

- [x] `BapSession` offline (framing clear/encrypted + `SessionCryptoContext` + AES-GCM).
- [x] Dirección obligatoria para `kind=1`; clear no consume nonce.
- [x] Counters C→S / S→C independientes; sin transporte/sockets.
- [x] CLI `bap-session-verify` sobre captura `20260529-003132` (wire PCAP + correlación JSONL).
- [x] Tests sintéticos (secuencia mixta, errores, round-trip).

### M2.7 — Stream buffer / framing incremental — DONE

Documentación: [stream-framing.md](../networking/stream-framing.md).

- [x] `BapStreamDecoder` offline (`push` → 0..N `RawBapFrame`).
- [x] Header/body parciales, multi-frame, magic/kind/size errors.
- [x] Separado de `BapSession` (sin crypto en el decoder).
- [x] CLI `bap-stream-verify`: chunking artificial + 128 frames → `BapSession` VERIFIED.
- [x] Tests sintéticos exhaustivos + paridad M2.6.

### M2.8 — ByteSource offline + pipeline BAP completo — DONE

Documentación: [byte-source.md](../networking/byte-source.md).

- [x] Trait `ByteSource` + `MockByteSource` determinista.
- [x] `BapOfflinePipeline` (source → decoder → session); capas separadas.
- [x] Dirección explícita (`run_unidirectional` / `run_directed`).
- [x] CLI `bap-pipeline-verify` → 128/128 VERIFIED sobre `20260529-003132`.
- [x] Errores: EOF limpio, incompleto, source error, chunking agresivo.

### M2.9 — Multi-capture stability validation — DONE

Documentación: [multi-capture-validation.md](../networking/multi-capture-validation.md).

- [x] Infraestructura `CaptureValidationReport` + `compare_captures`.
- [x] Captura 1: `20260529-003132` (128 frames) pipeline VERIFIED.
- [x] Captura 2: `20260608-231100` (126 frames, 1ª sesión BAP) pipeline VERIFIED **sin cambiar reglas crypto**.
- [x] CLI `multi-capture-verify` → **VERIFIED_MULTI_CAPTURE**.
- [x] Invariantes framing/GCM/nonce/startup/keepalive-presencia → **STABLE**; timing keepalive → **UNKNOWN**.

**M2.10** — TCP transport abstraction — **DONE**.

Documentación: [tcp-byte-source.md](../networking/tcp-byte-source.md).

- [x] `TcpEndpoint` + `TcpByteSource` (std::net, read-only) implementa `ByteSource`.
- [x] Sin Tokio; `MockByteSource` / `BapOfflinePipeline` intactos.
- [x] Tests loopback: chunks, frames BAP, split, EOF, IncompleteAtEnd, refused.
- [x] Replay wire captura local / sintético por TCP local.
- [x] Sin write / sin Bungie / sin UDP.

### Resto de M2 (no implementado)

- más capturas / otras plataformas;
- AAD no vacío;
- rekey / resync;
- UDP / gameplay.

## Milestone 3 — Message understanding + client path

### M3.1 — Message inventory — DONE

Documentación: [message-inventory.md](../networking/message-inventory.md).

- [x] `MessageObservation` / `MessageInventory` / cross-capture comparison.
- [x] Fingerprints SHA-256 + byte-diff posicional.
- [x] CLI `message-inventory` sobre las dos capturas VERIFIED.
- [x] Export seguro (sin keys / sin payload_hex versionado).
- [x] Startup sequences + `OBSERVED_SEQUENCE_PAIR` (sin afirmar semántica request/response).

**M3.2** — Payload structure analysis — **DONE**.

Documentación: [payload-structure.md](../networking/payload-structure.md).

- [x] Análisis byte-by-byte + longitudes + regiones candidatas.
- [x] Candidatos numéricos / bits / texto (sin promoción semántica).
- [x] Comparación within-capture vs cross-capture.
- [x] CLI `payload-structure-verify` + export seguro.
- [x] Validación real sobre `20260529-003132` + `20260608-231100`.

**M3.3** — Message correlation & sequence analysis — **DONE**.

Documentación: [message-correlation.md](../networking/message-correlation.md).

- [x] N-grams, subsecuencias estables, divergencia / alineación.
- [x] Transition graph + stable / capture-specific edges.
- [x] Timing ordinal (`frame_order`), clusters, periodicidad aproximada.
- [x] Context + fingerprint correlation.
- [x] REQUEST_RESPONSE_CANDIDATE conservador (sin confirmación semántica).
- [x] CLI `message-correlation-verify` + export seguro.
- [x] Validación real sobre `20260529-003132` + `20260608-231100`.

**M3.4** — Protocol state machine & semantic evidence — **DONE**.

Documentación: [state-machine.md](../networking/state-machine.md).

- [x] Estados neutrales + graph + traces deterministas.
- [x] Startup sequence OBSERVED; branches; repeating cluster.
- [x] RR candidates preservados como hipótesis; external refs separadas.
- [x] CLI `state-machine-verify` + export seguro.
- [x] Validación real sobre ambas capturas VERIFIED.

## Milestone 4 — Account flow

### M4.1 — Protocol implementation specification — DONE

Documentación: [protocol-spec-v0.1.md](../networking/protocol-spec-v0.1.md),
[unknown-registry.md](../networking/unknown-registry.md).

- [x] Matriz 28 IDs + readiness + unknown registry.
- [x] Crypto/framing/startup/state machine documentados con labels correctos.
- [x] CLI `protocol-spec-verify` → `VERIFIED_PROTOCOL_SPEC`.
- [x] Export `fixtures/protocol_spec/protocol_spec_safe.json` (sin secretos).

### M4.2 — Local BAP Compatibility Server & Replay — DONE

Documentación: [local-server.md](../networking/local-server.md).

- [x] `LocalBapServer` + `BapReplayClient` sobre TCP `127.0.0.1`.
- [x] `SIMULATED_HANDSHAKE` (separado de la SM observacional M3.4).
- [x] Clear + AES-GCM bidireccional con fixtures sintéticas.
- [x] CLI `local-server` / `local-replay` → `LOCAL_REPLAY: VERIFIED`.
- [x] E2E + negative tests (wrong key/nonce, magic, kind, unexpected, chunking).

### M4.3 — UDP Evidence & Transport Discovery — DONE

Documentación: [udp-evidence.md](../networking/udp-evidence.md).

- [x] Inventario UDP offline de capturas `20260529-003132` / `20260608-231100`.
- [x] Flows, lengths, timing, fingerprints, correlaciones TCP/BAP/NAT (temporales).
- [x] Cross-capture + safe export (sin payloads/IPs/secretos).
- [x] Unknown registry `UNK-UDP-*` (ninguno resuelto).
- [x] CLI `udp-evidence-verify` → `UDP_EVIDENCE_ANALYSIS: VERIFIED`.

### M4.4 — BAP Message Codec & Dispatch Layer — DONE

Documentación: [message-codec.md](../networking/message-codec.md).

- [x] Registry central (28 IDs) + codecs conocidos / unknown raw.
- [x] Validación estructural `0x1A` (sin decrypt en el codec).
- [x] Dispatcher observacional (no muta M3.4).
- [x] Integración segura con local server M4.2.
- [x] CLI `message-codec-verify` → `MESSAGE_CODEC_VERIFY: VERIFIED`.

### M4.5 — Stateful Local BAP Server — DONE

Documentación: [stateful-server.md](../networking/stateful-server.md).

- [x] `ProtocolState` + transiciones centralizadas (policy local, no SM Bungie).
- [x] `StatefulBapSession` + `ResponsePolicy` por conexión.
- [x] Validación de secuencia `0x1E/0x19/0x79/0x7A`; unknown observe-only.
- [x] Aislamiento multi-cliente / reconnect / crypto sintético.
- [x] CLI `stateful-server-verify` → `STATEFUL_SERVER_VERIFY: VERIFIED`.

### M4.6 — Local BAP Compatibility Client — DONE

Documentación: [compatibility-client.md](../networking/compatibility-client.md).

- [x] `BapCompatibilityClient` + `ClientProtocolState` (localhost only).
- [x] Handshake sintético E2E contra `LocalBapServer`.
- [x] Crypto `SYNTHETIC_TEST_ONLY` centralizado; chunking / multi-client / reconnect.
- [x] CLI `compatibility-client-verify` → `COMPATIBILITY_CLIENT_VERIFY: VERIFIED`.

### M4.7 — External Client Compatibility Boundary — DONE

Documentación: [external-client-boundary.md](../networking/external-client-boundary.md).

- [x] `ExternalClientBoundary` / listener localhost-only + lifecycle.
- [x] Reutiliza decoder + `StatefulBapSession` (sin parser BAP duplicado).
- [x] Eventos seguros; multi-client; fragmentación; negativos.
- [x] CLI `external-boundary-verify` → `EXTERNAL_BOUNDARY_VERIFY: VERIFIED`.

### M4.8 — Real Client Observation Harness — DONE

Documentación: [observation-harness.md](../networking/observation-harness.md).

- [x] `ObservationTrace` / `ObservationAnalyzer` / `ObservationDiff` (metadata-only).
- [x] Clasificación `Observed` / `Structural` / `Hypothesis` / `Confirmed` / `Unknown` (sin auto-promoción).
- [x] `SafeFingerprint`; rechazo de campos sensibles; escenarios de referencia.
- [x] CLI `observation-verify` → `OBSERVATION_VERIFY: VERIFIED`.

### M4.9 — Protocol Compatibility Test Matrix — DONE

Documentación: [compatibility-matrix.md](../networking/compatibility-matrix.md).

- [x] Matriz machine-readable (`get_compatibility_matrix`) — single source of truth.
- [x] Dimensiones separadas evidence / implementation / verification / scope.
- [x] 28 message IDs + áreas bloqueadas (SignOn / real client / real server / gameplay).
- [x] CLI `compatibility-matrix-verify` → `COMPATIBILITY_MATRIX: VERIFIED` (`real_client_verified=0`, `real_server_verified=0`).

### M4.10 — SignOn Protocol Analysis & Offline Session Boundary — DONE

Documentación: [signon-analysis.md](../networking/signon-analysis.md).

- [x] Modelo offline `SignOnEvidence` / `SignOnField` / `SignOnSessionMaterial` (sin secretos).
- [x] `SessionMaterialProvider` + `OfflineSessionMaterialProvider` (`SYNTHETIC_TEST_ONLY`) → `SessionCryptoContext`.
- [x] Analyzer + spec machine-readable; CLI `signon-verify` → `SIGNON_ANALYSIS: VERIFIED` (`secret_values_stored=0`).
- [x] Real SignOn permanece `NOT_IMPLEMENTED` / `BLOCKED`.

**M5** — **no iniciado**.

Objetivo general del milestone: conectar un cliente experimental con servicios comunitarios y obtener una cuenta/personaje.

## Milestone 5 — Orbit

Objetivo: completar el flujo de login hasta Orbit.

## Milestone 6 — First multiplayer test

Objetivo: conectar dos clientes y demostrar comunicación entre jugadores.

## Milestone 7 — Activities

Expandir progresivamente a destinos y actividades.

## Regla

Cada milestone debe producir una prueba reproducible antes de avanzar.

No saltar de la documentación de red directamente a un servidor sin evidencia y reconstrucción de sesión offline.
