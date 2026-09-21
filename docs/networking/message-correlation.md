# Message Correlation & Sequence Analysis (M3.3)

Offline correlation of message order, timing (ordinal), context, and fingerprints across the two verified captures.

## 1. Objetivo

Estudiar relaciones **observables** entre mensajes:

- orden / n-grams / subsecuencias;
- transición de dirección;
- context;
- fingerprints;
- proximidad temporal (vía `frame_order`);
- candidatos conservadores request/response;
- alineación y divergencia cross-capture.

**No** asigna semántica definitiva.

## 2. Fuentes

| Captura | Fixture (gitignored) |
| ------- | -------------------- |
| `20260529-003132` | `evidence/local/bap_session_verify.json` |
| `20260608-231100` | `evidence/local/bap_session_verify_20260608-231100.json` |

Reutiliza `MessageObservation` / `MessageInventory` / `BapOfflinePipeline`.  
Timing: **`frame_order`** como ordinal (`timing_basis=frame_order`); no hay wall-clock ms en el fixture de pipeline.

## 3. Labels

| Label | Uso |
| ----- | --- |
| **OBSERVED** | Hecho de secuencia / conteo / fingerprint |
| **STRUCTURAL_HYPOTHESIS** | Candidato RR, periodicidad aproximada, context transition |
| **CORRELATION** | Transición de dirección / valor compartido entre mensajes |
| **EXTERNAL_REFERENCE** | Nombre de `messages.rs` (p. ej. keepalive) |
| **UNKNOWN** | Semántica / confirmación |

## 4. Secuencias y n-grams

`MessageSequence` por captura + 1..4-grams con `STABLE_SEQUENCE` / `CAPTURE_SPECIFIC`.  
Startup multi-mensaje se reporta como `startup_sequence_candidate` vía subsecuencias estables; el nombre “login” solo como EXTERNAL_REFERENCE si aplica.

## 5. Transition graph

Edges `A→B` con count, dirección relativa, median Δ(`frame_order`), clase:

```text
STABLE_EDGE | CAPTURE_SPECIFIC_EDGE | DIVERGENT_EDGE
```

## 6. Request/response candidates

Solo si ≥3 señales (dirección opuesta, IDs consecutivos, estable cross-capture, repetición, context, longitudes, stable edge).

```text
REQUEST_RESPONSE_CANDIDATE
confidence: STRUCTURAL_HYPOTHESIS
semantic_confirmation: UNKNOWN
```

Nunca `CONFIRMED_REQUEST` / `CONFIRMED_RESPONSE`.

## 7. Limitaciones

- Sin TCP / sockets / Tokio / UDP / servidor.
- Sin re-crypto / re-framing.
- Δ temporal en unidades `frame_order`, no milisegundos de pared.
- No inicia M3.4 ni M2.10.

## CLI

```bash
cargo run -- message-correlation-verify fixtures/multi_capture/manifest.json
```

Export: `fixtures/message_correlation/cross_capture_safe.json`

## Related

- [message-inventory.md](message-inventory.md) (M3.1)
- [payload-structure.md](payload-structure.md) (M3.2)
- [message-matrix.md](message-matrix.md)
