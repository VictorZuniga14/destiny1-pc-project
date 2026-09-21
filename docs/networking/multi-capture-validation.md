# Multi-Capture Stability Validation (M2.9)

Offline comparison of networking/crypto invariants across independent captures.

## Objetivo

Determinar qué reglas de M2.3–M2.8 son **estables** entre capturas y cuáles siguen siendo solo observaciones locales.

## Metodología

```text
fixture / evidence (gitignored secrets)
        ↓
multi_capture_verify loader
        ↓
BapOfflinePipeline → BapStreamDecoder → BapSession → SessionCryptoContext
        ↓
CaptureValidationReport
        ↓
compare_captures
        ↓
STABLE | OBSERVED | CAPTURE_SPECIFIC | DIVERGENT | UNKNOWN
```

No se modificaron reglas crypto para “hacer pasar” la segunda captura.

## Capturas utilizadas

| Capture ID | Pipeline fixture (gitignored) | Frames | Result |
| ---------- | ----------------------------- | ------ | ------ |
| `20260529-003132` | `evidence/local/bap_session_verify.json` | 128 (4 clear / 124 enc) | VERIFIED |
| `20260608-231100` | `evidence/local/bap_session_verify_20260608-231100.json` | 126 (4 clear / 122 enc, **first BAP session only**) | VERIFIED |

Ambas son capturas PS3 independientes de `external/d1-re/captures/`.  
Los ~66 directorios restantes **no** cuentan hasta tener fixture pipeline-ready.

Preparación de la segunda captura (offline, local):

- `traffic.pcap` + `https_flows.jsonl` + `decrypted_bap.jsonl`
- session key/nonce vía SignOn → `0x1A` (tool externo d1-re como librería local; no copiado a `network/`)
- wire `frame_hex` desde PCAP + `frame_offset` / dirección del JSONL

## Invariantes (resultado)

| Invariante | Status |
| ---------- | ------ |
| BAP framing | **STABLE** |
| AES-GCM (todos los encrypted con wire) | **STABLE** |
| AAD empty | **STABLE** (2 capturas; no implica AAD vacío en todo Destiny) |
| C→S nonce XOR-last-1 | **STABLE** |
| S→C nonce Identity | **STABLE** |
| Direction counters independientes | **STABLE** |
| `0x1A` AES-CBC/HMAC path | **STABLE** |
| Startup `0x1E→0x1F→0x19→0x1A→0x79→0x7A` | **STABLE** |
| Keepalive `0xFA` / `0xFB` presencia | **STABLE** |
| Keepalive timing (~interval) | **UNKNOWN** |

## RESULT

```text
VERIFIED_MULTI_CAPTURE
```

Reglas actuales pasaron en la segunda captura **sin modificar** `SessionCryptoContext` / GCM / framing.

## Capture-specific observations

- Conteos de frames distintos (128 vs 126): esperado; no es divergencia de reglas.
- `20260608-231100` tiene **2** conexiones BAP en el JSONL; el fixture usa solo la **primera** sesión (126 frames).

## UNKNOWN

- AAD no vacío
- Rekey / resync
- Keepalive interval como constante de protocolo
- Otras plataformas (PS4 / Xbox / PC)
- UDP / gameplay
- Sesiones BAP adicionales dentro de la misma captura (2ª conexión de `20260608-231100`)

## Limitaciones

- Secretos no van a git.
- No se copió código de d1-re a `network/`.
- Multi-capture ≠ prueba universal de Destiny; solo estabilidad entre estas dos evidencias PS3.

## CLI

```bash
cargo run -- multi-capture-verify fixtures/multi_capture/manifest.json
```

## Relación con M2.10

No iniciado automáticamente. Candidatos: más capturas, 2ª sesión BAP de la misma captura, o transporte — aparte.

## Related

- [byte-source.md](byte-source.md) — M2.8
- [bap-session.md](bap-session.md) — M2.6
- [gcm-channel-validation.md](gcm-channel-validation.md)
