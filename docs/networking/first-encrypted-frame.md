# First Encrypted Frame

## Capture

`20260529-003132` (PS3)

| Ítem | Valor |
| ---- | ----- |
| Evidencia | `evidence/local/decrypted_bap.jsonl` (**gitignored**) |
| Origen | `kallsyms/d1-re` captura homónima |
| Milestone | **M2.4a** — caracterización only (sin decrypt GCM propio) |

No se versionan ciphertext, plaintext, nonces ni keys.

## Previous session state

Orden cronológico observado en esta captura (sort d1-re: `frame_ts`, `frame_order`, direction, …):

```text
0x1E  clear  C→S   destiny-service-handshake-request
0x1F  clear  S→C   destiny-service-handshake-response
0x19  clear  C→S   session-login-request
0x1A  clear  S→C   session-login-response     ← session record (M2.1–M2.3)
0x79  enc    C→S   encrypted-handshake-request  ← PRIMER frame_kind=1
0x7A  enc    S→C   encrypted-handshake-status
0x12E enc    C→S   nat-report
0x12F enc    S→C   nat-report-status
…
```

**CONFIRMED** para esta captura: no hay ningún `frame_kind=1` **antes** de `0x1A`.

## First encrypted frame

Primer `frame_kind = 1` **después** de `0x1A`:

| Campo | Valor | Origen | Confianza |
| ----- | ----- | ------ | --------- |
| Posición relativa | inmediatamente después de `0x1A` (~**+11.7 ms**) | `frame_ts` delta | CONFIRMED |
| `direction` | `client_to_server` | JSONL | CONFIRMED |
| `frame_kind` | **1** | JSONL | CONFIRMED |
| `frame_index` | **2** (por dirección cliente; 0=`0x1E`, 1=`0x19`) | JSONL | CONFIRMED |
| `frame_order` | 244 | JSONL | CONFIRMED |
| `frame_offset` | 405 (offset en stream TCP cliente) | JSONL | CONFIRMED |
| `id` / `id_hex` | **121** / **`0x79`** | post-decrypt | CONFIRMED (evidencia d1-re) |
| `name` | `encrypted-handshake-request` | tabla d1-re | CONFIRMED as tool naming |
| `context` | **2** | post-decrypt | CONFIRMED (evidencia d1-re) |
| Message payload length | **0** | `payload_len` | CONFIRMED (post-decrypt) |
| Plaintext length | **6** bytes (`msg_id`+`context`, sin payload) | `plaintext_hex` length | CONFIRMED (post-decrypt artifact) |
| Relative timestamp | `0x1A` → **+11.679 ms** → este frame | `frame_ts` | CONFIRMED |

### Wire lengths

| Campo wire | Valor en JSONL | Notas |
| ---------- | -------------- | ----- |
| Body length (`body_len` BAP) | **UNKNOWN** | `decrypted_bap.jsonl` **no** emite tag/ciphertext/body wire |
| Tag length | **UNKNOWN** en JSONL | |
| Ciphertext length | **UNKNOWN** en JSONL | |

#### EXTERNAL EVIDENCE / HYPOTHESIS (d1-re — no CONFIRMED wire)

```text
Fuente: kallsyms/d1-re/tools/ps3_decrypt_capture.py
función/script: decrypt_bap_direction_docs
```

El decryptor trata el body `kind=1` como:

```text
body = [tag:16][ciphertext...]
AES-GCM decrypt(nonce, ciphertext || tag, aad=None)
```

Bajo AES-GCM, `|ciphertext| == |plaintext|` cuando el decrypt tiene éxito.  
Con plaintext post-decrypt de **6** bytes, la hipótesis externa implica:

| Inferido (no medido en JSONL) | Valor hipotético |
| ----------------------------- | ---------------- |
| tag | 16 bytes |
| ciphertext | 6 bytes |
| wire `body_len` | 22 bytes |

**No** se marca CONFIRMED: no hay medición directa del wire en este artefacto.

## Relación con `0x79` / `0x7A`

| Pregunta | Respuesta (esta captura) | Confianza |
| -------- | ------------------------ | --------- |
| ¿El primer frame cifrado es `0x79`? | **Sí** | CONFIRMED (post-decrypt id) |
| ¿Es `0x7A`? | No; `0x7A` es el **segundo** encrypted | CONFIRMED |
| Orden post-`0x1A` | `0x79` (C→S) → `0x7A` (S→C) → `0x12E` → `0x12F` → … | CONFIRMED |

No se asume que siempre sea así en otras capturas/plataformas (**UNKNOWN** generalización).

## Wire vs decrypted evidence

| Capa | Qué representa | En este JSONL |
| ---- | -------------- | ------------- |
| **Wire** | Bytes BAP en TCP: magic, `kind`, `body_len`, body (`tag`+`ciphertext` si kind=1) | Solo metadatos de framing parcial (`frame_kind`, offsets/ts). **Sin** body encrypted |
| **Post-decrypt** | Resultado del AES-GCM de d1-re: `id`, `context`, `payload_*`, `plaintext_hex`, `nonce` usado | Presente para el primer encrypted |

**CONFIRMED:** `plaintext_hex` **no** es el material wire; es el plaintext tras GCM del tool externo.

**CONFIRMED:** el campo `nonce` del JSONL es el nonce que **d1-re aplicó** a ese frame (hipótesis del tool), no una prueba independiente de nuestro proyecto.

## UNKNOWN

Registrar explícitamente (M2.4a **no** investiga estos):

| Ítem | Estado |
| ---- | ------ |
| AAD exacto del AES-GCM | **UNKNOWN** (d1-re usa `None` / vacío — EXTERNAL HYPOTHESIS only) |
| Nonce inicial GCM “de verdad” del protocolo | **UNKNOWN** (no re-derivado aquí; ver M2.3 plaintext offsets como candidatos) |
| Transformación del nonce de sesión → primer frame | **UNKNOWN** / EXTERNAL HYPOTHESIS en [encrypted-channel.md](encrypted-channel.md) (base + XOR último byte en C→S) |
| Contador / incremento por frame | **UNKNOWN** como hecho de Destiny; EXTERNAL HYPOTHESIS = `increment_nonce` de d1-re |
| Separación client/server de nonces | EXTERNAL HYPOTHESIS (d1-re); no CONFIRMED por nosotros |
| Key usage exacta (session key del record) en GCM | EXTERNAL HYPOTHESIS; **no** verificado en M2.4a |
| `body_len` / tag / ciphertext wire del primer frame | **UNKNOWN** en JSONL (inferencia GCM no promovida) |
| Relación semántica completa `0x79`/`0x7A` (handshake cifrado) | **UNKNOWN** más allá de id/nombre/orden |

## M2.4a status

```text
M2.4a — First encrypted frame characterization
DONE
```

**No** implementa decrypt AES-GCM propio. **No** avanza a M2.4b automáticamente.
