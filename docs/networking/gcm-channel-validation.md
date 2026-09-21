# GCM Channel Validation

## Capture

`20260529-003132` (PS3)

Milestone **M2.4d** — validación GCM bidireccional + investigación de nonce progression.

Wire primario: `traffic.pcap`.  
Metadata / post-decrypt: `decrypted_bap.jsonl` (gitignored).  
Material sensible: `evidence/local/gcm_sequence_verify.json` (gitignored).

CLI:

```bash
cargo run -- gcm-sequence-verify ../evidence/local/gcm_sequence_verify.json
```

Primitive AEAD: `decrypt_aes_gcm` (**sin** modificar `aead.rs`).

```text
M2.4d — DONE
```

---

## 1. Confirmed (reproducido por nuestra implementación)

### Sesión previa (M2.1–M2.4c)

| Hecho | Estado |
| ----- | ------ |
| `0x1A` AES-CBC+HMAC + plaintext 28 B | CONFIRMED |
| Session key 16 B / session nonce 12 B (offsets 12 / 0) | CONFIRMED para uso GCM en esta captura |
| `0x79` C→S GCM con XOR-last-1 + AAD vacío + wire PCAP | CONFIRMED (M2.4c) |

### `0x7A` (esta captura)

| Campo | Valor | Confianza |
| ----- | ----- | --------- |
| Dirección | S→C | CONFIRMED |
| `frame_index` | 2 | CONFIRMED (JSONL) |
| `frame_order` | 245 | CONFIRMED |
| `frame_offset` | **240** (stream servidor) | CONFIRMED (PCAP + metadata) |
| magic / kind | 1 / 1 | CONFIRMED (PCAP) |
| `body_len` | **24** | CONFIRMED (medido PCAP) |
| tag | 16 | CONFIRMED |
| ciphertext | 8 | CONFIRMED |
| Nonce | session nonce **Identity** (primer S→C) | CONFIRMED (decrypt OK) |
| AAD | vacío | CONFIRMED compatible (decrypt OK) |
| plaintext length | 8 (payload_len post-decrypt = 2) | CONFIRMED |
| Coincide plaintext d1-re | sí | CONFIRMED |

**`0x7A = VERIFIED FOR CAPTURE 20260529-003132`**

### Frames GCM posteriores (secuencia de 8)

Orden cronológico tras `0x1A`:

| # | id | direction | body_len | ct_len | decrypt | pt_len | nonce_status |
| - | -- | --------- | -------- | ------ | ------- | ------ | ------------ |
| 1 | `0x79` | C→S | 22 | 6 | success | 6 | base C→S = XOR-last-1 |
| 2 | `0x7A` | S→C | 24 | 8 | success | 8 | base S→C = Identity |
| 3 | `0x12E` | C→S | 62 | 46 | success | 46 | `inc` ×1 desde base C→S |
| 4 | `0x12F` | S→C | 24 | 8 | success | 8 | `inc` ×1 desde base S→C |
| 5 | `0x0A` | C→S | 69 | 53 | success | 53 | `inc` ×2 desde base C→S |
| 6 | `0x0B` | S→C | 78 | 62 | success | 62 | `inc` ×2 desde base S→C |
| 7 | `0x0A` | C→S | 33 | 17 | success | 17 | `inc` ×3 desde base C→S |
| 8 | `0x0B` | S→C | 4199 | 4183 | success | 4183 | `inc` ×3 desde base S→C |

Para cada fila: tag=16 medido; AAD vacío; plaintext coincide con JSONL d1-re; nonce de estado coincide con campo `nonce` del JSONL.

**CONFIRMED (esta captura, 8 frames):** canal AES-128-GCM bidireccional con:

1. bases C→S / S→C distintas (XOR-last-1 vs Identity);
2. contadores **independientes por dirección**;
3. tras cada `kind=1`, `increment_nonce` (byte 0… wrap) en esa dirección;
4. AAD vacío compatible en todos estos frames.

---

## 2. External Evidence

```text
Fuente: kallsyms/d1-re/tools/ps3_decrypt_capture.py
decrypt_bap / decrypt_bap_direction_docs / increment_nonce
```

- C→S base = `nonce[-1] ^= 1`; S→C base = nonce de sesión.
- Incremento tras cada intento de decrypt `kind=1` por dirección.
- AAD = `None`.
- Body wire = `[tag:16][ciphertext...]`.

Usado como hipótesis operativa; **validado** en esta captura por decrypt propio (sección 1), no solo por cita.

---

## 3. Nonce progression

### Confirmado (esta captura)

```text
C→S:  base0 = session ⊕ last_byte(1)
      frame_k = increment^k(base0)   // k = ordinal encrypted C→S (0-based)

S→C:  base0 = session
      frame_k = increment^k(base0)   // k = ordinal encrypted S→C (0-based)
```

`increment` = sumar 1 al byte[0], carry hacia byte[1]… (algoritmo d1-re; reproducido).

Los contadores **no** se comparten entre direcciones: tras `0x79` (C→S), el primer S→C (`0x7A`) sigue usando Identity(session), no un incremento del nonce C→S.

### Probable

- Que el mismo esquema aplique al resto de frames encrypted de **esta** captura más allá de los 8 analizados (no se agotó la captura aquí; patrón estable en la muestra).

### Desconocido (UNKNOWN)

- Otras capturas / plataformas.
- Rekey, resync, límites de contador.
- Si algún mensaje especial resetea el nonce.
- Semántica de producto de los payloads.

---

## 4. AAD

| Afirmación | Nivel |
| ---------- | ----- |
| AAD vacío funciona para los 8 frames analizados | **CONFIRMED** (esta captura) |
| AAD vacío es la regla universal del protocolo | **UNKNOWN** (EXTERNAL: d1-re usa None) |
| Otras construcciones de AAD | **UNKNOWN** — no investigadas (sin evidencia explícita; sin brute force) |

---

## 5. Frames analizados

Ver tabla en §1. Resumen:

- Prioridad cubierta: `0x79`, `0x7A`, luego `0x12E`, `0x12F`, `0x0A`, `0x0B` (×2).
- Correspondencia PCAP ↔ JSONL: offsets/body_len medidos; plaintext/nonce alineados.

---

## SessionCryptoContext

Milestone **M2.5** — formalización del estado ya CONFIRMED en M2.4d.

Módulo: `network/src/crypto/session_context.rs`.  
`gcm_sequence.rs` genera nonces **solo** vía este contexto (única fuente de verdad).

### Estado

```text
SessionCryptoContext
├── session_key              [16]
├── session_nonce            [12]   // base inmutable
├── client_to_server_nonce   [12]   // estado actual C→S
├── server_to_client_nonce   [12]   // estado actual S→C
├── client_to_server_counter u64
└── server_to_client_counter u64
```

Al construir (`new`): counters = 0; bases aplicadas a los nonces de dirección; `session_nonce` no se altera nunca.

### Nonce base

| Dirección | Base |
| --------- | ---- |
| C→S | `copy(session_nonce); last_byte ^= 1` |
| S→C | `session_nonce` (Identity) |

### Progression

```text
next_nonce(dir):
  1. emit current direction nonce
  2. increment_nonce on that direction only
  3. counter[dir] += 1
```

`increment_nonce`: suma 1 en byte[0], carry a byte[1]… (mismo algoritmo que M2.4d).

Equivalente: nonce en ordinal `k` = `increment` aplicado `k` veces desde la base de esa dirección (`nonce_after_increments`).

### Alcance

```text
CONFIRMED FOR CAPTURE 20260529-003132
```

(8 frames vía `gcm-sequence-verify` + tests unitarios del contexto.)

UNKNOWN: otras plataformas/sesiones, rekey, UDP/gameplay, variantes no observadas.

```text
M2.5 — DONE
```

---

## 6. Limitaciones

- PS4 / Xbox / PC: **UNKNOWN**
- Protocolo GCM “completo” de Destiny: **UNKNOWN** (solo canal TCP/BAP post-sesión en esta captura)
- UDP / gameplay: **UNKNOWN** / fuera de alcance
- Progression **general** más allá de la muestra: **PROBABLE** en esta captura; **UNKNOWN** fuera
- No se implementó servidor, sockets, ni cliente

---

## Tooling

| Pieza | Rol |
| ----- | --- |
| `crypto/gcm_nonce.rs` | `XorLastByte(1)`, `Identity`, `increment_nonce` |
| `crypto/session_context.rs` | `SessionCryptoContext` (M2.5) |
| `gcm_sequence.rs` + CLI `gcm-sequence-verify` | secuencia offline vía contexto |
| `fixtures/gcm_sequence_verify.template.json` | formato sin secretos |

Tests: contexto (counters, bases, independencia); secuencia sintética; captura real (8 frames).
