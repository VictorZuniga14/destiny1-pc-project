# First AES-GCM Frame — 0x79

## Capture

`20260529-003132` (PS3)

| Ítem | Valor |
| ---- | ----- |
| Frame | `0x79` `encrypted-handshake-request` |
| Dirección | C→S |
| Milestone | **M2.4c** |

## Inputs

Solo tipos/longitudes (valores en `evidence/local/gcm_first_frame_verify.json`, **gitignored**):

| Input | Longitud | Origen |
| ----- | -------- | ------ |
| Session key | 16 | Plaintext M2.3 offsets `[12..28)` |
| Frame nonce | 12 | M2.4b: session nonce con último byte XOR `1` |
| Tag | 16 | Wire BAP body `[0..16)` |
| Ciphertext | 6 | Wire BAP body `[16..)` |
| AAD | 0 | Caso A — vacío |
| Expected plaintext length | 6 | Evidencia post-decrypt d1-re / M2.4a |

CLI:

```bash
cargo run -- gcm-first-frame-verify ../evidence/local/gcm_first_frame_verify.json
```

Usa `decrypt_aes_gcm` **sin modificar** `aead.rs`.

## Wire evidence

| Pregunta | Respuesta |
| -------- | --------- |
| ¿`decrypted_bap.jsonl` trae tag/ciphertext? | **No** |
| ¿Dónde está el wire? | `external/d1-re/captures/20260529-003132/traffic.pcap` |
| ¿Cómo se localiza el frame? | Stream TCP **cliente** de la conexión BAP; `frame_offset` = **405** (metadata JSONL) |
| Magic / kind | `0x01` / `kind=1` |
| `body_len` medido en PCAP | **22** |

### Longitudes wire

| Campo | Valor | Clasificación |
| ----- | ----- | ------------- |
| `body_len` | 22 | **CONFIRMED** (medido en PCAP) |
| tag | 16 | **CONFIRMED** (primeros 16 bytes del body) |
| ciphertext | 6 | **CONFIRMED** (`body_len - 16`) |

Layout `[tag:16][ciphertext...]` también es **EXTERNAL EVIDENCE** en d1-re; aquí las longitudes se **midieron** en el PCAP local.

**No** se inventó ciphertext a partir del plaintext.

## Nonce

Ver [gcm-nonce.md](gcm-nonce.md) (M2.4b).

Para este frame: `XorLastByte(1)` sobre el nonce de sesión M2.3.  
Comparación estructural con el campo `nonce` del JSONL: coincide (M2.4b).

## AAD

| Caso | Valor | Evidencia |
| ---- | ----- | --------- |
| **A (usado)** | vacío (`aad_len=0`, `None` en d1-re) | EXTERNAL EVIDENCE: `AESGCM.decrypt(..., aad=None)` en `decrypt_bap_direction_docs` |
| B | otro AAD específico | **no** hay evidencia de construcción alternativa → no probado |

**UNKNOWN** a nivel de protocolo general: si Destiny siempre usa AAD vacío en todas las plataformas/versiones.

## Decrypt result

Corrida con nuestra primitive (`gcm-first-frame-verify` / precheck equivalente):

```text
key_length: 16
nonce_length: 12
ciphertext_length: 6
tag_length: 16
aad_length: 0
aes_gcm_decrypt: success
plaintext_length: 6
plaintext_expected_length: 6
plaintext_length_matches_expected: true
```

Además (offline, sin publicar bytes): el plaintext coincide byte-a-byte con `plaintext_hex` del JSONL d1-re para este `0x79`.

```text
VERIFIED FOR CAPTURE 20260529-003132
```

## Interpretation

### CONFIRMED (esta captura)

- Wire tag/ciphertext del `0x79` recuperables desde el PCAP en `frame_offset=405`.
- `body_len=22` = 16 + 6.
- AES-GCM (nuestra `decrypt_aes_gcm`) con:
  - session key M2.3,
  - nonce M2.4b (XOR último byte),
  - tag/ciphertext wire reales,
  - AAD vacío  
  produce plaintext de **6** bytes que coincide con la evidencia post-decrypt de d1-re.

### EXTERNAL EVIDENCE

- AAD vacío como comportamiento del decryptor público.
- Naming / flujo general del canal GCM en d1-re.

### UNKNOWN / no promovido

- AAD del protocolo en general.
- Nonce progression / frames posteriores (`0x7A`, `0x12E`, …).
- Otras capturas / plataformas.
- Protocolo GCM “completo” de Destiny.

## M2.4c status

```text
M2.4c — First real AES-GCM decrypt of 0x79
DONE
```

**No** inicia M2.4d automáticamente.
