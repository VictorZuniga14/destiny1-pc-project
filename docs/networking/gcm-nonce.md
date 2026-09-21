# GCM Nonce Reconstruction

## Scope

Reconstrucción **offline** del nonce AES-GCM candidato para el **primer** frame cifrado:

`0x79 — encrypted-handshake-request` (C→S) en la captura `20260529-003132`.

| Hace | No hace |
| ---- | ------- |
| Documentar transformación session → first-frame | Decrypt de `0x79` |
| Herramienta determinista de transform + compare | AAD / progression completa |
| Clasificar CONFIRMED vs EXTERNAL vs PROBABLE | Brute force / múltiples variantes |

```text
M2.4b — GCM nonce reconstruction (first frame 0x79)
DONE
```

**No** afirma todavía que ese nonce descifra el wire de `0x79` con nuestra primitive GCM (eso es M2.4c+).

## Known inputs

| Input | Fuente | Notas |
| ----- | ------ | ----- |
| Session nonce candidato (12 B) | Plaintext del record `0x1A` tras M2.3: offsets `[0..12)` | Candidato estructural; en esta captura **igual** al `nonce` de `bap_connection` |
| Session key candidata (16 B) | Offsets `[12..28)` del mismo plaintext | **No** usada en M2.4b |
| Dirección | C→S (`client_to_server`) | Primer encrypted = `0x79` |
| `frame_index` BAP | 2 en el cliente | **No** entra en la construcción del *primer* nonce GCM (ver abajo) |
| `context` | 2 | Metadata de mensaje; **no** es el nonce |
| Nonce registrado en JSONL para `0x79` | Campo `nonce` post-decrypt d1-re | Solo para comparación estructural |

Material real: gitignored (`evidence/local/…`). Sin valores en este documento.

## External evidence

```text
Fuente: kallsyms/d1-re/tools/ps3_decrypt_capture.py
función/script: derive_bap_session, decrypt_bap, decrypt_bap_direction_docs, increment_nonce
```

### Qué implementa d1-re (EXTERNAL EVIDENCE)

1. Del plaintext del record `0x1A` (si `len >= 0x1C`):
   - `nonce = plaintext[0:12]`
   - `session_key = plaintext[12:28]`
2. Al abrir el canal:
   - **S→C:** pasa `nonce` tal cual a `decrypt_bap_direction_docs`.
   - **C→S:** pasa `nonce` con **último byte XOR `1`**:  
     `bytes([*nonce[:-1], nonce[-1] ^ 1])`.
3. Dentro de cada dirección, para cada frame `frame_kind=1`:
   - usa el nonce **actual** de esa dirección;
   - tras el intento de decrypt, llama `increment_nonce` (incremento byte a byte desde el índice 0, wrap 0xFF→0x00 y carry).
4. AAD: `None` (vacío) en la llamada AES-GCM.

Esto es comportamiento del **tool**, no una prueba automática de Destiny en todas las plataformas.

## Candidate construction

### Primer frame C→S (`0x79`) — hipótesis operativa

```text
session_nonce_12  (desde 0x1A plaintext[0..12])
        │
        ▼
  last_byte ^= 0x01
        │
        ▼
frame_nonce_12   ← candidato para el PRIMER encrypted C→S
```

**No** se aplica `increment_nonce` antes del primer `kind=1` de esa dirección.

### Primer frame S→C (`0x7A`, contraste)

```text
session_nonce_12
        │
        ▼
Identity (sin XOR)
        │
        ▼
frame_nonce_12   ← candidato para el PRIMER encrypted S→C
```

### Nota sobre `frame_index`

En esta captura el cliente tiene `frame_index=2` en `0x79` porque hubo clears previos (`0x1E`, `0x19`). Ese índice **no** es un contador GCM: el primer encrypted C→S usa la base transformada, no `session + 2`.

## Evidence from this capture (`20260529-003132`)

Comparaciones **estructurales** (igualdad de buffers; sin publicar bytes):

| Comprobación | Resultado | Clasificación |
| ------------ | --------- | ------------- |
| M2.3 unpadded `[0..12)` == `bap_connection.nonce` | **igual** | **CONFIRMED** (esta captura) |
| Nonce JSONL de `0x79` == `session_nonce` con último byte XOR `1` | **igual** | **CONFIRMED** (esta captura) |
| Nonce JSONL de `0x7A` == `session_nonce` (Identity) | **igual** | **CONFIRMED** (esta captura) |
| 2º encrypted C→S (`0x12E`) == `increment(nonce_0x79)` | **igual** | **CONFIRMED** como consistencia con d1-re en esta captura (progression; fuera del alcance de “first frame only”, pero documentado) |
| 2º encrypted S→C (`0x12F`) == `increment(nonce_0x7A)` | **igual** | idem |
| Que nuestro AES-GCM descifre el wire de `0x79` con ese nonce | **no intentado** | **PROBABLE** / pendiente M2.4c |
| AAD | no investigado | **UNKNOWN** (EXTERNAL: vacío en d1-re) |

## Offline tool

Primitive: `network/src/crypto/gcm_nonce.rs` (no toca `aead.rs`).

CLI:

```bash
cargo run -- gcm-nonce-reconstruct ../evidence/local/gcm_nonce_reconstruct.json
```

Plantilla (sin secretos): `network/fixtures/gcm_nonce_reconstruct.template.json`.

Salida segura (ejemplo de forma):

```text
direction: client_to_server
transform: XorLastByte(1)
session_nonce_length: 12
derived_nonce_length: 12
matches_expected: true
```

Nunca imprime nonces.

## Status

### CONFIRMED (captura `20260529-003132`)

- Longitud de nonce de sesión / frame: 12 bytes.
- Candidato `[0..12)` del plaintext M2.3 coincide con el nonce de sesión del JSONL.
- Para el primer C→S encrypted (`0x79`):  
  `frame_nonce = session_nonce` con **último byte XOR 1**.
- Para el primer S→C encrypted (`0x7A`):  
  `frame_nonce = session_nonce` (Identity).
- La reconstrucción candidata es ejecutable de forma determinista offline (`gcm-nonce-reconstruct`).

### EXTERNAL EVIDENCE

- Reglas anteriores tal como las implementa `ps3_decrypt_capture.py`.
- `increment_nonce` tras cada `kind=1` por dirección.
- AAD = `None` en el decryptor.

### PROBABLE

- Que la misma transformación sea la que Destiny usa en wire (compatible con d1-re + consistencia local; **no** demostrado con decrypt propio del body `0x79`).
- Que offsets `0` / `12` del plaintext `0x1A` sean semánticamente “nonce de sesión” / “session key” (reforzado por igualdad con `bap_connection.nonce`, aún sin GCM propio).

### UNKNOWN

- AAD exacto del protocolo.
- Rekey / resync / límites.
- Equivalencia PS4 / Xbox / PC.
- Uso del `frame_index` BAP como parte del nonce (no observado para el primer frame).
- Decrypt propio de `0x79` (M2.4c).

## M2.4b

```text
DONE
```

Siguiente (no iniciado): **M2.4c** — intentar decrypt AES-GCM del primer frame `0x79` con key/nonce candidatos, AAD explícito, sin progression completa.
