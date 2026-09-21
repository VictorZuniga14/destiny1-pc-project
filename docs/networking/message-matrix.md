# Message matrix

Evidencia primaria: **PS3** vía `kallsyms/d1-re`.

Equivalencia PS4 / Xbox / PC: **UNKNOWN**.

Núcleo de transporte documentado: **TCP + BAP**. UDP gameplay: **UNKNOWN** (no asumir).

## Conceptos (no son msg_id BAP)

| ID | Nombre | Dirección | Transporte | Estado | Cifrado | Campos conocidos | Desconocidos | Confianza | Fuente |
| -- | ------ | --------- | ---------- | ------ | ------- | ---------------- | ------------ | --------- | ------ |
| — | SignOn HTTPS `/SignOn` | C↔S | HTTPS/TCP | pre-BAP | TLS | path, `platform`, `build`; tokens AES/MAC; endpoints IP:port (cuando parseables) | schema protobuf completo; auth tickets | CONFIRMED (flujo PS3); schema UNKNOWN | `d1-re` README; `ps3_decrypt_capture.py` `load_https_secrets` / `collect_signon_secrets` |
| — | BAP outer frame | bi | **TCP** | siempre en streams BAP | header clear | `0x01`, `kind`, `body_len` BE | otros `kind`; extensiones | CONFIRMED | `iter_bap_frames` |
| — | BAP body clear (`kind=2`) | bi | TCP | pre-sesión (y posiblemente otros) | clear | `msg_id` u16 BE, `context` u32 BE, payload | semántica de `context`; payloads | CONFIRMED estructura | `decrypt_bap_direction_docs` / `message_doc` |
| — | BAP body encrypted (`kind=1`) | bi | TCP | post session key | AES-GCM | tag 16 + ciphertext; plaintext como clear | AAD; rekey | CONFIRMED en decryptor | `decrypt_bap_direction_docs` |

## Mensajes BAP (msg_id)

| ID | Nombre | Dirección | Transporte | Estado | Cifrado | Campos conocidos | Desconocidos | Confianza | Fuente |
| -- | ------ | --------- | ---------- | ------ | ------- | ---------------- | ------------ | --------- | ------ |
| `0x1E` | destiny-service-handshake-request | C→S (PROBABLE) | TCP BAP | inicio | clear (`kind=2`) típico | id, context | payload | CONFIRMED id/nombre; payload UNKNOWN | `BAP_NAMES`, `looks_like_bap_pair` |
| `0x1F` | destiny-service-handshake-response | S→C (PROBABLE) | TCP BAP | inicio | clear típico | id, context | payload | CONFIRMED id/nombre; payload UNKNOWN | idem |
| `0x19` | session-login-request | C→S (PROBABLE) | TCP BAP | login | clear típico | id, context | payload completo | CONFIRMED id/nombre; payload UNKNOWN | `BAP_NAMES` |
| `0x1A` | session-login-response | S→C (PROBABLE) | TCP BAP | login | clear + registro AES-CBC/HMAC | registro → nonce + session key (offsets del decryptor) | resto del response / plaintext | CONFIRMED crypto path; resto UNKNOWN | `derive_bap_session`, `decrypt_bap_session_record` |
| `0x79` | encrypted-handshake-request | UNKNOWN | TCP BAP | post-key (PROBABLE) | UNKNOWN (PROBABLE GCM) | id | payload, dirección, orden | CONFIRMED nombre; resto UNKNOWN | `BAP_NAMES` |
| `0x7A` | encrypted-handshake-status | UNKNOWN | TCP BAP | post-key (PROBABLE) | UNKNOWN (PROBABLE GCM) | id | payload, dirección | CONFIRMED nombre; resto UNKNOWN | `BAP_NAMES` |
| `0xFA` | keepalive-request | UNKNOWN | TCP BAP | sesión | UNKNOWN | id | intervalo, payload, dirección | CONFIRMED nombre; **no inventar intervalo** | `BAP_NAMES` |
| `0xFB` | keepalive-status | UNKNOWN | TCP BAP | sesión | UNKNOWN | id | payload, dirección | CONFIRMED nombre | `BAP_NAMES` |
| `0x12D` | activity-state | UNKNOWN | TCP BAP | actividad (PROBABLE) | UNKNOWN | id | **schema payload** | CONFIRMED nombre; schema UNKNOWN | `BAP_NAMES` |
| `0x12E` | nat-report | UNKNOWN | TCP BAP | sesión | UNKNOWN | id | payload; **no es gameplay UDP afirmado** | CONFIRMED nombre | `BAP_NAMES` |
| `0x12F` | nat-report-status | UNKNOWN | TCP BAP | sesión | UNKNOWN | id | payload | CONFIRMED nombre | `BAP_NAMES` |
| `0x0A` | generated-completion-request | UNKNOWN | TCP BAP | UNKNOWN | UNKNOWN | id | todo lo demás | CONFIRMED nombre solamente | `BAP_NAMES` |
| `0x0B` | generated-completion-response | UNKNOWN | TCP BAP | UNKNOWN | UNKNOWN | id | todo lo demás | CONFIRMED nombre solamente | `BAP_NAMES` |
| `0x0C` | status-like-request | UNKNOWN | TCP BAP | UNKNOWN | UNKNOWN | id | todo lo demás | CONFIRMED nombre solamente | `BAP_NAMES` |
| `0x0D` | status-like-response | UNKNOWN | TCP BAP | UNKNOWN | UNKNOWN | id | todo lo demás | CONFIRMED nombre solamente | `BAP_NAMES` |

### IDs observados sin nombre (captura PS3 `20260529-003132`)

Existencia **CONFIRMED** en esa captura; semántica **UNKNOWN**. No añadidos a la tabla de nombres.

| ID | Confianza |
| -- | --------- |
| `0x7B` | CONFIRMED seen / UNKNOWN meaning |
| `0x20` / `0x21` | CONFIRMED seen / UNKNOWN meaning |
| `0x15` / `0x16` | CONFIRMED seen / UNKNOWN meaning |
| `0x17` / `0x18` | CONFIRMED seen / UNKNOWN meaning |
| `0x12` / `0x13` | CONFIRMED seen / UNKNOWN meaning |
| `0xAB` | CONFIRMED seen / UNKNOWN meaning |

Detalle: [capture-20260529-003132-notes.md](capture-20260529-003132-notes.md).

## Fuera de matriz (explícito)

| Tema | Estado |
| ---- | ------ |
| UDP gameplay | UNKNOWN |
| UDP physics | UNKNOWN |
| Peer networking | UNKNOWN |
| NAT traversal de bajo nivel | UNKNOWN |
| Equivalencia PS4/Xbox/PC | UNKNOWN |

## Lectura rápida del cierre Milestone 1

```text
SignOn HTTPS
     ↓
tokens + endpoints
     ↓
TCP
     ↓
BAP framing
     ↓
0x1E / 0x1F
     ↓
0x19 / 0x1A
     ↓
session key + nonce
     ↓
AES-GCM
     ↓
0x79 / 0x7A
0xFA / 0xFB
0x12D
0x12E / 0x12F
```
