# Evidence JSONL (`decrypted_bap.jsonl`)

Documentación del schema on-disk producido por la herramienta pública de
`kallsyms/d1-re`, basado en el código del decryptor (no en muestras de
capturas reales commiteadas aquí).

## Origen

| Ítem | Valor |
| ---- | ----- |
| Proyecto | `kallsyms/d1-re` |
| Plataforma de evidencia | **PS3** |
| Artefacto | `captures/<timestamp>/decrypted/decrypted_bap.jsonl` |
| Generador | `tools/ps3_decrypt_capture.py` |

```text
Fuente: kallsyms/d1-re/README.md
Fuente: kallsyms/d1-re/tools/ps3_decrypt_capture.py
función/script: decrypt_bap, decrypt_bap_direction_docs, message_doc, write_jsonl
```

Relación con BAP: el archivo es la salida **ya procesada** de streams TCP BAP
(reensamblados desde PCAP) más material SignOn HTTPS. No es el wire crudo.

**UNKNOWN:** equivalencia del mismo JSONL en PS4/Xbox/PC.

## Tipos de registro

Cada línea es un objeto JSON. El discriminador es el campo string `kind`.

### `kind = "bap_connection"` — CONFIRMED

Escrito al detectar/derivar una sesión BAP (éxito o error de session record).

| Campo | Tipo observado | Confianza | Notas |
| ----- | -------------- | --------- | ----- |
| `kind` | string `"bap_connection"` | CONFIRMED | |
| `client` | string `ip:port` | CONFIRMED | |
| `server` | string `ip:port` | CONFIRMED | |
| `token_source` | string | CONFIRMED | presente en éxito |
| `key_sha256_8` | string hex (8 bytes truncados del sha256) | CONFIRMED | **hash**, no la key |
| `nonce` | string hex | CONFIRMED | nonce de sesión en éxito |
| `error` | string | CONFIRMED | presente si no se pudo derivar sesión |

Este tipo **no** es un frame BAP. Un adaptador a `EvidenceRecord` debe ignorarlo
para la timeline de mensajes.

### `kind = "bap_frame"` — CONFIRMED

Un frame BAP (clear u originally-encrypted) en una dirección.

| Campo | Tipo observado | Confianza | Notas |
| ----- | -------------- | --------- | ----- |
| `kind` | string `"bap_frame"` | CONFIRMED | |
| `direction` | `"client_to_server"` \| `"server_to_client"` | CONFIRMED | |
| `frame_index` | integer | CONFIRMED | índice por dirección antes del sort global |
| `frame_kind` | integer (`1` o `2`) | CONFIRMED | byte `kind` del framing BAP |
| `frame_ts` | float (segundos) | CONFIRMED cuando hay spans PCAP | ausente si no hay timing |
| `frame_order` | integer | CONFIRMED cuando hay spans | |
| `frame_offset` | integer | CONFIRMED cuando hay spans | offset en stream TCP |

## Campos de mensaje (tras parse clear o decrypt)

```text
Fuente: kallsyms/d1-re/tools/ps3_decrypt_capture.py
función/script: message_doc
```

Presentes cuando el body clear (`frame_kind=2`) tiene ≥ 6 bytes, o cuando
`frame_kind=1` descifra plaintext ≥ 6 bytes:

| Campo | Tipo | Confianza | Notas |
| ----- | ---- | --------- | ----- |
| `id` | integer | CONFIRMED | `msg_id` u16 |
| `id_hex` | string | CONFIRMED | presentación |
| `name` | string | CONFIRMED | tabla local del decryptor; puede ser `"unknown"` |
| `context` | integer | CONFIRMED | u32 |
| `payload_len` | integer | CONFIRMED | len(payload) |
| `payload_hex` | string hex | CONFIRMED | bytes **después** de msg_id+context |

## Representación encrypted (`frame_kind = 1`)

| Campo | Confianza | Notas |
| ----- | --------- | ----- |
| `nonce` | CONFIRMED | hex del nonce usado en ese frame (decryptor) |
| `plaintext_hex` | CONFIRMED en éxito | plaintext completo post-AES-GCM |
| `error` | CONFIRMED en fallo | p. ej. decrypt fallido / body corto |
| tag/ciphertext wire en el JSONL | **UNKNOWN / no emitidos** | el decryptor **no** escribe `tag` ni `ciphertext` del body wire tras el intento; solo metadatos + resultado |

**CONFIRMED:** para timeline de *mensajes lógicos*, la evidencia útil post-decrypt
son `id` / `context` / `payload_hex` (y/o `plaintext_hex`), no un body encrypted opaco.

## Orden de líneas en el archivo

```text
Fuente: kallsyms/d1-re/tools/ps3_decrypt_capture.py
función/script: bap_frame_sort_key, decrypt_bap
```

Los `bap_frame` se ordenan por `(frame_ts, frame_order, direction, frame_offset, frame_index)`
antes de escribirse. Puede haber un `bap_connection` previo por conexión.

## Campos mínimos para nuestro `EvidenceRecord`

| Nuestro campo | Mapeo desde JSONL externo | Confianza |
| ------------- | ------------------------- | --------- |
| `timestamp_ms` | `floor(frame_ts * 1000)` si existe; si no, fallback documentado | CONFIRMED path con `frame_ts`; fallback REQUIRES TEST |
| `direction` | `direction` | CONFIRMED |
| clear body | `id`, `context`, `payload_hex` → frame lógico clear | CONFIRMED cuando `id` presente |
| encrypted opaco wire | no disponible en JSONL post-decrypt | N/A en este artefacto |

## Ambiguities / UNKNOWN

- Variación entre capturas concretas del repo (no se re-inspeccionan aquí bodies reales).
- Frames `bap_frame` con `error` y sin `id`: no aportan mensaje clasificable.
- Semántica de `name` del decryptor vs nuestra tabla (`messages.rs`): pueden diferir;
  nuestro adaptador **reclasifica** con la matriz del proyecto.
- AAD / nonce rules del protocolo: ver [encrypted-channel.md](encrypted-channel.md);
  este documento solo describe el JSONL de salida.

## Legal

No copiar código de `d1-re` (licencia no declarada).  
No commitear `decrypted_bap.jsonl` reales, PCAPs, tokens ni claves.
