# Stream Framing Incremental (M2.7)

Offline byte-stream → complete BAP frames. **No TCP, sockets, or transport.**

## Problema

Un stream (p. ej. TCP en el futuro) no garantiza que un frame BAP llegue completo en una sola lectura. Puede llegar:

- un header parcial;
- header + body parcial;
- varios frames en un chunk;
- un frame completo + el inicio del siguiente.

## Solución

```text
chunk 1
chunk 2
chunk 3
   ↓
BapStreamDecoder
   ↓
0..N RawBapFrame (completos)
   ↓
BapSession
   ↓
DecodedBapFrame
```

Incomplete data **no** es error: el decoder bufferiza y `push` puede devolver cero frames.
Datos inválidos (magic, kind, body demasiado grande) **sí** son error.

## Responsabilidades

| Capa | Rol |
| ---- | --- |
| `BapStreamDecoder` | buffering, header, `body_len`, límites de frame |
| `BapSession` | clear/encrypted, dirección, nonce, AES-GCM |
| `SessionCryptoContext` | única fuente de nonces |

`BapStreamDecoder` **no** conoce AES, keys, nonces ni dirección.

## Framing

```text
[0x01][kind:u8][body_len:u32 BE][body...]
```

- Header = 6 bytes; no se interpreta un frame sin header completo.
- Kinds aceptados por el stream decoder: `1` (encrypted) y `2` (clear). Otro kind → `InvalidKind`.
- `MAX_BODY_LEN` = 4 MiB (techo de seguridad offline; no es un claim de Destiny).

## API

```text
BapStreamDecoder::new()
push(bytes) -> Result<Vec<RawBapFrame>, StreamFramingError>
finish()    -> Result<(), StreamFramingError>   // buffer debe quedar vacío
```

`RawBapFrame` expone `raw_bytes` listos para `BapSession::decode_frame(direction, &raw.raw_bytes)`.

## Futuro (NO implementado en M2.7)

```text
TCP transport
    ↓
BapStreamDecoder
    ↓
BapSession
```

El transporte real queda fuera de alcance.

## CLI

```bash
cargo run -- bap-stream-verify ../evidence/local/bap_session_verify.json
```

Reutiliza el JSON de M2.6: concatena `frame_hex`, lo parte en chunks artificiales, recupera frames y los pasa por `BapSession`.

## Evidence status

### CONFIRMED

- Framing incremental reconstruye los 128 frames wire de `20260529-003132` bajo chunking artificial.
- Tras el buffer, `BapSession` mantiene 4 clear / 124 encrypted / 124 decrypt / nonce válido (paridad con M2.6).

### UNKNOWN

- Comportamiento ante reordenamiento o pérdida de bytes en un transporte real (no aplica offline).
- Kinds distintos de 1/2 en captura (no observados aquí).
- Límite de tamaño de body en el cliente real.

## Related

- [bap-session.md](bap-session.md) — M2.6
- [framing-bap.md](framing-bap.md) — layout BAP
