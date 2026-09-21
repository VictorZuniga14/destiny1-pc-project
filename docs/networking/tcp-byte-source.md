# TCP ByteSource (M2.10)

Read-only TCP transport that feeds the existing offline BAP stack:

```text
TcpByteSource
      ↓
BapStreamDecoder
      ↓
BapSession
      ↓
DecodedBapFrame
```

## Objetivo

Entregar **bytes TCP** al pipeline ya validado. No SignOn, no auth, no handshake
de sesión, no AES, no servidor de juego, no UDP, no Bungie live.

## Arquitectura

```text
ByteSource
 ├── MockByteSource   (M2.8, offline)
 └── TcpByteSource    (M2.10, std::net blocking)
```

`BapStreamDecoder` / `BapSession` / `BapOfflinePipeline` no conocen el origen
de los bytes.

M2.10 usa **`std::net::TcpStream` bloqueante** (sin Tokio) para no convertir el
crate a async ni romper `MockByteSource` / `BapOfflinePipeline`.

## TcpEndpoint

```text
host
port
connect_timeout   (obligatorio, ≠ 0)
read_timeout      (opcional, ≠ 0 si se setea)
```

Sin default a hosts de Bungie / PSN. Helper de tests: `TcpEndpoint::loopback(port, …)`.

## Semántica de read

| Resultado | Significado |
| --------- | ----------- |
| `Ok(Some(bytes))` | DATA |
| `Ok(None)` | EOF limpio (peer cerró) |
| `Err(...)` | error de transporte |

EOF **no** es error. `TcpByteSource` no parsea BAP ni reensambla frames.

## Errores

```text
InvalidAddress
InvalidTimeout
ConnectionFailed
ReadFailed
Timeout
Closed
```

Se mapean a `ByteSourceError::Failed` cuando se usa el trait `ByteSource`.

## Solo lectura

No hay `write` / `send` / request-response en M2.10.

## Tests

Todos en `127.0.0.1`:

- lectura básica byte-for-byte;
- chunks fragmentados;
- múltiples frames BAP;
- frame partido;
- EOF → `None`;
- frame incompleto → `IncompleteAtEnd` vía `finish()`;
- connection refused;
- replay de wire de captura local (si `evidence/local/` existe) o sintético.

## Limitaciones

- Sin conexión a Internet / Bungie en CI.
- Sin escritura TCP.
- Sin half-close semántica avanzada (UNKNOWN).
- No inicia cliente de sesión / M3.4.

## Related

- [byte-source.md](byte-source.md) (M2.8)
- [stream-framing.md](stream-framing.md) (M2.7)
- [bap-session.md](bap-session.md) (M2.6)
