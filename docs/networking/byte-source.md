# ByteSource (M2.8)

Offline byte ingress for the BAP pipeline. **No TCP, sockets, or async runtime.**

## ByteSource

Responsabilidad: entregar chunks de bytes (o EOF / error).

```text
Ok(Some(bytes))  → datos
Ok(None)         → EOF limpio
Err(...)         → fallo de fuente (≠ EOF)
```

No hace framing, parsing ni crypto.

## MockByteSource

Cola determinista de chunks en memoria:

```text
MockByteSource::new(vec![chunk1, chunk2, ...])
```

Cada `read()` devuelve el siguiente chunk; al vaciarse → `None`.

También admite errores intencionales vía `from_results` para tests de propagación.

## Pipeline

```text
ByteSource
    ↓
BapStreamDecoder
    ↓
BapSession
    ↓
DecodedBapFrame
```

`BapOfflinePipeline` compone las tres capas sin mezclar responsabilidades:

| Capa | Hace | No hace |
| ---- | ---- | ------- |
| `ByteSource` | bytes | framing / crypto |
| `BapStreamDecoder` | boundaries de frame | crypto / dirección |
| `BapSession` | clear/encrypted + nonce + GCM | buffering / lectura |

Dirección:

- `run_unidirectional(source, direction)` — todos los frames misma dirección;
- `run_directed(source, &[Direction...])` — una dirección por frame recuperado (C↔S intercalados).

La dirección **nunca** se infiere del wire.

## Errores

| Caso | Resultado |
| ---- | --------- |
| EOF limpio | `Ok(None)` en la fuente; `finish()` del decoder OK si buffer vacío |
| Stream incompleto | `StreamFramingError::IncompleteAtEnd` tras EOF |
| Source error | `ByteSourceError` propagado (no silenciado como EOF) |
| Framing inválido | `StreamFramingError` (magic/kind/size) |
| Crypto / sesión | `BapSessionError` vía pipeline |

## CLI

```bash
cargo run -- bap-pipeline-verify ../evidence/local/bap_session_verify.json
```

Pipeline: `MockByteSource` (chunks artificiales) → decoder → session. Metadata only.

## Futuro (fuera de M2.8; ver M2.10)

```text
TCP socket
    ↓
TcpByteSource   ← M2.10 DONE (read-only, std::net)
    ↓
BapStreamDecoder
    ↓
BapSession
```

Documentación: [tcp-byte-source.md](tcp-byte-source.md).

## Evidence status

### CONFIRMED

- Mock + pipeline reconstruyen y descifran los 128 frames de `20260529-003132`.
- Counters C→S / S→C independientes con `run_directed`.
- Paridad con M2.6 / M2.7 verify.

### UNKNOWN

- Semántica avanzada de half-close / reset TCP en producción.
- Comportamiento contra endpoints públicos (fuera de alcance).

## Related

- [stream-framing.md](stream-framing.md) — M2.7
- [bap-session.md](bap-session.md) — M2.6
