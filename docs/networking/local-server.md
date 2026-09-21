# Local BAP Compatibility Server (M4.2)

## Status

```text
M4.2 DONE
```

## Objetivo

Demostrar interoperabilidad **local** del stack BAP ya verificado (M1–M4.1):

```text
Replay Client
     │ TCP 127.0.0.1
     ▼
Local BAP Server
     │
     ▼
BapSession + SessionCryptoContext
```

Todo es determinista, reproducible y basado en fixtures sintéticas.

## Arquitectura

| Componente | Rol |
| ---------- | --- |
| `LocalBapServer` | Bind/accept TCP, `BapStreamDecoder`, sesión, dispatcher |
| `BapReplayClient` | Cliente de harness (no Destiny/Bungie) |
| `LocalMessageDispatcher` | Acciones `SendFrame` / `ChangeState` / errores |
| `SimState` | Máquina de estados del harness (`SIM_*`) |
| `SessionCryptoContext` | Nonces C2S/S2C independientes (reutilizado) |

No se duplica framing, AES-GCM, nonce ni `BapSession`.

## SIMULATED_HANDSHAKE

**No es el handshake real de Bungie.** Etiqueta explícita: `SIMULATED_HANDSHAKE`.

Orden sintético:

```text
C2S 0x1E (clear) → S2C 0x1F (clear)
C2S 0x19 (clear) → S2C 0x1A (clear)
C2S 0x79 (encrypted) → S2C 0x7A (encrypted)
→ SIM_READY → mensajes encrypted sintéticos A/B
```

Payloads y claves son fixtures locales. La SM observacional M3.4 (`START` / `STARTUP_SEQUENCE` / …) **no** se modifica.

Estados del harness:

```text
SIM_START → SIM_1E_SENT → SIM_1F_SENT → SIM_19_SENT → SIM_1A_SENT
         → SIM_79_SENT → SIM_7A_SENT → SIM_READY
```

## Replay client

```bash
cargo run -- local-replay fixtures/local_server/handshake_replay.json
```

Resultado esperado:

```text
LOCAL_REPLAY: VERIFIED
```

## Server CLI

```bash
cargo run -- local-server
```

```text
LOCAL_BAP_SERVER
host: 127.0.0.1
port: <ephemeral>
status: LISTENING
key_present=true
nonce_present=true
```

Solo localhost. Sin tráfico externo.

## TCP

- `std::net` blocking
- `port=0` → puerto efímero
- Un thread de accept + un thread por conexión
- Framing incremental vía `BapStreamDecoder` (chunking / multi-frame)

## Crypto fixture

`network/fixtures/local_server/crypto_fixture.json`:

- session key / nonce **sintéticos** (16 / 12 bytes)
- Nunca claves de captura, SignOn ni tokens
- Logs: solo `key_present` / `nonce_present`

## E2E

`network/tests/local_server_e2e.rs` → `test_simulated_handshake_end_to_end`:

TCP + clear + activación crypto + AES-GCM bidireccional + nonces independientes + shutdown limpio.

## Negative tests

| Caso | Resultado |
| ---- | --------- |
| Wrong key | `AUTH/CRYPTO` / `GCM DECRYPT FAILURE` + close |
| Wrong nonce | `GCM DECRYPT FAILURE` |
| Invalid magic / kind | `PROTOCOL_ERROR` |
| `0x7A` antes de `0x79` | `UNEXPECTED_MESSAGE` |
| Truncated frame | decoder espera; sin panic |
| EOF | trace `EOF`; sin threads colgados |

## Limitaciones (explícitas)

```text
M4.2 does NOT prove compatibility with the Destiny client.
M4.2 does NOT prove compatibility with Bungie servers.
M4.2 does NOT prove the real server-side semantics.
M4.2 does NOT implement SignOn.
M4.2 does NOT implement UDP.
M4.2 does NOT implement gameplay.
```

Lo que sí demuestra:

```text
Our local implementation can perform
a deterministic bidirectional BAP-like
session using the verified framing,
crypto and nonce machinery.
```

## Security / scope

| Check | Value |
| ----- | ----- |
| Bungie connection | NONE |
| External network | NONE |
| Destiny client | NONE |
| Real credentials / keys / tokens | NONE |
| UDP / gameplay | NONE |
| Server | LOCAL ONLY |
| Protocol | SIMULATED / evidence-based stack |
