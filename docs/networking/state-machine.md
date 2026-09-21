# Protocol State Machine (M3.4)

Máquina de estados **observacional** del protocolo BAP a partir de capturas
verificadas. Representa lo que las capturas demuestran, no una semántica de
cliente Destiny.

## 1. Objetivo

Derivar estados, transiciones y evidencia semántica separada desde M1–M3.3.

## 2. Fuentes

| Captura | Fixture |
| ------- | ------- |
| `20260529-003132` | `evidence/local/bap_session_verify.json` |
| `20260608-231100` | `evidence/local/bap_session_verify_20260608-231100.json` |

Reutiliza inventario (M3.1), estructura (M3.2) y correlación (M3.3).

## 3. Metodología

Labels: `OBSERVED` / `STRUCTURAL_HYPOTHESIS` / `EXTERNAL_REFERENCE` / `UNKNOWN`
(+ `STABLE_CROSS_CAPTURE` / `CAPTURE_SPECIFIC` en edges).

Estados neutrales: `START`, `STARTUP_SEQUENCE`, `POST_STARTUP`,
`REPEATING_CLUSTER_01`, `BRANCH_CAPTURE_A_01`, `BRANCH_CAPTURE_B_01`.

## 4–5. Estados y transiciones

Construidos por replay determinista de `MessageObservation` ordenadas.
Cada edge: from/to, message_id, direction, context, counts, captures.

## 6. Startup sequence

```text
0x1E→0x1F→0x19→0x1A→0x79→0x7A→0x12E→0x12F
```

Etiqueta estructural: `STABLE_STARTUP_SEQUENCE` (OBSERVED si ambas capturas).
No se llama `LOGIN` / `AUTHENTICATED` internamente.

## 7–8. Branches y repeating cluster

Divergencia M3.3 → branches A/B.
`0xFA`↔`0xFB` → `REPEATING_CLUSTER_01` (repeating=true; periodicity UNKNOWN/APPROXIMATE).
Nombre keepalive solo como `EXTERNAL_REFERENCE` (`messages.rs`).

## 9–11. Context, dirección, RR

Context transitions = hipótesis estructural; context ≠ state.
Dirección C2S/S2C conservada.
Candidatos RR de M3.3: `request_response_candidate=true`, `semantic_status=UNKNOWN`.

## 12–13. External + matrix

Sección `external_semantics` separada.
Matriz: Observed / Structural / External / Semantic confidence / Unknowns.

## 14. Limitaciones

Sin SignOn, TCP write, Bungie, UDP, gameplay, autenticación confirmada.
No inicia M2.11 ni etapas posteriores.

## CLI

```bash
cargo run -- state-machine-verify fixtures/multi_capture/manifest.json
```

Export: `fixtures/state_machine/cross_capture_safe.json`

## Related

- [message-correlation.md](message-correlation.md)
- [message-inventory.md](message-inventory.md)
- [message-matrix.md](message-matrix.md)
