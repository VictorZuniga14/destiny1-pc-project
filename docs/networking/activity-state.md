# Activity state

## Mensaje

| ID | Nombre |
| -- | ------ |
| `0x12D` | `activity-state` |

```text
Fuente: kallsyms/d1-re/tools/ps3_decrypt_capture.py
función/script: BAP_NAMES
```

## CONFIRMED

- El ID `0x12D` está asociado al nombre `activity-state` en el decryptor público.

## UNKNOWN

- Schema completo del payload.
- Campos (activity hash, phase, players, host, etc.).
- Dirección (quién lo emite).
- Si es periódico, event-driven, o ambos.
- Relación con activity servers / world servers / physics hosts.
- Equivalencia multiplataforma.

## Qué no afirmar

- Inventar estructuras de “activity state” estilo API moderna de Destiny.
- Que este mensaje baste para entrar a una actividad o a Orbit.

## REQUIRES TEST

- Agrupar payloads `0x12D` por longitud y prefijos comunes en JSONL local.
- Correlacionar timestamps con `LOG` de operador en capturas (`inventory`, `character menu`, etc.) sin asumir causalidad.
