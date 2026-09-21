# Keepalive

## Mensajes

Keepalive **no** se documenta aquí como un único “mensaje keepalive”.

Es un **par** de IDs nombrados en `d1-re`:

| ID | Nombre |
| -- | ------ |
| `0xFA` | `keepalive-request` |
| `0xFB` | `keepalive-status` |

```text
Fuente: kallsyms/d1-re/tools/ps3_decrypt_capture.py
función/script: BAP_NAMES
```

## CONFIRMED

- Existencia de los IDs y nombres anteriores en el decryptor público.
- Forman parte del conjunto de mensajes BAP reconocidos por nombre.

## UNKNOWN / no afirmado

| Tema | Estado |
| ---- | ------ |
| Dirección real en wire (quién envía `0xFA` vs `0xFB`) | UNKNOWN (el naming sugiere request/status, pero no hay evidencia citada aquí de capturas tabuladas) |
| Intervalo temporal | UNKNOWN — **no inventar** |
| Payload / campos | UNKNOWN |
| Si van siempre cifrados (`kind = 1`) | UNKNOWN / PROBABLE post-sesión, sin inventario |
| Comportamiento si faltan | UNKNOWN |
| Equivalencia multiplataforma | UNKNOWN |

## Qué no afirmar

- “Keepalive cada N segundos”.
- Que baste responder `0xFB` con un body vacío para mantener sesión.
- Semántica de producto más allá del nombre.

## REQUIRES TEST

- Timeline analyzer sobre JSONL local: orden, dirección y spacing entre `0xFA`/`0xFB`.
- Comparar payloads entre capturas (longitud y patrones), sin publicar secretos.
