# Handshake — destiny-service-handshake

## Mensajes

| ID | Nombre |
| -- | ------ |
| `0x1E` | `destiny-service-handshake-request` |
| `0x1F` | `destiny-service-handshake-response` |

```text
Fuente: kallsyms/d1-re/tools/ps3_decrypt_capture.py
función/script: BAP_NAMES, looks_like_bap_pair, first_bap_clear_ids
```

## CONFIRMED

- Los IDs y nombres anteriores están definidos en el decryptor público.
- Se esperan como frames cleartext (`kind = 2`) al inicio de una conexión BAP, cuando el handshake de servicio está presente.
- Dirección por convención de nombres:
  - `0x1E` request → cliente → servidor (**PROBABLE** por naming; el decryptor orienta streams client/server)
  - `0x1F` response → servidor → cliente (**PROBABLE** por naming)

## Patrones de inicio de conexión — CONFIRMED (detección)

El decryptor considera un par de streams “parecido a BAP” si:

**Patrón A — con service handshake:**

```text
client clear IDs:  0x1E, 0x19
server clear IDs:  0x1F, 0x1A
```

**Patrón B — sin service handshake previo en clear:**

```text
client clear ID:   0x19
server clear ID:   0x1A
```

```text
Fuente: kallsyms/d1-re/tools/ps3_decrypt_capture.py
función/script: looks_like_bap_pair
```

## UNKNOWN

- Layout completo del payload de `0x1E` y `0x1F`.
- Campos, versiones de protocolo, capabilities, o errores.
- Si el handshake es obligatorio en todas las sesiones / plataformas.
- Equivalencia PS4 / Xbox / PC.

## Qué no afirmar

- Contenido concreto de bytes del payload.
- Que el handshake “autentica al usuario” u otras semánticas de producto sin evidencia de campos.

## REQUIRES TEST

- Extraer payloads de `0x1E`/`0x1F` desde JSONL local y comparar longitudes/patrones entre capturas.
- Medir frecuencia del patrón A vs B.
