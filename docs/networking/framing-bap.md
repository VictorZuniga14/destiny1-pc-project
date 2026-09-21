# Framing BAP

## Resumen

BAP (nombre usado en la investigación pública) es el framing de mensajes de aplicación observado sobre **TCP** en capturas PS3 de `d1-re`.

**CONFIRMED:** el núcleo documentado es TCP + este framing.

**UNKNOWN:** otros usos de UDP u otros protocols de gameplay fuera de este framing.

```text
Fuente: kallsyms/d1-re/tools/ps3_decrypt_capture.py
función/script: iter_bap_frames, decrypt_bap_direction_docs, message_doc
```

## Outer frame — CONFIRMED

```text
[0x01]          magic / version byte
[kind:u8]       tipo de frame
[body_len:u32]  longitud del body, big-endian
[body...]       body_len bytes
```

El parser de `d1-re` exige que el primer byte sea `1`. Si no, deja de iterar frames en ese stream.

No se documentan aquí kinds distintos de los usados por el decryptor.

## kind = 2 (cleartext) — CONFIRMED

Body:

```text
[msg_id:u16 BE]
[context:u32 BE]
[payload...]
```

- `msg_id` identifica el tipo de mensaje (ver [message-matrix.md](message-matrix.md)).
- `context` es un campo de 4 bytes; **semántica = UNKNOWN**.
- `payload` depende del mensaje; layouts = UNKNOWN salvo lo dicho en [session.md](session.md) para el registro dentro de `0x1A`.

## kind = 1 (encrypted) — CONFIRMED (estructura) / CONFIRMED (AES-GCM en el decryptor)

Body:

```text
[tag:16]
[ciphertext...]
```

El decryptor:

1. Interpreta los primeros 16 bytes como tag AEAD.
2. Descifra `ciphertext || tag` con **AES-GCM**.
3. Espera plaintext con la misma forma que kind=2 (`msg_id`, `context`, `payload`) si hay al menos 6 bytes.

Detalle de nonces y direcciones: [encrypted-channel.md](encrypted-channel.md).

```text
Fuente: kallsyms/d1-re/tools/ps3_decrypt_capture.py
función/script: decrypt_bap_direction_docs
```

## Transporte

| Afirmación | Nivel |
| ---------- | ----- |
| Frames BAP reconstruidos desde streams TCP en PCAP | CONFIRMED |
| BAP usa UDP como transporte del framing documentado aquí | **No afirmado** — contradice la evidencia de `d1-re` |
| Existe tráfico UDP adicional de gameplay/physics | UNKNOWN |

## Qué no se inventa

- Campos extra en el outer header.
- Kinds no observados en el decryptor.
- Padding, checksums o versionado adicionales no presentes en el código citado.

## REQUIRES TEST

- Round-trip de framing con hex sintéticos propios (sin datos de capturas).
- Contar distribución de `kind` y `msg_id` sobre JSONL descifrado local.
