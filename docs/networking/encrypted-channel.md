# Encrypted channel (AES-GCM)

## Resumen

Después de un `session-login-response` (`0x1A`) procesado con tokens de SignOn, los frames BAP con `kind = 1` se tratan como ciphertext AES-GCM.

**Plataforma de evidencia:** PS3 (`kallsyms/d1-re`).

```text
Fuente: kallsyms/d1-re/tools/ps3_decrypt_capture.py
función/script: decrypt_bap_direction_docs, derive_bap_session, increment_nonce
```

## CONFIRMED

### Relación con framing

- Outer frame igual que cleartext: magic `0x01`, `kind`, `body_len`, body.
- Para `kind = 1`, body = `[tag:16][ciphertext...]`.
- Tras descifrar, el plaintext se interpreta como `[msg_id:u16 BE][context:u32 BE][payload...]` cuando hay ≥ 6 bytes.

Ver [framing-bap.md](framing-bap.md).

### Algoritmo

- **AES-GCM** (AEAD).
- Key: session key derivada del registro en `0x1A` (16 bytes en el decryptor).
- Tag: 16 bytes al inicio del body encrypted.

### Nonce — servidor

- El decryptor usa el nonce obtenido del registro de sesión como nonce base para la dirección **server → client**.

### Nonce — cliente

- Para **client → server**, el decryptor usa el mismo nonce base con el **último byte XOR `1`**.

### Incremento por frame

- Tras cada frame `kind = 1` descifrado (o intentado) en una dirección, el nonce de esa dirección se incrementa byte a byte (little-endian style increment en el array de bytes del nonce, según `increment_nonce`).

**CONFIRMED** como comportamiento del decryptor público.

**UNKNOWN:** si el juego real incrementa exactamente igual en todas las plataformas y versiones; si hay resync/rekey.

### Origen de key/nonce

Dependen de [session.md](session.md) + [signon-https.md](signon-https.md). Sin ese material, `d1-re` no puede descifrar el canal.

## PROBABLE

- Que mensajes posteriores al login (`0x79`, `0xFA`, etc.) viajen mayoritariamente como `kind = 1` una vez establecido el canal.
- Que cleartext (`kind = 2`) quede limitado a la fase pre-sesión en conexiones normales.

Estas son inferencias de diseño del decryptor / flujo; no se tratan como inventario exhaustivo de capturas en este documento.

## UNKNOWN

- AAD (additional authenticated data): el decryptor pasa `None` como AAD.
- Rekeying, rotación de nonce, límites de frames.
- Equivalencia PS4 / Xbox / PC.
- Cualquier capa UDP distinta de este canal TCP/BAP.

## Qué no afirmar

- Que “todo Destiny 1 networking” sea AES-GCM sobre TCP.
- Detalles de payload de mensajes cifrados individuales.

## REQUIRES TEST

- Verificar en JSONL local la secuencia clear → encrypted y el éxito de decrypt por dirección.
- Comprobar fallos al invertir la regla del último byte del nonce.
