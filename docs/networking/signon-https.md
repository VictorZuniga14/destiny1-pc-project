# SignOn HTTPS

## Resumen

Antes del tráfico BAP sobre TCP, el cliente PS3 realiza un SignOn por HTTPS. La respuesta aporta material que `d1-re` usa para descifrar el registro de sesión BAP (`0x1A`) y localizar endpoints BAP.

**Plataforma de evidencia:** PS3.

```text
Fuente: kallsyms/d1-re/README.md
Fuente: kallsyms/d1-re/tools/ps3_decrypt_capture.py
función/script: load_https_secrets, collect_signon_secrets, http_body
```

## CONFIRMED

### Transporte

- HTTPS (TLS) sobre TCP.
- El decryptor asume plaintext HTTPS disponible vía log MITM (`https_flows.jsonl`), no mediante descifrado TLS dentro del propio script.

### Endpoint

- Path observado en capturas PS3: `/SignOn` con query que incluye plataforma y build.
- Ejemplo de forma (sin secretos):

```text
POST /SignOn?platform=ps3_ppu&build=<build_id>
```

- Host de SignOn observado en metadatos de captura (ejemplo público): host bajo el dominio de SignOn usado en esa captura PS3.

**Nota:** no se reproducen aquí cuerpos, tokens ni claves.

### Plataforma y build

- Query `platform=ps3_ppu` aparece en evidencia PS3.
- Un identificador de build acompaña la request.

### Relación SignOn → BAP

1. Se parsea el cuerpo de respuesta SignOn (formato tipo wire/protobuf-like).
2. Se buscan campos de bytes interpretados como pares token (AES key / MAC key).
3. Se buscan varints interpretados como IP (endianness little-endian empaquetada) y puerto de endpoint BAP.
4. Ese material se usa después contra el registro cifrado dentro de `session-login-response` (`0x1A`).

```text
Fuente: kallsyms/d1-re/tools/ps3_decrypt_capture.py
función/script: collect_signon_secrets, derive_bap_session, decrypt_bap_session_record
```

### AES key y MAC key (existencia, no valores)

**CONFIRMED:**

- El decryptor espera pares `(key, mac_key)` derivados de la respuesta SignOn.
- La key AES usada en el registro de sesión se toma como 16 bytes.
- La MAC key se usa con HMAC-SHA256 (también se prueba el prefijo de 16 bytes).

**No CONFIRMED aquí:** valores concretos, rotación, lifetime, ni el significado semántico completo de cada campo SignOn.

### Endpoints BAP

**CONFIRMED:** cuando el parseo encuentra IP + puerto, se registran como candidatos `bap_endpoints`.

**UNKNOWN:** cuántos endpoints hay siempre, cómo elige el cliente, y si todos son TCP BAP.

## UNKNOWN

- Schema completo del request/response SignOn (protobuf u otro).
- Lista exhaustiva de campos y tipos.
- Autenticación de plataforma (tickets PSN, etc.) a nivel de bytes.
- Si PS4/Xbox usan el mismo path, host pattern y schema.
- Cómo se comporta SignOn en un entorno comunitario futuro (fuera del alcance de esta evidencia).

## Qué no documentamos a propósito

- Tokens, claves, hashes de claves, bodies base64 de capturas.
- Reconstrucción completa del protobuf “por intuición”.

## REQUIRES TEST

- Inventariar campos wire de SignOn sobre capturas públicas locales (sin publicar secretos).
- Verificar si siempre aparecen endpoints BAP junto a los tokens.
- Comparar SignOn PS3 vs otras plataformas cuando exista evidencia.
