# Session Login Response — 0x1A

## Scope

**M2.1** investiga **offline** la estructura de `0x1A` (`session-login-response`) usando evidencia real PS3.

### Qué se hace

- Localizar el frame real en la captura validada.
- Documentar qué campos están disponibles en `decrypted_bap.jsonl`.
- Contrastar con la interpretación pública de `kallsyms/d1-re` (sin copiar código).
- Separar **CONFIRMED** / **PROBABLE** / **UNKNOWN**.

### Qué NO se implementa en M2.1

- servidor / sockets / UDP / gameplay;
- `SessionCryptoContext`;
- decrypt automático de sesión;
- nonce progression / AAD;
- cambios a la primitive AES-GCM genérica (`network/src/crypto/aead.rs`);
- commits de evidencia real, payloads, claves o nonces.

## Evidence

| Ítem | Valor |
| ---- | ----- |
| Captura | `20260529-003132` |
| Plataforma | **PS3** |
| Evidencia local | `evidence/local/decrypted_bap.jsonl` (**gitignored**) |
| Fuente externa | [kallsyms/d1-re](https://github.com/kallsyms/d1-re) |
| Validación previa del pipeline | [capture-20260529-003132-notes.md](capture-20260529-003132-notes.md) |

No generalizar a PS4 / Xbox / PC.

## Observed frame

Metadata **segura** del único `0x1A` en esta captura (sin payloads ni secretos):

| Campo | Valor |
| ----- | ----- |
| JSONL line (1-based) | 5 |
| `direction` | `server_to_client` |
| `frame_index` | 1 |
| `frame_kind` (wire) | **2** (cleartext) |
| `frame_ts` | presente (epoch float) |
| `frame_order` | 243 |
| `frame_offset` | 142 |
| `id` | `0x1A` (26) |
| `name` (d1-re) | `session-login-response` |
| `context` | 1 |
| `payload_len` | **86** |

### Campos presentes en el JSONL para este frame

**CONFIRMED** presentes:

- `kind`, `direction`, `frame_index`, `frame_kind`, `frame_ts`, `frame_order`, `frame_offset`
- `id`, `id_hex`, `name`, `context`, `payload_len`, `payload_hex`

**CONFIRMED** ausentes en este registro (porque es clear, no un frame AES-GCM post-sesión):

- `plaintext_hex`
- `nonce` (campo JSONL de frames `frame_kind=1`)
- `error`

El `payload_hex` **existe** en el archivo local, pero **no se reproduce ni se versiona** aquí.

## Known structure

### A) Lo que el JSONL demuestra sin descifrar (esta captura)

Sobre el payload de 86 bytes (análisis de **longitudes / enteros de cabecera** solamente):

| Observación | Valor | Confianza |
| ----------- | ----- | --------- |
| Longitud total del payload | 86 | CONFIRMED |
| Prefijo de 2 bytes antes del “record” | `u16` BE = **200** (LE = 51200) | CONFIRMED como bytes presentes; **significado UNKNOWN** |
| Bytes restantes tras el prefijo (“record”) | 84 | CONFIRMED |
| Primer `u32` BE del record | **80** | CONFIRMED |
| `4 + 80 == 84` (el record se consume entero) | sí | CONFIRMED en esta captura |
| Cola tras el material | 0 bytes | CONFIRMED en esta captura |

Esto es compatible con un layout:

```text
payload[0x1A] =
  [u16_be prefix = 200]      // significado UNKNOWN
  [u32_be record_len = 80]
  [record_len bytes de material]
```

**CONFIRMED** para esta captura PS3: las longitudes encajan sin bytes sobrantes.  
**No** se afirma el contenido interno del material sin una verificación criptográfica propia (fuera de M2.1).

### B) Interpretación en `kallsyms/d1-re` (evidencia externa)

```text
Fuente: kallsyms/d1-re/tools/ps3_decrypt_capture.py
función/script: derive_bap_session, decrypt_bap_session_record
```

El decryptor público, al procesar el body clear de `0x1A`:

1. Toma el payload tras `msg_id` + `context`.
2. Omite **2 bytes** iniciales del payload (`record = payload[2:]`).
3. Interpreta el record como:
   - `record_len`: `u32` **big-endian**;
   - requiere `record_len >= 0x30` (48);
   - `material = record[0 : 4 + record_len]`;
   - **IV**: 16 bytes en `material[4:20]`;
   - `cipher_len = record_len - 0x30`;
   - **ciphertext**: `cipher_len` bytes;
   - **HMAC-SHA256**: 32 bytes finales;
   - HMAC se calcula sobre `material[:20 + cipher_len]` (es decir, length+IV+ciphertext, sin el tag);
   - prueba HMAC con `mac_key` completo y también con `mac_key[:16]`;
   - descifra ciphertext con **AES-CBC**, key SignOn de 16 bytes, IV del record.
4. Del plaintext del registro, si `len >= 0x1C`:
   - bytes `[0x00 .. 0x0C)` → **nonce** (12 bytes) usado luego en AES-GCM;
   - bytes `[0x0C .. 0x1C)` → **session key** AES (16 bytes).

Aplicado a las longitudes de **esta** captura:

| Campo (según d1-re) | Tamaño implicado | Confianza |
| ------------------- | ---------------- | --------- |
| `record_len` | 80 | CONFIRMED length field in this capture; interpretation as d1-re layout = **PROBABLE** (matches tool) / sizes **CONFIRMED** |
| IV | 16 | CONFIRMED as d1-re behavior; **REQUIRES TEST** si lo verificamos nosotros con SignOn tokens (no hecho en M2.1) |
| ciphertext | `80 - 0x30` = **32** | CONFIRMED by length arithmetic under d1-re layout |
| HMAC-SHA256 tag | 32 | CONFIRMED as d1-re behavior |
| AES-CBC | — | CONFIRMED as d1-re behavior |
| plaintext ≥ 28 bytes (`0x1C`) expected | ciphertext 32 sugiere un bloque AES | PROBABLE; padding exacto **UNKNOWN** |
| nonce 12 + key 16 en plaintext | offsets `0x00` / `0x0C` | CONFIRMED as d1-re behavior; **no** re-derivado aquí |

### C) Relación con el canal cifrado

En esta captura, el arranque observado fue:

```text
0x1E → 0x1F → 0x19 → 0x1A → 0x79 → 0x7A → …
```

`0x1A` es clear (`frame_kind=2`). Los mensajes siguientes (`0x79`…) aparecen en el JSONL ya como plaintext lógico tras AES-GCM del decryptor.

**CONFIRMED:** `0x1A` precede al tráfico tratado como canal cifrado en esta captura.  
**UNKNOWN:** semántica completa de producto del login.

## Unknowns

- Significado del prefijo `u16` (= 200 en esta captura).
- Contenido exacto del IV / ciphertext / MAC (**no publicado**).
- HMAC key exacta (SignOn); si siempre se usa key completa vs `[:16]`.
- Padding AES-CBC del plaintext del record.
- Campos del plaintext **después** de offset `0x1C`.
- Layout completo de `0x19` (payload_len = 253 en la misma captura; no analizado en M2.1).
- Endianness de campos **dentro** del plaintext (solo se documentaron BE en length/prefix del record wire).
- Versiones / flags / headers adicionales no demostrados.
- Variación del layout entre capturas / plataformas.
- AAD del AES-GCM posterior (sigue UNKNOWN a nivel de protocolo).

## Evidence source

- Captura y JSONL: `kallsyms/d1-re` (artefactos públicos; copia de trabajo local gitignored).
- Interpretación crypto del record: `tools/ps3_decrypt_capture.py` (`derive_bap_session`, `decrypt_bap_session_record`).
- **No** se copia código de d1-re a este repositorio.
- **No** se modifica la primitive AES-GCM del proyecto en M2.1.

## M2.1 status

```text
M2.1 — 0x1A structure investigation
DONE
```

Incógnitas que quedan fuera de M2.1 (parcialmente cerradas en M2.3): significado del prefijo u16; comparación multi-captura; semántica nonce/session key en GCM (M2.4).

## M2.2 — Offline cryptographic verification

Primitive aislada: `network/src/crypto/cbc_hmac.rs` (no toca `aead.rs`).  
CLI: `destiny1-network session-crypto-verify <ruta-local>`.

### Hipótesis HMAC (explícita)

```text
Fuente: kallsyms/d1-re/tools/ps3_decrypt_capture.py
función/script: decrypt_bap_session_record
```

Input autenticado documentado por d1-re:

```text
HMAC-SHA256(key,  u32_be(record_len) || iv(16) || ciphertext )
```

En código: `HmacMessageKind::LengthIvCiphertext` — el caller **debe** elegir el kind; no se infiere dentro de `verify_hmac_sha256`.  
M2.3 verifica **solo** la key HMAC suministrada (sin fallback `[:16]`). En la captura `20260529-003132` la MAC key SignOn tenía 16 bytes y validó completa.

AES-CBC: decrypt raw (sin strip de padding en el path hazmat), luego validación PKCS#7 **separada** en el reporte.

### Formato de material local (sin valores reales)

Plantilla versionada (campos vacíos): `network/fixtures/session_crypto_verify.template.json`.

Copia de trabajo (gitignored): `evidence/local/session_crypto_verify.json`.

| Campo | Tipo | Notas |
| ----- | ---- | ----- |
| `hmac_message_kind` | string | Debe ser `LengthIvCiphertext` |
| `record_len` | u32 | BE wire length (p.ej. 80 en captura documentada) |
| `iv_hex` | hex | 16 bytes |
| `ciphertext_hex` | hex | múltiplo de 16 |
| `hmac_hex` | hex | 32 bytes |
| `aes_key_hex` | hex | 16 bytes (SignOn AES), **manual** |
| `hmac_key_hex` | hex | HMAC key SignOn, **manual** |

- Vive fuera de Git bajo `evidence/local/`.
- No se hardcodea en código, tests públicos ni docs.
- La CLI / reportes solo emiten longitudes, booleanos y pass/fail.

```bash
cargo run -- session-crypto-verify ../evidence/local/session_crypto_verify.json
```

### Verified locally

| Ítem | Estado |
| ---- | ------ |
| Primitive CBC+HMAC con vectores **sintéticos** | CONFIRMED (tests unitarios) |
| HMAC sobre `LengthIvCiphertext` en sintéticos | CONFIRMED (implementación + tests) |
| Reproducción exitosa HMAC+CBC+PKCS#7 con material **real** de captura | **CONFIRMED** (M2.3, captura `20260529-003132`) |

### Not verified

- Que Destiny/PS3 use exactamente este HMAC input en la captura `20260529-003132` (hipótesis d1-re hasta verificación local con keys reales).
- Padding PKCS#7 vs plaintext “raw” de 32 bytes en material real.
- Semántica de campos del plaintext tras offset `0x1C`.
- Protocolo de sesión completo / AES-GCM frame-a-frame / AAD / nonce progression.

### Security / handling

- Material real: **gitignored** (`evidence/local/`, `*.key`, `**/https_flows.jsonl`, etc.).
- Tests versionados: **solo** vectores sintéticos inventados.
- Salida del verificador: nunca IV, keys, HMAC completo, ciphertext, plaintext, tokens ni hashes.

## M2.1 / M2.2 status

```text
M2.1 — 0x1A structure investigation
DONE

M2.2 — Offline cryptographic verification
DONE
```

**M2** (session reconstruction) **no** está DONE (falta M2.4+).

## M2.3 — Real verification

### Scope

Verificación **offline** del record `0x1A` de la captura `20260529-003132` usando:

- IV / ciphertext / HMAC ya presentes en `evidence/local/session_crypto_verify.json` (gitignored);
- `aes_key_hex` / `hmac_key_hex` suministrados **manualmente** (sin extracción automática);
- hipótesis fija: `HmacMessageKind::LengthIvCiphertext` → `u32_be(record_len) || iv || ciphertext`;
- **sin** fallback de truncar HMAC key, **sin** probar otras composiciones HMAC.

CLI: `cargo run -- session-crypto-verify ../evidence/local/session_crypto_verify.json`

Clasificación de salida: `VERIFIED` | `PARTIAL` | `FAILED` (nunca imprime secretos).

### Input validation (pre-crypto)

Antes de crypto, el loader exige (solo longitudes / enteros):

| Campo | Esperado |
| ----- | -------- |
| `record_len` | 80 |
| `iv_hex` | 16 bytes |
| `ciphertext_hex` | 32 bytes |
| `hmac_hex` | 32 bytes |
| `aes_key_hex` | 16 bytes |
| `hmac_key_hex` | ≥ 16 bytes |

### Resultado de esta corrida

```text
hmac_message_kind: LengthIvCiphertext (d1-re hypothesis)
hmac_valid: true
aes_cbc_decrypt: success
plaintext_length: 32
padding_valid: true
pkcs7_unpadded_length: 28
candidate_nonce_length: 12
candidate_session_key_length: 16
candidate_nonce_offset: 0
candidate_session_key_offset: 12
structure_length_compatible: true
result: VERIFIED
```

| Comprobación | Resultado |
| ------------ | --------- |
| Captura | `20260529-003132` |
| Keys | suministradas manualmente al JSON gitignored desde material SignOn de **esta** captura (`https_flows.jsonl` local); **no** versionadas |
| Par SignOn usado | un único candidato; pairing label `field2-field3` (sin publicar valores); HMAC key length = 16 |
| HMAC (`LengthIvCiphertext`) | **true** |
| AES-CBC decrypt | **success** |
| Padding PKCS#7 | **true** (unpadded = 28) |
| Compatibilidad estructural 12+16 | **sí** (offsets candidatos 0 / 12; **no** prueba semántica) |
| Clasificación CLI | **VERIFIED** (exit 0) |

Hipótesis **no** modificada. Sin fallback `mac_key[:16]` (no hizo falta).

### Verified locally (M2.3) → promovible a CONFIRMED

Para **esta** captura PS3 `20260529-003132`:

| Afirmación | Nivel |
| ---------- | ----- |
| HMAC-SHA256 sobre `u32_be(record_len) \|\| iv \|\| ciphertext` con MAC key SignOn | **CONFIRMED** |
| AES-128-CBC del ciphertext del record con AES key SignOn (16 B) + IV del record | **CONFIRMED** |
| PKCS#7 válido; plaintext raw 32 B → 28 B sin padding | **CONFIRMED** |
| Layout de longitudes del record (80 = 16+32+32) | **CONFIRMED** (ya M2.1; reforzado) |

### Not verified / UNKNOWN (no promover a CONFIRMED solo por longitud)

- Que bytes `[0..12)` / `[12..28)` sean **semánticamente** nonce / session key (compatible en longitud + hipótesis d1-re = **PROBABLE**).
- Uso de ese material en AES-GCM de frames `0x79` / `0x7A` / `kind=1` (M2.4).
- AAD, nonce progression, XOR cliente.
- Otras capturas / plataformas.
- Significado del prefijo `u16` (= 200).

### Security / handling

- `evidence/local/session_crypto_verify.json` permanece gitignored (`git check-ignore` OK).
- Docs y tests versionados: sin valores secretos.

## Status (M2.1–M2.3)

```text
M2.1 — DONE
M2.2 — DONE
M2.3 — DONE
M2   — open (siguiente: M2.4 canal AES-GCM con evidencia real; no iniciado)
```

### Siguiente sub-milestone sugerido (no implementado)

**M2.4** — con session key + nonce candidatos del plaintext verificado, reconstruir offline el canal AES-GCM hacia frames reales (`0x79` / `0x7A` / …), sin servidor ni sockets.
