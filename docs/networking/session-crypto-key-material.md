# Session crypto key material — origins (investigation)

**Scope:** investigación documental offline.  
**Captura de referencia:** `20260529-003132` (PS3, `kallsyms/d1-re`).  
**No** es una guía de extracción automática. **No** contiene valores de claves.

```text
Fuentes:
  kallsyms/d1-re/README.md
  kallsyms/d1-re/tools/ps3_decrypt_capture.py
    load_https_secrets, collect_signon_secrets,
    derive_bap_session, decrypt_bap_session_record,
    write_secrets_summary
Docs locales: signon-https.md, session.md, session-login-response.md
```

## Por qué M2.3 no tiene `aes_key_hex` / `hmac_key_hex`

**CONFIRMED (proceso de este proyecto):**

1. El stub `evidence/local/session_crypto_verify.json` se rellenó solo con material **estructural del wire `0x1A`** (IV, ciphertext, HMAC tag, `record_len`).
2. Las keys AES/HMAC **no viven en el payload `0x1A`**; en el workflow de `d1-re` vienen del **SignOn HTTPS** (ver abajo).
3. La política M2.2/M2.3 exige **input manual** de keys y **prohíbe** extracción/scraping automático hacia el verificador.
4. Por eso los campos de key siguen vacíos: **falta el paso manual del operador**, no porque el record `0x1A` “debería” contener esas keys.

---

## 1. Qué material necesita M2.3

Para la hipótesis fija `LengthIvCiphertext` + AES-CBC del record:

| Campo en `session_crypto_verify.json` | Rol | Origen esperado (d1-re) |
| ------------------------------------- | --- | ----------------------- |
| `record_len` | longitud BE del record | wire `0x1A` |
| `iv_hex` | IV AES-CBC (16 B) | wire `0x1A` (dentro del record) |
| `ciphertext_hex` | ciphertext AES-CBC | wire `0x1A` |
| `hmac_hex` | tag HMAC-SHA256 (32 B) | wire `0x1A` |
| `aes_key_hex` | key AES-128-CBC del **record** | **SignOn** (token AES, 16 B) |
| `hmac_key_hex` | key HMAC-SHA256 | **SignOn** (token MAC, ≥16 B) |

**No** son inputs de M2.3 (son **salidas** tras un decrypt exitoso del record, según d1-re):

| Material | Rol posterior |
| -------- | ------------- |
| session key (16 B) | AES-GCM del canal (`kind=1`) |
| nonce (12 B) | base de nonce AES-GCM |

---

## 2. De dónde debería provenir (workflow d1-re)

### Diagrama lógico

```text
MITM HTTPS log (https_flows.jsonl)
        │
        ▼
 SignOn response body (plaintext)
        │  collect_signon_secrets
        ▼
 candidate (aes_key[:16], mac_key) pairs
        │
        ├──► capture_secrets_summary.json  (solo hashes + labels)
        │
        ▼
 PCAP TCP BAP → find clear 0x1A
        │  derive_bap_session / decrypt_bap_session_record
        ▼
 HMAC check + AES-CBC decrypt of session record
        │
        ▼
 plaintext → candidate nonce + session key  →  AES-GCM frames
```

### Clasificación por fuente

| Material | Fuente | Tipo | Confianza |
| -------- | ------ | ---- | --------- |
| Pares AES/MAC para el record `0x1A` | Respuesta **SignOn** en `https_flows.jsonl` | Aparece en evidencia HTTPS (plaintext MITM); **no** en el frame BAP | **CONFIRMED** (comportamiento del decryptor + README d1-re) |
| Candidatos múltiples de pares | Mismo body SignOn: prueba combinaciones de campos wire `1/2/3` (`field2-field3`, `field1-field2`, `field1-field3`) | Derivado del parseo SignOn (heurística del tool) | **CONFIRMED** como comportamiento de `collect_signon_secrets`; semántica de campos **UNKNOWN** |
| AES key usada en CBC | `key[:16]` del candidato elegido | SignOn → truncado a 16 | **CONFIRMED** (código d1-re) |
| HMAC/MAC key | `mac_key` completo; d1-re también prueba `mac_key[:16]` | SignOn | **CONFIRMED** (código); cuál variante usa Destiny siempre = **UNKNOWN** / **REQUIRES TEST** en M2.3 estricto |
| IV, ciphertext, HMAC tag | Payload clear de **`0x1A`** en el stream BAP (PCAP / JSONL) | Captura BAP | **CONFIRMED** |
| Prefijo `u16` antes del record | Payload `0x1A` | Captura BAP; significado | **UNKNOWN** |
| Session key + nonce AES-GCM | **Plaintext** del record tras CBC | **Derivado** de `0x1A` + keys SignOn | **CONFIRMED** como salida de `derive_bap_session` |
| `capture_secrets_summary.json` | Escrito por el decryptor | Solo `source` + **hashes** truncados de AES/MAC keys; **no** recupera keys | **CONFIRMED** |
| Keys en `session_crypto_verify.json` | Operador | **Input manual** (política de este repo) | **CONFIRMED** (diseño M2.2/M2.3) |

### Qué **no** es (según evidencia pública)

| Afirmación | Estado |
| ---------- | ------ |
| Las AES/HMAC keys del record salen del propio ciphertext `0x1A` sin SignOn | **False** respecto al workflow d1-re (**CONFIRMED** dependencia de SignOn) |
| Hay key derivation tipo KDF documentada aparte de “tomar bytes del SignOn” | **UNKNOWN** / no aparece en el decryptor público (usa bytes de campos wire) |
| Las keys se introducen interactivamente en d1-re por el operador | **False** para el path documentado: las lee del `--https-log` (**CONFIRMED**) |
| Hace falta autenticarse a servicios vivos para re-obtener keys de esta captura | **No** para reproducir **esta** captura si el `https_flows.jsonl` local ya tiene el SignOn plaintext (**CONFIRMED** presencia del artefacto; ver §4) |

---

## 3. Qué tenemos actualmente

Inventario **local** para `20260529-003132` (existencia de artefactos; sin valores):

| Artefacto | ¿Presente? | Contiene keys AES/MAC del record? |
| --------- | ---------- | --------------------------------- |
| `external/d1-re/captures/20260529-003132/traffic.pcap` | sí | no (BAP cifrado/clear según frame; keys SignOn no) |
| `…/https_flows.jsonl` | sí (flujo SignOn-like presente) | **sí, en plaintext MITM** (cuerpo SignOn) — evidencia sensible, gitignored en este repo |
| `…/decrypted/decrypted_bap.jsonl` | sí | no (frames; no sustituye keys SignOn) |
| `…/decrypted/capture_secrets_summary.json` | sí (~35 pares candidatos) | **no** — solo hashes + labels |
| `…/LOG` | sí | notas de operador; no keys |
| `evidence/local/decrypted_bap.jsonl` | sí (copia de trabajo) | no |
| `evidence/local/session_crypto_verify.json` | sí | IV/CT/HMAC/`record_len=80` **sí**; `aes_key_hex` / `hmac_key_hex` **vacíos** |

### Resumen

| Necesario para M2.3 | Estado |
| ------------------- | ------ |
| IV / ciphertext / HMAC / `record_len` | **tenemos** (stub local) |
| AES key SignOn (16 B) | **falta en el JSON de verify** (existe en evidencia SignOn local, no transferida manualmente) |
| HMAC key SignOn | **idem** |
| Session key / nonce GCM | **no** requeridos como input de M2.3 |

---

## 4. Qué permite realmente reproducir la captura

### Reproducción completa al estilo d1-re

**CONFIRMED:** con `traffic.pcap` + `https_flows.jsonl` de esta captura, el tool público `ps3_decrypt_capture.py` puede (y en el árbol de d1-re ya produjo) `decrypted_bap.jsonl` + summary de hashes.

### Completar M2.3 en *este* proyecto (verificador propio)

**PROBABLE / factible en principio:** sí, **si** un operador **copia manualmente** el par AES/MAC correcto desde el material SignOn ya presente en el `https_flows.jsonl` local (gitignored) hacia `evidence/local/session_crypto_verify.json`, y luego corre `session-crypto-verify` con la hipótesis fija.

**CONFIRMED limitaciones:**

- `capture_secrets_summary.json` **no basta**: no contiene keys recuperables (solo hashes).
- Automatizar esa copia en el CLI **está fuera de política** M2.3.
- d1-re genera **muchos** pares candidatos; solo el que valida HMAC/CBC del `0x1A` es el útil. Elegir el par correcto puede requerir prueba offline **manual** (humano / sesión de análisis), no brute force en nuestro tool.
- M2.3 estricto **no** prueba `mac_key[:16]` automáticamente; si el par real solo valida con el prefijo de 16, el resultado puede ser `FAILED` aunque d1-re hubiera tenido éxito con fallback — eso sería un hallazgo, no un motivo para cambiar la hipótesis sin documentarlo.

### Evidencia que “falta” para M2.3

No falta un PCAP ni un SignOn log en el clone local de d1-re.

**Falta explícitamente:**

1. Transferencia **manual** de `aes_key_hex` / `hmac_key_hex` al JSON gitignored de verify; y/o  
2. Confirmación documentada de **cuál** candidato SignOn (label/hash en summary) corresponde al par que abre el `0x1A` de esta captura — sin publicar la key.

---

## 5. Próximo paso permitido (no implementado aquí)

**Solo documental / experimental manual:**

1. Operador (humano): identificar en el análisis local el par SignOn que d1-re usó con éxito para esta captura (p.ej. contrastar `token_source` / hashes en artefactos ya descifrados, **sin** commitear secretos).
2. Pegar **manualmente** AES (16 B) y MAC key en `evidence/local/session_crypto_verify.json`.
3. Re-ejecutar `session-crypto-verify` y documentar `VERIFIED` / `PARTIAL` / `FAILED` en `session-login-response.md` § M2.3.

**No** implementar extracción automática, scraping, ni cambiar la hipótesis HMAC en ese paso.

---

## Tabla CONFIRMED / PROBABLE / UNKNOWN

| Afirmación | Nivel |
| ---------- | ----- |
| d1-re obtiene tokens BAP del plaintext SignOn en `https_flows.jsonl` | **CONFIRMED** |
| Esos tokens alimentan `decrypt_bap_session_record` sobre el record en `0x1A` | **CONFIRMED** |
| IV/CT/HMAC del record están en el wire `0x1A` | **CONFIRMED** |
| Session key + nonce GCM salen del plaintext del record | **CONFIRMED** (path d1-re) |
| `capture_secrets_summary` no expone keys en claro | **CONFIRMED** |
| Esta captura local incluye `https_flows.jsonl` con SignOn | **CONFIRMED** (existencia) |
| M2.3 carece de keys porque el stub no las copió (política manual) | **CONFIRMED** (histórico); **resuelto** tras copia manual → CLI `VERIFIED` |
| Schema exacto / significado de campos SignOn 1/2/3 | **UNKNOWN** |
| Que Destiny use siempre MAC key completa vs `[:16]` | **UNKNOWN** (d1-re prueba ambas) |
| Equivalencia PS4/Xbox/PC del mismo material | **UNKNOWN** |

## Seguridad

- No versionar keys, bodies SignOn, ni `https_flows.jsonl`.
- No copiar código de `d1-re` a este repo.
- Este documento no incluye secretos ni hashes completos de keys.
