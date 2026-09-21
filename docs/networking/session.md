# Session login

## Mensajes

| ID | Nombre |
| -- | ------ |
| `0x19` | `session-login-request` |
| `0x1A` | `session-login-response` |

```text
Fuente: kallsyms/d1-re/tools/ps3_decrypt_capture.py
función/script: BAP_NAMES, derive_bap_session, decrypt_bap_session_record
```

## CONFIRMED

### Rol en el flujo

- Aparecen como mensajes cleartext (`kind = 2`) en el establecimiento de sesión BAP.
- Tras un `0x1A` válido y descifrable, el decryptor obtiene material para el canal AES-GCM.

### Dirección (por naming + orientación de streams)

- `0x19` — cliente → servidor (**PROBABLE**)
- `0x1A` — servidor → cliente (**PROBABLE** / **CONFIRMED** como el frame del que se deriva la sesión en el decryptor)

### Relación con SignOn

Los tokens AES/MAC obtenidos del SignOn HTTPS se usan para descifrar un **session record** embebido en el payload de `0x1A`.

Ver [signon-https.md](signon-https.md).

### Procesamiento del registro en `0x1A` (según decryptor)

A alto nivel (sin copiar código):

1. Se toma el body cleartext de `0x1A`.
2. Tras `msg_id` + `context`, el payload contiene un registro con longitud y material cifrado.
3. Se verifica un MAC **HMAC-SHA256**.
4. Se descifra con **AES-CBC** usando la key de SignOn y un IV presente en el registro.
5. Del plaintext del registro se leen:
   - un nonce (12 bytes al inicio del plaintext, según offsets usados por el decryptor);
   - una session key AES (16 bytes a continuación).

**CONFIRMED:** ese path criptográfico es el que implementa `d1-re` para pasar al canal GCM.

**UNKNOWN:** el resto del plaintext del registro; el layout completo de `0x19`; campos de cuenta/personaje/sesión a nivel de producto.

Investigación detallada M2.1 (captura real, sin secretos): [session-login-response.md](session-login-response.md).

```text
Fuente: kallsyms/d1-re/tools/ps3_decrypt_capture.py
función/script: decrypt_bap_session_record, derive_bap_session
```

### Offsets usados por el decryptor (evidencia de implementación, no schema oficial)

Tras descifrar el registro, el decryptor usa:

| Región del plaintext del registro | Uso en d1-re |
| --------------------------------- | ------------ |
| primeros `0x0C` bytes | nonce |
| siguientes `0x10` bytes (`0x0C`..`0x1C`) | AES key de sesión |

**CONFIRMED** como comportamiento del decryptor público.

**UNKNOWN** si existen más campos obligatorios antes/después y su significado.

## UNKNOWN

- Schema completo de `session-login-request` (`0x19`).
- Schema completo de `session-login-response` más allá del registro usado para crypto.
- Códigos de error / rechazo de login.
- Diferencias por plataforma.

## Qué no afirmar

- Inventar campos de usuario, character ID, inventory, etc. en el payload.
- Que este mensaje sea “el login de Orbit” completo del cliente.

## REQUIRES TEST

- Comparar longitudes de payload `0x19`/`0x1A` entre capturas.
- Documentar bytes del registro (estructura) en notas privadas locales; no publicar secretos.
- Confirmar si siempre hace falta SignOn fresco para cada `0x1A`.
