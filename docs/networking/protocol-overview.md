# Protocol overview

## Alcance de esta evidencia

**CONFIRMED:** el flujo documentado aquí corresponde a capturas y herramientas públicas de Destiny 1 en **PS3** publicadas en `kallsyms/d1-re`.

**UNKNOWN:** si el mismo flujo, framing y cifrado se aplican sin cambios a PS4, Xbox o a una futura implementación PC.

## Núcleo (no UDP)

El núcleo observado no es un stack UDP de gameplay.

Es:

```text
SignOn HTTPS
    ↓
tokens + endpoints BAP
    ↓
TCP BAP
    ↓
destiny-service-handshake (0x1E / 0x1F)
    ↓
session-login (0x19 / 0x1A)
    ↓
session key / nonce
    ↓
AES-GCM encrypted frames (kind = 1)
    ↓
mensajes posteriores (p. ej. 0x79/0x7A, 0xFA/0xFB, 0x12D, 0x12E/0x12F)
```

```text
UDP gameplay / physics / peers / NAT de bajo nivel = UNKNOWN
```

## Flujo observado

### 1. SignOn HTTPS

El cliente contacta un servicio SignOn por HTTPS.

**CONFIRMED (PS3):** existe un paso HTTPS previo al tráfico BAP; la respuesta aporta material usado para descifrar/establecer la sesión BAP.

Detalle: [signon-https.md](signon-https.md).

```text
Fuente: kallsyms/d1-re/README.md
Fuente: kallsyms/d1-re/tools/ps3_decrypt_capture.py
función/script: load_https_secrets, collect_signon_secrets
```

### 2. Tokens y endpoints BAP

Del SignOn se obtienen pares de material criptográfico y, cuando están presentes, endpoints IP:puerto asociados a BAP.

**CONFIRMED:** el decryptor de `d1-re` trata ese material como necesario para procesar `session-login-response` (`0x1A`).

**UNKNOWN:** schema completo de la respuesta SignOn.

Detalle: [signon-https.md](signon-https.md).

### 3. TCP + framing BAP

El tráfico BAP analizado en `d1-re` se reconstruye desde **conexiones TCP** en PCAPs.

**CONFIRMED:** BAP viaja sobre TCP en esta evidencia PS3.

**UNKNOWN:** qué otros transportes existen fuera de este núcleo.

Detalle: [framing-bap.md](framing-bap.md).

```text
Fuente: kallsyms/d1-re/tools/ps3_decrypt_capture.py
función/script: read_pcap, parse_tcp_packet, iter_bap_frames, decrypt_bap
```

### 4. Service handshake

Mensajes:

- `0x1E` — `destiny-service-handshake-request`
- `0x1F` — `destiny-service-handshake-response`

Pueden aparecer antes del session login, o el flujo puede empezar directamente en `0x19` / `0x1A`.

Detalle: [handshake.md](handshake.md).

### 5. Session login

Mensajes:

- `0x19` — `session-login-request`
- `0x1A` — `session-login-response`

**CONFIRMED:** el cuerpo de `0x1A` contiene un registro que, con tokens de SignOn, permite obtener parámetros usados después en AES-GCM.

Detalle: [session.md](session.md).

### 6. Canal cifrado

Tras la sesión, frames con `kind = 1` se tratan como AES-GCM.

Detalle: [encrypted-channel.md](encrypted-channel.md).

### 7. Mensajes posteriores

Identificados por nombre/ID en el decryptor (payloads mayormente UNKNOWN):

| ID | Nombre |
| -- | ------ |
| `0x79` / `0x7A` | encrypted-handshake-request / encrypted-handshake-status |
| `0xFA` / `0xFB` | keepalive-request / keepalive-status |
| `0x12D` | activity-state |
| `0x12E` / `0x12F` | nat-report / nat-report-status |

Ver [message-matrix.md](message-matrix.md) y [unknowns.md](unknowns.md).

## Qué no afirma este overview

- Que BAP use UDP.
- Que PS3 = PS4 = Xbox = PC.
- Layouts de payload no demostrados.
- Que `nat-report` sea el gameplay UDP.
- Un servidor o implementación runnable.

## REQUIRES TEST

- Reproducir el decryptor de `d1-re` localmente sobre una captura pública y construir una timeline de mensajes (sin commitear secretos).
- Comparar el mismo flujo en otras plataformas cuando exista evidencia.
