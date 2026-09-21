# Payload Structure Analysis (M3.2)

Offline analysis of decrypted BAP payload bytes across the two verified captures.

## 1. Objetivo

Determinar **estructura observable de bytes** a partir de las capturas, sin afirmar semántica definitiva.

Pregunta:

> ¿Qué estructura interna de bytes puede demostrarse a partir de las dos capturas?

## 2. Fuentes

| Captura | Fixture (gitignored) |
| ------- | -------------------- |
| `20260529-003132` | `evidence/local/bap_session_verify.json` |
| `20260608-231100` | `evidence/local/bap_session_verify_20260608-231100.json` |

Reutiliza `MessageObservation` / `MessageInventory` / `BapOfflinePipeline` (M3.1 + M2.8).  
No re-parsea framing BAP ni reimplementa AES-GCM.

## 3. Metodología

Niveles de evidencia (estrictos):

| Label | Significado |
| ----- | ----------- |
| **OBSERVED** | Demostrable directamente de bytes |
| **STRUCTURAL_HYPOTHESIS** | Interpretación estructural posible (no confirmada) |
| **EXTERNAL_REFERENCE** | Nombre/semántica de `messages.rs` / message-matrix / d1-re |
| **UNKNOWN** | Evidencia insuficiente |

Los payloads completos (`payload_hex`) permanecen en memoria o en `evidence/local/` (gitignored). El export versionado no incluye secretos ni bytes crudos.

## 4. Análisis byte-by-byte

Para cada `message_id` con ≥2 observaciones comparables, cada offset se clasifica:

```text
CONSTANT | VARIABLE | UNOBSERVED | LENGTH_DEPENDENT
```

Se separa:

```text
within_capture_stability
cross_capture_stability
```

Un offset puede ser constante dentro de cada captura y **VARIABLE** entre capturas (valor de sesión).

## 5. Análisis de longitud

Por message ID:

```text
lengths_a / lengths_b / union
FIXED_LENGTH | VARIABLE_LENGTH
CROSS_CAPTURE_LENGTH_STABLE | CROSS_CAPTURE_LENGTH_DIVERGENT
```

Ejemplo esperado (M3.1): `0x7B` / `0xAB` con longitudes distintas entre capturas → `CROSS_CAPTURE_LENGTH_DIVERGENT`. No se inventa qué bytes “faltan”.

## 6. Candidatos numéricos

Ventanas de 1 / 2 / 4 / 8 bytes (incl. deslizantes) se interpretan como:

```text
u8, u16 BE/LE, u32 BE/LE, u64 BE/LE
```

Clasificación siempre:

```text
STRUCTURAL_HYPOTHESIS / NUMERIC_CANDIDATE
semantic_meaning: UNKNOWN
```

Nunca se promueve a `CONFIRMED_U32` / `CONFIRMED_FIELD` automáticamente.

## 7. Candidatos de bits

En regiones de 1 byte con variación:

```text
distinct_values, bitwise_or, bitwise_and
variable_bits / constant_bits
```

Sin afirmar “flags semánticos”.

## 8. Candidatos de texto

Regiones con `printable_ratio ≥ 80%` → `TEXT_CANDIDATE` (`STRUCTURAL_HYPOTHESIS`).  
No implica string de protocolo.

## 9. Regiones estructurales

Offsets consecutivos con la misma estabilidad cross-capture se agrupan en **candidate regions**.  
No se emite un `struct` tipado.

Correlaciones entre regiones variables → `OBSERVED_CORRELATION` (sin causalidad).

## 10. Estabilidad cross-capture

| Clasificación | Uso |
| ------------- | --- |
| `STRUCTURAL_STABLE` | Misma estructura/bytes estables en ambas |
| `STRUCTURAL_DIVERGENT` | Bytes o longitudes divergen |
| `CAPTURE_SPECIFIC` | Solo una captura / length-dependent |
| `UNKNOWN` | Sin evidencia |

## 11. Divergencias

Longitudes y offsets divergentes se reportan explícitamente (p. ej. `0x7B`, `0xAB`). No se normalizan ni se ocultan.

## 12. Limitaciones

- No schemas definitivos de payload.
- No nombres de campos inventados.
- No semántica (account_id, timestamp, etc.) sin evidencia adicional.
- Entropía alta ≠ cifrado (payloads ya descifrados por GCM).
- No inicia M3.3 ni M2.10.
- Offline only: sin TCP / sockets / Tokio / UDP / servidor.

## 13. Semántica

**UNKNOWN** salvo `EXTERNAL_REFERENCE` explícita desde documentación externa.

## CLI

```bash
cargo run -- payload-structure-verify fixtures/multi_capture/manifest.json
```

Export seguro: `fixtures/payload_structure/cross_capture_safe.json`  
(longitudes, offsets, estabilidad, candidatos; **sin** keys / tokens / `payload_hex`).

Para message IDs con muchas regiones (p. ej. `0x7B`), el export versionado incluye
conteos totales y hasta 64 regiones de muestra (constantes primero); el análisis
completo vive en memoria / reporte local gitignored.

## Related

- [message-inventory.md](message-inventory.md) (M3.1)
- [multi-capture-validation.md](multi-capture-validation.md) (M2.9)
- [message-matrix.md](message-matrix.md) (EXTERNAL_REFERENCE)
