# External projects

Esta carpeta documenta **y aloja clones locales** de proyectos externos usados como referencia o herramienta.

**Regla:** no copiar su código al árbol propio del proyecto (`network/`, `server/`, etc.) sin revisar licencia. Los clones viven aquí y **no se versionan** en `destiny1-pc-project` (ver `.gitignore`).

## Clones locales

```text
external/
├── d1-re/        # kallsyms/d1-re
├── tiger-pkg/    # v4nguard/tiger-pkg
└── quicktag/     # v4nguard/quicktag
```

Para (re)clonar:

```bash
cd external
git clone --depth 1 https://github.com/kallsyms/d1-re.git d1-re
git clone --depth 1 https://github.com/v4nguard/tiger-pkg.git tiger-pkg
git clone --depth 1 https://github.com/v4nguard/quicktag.git quicktag
```

## kallsyms/d1-re

- **URL:** https://github.com/kallsyms/d1-re
- **Clone local:** `external/d1-re/`
- **Qué es:** artefactos de investigación / capturas PS3 y herramienta de descifrado BAP.
- **Licencia:** no declarada.
- **Uso permitido aquí:** referencia e investigación; citar paths/funciones en `docs/networking/`.
- **No hacer:** copiar código a `network/`; commitear PCAPs, tokens, claves ni `decrypted_bap.jsonl` al repo principal.

Documentación derivada (propia): [docs/networking/](../docs/networking/).

Para validar el pipeline offline con evidencia real (fuera de Git):

```text
# copiar UNA captura ya descifrada a evidencia local gitignored
evidence/local/decrypted_bap.jsonl

cd network
cargo run -- timeline-external ../evidence/local/decrypted_bap.jsonl
```

Ejemplo de fuente dentro del clone (no commitear al repo principal):

```text
external/d1-re/captures/<timestamp>/decrypted/decrypted_bap.jsonl
external/d1-re/captures/<timestamp>/LOG
```

## v4nguard/tiger-pkg

- **URL:** https://github.com/v4nguard/tiger-pkg
- **Clone local:** `external/tiger-pkg/`
- **Qué es:** biblioteca para paquetes del motor Tiger (Destiny 1/2 y otros).
- **Licencia:** MIT.
- **Uso previsto:** análisis de paquetes Tiger (fase cliente/assets; no es la fuente del protocolo de sesión BAP).

## v4nguard/quicktag

- **URL:** https://github.com/v4nguard/quicktag
- **Clone local:** `external/quicktag/`
- **Qué es:** explorador de estructuras / tags / strings en packages Tiger.
- **Licencia:** GPL-3.0.
- **Uso:** herramienta externa.
- **No hacer:** integrar código GPL en componentes propios sin analizar implicaciones de licencia (copyleft).
