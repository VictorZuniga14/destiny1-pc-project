# Destiny 1 PC Project

Proyecto comunitario de investigación y desarrollo orientado a hacer posible la ejecución de Destiny 1 en PC mediante un cliente nativo/compatible y servicios comunitarios.

> Estado: investigación y prototipo.

## Objetivo

Investigar y desarrollar, por etapas:

- ejecución de Destiny 1 en PC;
- compatibilidad del cliente;
- implementación/reproducción del protocolo de red necesario;
- servicios comunitarios para cuentas, personajes y actividades;
- herramientas de investigación y debugging;
- launcher para Windows.

## Arquitectura

```
Destiny 1 PC Client
        |
        v
destiny1-network
        |
        v
destiny1-server
```

Las herramientas de investigación viven en `tools/` y la documentación técnica en `docs/`.

## Repositorios externos

Este proyecto puede apoyarse en proyectos de terceros como herramientas de reverse engineering, análisis de paquetes o emulación. Los repositorios externos no se consideran parte de este código y deben conservar sus licencias y atribuciones.

## Legal

Este proyecto no distribuye archivos de juego, contenido propietario ni copias de Destiny 1.

El objetivo es desarrollar software y documentación propia y permitir que el usuario utilice sus propios archivos obtenidos legalmente.

Antes de reutilizar código de terceros, revisar su licencia correspondiente.

## Roadmap

### Fase 0 — Investigación
- [ ] Documentar arquitectura del proyecto.
- [ ] Analizar investigaciones públicas sobre D1.
- [ ] Estudiar protocolo de red.
- [ ] Definir límites legales y de distribución.

### Fase 1 — Network
- [x] Identificar handshake (docs + evidencia PS3).
- [x] Identificar login/session (M2.1–M2.3 offline).
- [x] Framing BAP + canal AES-GCM offline (M2.4–M2.8).
- [ ] Transporte TCP real / servicios comunitarios.
- [ ] Documentar NAT y conexiones (parcial; UDP UNKNOWN).
- [x] Crear parser/prototipo de mensajes (crate `network/`).

### Fase 2 — Client
- [ ] Conseguir ejecución del cliente en PC.
- [ ] Character select.
- [ ] Login.
- [ ] Orbit.

### Fase 3 — Server
- [ ] Account.
- [ ] Character.
- [ ] Inventory.
- [ ] Activity.
- [ ] World/session.

### Fase 4 — Multiplayer
- [ ] Dos clientes conectados.
- [ ] Replicación de jugadores.
- [ ] Movimiento.
- [ ] Interacciones.
- [ ] Actividades.

### Fase 5 — Launcher
- [ ] Instalación/configuración.
- [ ] Verificación de archivos del usuario.
- [ ] Actualizaciones del proyecto.
- [ ] Inicio del cliente.

### Fase 6 — Web
- [ ] Sitio público.
- [ ] Documentación.
- [ ] Descargas del software propio.
- [ ] Estado del proyecto.

## Estructura

```
destiny1-pc-project/
├── client/
├── network/
├── server/
├── tools/
├── launcher/
├── web/
├── docs/
├── external/
└── README.md
```

## Principio del proyecto

Primero demostrar que una parte pequeña funciona. Después ampliar.

No se pretende construir todo el backend de Destiny 1 de una sola vez.
