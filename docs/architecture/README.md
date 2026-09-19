# Arquitectura

## Componentes

### Client

Responsable de ejecutar el juego en PC y comunicarse con la infraestructura comunitaria.

### Network

Contiene el conocimiento y código relacionado con el protocolo de comunicación.

### Server

Implementa los servicios necesarios para una experiencia de juego comunitaria.

### Tools

Herramientas de investigación, parsing, debugging y análisis.

### Launcher

Aplicación Windows que prepara y ejecuta el cliente.

### Web

Sitio público del proyecto.

## Regla de separación

El cliente, la capa de red y los servicios deben poder evolucionar independientemente.

No mezclar herramientas experimentales con código de producción.
