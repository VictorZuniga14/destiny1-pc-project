# destiny1-network

Capa de red del proyecto.

## Objetivos iniciales

- documentar el protocolo;
- definir estructuras de mensajes;
- implementar parsing;
- manejar sesiones;
- investigar transporte UDP/TCP/HTTPS según corresponda;
- documentar NAT y actividad.

## Primera tarea

No implementar todo el protocolo.

Primero reproducir y documentar el flujo mínimo:

```
Handshake
  ↓
Session Login
  ↓
Session State
  ↓
Keepalive
```

Los detalles deben basarse en evidencia reproducible y no en suposiciones.
