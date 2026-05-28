# Phoenix Presupuestos — Guía de Despliegue

## Arquitectura de seguridad

- **JWT con rotation**: access token 15 min + refresh token 30 días en cookie httpOnly
- **bcrypt rounds 12**: ~300ms por hash (protege contra fuerza bruta)
- **Rate limiting**: 10 intentos de login por 15 min por IP
- **Stripe webhook con firma**: verifica que el evento viene de Stripe, no de un atacante
- **Función SQL atómica**: consumir_creditos() con FOR UPDATE evita race conditions
- **Usuario PostgreSQL sin superpermisos**: solo acceso a la BD de la app
- **Idempotencia en pagos**: nunca se añaden créditos dos veces por el mismo evento
- **Timing attack prevention**: siempre se compara el hash aunque el usuario no exista

---

## 1. Preparar PostgreSQL en tu VPS

```bash
# Conectar a PostgreSQL como superusuario
psql -U postgres

# Crear BD y usuario específico (si no existe ya)
CREATE DATABASE phoenix_presupuestos;
\c phoenix_presupuestos
\i schema.sql
```

---

## 2. Configurar Stripe

### Crear producto y precio en Stripe Dashboard:
1. Ir a https://dashboard.stripe.com/products
2. Crear producto: "Créditos Phoenix Presupuestos"
3. Añadir precio: 40,00 € · pago único · nombre: "20 créditos"
4. Copiar el Price ID (empieza por `price_`)

### Configurar webhook:
1. Ir a https://dashboard.stripe.com/webhooks
2. Añadir endpoint: `https://TU_DOMINIO/pagos/webhook`
3. Seleccionar eventos:
   - `checkout.session.completed`
   - `checkout.session.expired`
   - `charge.dispute.created`
4. Copiar el Webhook Secret (empieza por `whsec_`)

---

## 3. Variables de entorno (.env)

```bash
# Copiar plantilla
cp .env.example .env

# Generar JWT secrets
node -e "console.log(require('crypto').randomBytes(64).toString('hex'))"
# Ejecutar dos veces — uno para JWT_SECRET y otro para JWT_REFRESH_SECRET

# Rellenar .env con:
# - Credenciales PostgreSQL
# - JWT_SECRET y JWT_REFRESH_SECRET
# - STRIPE_SECRET_KEY (sk_live_...)
# - STRIPE_WEBHOOK_SECRET (whsec_...)
# - STRIPE_PRICE_20_CREDITOS (price_...)
# - FRONTEND_URL (https://tu-dominio.com)
```

---

## 4. Desplegar en EasyPanel

```bash
# En EasyPanel → Nuevo servicio → Docker
# Repositorio: tu repo de GitHub
# Variables de entorno: copiar del .env

# O con Docker directamente:
docker build -t phoenix-backend .
docker run -d \
  --name phoenix-backend \
  --env-file .env \
  -p 3001:3001 \
  --restart unless-stopped \
  phoenix-backend
```

---

## 5. API — Endpoints

### Autenticación
```
POST /auth/registro     → Crear cuenta (3 créditos de bienvenida)
POST /auth/login        → Iniciar sesión → {accessToken, usuario}
POST /auth/refresh      → Renovar token (cookie httpOnly automática)
POST /auth/logout       → Cerrar sesión
GET  /auth/perfil       → Datos del usuario autenticado
```

### Créditos y pagos
```
POST /pagos/checkout    → Crear sesión de pago Stripe → {url}
POST /pagos/webhook     → Recibir eventos Stripe (NO usar Authorization)
GET  /pagos/creditos    → Saldo actual
GET  /pagos/historial   → Historial de pagos
GET  /pagos/movimientos → Historial de créditos
```

### Presupuestos
```
POST /presupuestos      → Guardar (consume 1 crédito por estancia)
GET  /presupuestos      → Listar del usuario (paginado)
GET  /presupuestos/:id  → Detalle
```

---

## 6. Flujo del frontend (app v33)

```javascript
// 1. Login
const res = await fetch('https://api.tu-dominio.com/auth/login', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  credentials: 'include',   // necesario para la cookie de refresh
  body: JSON.stringify({ email, password })
});
const { accessToken, usuario } = await res.json();
// Guardar accessToken en memoria (NO en localStorage)

// 2. Usar API con token
const headers = { 'Authorization': `Bearer ${accessToken}` };

// 3. Cuando el token expire (401 TOKEN_EXPIRED), renovar:
const refresh = await fetch('https://api.tu-dominio.com/auth/refresh', {
  method: 'POST',
  credentials: 'include'   // envía la cookie httpOnly automáticamente
});
const { accessToken: nuevoToken } = await refresh.json();

// 4. Comprar créditos
const checkout = await fetch('https://api.tu-dominio.com/pagos/checkout', {
  method: 'POST',
  headers: { ...headers, 'Content-Type': 'application/json' },
  body: JSON.stringify({ paquete: '20_creditos' })
});
const { url } = await checkout.json();
window.location.href = url;  // Redirigir a Stripe

// 5. Guardar presupuesto
const guardar = await fetch('https://api.tu-dominio.com/presupuestos', {
  method: 'POST',
  headers: { ...headers, 'Content-Type': 'application/json' },
  body: JSON.stringify({
    datos:          wData,          // datos del wizard
    partidas:       calcPartidas(), // partidas calculadas
    estancias:      estSel.length,  // créditos a consumir
    total_estimado: totalGlobal(),
    nivel,
    calidad,
    cliente_nombre,
    cliente_email,
  })
});
```

---

## 7. Protección del frontend

Para que la lógica de precios no sea "fusilable":

1. **Mover calcPartidas() al backend** — el frontend envía wData, el servidor calcula las partidas
2. **El frontend no muestra precios hasta que el servidor los confirme**
3. **Ofuscar/minificar el HTML** con terser o similar antes de servir
4. **Servir el HTML desde el backend** (no como fichero estático)

Siguiente paso: integrar el frontend con esta API.

---

## Precios / modelo de negocio

| Pack | Créditos | Precio | €/crédito |
|------|----------|--------|-----------|
| Starter | 20 | 40 € | 2 €/presupuesto·estancia |

- 1 presupuesto de 1 estancia = **1 crédito = 2 €**
- 1 presupuesto de 3 estancias = **3 créditos = 6 €**
- **3 créditos gratis** al registrarse

