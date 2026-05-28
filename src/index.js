require('dotenv').config();
const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const cookieParser = require('cookie-parser');
const logger = require('./services/logger');

const app = express();

// ─────────────────────────────────────────
// SEGURIDAD — Headers HTTP
// ─────────────────────────────────────────
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc:  ["'self'"],
      styleSrc:   ["'self'"],
      imgSrc:     ["'self'", 'data:'],
    },
  },
  hsts: {
    maxAge:            31536000,  // 1 año
    includeSubDomains: true,
    preload:           true,
  },
}));

// ─────────────────────────────────────────
// CORS — solo el dominio del frontend
// ─────────────────────────────────────────
app.use(cors({
  origin:      process.env.FRONTEND_URL,
  credentials: true,   // necesario para cookies
  methods:     ['GET', 'POST', 'PUT', 'DELETE'],
  allowedHeaders: ['Content-Type', 'Authorization'],
}));

// ─────────────────────────────────────────
// RATE LIMITING global
// ─────────────────────────────────────────
const globalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,  // 15 minutos
  max:      200,
  standardHeaders: true,
  legacyHeaders:   false,
  message: { error: 'Demasiadas solicitudes. Espera unos minutos.' },
});
app.use(globalLimiter);

// ─────────────────────────────────────────
// BODY PARSERS
// IMPORTANTE: /pagos/webhook necesita body raw
// ─────────────────────────────────────────
app.use('/pagos/webhook', express.raw({ type: 'application/json' }));
app.use(express.json({ limit: '1mb' }));
app.use(express.urlencoded({ extended: false }));
app.use(cookieParser());

// ─────────────────────────────────────────
// Proxy trust (EasyPanel/nginx)
// ─────────────────────────────────────────
app.set('trust proxy', 1);

// ─────────────────────────────────────────
// RUTAS
// ─────────────────────────────────────────
app.use('/auth',         require('./routes/auth'));
app.use('/pagos',        require('./routes/pagos'));
app.use('/presupuestos', require('./routes/presupuestos'));

// ─────────────────────────────────────────
// Health check
// ─────────────────────────────────────────
app.get('/health', (req, res) => {
  res.json({ ok: true, env: process.env.NODE_ENV, ts: new Date().toISOString() });
});

// ─────────────────────────────────────────
// 404
// ─────────────────────────────────────────
app.use((req, res) => {
  res.status(404).json({ error: 'Endpoint no encontrado' });
});

// ─────────────────────────────────────────
// Error handler global
// ─────────────────────────────────────────
app.use((err, req, res, next) => {
  logger.error('Error no controlado', { error: err.message, stack: err.stack });
  res.status(500).json({ error: 'Error interno del servidor' });
});

// ─────────────────────────────────────────
// ARRANCAR
// ─────────────────────────────────────────
const PORT = process.env.PORT || 3001;
app.listen(PORT, () => {
  logger.info(`Phoenix Backend arrancado`, {
    port: PORT,
    env:  process.env.NODE_ENV,
  });
});

module.exports = app;
