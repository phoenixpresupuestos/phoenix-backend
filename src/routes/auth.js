root@srv1475878:~# docker exec $(docker ps -q --filter name=phai-api) cat /app/src/index.js
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
root@srv1475878:~# docker exec $(docker ps -q --filter name=phai-api) cat /app/src/routes/auth.js
const express = require('express');
const bcrypt = require('bcrypt');
const { body, validationResult } = require('express-validator');
const rateLimit = require('express-rate-limit');
const db = require('../db');
const jwtService = require('../services/jwt');
const { autenticar } = require('../middleware/auth');
const logger = require('../services/logger');

const router = express.Router();

// Rate limiting estricto para auth
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,  // 15 minutos
  max: 10,
  message: { error: 'Demasiados intentos. Espera 15 minutos.' },
  standardHeaders: true,
  legacyHeaders: false,
});

// ─────────────────────────────────────────
// POST /auth/registro
// ─────────────────────────────────────────
router.post('/registro',
  authLimiter,
  [
    body('email').isEmail().normalizeEmail().withMessage('Email inválido'),
    body('password')
      .isLength({ min: 8 })
      .matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)/)
      .withMessage('Contraseña: mínimo 8 caracteres, una mayúscula, una minúscula y un número'),
    body('nombre').trim().isLength({ min: 2, max: 255 }).withMessage('Nombre inválido'),
    body('empresa').optional().trim().isLength({ max: 255 }),
    body('nif').optional().trim().isLength({ max: 20 }),
    body('telefono').optional().trim().isLength({ max: 20 }),
  ],
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errores: errors.array() });
    }

    const { email, password, nombre, empresa, nif, telefono } = req.body;

    try {
      // Comprobar si ya existe
      const { rows: existe } = await db.query(
        'SELECT id FROM usuarios WHERE email = $1', [email]
      );
      if (existe.length > 0) {
        return res.status(409).json({ error: 'Ya existe una cuenta con ese email' });
      }

      // Hash de contraseña
      const rounds = parseInt(process.env.BCRYPT_ROUNDS) || 12;
      const passwordHash = await bcrypt.hash(password, rounds);

      // Crear usuario — 3 créditos gratis de bienvenida
      const { rows } = await db.query(
        `INSERT INTO usuarios (email, password_hash, nombre, empresa, nif, telefono, creditos)
         VALUES ($1, $2, $3, $4, $5, $6, 3)
         RETURNING id, email, nombre, creditos`,
        [email, passwordHash, nombre, empresa || null, nif || null, telefono || null]
      );

      const usuario = rows[0];

      // Registrar créditos de bienvenida
      await db.query(
        `INSERT INTO movimientos_creditos 
         (usuario_id, tipo, cantidad, saldo_anterior, saldo_posterior, descripcion)
         VALUES ($1, 'bonus', 3, 0, 3, 'Créditos de bienvenida')`,
        [usuario.id]
      );

      // Generar tokens
      const accessToken = jwtService.generarAccessToken(usuario);
      const refreshToken = await jwtService.generarRefreshToken(
        usuario.id,
        req.ip,
        req.headers['user-agent']
      );

      logger.info('Nuevo usuario registrado', { email, id: usuario.id });

      // Refresh token en cookie httpOnly
      res.cookie('refreshToken', refreshToken, {
        httpOnly: true,
        secure:   process.env.NODE_ENV === 'production',
        sameSite: 'strict',
        maxAge:   30 * 24 * 60 * 60 * 1000,  // 30 días
        path:     '/auth/refresh',
      });

      return res.status(201).json({
        accessToken,
        usuario: {
          id:       usuario.id,
          email:    usuario.email,
          nombre:   usuario.nombre,
          creditos: usuario.creditos,
        },
        mensaje: '¡Registro completado! Tienes 3 créditos de bienvenida.',
      });

    } catch (err) {
      logger.error('Error en registro', { error: err.message });
      return res.status(500).json({ error: 'Error interno del servidor' });
    }
  }
);

// ─────────────────────────────────────────
// POST /auth/login
// ─────────────────────────────────────────
router.post('/login',
  authLimiter,
  [
    body('email').isEmail().normalizeEmail(),
    body('password').notEmpty(),
  ],
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ error: 'Credenciales inválidas' });
    }

    const { email, password } = req.body;

    try {
      const { rows } = await db.query(
        `SELECT id, email, nombre, password_hash, creditos, activo
         FROM usuarios WHERE email = $1`,
        [email]
      );

      // Siempre comparar aunque no exista (evitar timing attacks)
      const hashFalso = '$2b$12$invalidhashtopreventtimingattacksxxxxxxxxxxxxxxxxxx';
      const hashReal = rows[0]?.password_hash || hashFalso;
      const coincide = await bcrypt.compare(password, hashReal);

      if (!coincide || rows.length === 0) {
        logger.warn('Intento de login fallido', { email, ip: req.ip });
        return res.status(401).json({ error: 'Email o contraseña incorrectos' });
      }

      const usuario = rows[0];

      if (!usuario.activo) {
        return res.status(403).json({ error: 'Cuenta desactivada' });
      }

      const accessToken = jwtService.generarAccessToken(usuario);
      const refreshToken = await jwtService.generarRefreshToken(
        usuario.id, req.ip, req.headers['user-agent']
      );

      res.cookie('refreshToken', refreshToken, {
        httpOnly: true,
        secure:   process.env.NODE_ENV === 'production',
        sameSite: 'strict',
        maxAge:   30 * 24 * 60 * 60 * 1000,
        path:     '/auth/refresh',
      });

      return res.json({
        accessToken,
        usuario: {
          id:       usuario.id,
          email:    usuario.email,
          nombre:   usuario.nombre,
          creditos: usuario.creditos,
        },
      });

    } catch (err) {
      logger.error('Error en login', { error: err.message });
      return res.status(500).json({ error: 'Error interno del servidor' });
    }
  }
);

// ─────────────────────────────────────────
// POST /auth/refresh — rotar tokens
// ─────────────────────────────────────────
router.post('/refresh', authLimiter, async (req, res) => {
  const token = req.cookies?.refreshToken;

  if (!token) {
    return res.status(401).json({ error: 'Refresh token requerido' });
  }

  try {
    const resultado = await jwtService.rotarRefreshToken(
      token, req.ip, req.headers['user-agent']
    );

    if (!resultado) {
      res.clearCookie('refreshToken', { path: '/auth/refresh' });
      return res.status(401).json({ error: 'Sesión expirada. Vuelve a iniciar sesión.' });
    }

    res.cookie('refreshToken', resultado.refreshToken, {
      httpOnly: true,
      secure:   process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      maxAge:   30 * 24 * 60 * 60 * 1000,
      path:     '/auth/refresh',
    });

    return res.json({
      accessToken: resultado.accessToken,
      usuario:     resultado.usuario,
    });

  } catch (err) {
    logger.error('Error en refresh', { error: err.message });
    return res.status(500).json({ error: 'Error interno del servidor' });
  }
});

// ─────────────────────────────────────────
// POST /auth/logout
// ─────────────────────────────────────────
router.post('/logout', autenticar, async (req, res) => {
  try {
    await jwtService.revocarTodosLosTokens(req.usuario.id);
    res.clearCookie('refreshToken', { path: '/auth/refresh' });
    return res.json({ mensaje: 'Sesión cerrada correctamente' });
  } catch (err) {
    return res.status(500).json({ error: 'Error al cerrar sesión' });
  }
});

// ─────────────────────────────────────────
// GET /auth/perfil — datos del usuario autenticado
// ─────────────────────────────────────────
router.get('/perfil', autenticar, async (req, res) => {
  try {
    const { rows } = await db.query(
      `SELECT id, email, nombre, empresa, nif, telefono, creditos, creado_en
       FROM usuarios WHERE id = $1`,
      [req.usuario.id]
    );
    if (rows.length === 0) return res.status(404).json({ error: 'Usuario no encontrado' });
    return res.json(rows[0]);
  } catch (err) {
    return res.status(500).json({ error: 'Error interno' });
  }
});

module.exports = router;
root@srv1475878:~# 
