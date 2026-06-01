const express = require('express');
const bcrypt = require('bcrypt');
const { body, validationResult } = require('express-validator');
const rateLimit = require('express-rate-limit');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
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
// MULTER — configuración para logos
// ─────────────────────────────────────────
const logosDir = '/home/phoenix-logos';
if (!fs.existsSync(logosDir)) fs.mkdirSync(logosDir, { recursive: true });

const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, logosDir),
  filename: (req, file, cb) => {
    const ext = path.extname(file.originalname).toLowerCase();
    cb(null, `logo_${req.usuario.id}${ext}`);
  }
});

const upload = multer({
  storage,
  limits: { fileSize: 2 * 1024 * 1024 }, // 2MB máximo
  fileFilter: (req, file, cb) => {
    const allowed = ['.jpg', '.jpeg', '.png', '.gif', '.webp'];
    const ext = path.extname(file.originalname).toLowerCase();
    if (allowed.includes(ext)) cb(null, true);
    else cb(new Error('Solo se permiten imágenes JPG, PNG, GIF o WEBP'));
  }
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

      // Crear usuario — sin créditos de bienvenida, acceso libre para explorar
      const { rows } = await db.query(
        `INSERT INTO usuarios (email, password_hash, nombre, empresa, nif, telefono, creditos)
         VALUES ($1, $2, $3, $4, $5, $6, 0)
         RETURNING id, email, nombre, creditos`,
        [email, passwordHash, nombre, empresa || null, nif || null, telefono || null]
      );

      const usuario = rows[0];

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
        mensaje: '¡Registro completado! Explora la herramienta y adquiere un presupuesto cuando quieras.',
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
      `SELECT id, email, nombre, empresa, nif, telefono, direccion, logo_url, creditos, creado_en
       FROM usuarios WHERE id = $1`,
      [req.usuario.id]
    );
    if (rows.length === 0) return res.status(404).json({ error: 'Usuario no encontrado' });
    return res.json(rows[0]);
  } catch (err) {
    return res.status(500).json({ error: 'Error interno' });
  }
});

// ─────────────────────────────────────────
// PUT /auth/perfil — actualizar datos del usuario
// ─────────────────────────────────────────
router.put('/perfil', autenticar, [
  body('nombre').optional().trim().isLength({ min: 2, max: 255 }),
  body('empresa').optional().trim().isLength({ max: 255 }),
  body('nif').optional().trim().isLength({ max: 20 }),
  body('telefono').optional().trim().isLength({ max: 20 }),
  body('direccion').optional().trim().isLength({ max: 500 }),
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errores: errors.array() });
  }

  const { nombre, empresa, nif, telefono, direccion } = req.body;

  try {
    const { rows } = await db.query(
      `UPDATE usuarios 
       SET nombre    = COALESCE($1, nombre),
           empresa   = COALESCE($2, empresa),
           nif       = COALESCE($3, nif),
           telefono  = COALESCE($4, telefono),
           direccion = COALESCE($5, direccion)
       WHERE id = $6
       RETURNING id, email, nombre, empresa, nif, telefono, direccion, logo_url, creditos`,
      [nombre || null, empresa || null, nif || null, telefono || null, direccion || null, req.usuario.id]
    );

    return res.json(rows[0]);
  } catch (err) {
    logger.error('Error actualizando perfil', { error: err.message });
    return res.status(500).json({ error: 'Error interno' });
  }
});

// ─────────────────────────────────────────
// POST /auth/logo — subir logo del usuario
// ─────────────────────────────────────────
router.post('/logo', autenticar, upload.single('logo'), async (req, res) => {
  if (!req.file) {
    return res.status(400).json({ error: 'No se ha subido ningún archivo' });
  }

  const ext = path.extname(req.file.originalname).toLowerCase();
  const logoUrl = `/logos/logo_${req.usuario.id}${ext}`;

  try {
    await db.query(
      'UPDATE usuarios SET logo_url = $1 WHERE id = $2',
      [logoUrl, req.usuario.id]
    );

    logger.info('Logo actualizado', { usuario_id: req.usuario.id, logo: logoUrl });
    return res.json({ logo_url: logoUrl, mensaje: 'Logo actualizado correctamente' });
  } catch (err) {
    logger.error('Error guardando logo', { error: err.message });
    return res.status(500).json({ error: 'Error interno' });
  }
});

// ─────────────────────────────────────────
// DELETE /auth/logo — eliminar logo
// ─────────────────────────────────────────
router.delete('/logo', autenticar, async (req, res) => {
  try {
    const { rows } = await db.query(
      'SELECT logo_url FROM usuarios WHERE id = $1',
      [req.usuario.id]
    );

    if (rows[0]?.logo_url) {
      const filePath = `/home/phoenix-logos${rows[0].logo_url.replace('/logos', '')}`;
      if (fs.existsSync(filePath)) fs.unlinkSync(filePath);
    }

    await db.query('UPDATE usuarios SET logo_url = NULL WHERE id = $1', [req.usuario.id]);
    return res.json({ mensaje: 'Logo eliminado' });
  } catch (err) {
    return res.status(500).json({ error: 'Error interno' });
  }
});

module.exports = router;
