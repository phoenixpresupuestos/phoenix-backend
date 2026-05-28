const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const db = require('../db');
const logger = require('./logger');

// Generar access token (vida corta: 15 min)
function generarAccessToken(usuario) {
  return jwt.sign(
    {
      sub:    usuario.id,
      email:  usuario.email,
      nombre: usuario.nombre,
    },
    process.env.JWT_SECRET,
    {
      expiresIn: process.env.JWT_EXPIRES_IN || '15m',
      issuer:    'phoenix-presupuestos',
      audience:  'phoenix-app',
    }
  );
}

// Generar refresh token (vida larga: 30 días) y guardarlo en BD
async function generarRefreshToken(usuarioId, ip, userAgent) {
  const token = crypto.randomBytes(64).toString('hex');
  const tokenHash = crypto.createHash('sha256').update(token).digest('hex');

  const expira = new Date();
  expira.setDate(expira.getDate() + 30);

  await db.query(
    `INSERT INTO refresh_tokens (usuario_id, token_hash, expira_en, ip_origen, user_agent)
     VALUES ($1, $2, $3, $4, $5)`,
    [usuarioId, tokenHash, expira, ip, userAgent]
  );

  return token;
}

// Verificar y rotar refresh token
async function rotarRefreshToken(token, ip, userAgent) {
  const tokenHash = crypto.createHash('sha256').update(token).digest('hex');

  const { rows } = await db.query(
    `SELECT rt.*, u.id as uid, u.email, u.nombre, u.creditos, u.activo
     FROM refresh_tokens rt
     JOIN usuarios u ON rt.usuario_id = u.id
     WHERE rt.token_hash = $1 AND rt.revocado = false AND rt.expira_en > NOW()`,
    [tokenHash]
  );

  if (rows.length === 0) {
    // Token inválido o expirado — posible robo de token
    // Revocar TODOS los tokens del usuario si hay señal de robo
    const { rows: stale } = await db.query(
      `SELECT usuario_id FROM refresh_tokens WHERE token_hash = $1`,
      [tokenHash]
    );
    if (stale.length > 0) {
      logger.warn('Intento de uso de refresh token ya usado — posible robo', {
        usuario_id: stale[0].usuario_id, ip
      });
      // Revocar todos los tokens del usuario
      await db.query(
        `UPDATE refresh_tokens SET revocado = true WHERE usuario_id = $1`,
        [stale[0].usuario_id]
      );
    }
    return null;
  }

  const rt = rows[0];

  if (!rt.activo) {
    throw new Error('Cuenta desactivada');
  }

  // Revocar el token usado
  await db.query(
    `UPDATE refresh_tokens SET revocado = true WHERE token_hash = $1`,
    [tokenHash]
  );

  // Generar nuevos tokens
  const usuario = { id: rt.uid, email: rt.email, nombre: rt.nombre };
  const nuevoAccessToken = generarAccessToken(usuario);
  const nuevoRefreshToken = await generarRefreshToken(rt.uid, ip, userAgent);

  return {
    accessToken:  nuevoAccessToken,
    refreshToken: nuevoRefreshToken,
    usuario:      { id: rt.uid, email: rt.email, nombre: rt.nombre, creditos: rt.creditos },
  };
}

// Revocar todos los refresh tokens de un usuario (logout)
async function revocarTodosLosTokens(usuarioId) {
  await db.query(
    `UPDATE refresh_tokens SET revocado = true WHERE usuario_id = $1`,
    [usuarioId]
  );
}

module.exports = {
  generarAccessToken,
  generarRefreshToken,
  rotarRefreshToken,
  revocarTodosLosTokens,
};
