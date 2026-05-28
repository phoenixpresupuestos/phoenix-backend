const jwt = require('jsonwebtoken');
const logger = require('../services/logger');

function autenticar(req, res, next) {
  const authHeader = req.headers['authorization'];

  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Token de acceso requerido' });
  }

  const token = authHeader.slice(7);

  try {
    const payload = jwt.verify(token, process.env.JWT_SECRET, {
      issuer:   'phoenix-presupuestos',
      audience: 'phoenix-app',
    });

    req.usuario = {
      id:     payload.sub,
      email:  payload.email,
      nombre: payload.nombre,
    };

    next();
  } catch (err) {
    if (err.name === 'TokenExpiredError') {
      return res.status(401).json({ error: 'Token expirado', code: 'TOKEN_EXPIRED' });
    }
    if (err.name === 'JsonWebTokenError') {
      logger.warn('JWT inválido', { error: err.message, ip: req.ip });
      return res.status(401).json({ error: 'Token inválido' });
    }
    return res.status(500).json({ error: 'Error de autenticación' });
  }
}

module.exports = { autenticar };
