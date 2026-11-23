const express = require('express');
const { body, param, validationResult } = require('express-validator');
const db = require('../db');
const { autenticar } = require('../middleware/auth');
const logger = require('../services/logger');

const router = express.Router();

// Acceso privado: solo la cuenta indicada en la variable de entorno VERIF_EMAIL.
// Si la variable no existe, nadie puede entrar.
function soloPropietario(req, res, next) {
  const permitido = String(process.env.VERIF_EMAIL || '').trim().toLowerCase();
  const email = String(req.usuario && req.usuario.email || '').trim().toLowerCase();
  if (!permitido || email !== permitido) {
    logger.warn('Acceso denegado a verificaciones', { usuario: req.usuario && req.usuario.id, ip: req.ip });
    return res.status(403).json({ error: 'Acceso no autorizado' });
  }
  next();
}
router.use(autenticar, soloPropietario);
const ESTADOS = ['en_curso', 'verificado', 'parado'];

const validar = [
  body('cliente_nombre').trim().notEmpty().withMessage('Nombre del cliente requerido').isLength({ max: 255 }),
  body('telefono').optional({ nullable: true }).trim().isLength({ max: 30 }),
  body('direccion').optional({ nullable: true }).trim().isLength({ max: 500 }),
  body('notas').optional({ nullable: true }).isLength({ max: 20000 }),
  body('checks').optional().isObject(),
  body('alarmas').optional().isObject(),
  body('estado').optional().isIn(ESTADOS),
];
const idValido = param('id').isInt({ min: 1 });

function errores(req, res) {
  const e = validationResult(req);
  if (!e.isEmpty()) { res.status(400).json({ errores: e.array() }); return true; }
  return false;
}

// GET /verificaciones — listado del usuario
router.get('/', autenticar, async (req, res) => {
  try {
    const { rows } = await db.query(
      `SELECT id, cliente_nombre, telefono, direccion, estado, creado_en, actualizado_en
       FROM verificaciones_clientes WHERE usuario_id = $1
       ORDER BY actualizado_en DESC`,
      [req.usuario.id]
    );
    return res.json({ verificaciones: rows });
  } catch (err) {
    logger.error('Error listando verificaciones', { error: err.message });
    return res.status(500).json({ error: 'Error al obtener verificaciones' });
  }
});

// GET /verificaciones/:id — detalle
router.get('/:id', autenticar, idValido, async (req, res) => {
  if (errores(req, res)) return;
  try {
    const { rows } = await db.query(
      'SELECT * FROM verificaciones_clientes WHERE id = $1 AND usuario_id = $2',
      [req.params.id, req.usuario.id]
    );
    if (!rows.length) return res.status(404).json({ error: 'Ficha no encontrada' });
    return res.json(rows[0]);
  } catch (err) {
    return res.status(500).json({ error: 'Error al obtener la ficha' });
  }
});

// POST /verificaciones — crear
router.post('/', autenticar, validar, async (req, res) => {
  if (errores(req, res)) return;
  const { cliente_nombre, telefono = null, direccion = null, notas = null,
          checks = {}, alarmas = {}, estado = 'en_curso' } = req.body;
  try {
    const { rows } = await db.query(
      `INSERT INTO verificaciones_clientes
        (usuario_id, cliente_nombre, telefono, direccion, notas, checks, alarmas, estado)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8) RETURNING *`,
      [req.usuario.id, cliente_nombre, telefono, direccion, notas,
       JSON.stringify(checks), JSON.stringify(alarmas), estado]
    );
    return res.status(201).json(rows[0]);
  } catch (err) {
    logger.error('Error creando verificación', { error: err.message });
    return res.status(500).json({ error: 'Error al guardar la ficha' });
  }
});

// PUT /verificaciones/:id — actualizar
router.put('/:id', autenticar, idValido, validar, async (req, res) => {
  if (errores(req, res)) return;
  const { cliente_nombre, telefono = null, direccion = null, notas = null,
          checks = {}, alarmas = {}, estado = 'en_curso' } = req.body;
  try {
    const { rows } = await db.query(
      `UPDATE verificaciones_clientes
       SET cliente_nombre=$3, telefono=$4, direccion=$5, notas=$6,
           checks=$7, alarmas=$8, estado=$9, actualizado_en=NOW()
       WHERE id=$1 AND usuario_id=$2 RETURNING *`,
      [req.params.id, req.usuario.id, cliente_nombre, telefono, direccion, notas,
       JSON.stringify(checks), JSON.stringify(alarmas), estado]
    );
    if (!rows.length) return res.status(404).json({ error: 'Ficha no encontrada' });
    return res.json(rows[0]);
  } catch (err) {
    logger.error('Error actualizando verificación', { error: err.message });
    return res.status(500).json({ error: 'Error al guardar la ficha' });
  }
});

// DELETE /verificaciones/:id — borrar
router.delete('/:id', autenticar, idValido, async (req, res) => {
  if (errores(req, res)) return;
  try {
    const { rowCount } = await db.query(
      'DELETE FROM verificaciones_clientes WHERE id=$1 AND usuario_id=$2',
      [req.params.id, req.usuario.id]
    );
    if (!rowCount) return res.status(404).json({ error: 'Ficha no encontrada' });
    return res.json({ ok: true });
  } catch (err) {
    return res.status(500).json({ error: 'Error al borrar la ficha' });
  }
});

module.exports = router;
