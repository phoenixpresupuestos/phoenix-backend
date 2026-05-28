const express = require('express');
const { body, validationResult } = require('express-validator');
const rateLimit = require('express-rate-limit');
const db = require('../db');
const { autenticar } = require('../middleware/auth');
const logger = require('../services/logger');

const router = express.Router();

// Rate limit: máximo 30 presupuestos por hora
const presLimiter = rateLimit({
  windowMs: 60 * 60 * 1000,
  max: 30,
  message: { error: 'Límite de presupuestos por hora alcanzado' },
  keyGenerator: (req) => req.usuario?.id || req.ip,
});

// ─────────────────────────────────────────
// Generar referencia única P-YYYY-NNNN
// ─────────────────────────────────────────
async function generarReferencia() {
  const anio = new Date().getFullYear();
  const { rows } = await db.query(
    `SELECT COUNT(*) as n FROM presupuestos
     WHERE EXTRACT(YEAR FROM creado_en) = $1`,
    [anio]
  );
  const n = parseInt(rows[0].n) + 1;
  return `P-${anio}-${String(n).padStart(4, '0')}`;
}

// ─────────────────────────────────────────
// POST /presupuestos — guardar (consume créditos)
// ─────────────────────────────────────────
router.post('/',
  autenticar,
  presLimiter,
  [
    body('datos').isObject().withMessage('Datos del presupuesto requeridos'),
    body('partidas').isArray().withMessage('Partidas requeridas'),
    body('estancias').isInt({ min: 1, max: 50 }).withMessage('Número de estancias inválido'),
    body('total_estimado').isFloat({ min: 0 }).withMessage('Total inválido'),
    body('nivel').optional().isIn(['somero', 'detallado']),
    body('calidad').optional().isIn(['basica', 'media', 'alta']),
    body('cliente_nombre').optional().trim().isLength({ max: 255 }),
    body('cliente_email').optional().isEmail().normalizeEmail(),
    body('cliente_telefono').optional().trim().isLength({ max: 20 }),
  ],
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errores: errors.array() });
    }

    const {
      datos, partidas, estancias, total_estimado,
      nivel = 'detallado', calidad = 'media',
      cliente_nombre, cliente_email, cliente_telefono,
    } = req.body;

    try {
      // Consumir créditos de forma atómica
      const { rows: resultado } = await db.query(
        `SELECT * FROM consumir_creditos($1, $2, NULL, $3)`,
        [
          req.usuario.id,
          estancias,
          `Presupuesto con ${estancias} estancia(s)`,
        ]
      );

      const r = resultado[0];

      if (!r.ok) {
        return res.status(402).json({
          error: r.mensaje,
          creditos_actuales: r.saldo_nuevo,
          code: 'CREDITOS_INSUFICIENTES',
        });
      }

      // Crear presupuesto
      const referencia = await generarReferencia();

      const { rows: pres } = await db.query(
        `INSERT INTO presupuestos
           (usuario_id, referencia, datos, partidas, total_estimado, nivel, calidad,
            estancias, cliente_nombre, cliente_email, cliente_telefono)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
         RETURNING id, referencia, total_estimado, estancias, creado_en`,
        [
          req.usuario.id,
          referencia,
          JSON.stringify(datos),
          JSON.stringify(partidas),
          total_estimado,
          nivel,
          calidad,
          estancias,
          cliente_nombre || null,
          cliente_email || null,
          cliente_telefono || null,
        ]
      );

      // Actualizar referencia en movimiento de créditos
      await db.query(
        `UPDATE movimientos_creditos SET referencia = $1
         WHERE usuario_id = $2 AND tipo = 'consumo'
         ORDER BY creado_en DESC LIMIT 1`,
        [pres[0].id, req.usuario.id]
      );

      logger.info('Presupuesto guardado', {
        usuario_id:  req.usuario.id,
        presupuesto: pres[0].id,
        estancias,
        creditos_restantes: r.saldo_nuevo,
      });

      return res.status(201).json({
        presupuesto:        pres[0],
        creditos_restantes: r.saldo_nuevo,
      });

    } catch (err) {
      logger.error('Error guardando presupuesto', { error: err.message });
      return res.status(500).json({ error: 'Error interno del servidor' });
    }
  }
);

// ─────────────────────────────────────────
// GET /presupuestos — listar del usuario
// ─────────────────────────────────────────
router.get('/', autenticar, async (req, res) => {
  const pagina = Math.max(1, parseInt(req.query.pagina) || 1);
  const limite = Math.min(50, parseInt(req.query.limite) || 20);
  const offset = (pagina - 1) * limite;

  try {
    const { rows } = await db.query(
      `SELECT id, referencia, total_estimado, estancias, nivel, calidad,
              cliente_nombre, cliente_email, pdf_generado, creado_en
       FROM presupuestos
       WHERE usuario_id = $1
       ORDER BY creado_en DESC
       LIMIT $2 OFFSET $3`,
      [req.usuario.id, limite, offset]
    );

    const { rows: total } = await db.query(
      'SELECT COUNT(*) as n FROM presupuestos WHERE usuario_id = $1',
      [req.usuario.id]
    );

    return res.json({
      presupuestos: rows,
      total:        parseInt(total[0].n),
      pagina,
      limite,
    });
  } catch (err) {
    return res.status(500).json({ error: 'Error al obtener presupuestos' });
  }
});

// ─────────────────────────────────────────
// GET /presupuestos/:id — detalle
// ─────────────────────────────────────────
router.get('/:id', autenticar, async (req, res) => {
  try {
    const { rows } = await db.query(
      `SELECT * FROM presupuestos
       WHERE id = $1 AND usuario_id = $2`,
      [req.params.id, req.usuario.id]
    );

    if (rows.length === 0) {
      return res.status(404).json({ error: 'Presupuesto no encontrado' });
    }

    return res.json(rows[0]);
  } catch (err) {
    return res.status(500).json({ error: 'Error al obtener presupuesto' });
  }
});

module.exports = router;
