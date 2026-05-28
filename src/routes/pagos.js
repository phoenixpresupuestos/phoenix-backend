const express = require('express');
const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);
const db = require('../db');
const { autenticar } = require('../middleware/auth');
const logger = require('../services/logger');

const router = express.Router();

// ─────────────────────────────────────────
// Configuración de productos (SOLO en servidor)
// Nunca exponer precios en el cliente
// ─────────────────────────────────────────
const PAQUETES = {
  '20_creditos': {
    precio_id:    process.env.STRIPE_PRICE_20_CREDITOS,
    creditos:     20,
    importe:      4000,   // 40.00 € en céntimos
    descripcion:  '20 créditos — Phoenix Presupuestos',
  },
};

// ─────────────────────────────────────────
// POST /pagos/checkout — crear sesión de pago Stripe
// ─────────────────────────────────────────
router.post('/checkout', autenticar, async (req, res) => {
  const { paquete = '20_creditos' } = req.body;

  if (!PAQUETES[paquete]) {
    return res.status(400).json({ error: 'Paquete de créditos no válido' });
  }

  const pkg = PAQUETES[paquete];

  try {
    // Obtener datos del usuario
    const { rows } = await db.query(
      'SELECT email, nombre FROM usuarios WHERE id = $1',
      [req.usuario.id]
    );
    if (rows.length === 0) return res.status(404).json({ error: 'Usuario no encontrado' });

    const usuario = rows[0];

    const session = await stripe.checkout.sessions.create({
      mode:                 'payment',
      payment_method_types: ['card'],
      customer_email:       usuario.email,
      line_items: [{
        price:    pkg.precio_id,
        quantity: 1,
      }],
      metadata: {
        usuario_id:    req.usuario.id,
        paquete:       paquete,
        creditos:      String(pkg.creditos),
      },
      success_url: `${process.env.FRONTEND_URL}/pago/exito?session={CHECKOUT_SESSION_ID}`,
      cancel_url:  `${process.env.FRONTEND_URL}/pago/cancelado`,
      payment_intent_data: {
        metadata: {
          usuario_id: req.usuario.id,
          paquete:    paquete,
        },
      },
      // Caducidad de 30 minutos
      expires_at: Math.floor(Date.now() / 1000) + 1800,
    });

    // Registrar pago pendiente
    await db.query(
      `INSERT INTO pagos (usuario_id, stripe_session_id, importe, creditos_comprados, estado, metadata)
       VALUES ($1, $2, $3, $4, 'pendiente', $5)`,
      [
        req.usuario.id,
        session.id,
        pkg.importe / 100,
        pkg.creditos,
        JSON.stringify({ paquete }),
      ]
    );

    logger.info('Sesión de pago creada', {
      usuario_id: req.usuario.id,
      session_id: session.id,
      paquete,
    });

    return res.json({ url: session.url, session_id: session.id });

  } catch (err) {
    logger.error('Error creando sesión Stripe', { error: err.message });
    return res.status(500).json({ error: 'Error al procesar el pago' });
  }
});

// ─────────────────────────────────────────
// POST /pagos/webhook — recibir eventos de Stripe
// IMPORTANTE: este endpoint usa el body RAW (sin JSON.parse)
// ─────────────────────────────────────────
router.post('/webhook',
  express.raw({ type: 'application/json' }),  // body RAW para verificar firma
  async (req, res) => {
    const sig = req.headers['stripe-signature'];

    let event;
    try {
      event = stripe.webhooks.constructEvent(
        req.body,
        sig,
        process.env.STRIPE_WEBHOOK_SECRET
      );
    } catch (err) {
      logger.warn('Webhook Stripe inválido', { error: err.message });
      return res.status(400).json({ error: `Webhook inválido: ${err.message}` });
    }

    // Procesar evento
    try {
      switch (event.type) {

        case 'checkout.session.completed': {
          const session = event.data.object;

          if (session.payment_status !== 'paid') break;

          const usuarioId = session.metadata?.usuario_id;
          const creditos  = parseInt(session.metadata?.creditos) || 0;

          if (!usuarioId || !creditos) {
            logger.error('Webhook: metadata incompleta', { session_id: session.id });
            break;
          }

          // Verificar que no se ha procesado ya (idempotencia)
          const { rows: pago } = await db.query(
            `SELECT estado FROM pagos WHERE stripe_session_id = $1`,
            [session.id]
          );

          if (pago.length > 0 && pago[0].estado === 'completado') {
            logger.info('Webhook: pago ya procesado (idempotente)', { session_id: session.id });
            break;
          }

          // Transacción atómica: actualizar pago + añadir créditos
          await db.transaction(async (client) => {
            // Actualizar pago
            await client.query(
              `UPDATE pagos SET
                estado = 'completado',
                stripe_payment_intent = $1,
                completado_en = NOW()
               WHERE stripe_session_id = $2`,
              [session.payment_intent, session.id]
            );

            // Añadir créditos con función atómica
            await client.query(
              `SELECT anadir_creditos($1, $2, 'compra', $3, $4)`,
              [
                usuarioId,
                creditos,
                session.id,
                `Compra de ${creditos} créditos vía Stripe`,
              ]
            );
          });

          logger.info('Pago completado — créditos añadidos', {
            usuario_id: usuarioId,
            creditos,
            session_id: session.id,
          });
          break;
        }

        case 'checkout.session.expired': {
          const session = event.data.object;
          await db.query(
            `UPDATE pagos SET estado = 'fallido' WHERE stripe_session_id = $1`,
            [session.id]
          );
          break;
        }

        case 'charge.dispute.created': {
          // Alerta de contracargo — log inmediato
          logger.warn('CONTRACARGO CREADO', {
            charge_id: event.data.object.charge,
            amount:    event.data.object.amount,
          });
          break;
        }

        default:
          logger.debug('Evento Stripe no manejado', { type: event.type });
      }

      return res.json({ recibido: true });

    } catch (err) {
      logger.error('Error procesando webhook', { type: event.type, error: err.message });
      return res.status(500).json({ error: 'Error procesando evento' });
    }
  }
);

// ─────────────────────────────────────────
// GET /pagos/historial — historial de pagos
// ─────────────────────────────────────────
router.get('/historial', autenticar, async (req, res) => {
  try {
    const { rows } = await db.query(
      `SELECT stripe_session_id, importe, creditos_comprados, estado, creado_en, completado_en
       FROM pagos WHERE usuario_id = $1
       ORDER BY creado_en DESC LIMIT 50`,
      [req.usuario.id]
    );
    return res.json(rows);
  } catch (err) {
    return res.status(500).json({ error: 'Error al obtener historial' });
  }
});

// ─────────────────────────────────────────
// GET /pagos/creditos — saldo actual
// ─────────────────────────────────────────
router.get('/creditos', autenticar, async (req, res) => {
  try {
    const { rows } = await db.query(
      'SELECT creditos FROM usuarios WHERE id = $1',
      [req.usuario.id]
    );
    if (rows.length === 0) return res.status(404).json({ error: 'Usuario no encontrado' });
    return res.json({ creditos: rows[0].creditos });
  } catch (err) {
    return res.status(500).json({ error: 'Error al obtener créditos' });
  }
});

// ─────────────────────────────────────────
// GET /pagos/movimientos — historial de créditos
// ─────────────────────────────────────────
router.get('/movimientos', autenticar, async (req, res) => {
  try {
    const { rows } = await db.query(
      `SELECT tipo, cantidad, saldo_anterior, saldo_posterior, descripcion, creado_en
       FROM movimientos_creditos WHERE usuario_id = $1
       ORDER BY creado_en DESC LIMIT 100`,
      [req.usuario.id]
    );
    return res.json(rows);
  } catch (err) {
    return res.status(500).json({ error: 'Error al obtener movimientos' });
  }
});

module.exports = router;
