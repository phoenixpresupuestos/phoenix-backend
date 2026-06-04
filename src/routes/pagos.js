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
  'vivienda_normal': {
    precio_id:   process.env.STRIPE_PRICE_VIVIENDA_NORMAL,
    creditos:    5,
    importe:     3000,   // 30.00 € en céntimos
    descripcion: 'Vivienda Normal — hasta 5 estancias (5 créditos)',
    modo:        'payment',
  },
  'vivienda_grande': {
    precio_id:   process.env.STRIPE_PRICE_VIVIENDA_GRANDE,
    creditos:    7,
    importe:     5000,   // 50.00 € en céntimos
    descripcion: 'Vivienda Grande — hasta 7 estancias (7 créditos)',
    modo:        'payment',
  },
  'acceso_libre': {
    precio_id:   process.env.STRIPE_PRICE_ACCESO_LIBRE,
    creditos:    null,   // ilimitados — gestionado por suscripción activa
    importe:     7500,   // 75.00 € en céntimos
    descripcion: 'Acceso Libre — créditos ilimitados (suscripción mensual)',
    modo:        'subscription',
  },
};

// ─────────────────────────────────────────
// POST /pagos/checkout — crear sesión de pago Stripe
// ─────────────────────────────────────────
router.post('/checkout', autenticar, async (req, res) => {
  const { paquete } = req.body;

  if (!paquete || !PAQUETES[paquete]) {
    return res.status(400).json({
      error: 'Plan no válido. Opciones: vivienda_normal, vivienda_grande, acceso_libre',
    });
  }

  const pkg = PAQUETES[paquete];

  try {
    const { rows } = await db.query(
      'SELECT email, nombre, stripe_subscription_id FROM usuarios WHERE id = $1',
      [req.usuario.id]
    );
    if (rows.length === 0) return res.status(404).json({ error: 'Usuario no encontrado' });

    const usuario = rows[0];

    // Evitar doble suscripción activa
    if (paquete === 'acceso_libre' && usuario.stripe_subscription_id) {
      return res.status(409).json({ error: 'Ya tienes una suscripción activa' });
    }

    const sessionParams = {
      payment_method_types: ['card'],
      customer_email:       usuario.email,
      metadata: {
        usuario_id: String(req.usuario.id),
        paquete,
        creditos:   pkg.creditos !== null ? String(pkg.creditos) : 'ilimitados',
      },
      success_url: `${process.env.FRONTEND_URL}/pago-ok.html?session={CHECKOUT_SESSION_ID}`,
      cancel_url:  `${process.env.FRONTEND_URL}/phai-app.html`,
    };

    if (pkg.modo === 'payment') {
      sessionParams.mode = 'payment';
      sessionParams.line_items = [{ price: pkg.precio_id, quantity: 1 }];
      sessionParams.expires_at = Math.floor(Date.now() / 1000) + 1800; // 30 min
      sessionParams.payment_intent_data = {
        metadata: { usuario_id: String(req.usuario.id), paquete },
      };
    } else {
      // suscripción
      sessionParams.mode = 'subscription';
      sessionParams.line_items = [{ price: pkg.precio_id, quantity: 1 }];
      sessionParams.subscription_data = {
        metadata: { usuario_id: String(req.usuario.id), paquete },
      };
    }

    const session = await stripe.checkout.sessions.create(sessionParams);

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
// IMPORTANTE: body RAW (configurado en index.js)
// ─────────────────────────────────────────
router.post('/webhook', async (req, res) => {
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

  try {
    switch (event.type) {

      // ── Pago único completado ─────────────────────────────
      case 'checkout.session.completed': {
        const session = event.data.object;

        if (session.mode === 'payment' && session.payment_status !== 'paid') break;

        const usuarioId = session.metadata?.usuario_id;
        const paquete   = session.metadata?.paquete;
        const pkg       = PAQUETES[paquete];

        if (!usuarioId || !pkg) {
          logger.error('Webhook: metadata incompleta', { session_id: session.id });
          break;
        }

        // Idempotencia
        const { rows: pago } = await db.query(
          `SELECT estado FROM pagos WHERE stripe_session_id = $1`,
          [session.id]
        );
        if (pago.length > 0 && pago[0].estado === 'completado') {
          logger.info('Webhook: pago ya procesado (idempotente)', { session_id: session.id });
          break;
        }

        if (session.mode === 'payment') {
          // Pago único — añadir créditos
          const creditos = pkg.creditos;
          await db.transaction(async (client) => {
            await client.query(
              `UPDATE pagos SET estado = 'completado', stripe_payment_intent = $1, completado_en = NOW()
               WHERE stripe_session_id = $2`,
              [session.payment_intent, session.id]
            );
            await client.query(
              `SELECT anadir_creditos($1, $2, 'compra', $3, $4)`,
              [usuarioId, creditos, session.id, `Compra ${pkg.descripcion}`]
            );
          });
          logger.info('Pago único completado — créditos añadidos', { usuarioId, creditos, session_id: session.id });

        } else if (session.mode === 'subscription') {
          // Suscripción — guardar subscription_id, marcar acceso libre
          const subscriptionId = session.subscription;
          await db.transaction(async (client) => {
            await client.query(
              `UPDATE pagos SET estado = 'completado', completado_en = NOW()
               WHERE stripe_session_id = $1`,
              [session.id]
            );
            await client.query(
              `UPDATE usuarios SET stripe_subscription_id = $1, creditos = -1
               WHERE id = $2`,
              [subscriptionId, usuarioId]
            );
            // creditos = -1 significa acceso ilimitado — verificar en consumir_creditos()
          });
          logger.info('Suscripción activada — acceso libre', { usuarioId, subscriptionId });
        }
        break;
      }

      // ── Suscripción cancelada ─────────────────────────────
      case 'customer.subscription.deleted': {
        const subscription = event.data.object;
        const { rows } = await db.query(
          `SELECT id FROM usuarios WHERE stripe_subscription_id = $1`,
          [subscription.id]
        );
        if (rows.length > 0) {
          await db.query(
            `UPDATE usuarios SET stripe_subscription_id = NULL, creditos = 0 WHERE id = $1`,
            [rows[0].id]
          );
          logger.info('Suscripción cancelada — acceso libre revocado', { usuario_id: rows[0].id });
        }
        break;
      }

      // ── Sesión expirada ───────────────────────────────────
      case 'checkout.session.expired': {
        const session = event.data.object;
        await db.query(
          `UPDATE pagos SET estado = 'fallido' WHERE stripe_session_id = $1`,
          [session.id]
        );
        break;
      }

      // ── Contracargo ───────────────────────────────────────
      case 'charge.dispute.created': {
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
});

// ─────────────────────────────────────────
// GET /pagos/historial
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
      'SELECT creditos, stripe_subscription_id FROM usuarios WHERE id = $1',
      [req.usuario.id]
    );
    if (rows.length === 0) return res.status(404).json({ error: 'Usuario no encontrado' });

    const { creditos, stripe_subscription_id } = rows[0];
    const acceso_libre = !!stripe_subscription_id;

    return res.json({
      creditos:     acceso_libre ? null : creditos,
      acceso_libre,
    });
  } catch (err) {
    return res.status(500).json({ error: 'Error al obtener créditos' });
  }
});

// ─────────────────────────────────────────
// GET /pagos/movimientos
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

// ─────────────────────────────────────────
// GET /pagos/planes — info pública de planes
// ─────────────────────────────────────────
router.get('/planes', (req, res) => {
  return res.json([
    {
      id:          'vivienda_normal',
      nombre:      'Vivienda Normal',
      descripcion: 'Hasta 5 estancias',
      precio:      30,
      creditos:    5,
      tipo:        'pago_unico',
    },
    {
      id:          'vivienda_grande',
      nombre:      'Vivienda Grande',
      descripcion: 'Hasta 7 estancias',
      precio:      50,
      creditos:    7,
      tipo:        'pago_unico',
    },
    {
      id:          'acceso_libre',
      nombre:      'Acceso Libre',
      descripcion: 'Créditos ilimitados',
      precio:      75,
      creditos:    null,
      tipo:        'suscripcion_mensual',
    },
  ]);
});

module.exports = router;
