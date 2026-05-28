-- ═══════════════════════════════════════════════════
-- PHOENIX PRESUPUESTOS — Schema PostgreSQL
-- Ejecutar una sola vez para crear las tablas
-- ═══════════════════════════════════════════════════

-- Extensiones
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- ──────────────────────────────────────────
-- TABLA: usuarios (reformistas)
-- ──────────────────────────────────────────
CREATE TABLE IF NOT EXISTS usuarios (
  id            UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  email         VARCHAR(255) UNIQUE NOT NULL,
  password_hash VARCHAR(255) NOT NULL,
  nombre        VARCHAR(255) NOT NULL,
  empresa       VARCHAR(255),
  nif           VARCHAR(20),
  telefono      VARCHAR(20),
  creditos      INTEGER NOT NULL DEFAULT 0,
  activo        BOOLEAN NOT NULL DEFAULT true,
  email_verificado BOOLEAN NOT NULL DEFAULT false,
  token_verificacion VARCHAR(255),
  creado_en     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  actualizado_en TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_usuarios_email ON usuarios(email);

-- ──────────────────────────────────────────
-- TABLA: refresh_tokens
-- ──────────────────────────────────────────
CREATE TABLE IF NOT EXISTS refresh_tokens (
  id            UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  usuario_id    UUID NOT NULL REFERENCES usuarios(id) ON DELETE CASCADE,
  token_hash    VARCHAR(255) NOT NULL,
  expira_en     TIMESTAMPTZ NOT NULL,
  creado_en     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  revocado      BOOLEAN NOT NULL DEFAULT false,
  ip_origen     INET,
  user_agent    TEXT
);

CREATE INDEX idx_refresh_tokens_usuario ON refresh_tokens(usuario_id);
CREATE INDEX idx_refresh_tokens_hash ON refresh_tokens(token_hash);

-- ──────────────────────────────────────────
-- TABLA: presupuestos
-- ──────────────────────────────────────────
CREATE TABLE IF NOT EXISTS presupuestos (
  id            UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  usuario_id    UUID NOT NULL REFERENCES usuarios(id) ON DELETE CASCADE,
  referencia    VARCHAR(50) UNIQUE NOT NULL,  -- P-2024-001 etc.
  datos         JSONB NOT NULL,               -- el wData completo
  partidas      JSONB NOT NULL,               -- calcPartidas resultado
  total_estimado NUMERIC(10,2),
  nivel         VARCHAR(20) DEFAULT 'detallado',
  calidad       VARCHAR(20) DEFAULT 'media',
  estancias     INTEGER NOT NULL DEFAULT 1,   -- nº estancias = créditos consumidos
  cliente_nombre VARCHAR(255),
  cliente_email  VARCHAR(255),
  cliente_telefono VARCHAR(255),
  pdf_generado  BOOLEAN DEFAULT false,
  creado_en     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  actualizado_en TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_presupuestos_usuario ON presupuestos(usuario_id);
CREATE INDEX idx_presupuestos_creado ON presupuestos(creado_en DESC);

-- ──────────────────────────────────────────
-- TABLA: pagos (historial Stripe)
-- ──────────────────────────────────────────
CREATE TABLE IF NOT EXISTS pagos (
  id                UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  usuario_id        UUID NOT NULL REFERENCES usuarios(id) ON DELETE CASCADE,
  stripe_session_id VARCHAR(255) UNIQUE NOT NULL,
  stripe_payment_intent VARCHAR(255),
  importe           NUMERIC(10,2) NOT NULL,    -- 40.00 €
  creditos_comprados INTEGER NOT NULL,          -- 20
  estado            VARCHAR(50) NOT NULL DEFAULT 'pendiente',  -- pendiente|completado|fallido|reembolsado
  metadata          JSONB,
  creado_en         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  completado_en     TIMESTAMPTZ
);

CREATE INDEX idx_pagos_usuario ON pagos(usuario_id);
CREATE INDEX idx_pagos_stripe_session ON pagos(stripe_session_id);

-- ──────────────────────────────────────────
-- TABLA: movimientos_creditos (auditoría)
-- ──────────────────────────────────────────
CREATE TABLE IF NOT EXISTS movimientos_creditos (
  id            UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  usuario_id    UUID NOT NULL REFERENCES usuarios(id) ON DELETE CASCADE,
  tipo          VARCHAR(50) NOT NULL,   -- compra|consumo|bonus|ajuste
  cantidad      INTEGER NOT NULL,       -- positivo=añadir, negativo=consumir
  saldo_anterior INTEGER NOT NULL,
  saldo_posterior INTEGER NOT NULL,
  referencia    VARCHAR(255),           -- presupuesto ID o pago ID
  descripcion   TEXT,
  creado_en     TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_movimientos_usuario ON movimientos_creditos(usuario_id);

-- ──────────────────────────────────────────
-- FUNCIÓN: actualizar timestamp
-- ──────────────────────────────────────────
CREATE OR REPLACE FUNCTION actualizar_timestamp()
RETURNS TRIGGER AS $$
BEGIN
  NEW.actualizado_en = NOW();
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER tr_usuarios_actualizar
  BEFORE UPDATE ON usuarios
  FOR EACH ROW EXECUTE FUNCTION actualizar_timestamp();

CREATE TRIGGER tr_presupuestos_actualizar
  BEFORE UPDATE ON presupuestos
  FOR EACH ROW EXECUTE FUNCTION actualizar_timestamp();

-- ──────────────────────────────────────────
-- FUNCIÓN: consumir créditos (atómica)
-- ──────────────────────────────────────────
CREATE OR REPLACE FUNCTION consumir_creditos(
  p_usuario_id UUID,
  p_cantidad INTEGER,
  p_referencia VARCHAR DEFAULT NULL,
  p_descripcion TEXT DEFAULT NULL
) RETURNS TABLE(ok BOOLEAN, saldo_nuevo INTEGER, mensaje TEXT) AS $$
DECLARE
  v_saldo_actual INTEGER;
BEGIN
  -- Bloquear la fila para evitar race conditions
  SELECT creditos INTO v_saldo_actual
  FROM usuarios
  WHERE id = p_usuario_id
  FOR UPDATE;

  IF v_saldo_actual IS NULL THEN
    RETURN QUERY SELECT false, 0, 'Usuario no encontrado';
    RETURN;
  END IF;

  IF v_saldo_actual < p_cantidad THEN
    RETURN QUERY SELECT false, v_saldo_actual, 'Créditos insuficientes';
    RETURN;
  END IF;

  -- Actualizar saldo
  UPDATE usuarios SET creditos = creditos - p_cantidad
  WHERE id = p_usuario_id;

  -- Registrar movimiento
  INSERT INTO movimientos_creditos
    (usuario_id, tipo, cantidad, saldo_anterior, saldo_posterior, referencia, descripcion)
  VALUES
    (p_usuario_id, 'consumo', -p_cantidad, v_saldo_actual, v_saldo_actual - p_cantidad, p_referencia, p_descripcion);

  RETURN QUERY SELECT true, v_saldo_actual - p_cantidad, 'OK';
END;
$$ LANGUAGE plpgsql;

-- ──────────────────────────────────────────
-- FUNCIÓN: añadir créditos (tras pago)
-- ──────────────────────────────────────────
CREATE OR REPLACE FUNCTION anadir_creditos(
  p_usuario_id UUID,
  p_cantidad INTEGER,
  p_tipo VARCHAR DEFAULT 'compra',
  p_referencia VARCHAR DEFAULT NULL,
  p_descripcion TEXT DEFAULT NULL
) RETURNS INTEGER AS $$
DECLARE
  v_saldo_anterior INTEGER;
  v_saldo_nuevo INTEGER;
BEGIN
  SELECT creditos INTO v_saldo_anterior
  FROM usuarios WHERE id = p_usuario_id FOR UPDATE;

  UPDATE usuarios SET creditos = creditos + p_cantidad
  WHERE id = p_usuario_id
  RETURNING creditos INTO v_saldo_nuevo;

  INSERT INTO movimientos_creditos
    (usuario_id, tipo, cantidad, saldo_anterior, saldo_posterior, referencia, descripcion)
  VALUES
    (p_usuario_id, p_tipo, p_cantidad, v_saldo_anterior, v_saldo_nuevo, p_referencia, p_descripcion);

  RETURN v_saldo_nuevo;
END;
$$ LANGUAGE plpgsql;
