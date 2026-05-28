FROM node:20-alpine

# Seguridad: usuario no root
RUN addgroup -S phoenix && adduser -S phoenix -G phoenix

WORKDIR /app

# Instalar dependencias primero (cache de capas)
COPY package*.json ./
RUN npm ci --only=production && npm cache clean --force

# Copiar código fuente
COPY src/ ./src/

# Crear directorio de logs con permisos correctos
RUN mkdir -p logs && chown -R phoenix:phoenix /app

# Cambiar a usuario no root
USER phoenix

# Puerto de la aplicación
EXPOSE 3001

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
  CMD wget -qO- http://localhost:3001/health || exit 1

CMD ["node", "src/index.js"]
