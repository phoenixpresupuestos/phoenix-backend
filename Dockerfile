FROM node:20-alpine

RUN addgroup -S phoenix && adduser -S phoenix -G phoenix

WORKDIR /app

COPY package*.json ./
RUN npm install --omit=dev && npm cache clean --force

COPY src/ ./src/

RUN mkdir -p logs && chown -R phoenix:phoenix /app

USER phoenix

EXPOSE 3001

HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
  CMD wget -qO- http://localhost:3001/health || exit 1

CMD ["node", "src/index.js"]
