FROM node:20-alpine

WORKDIR /app

COPY package.json ./
RUN npm install --omit=dev && npm cache clean --force

COPY src/ ./src/

RUN addgroup -S phoenix && adduser -S phoenix -G phoenix && \
    mkdir -p logs && chown -R phoenix:phoenix /app

USER phoenix

EXPOSE 3001

CMD ["node", "src/index.js"]
