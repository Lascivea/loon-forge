FROM node:22-alpine

WORKDIR /app

COPY package.json ./
RUN npm install --omit=dev --no-audit --no-fund

COPY server.js ./
COPY lib ./lib
COPY public ./public

ENV PORT=8787
ENV DATA_DIR=/app/data
VOLUME ["/app/data"]

EXPOSE 8787

CMD ["node", "server.js"]
