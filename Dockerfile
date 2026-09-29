FROM node:22-slim@sha256:43ac6c60b8f89723f746e8a92ce91abd5017e627ce1ddfe4238355d3a30b772c

WORKDIR /app

RUN apt-get update && \
    apt-get upgrade -y && \
    rm -rf /var/lib/apt/lists/*

COPY package.json .
RUN npm install --omit=dev

COPY app.js .

RUN groupadd -g 10001 appgroup && \
    useradd -u 10001 -g appgroup -M -s /usr/sbin/nologin appuser && \
    chown -R 10001:10001 /app

USER 10001:10001

EXPOSE 4003

HEALTHCHECK --interval=30s --timeout=10s --start-period=15s --retries=3 \
    CMD node -e "require('http').get('http://localhost:4003/health', (res) => { process.exit(res.statusCode === 200 ? 0 : 1); }).on('error', () => process.exit(1))"

CMD ["node", "app.js"]
