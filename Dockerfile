FROM node:22-slim
RUN corepack enable
WORKDIR /app
COPY package.json pnpm-lock.yaml ./
RUN pnpm install --frozen-lockfile --prod && pnpm store prune
COPY src ./src
COPY config ./config
RUN mkdir -p /app/data && chown node:node /app/data
USER node
VOLUME ["/app/data"]
ENV NODE_ENV=production
CMD ["pnpm", "relay", "run", "--network", "mainnet"]
