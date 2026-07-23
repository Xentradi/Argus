FROM node:22-bookworm-slim AS build

WORKDIR /app
RUN corepack enable && apt-get update && apt-get install -y --no-install-recommends build-essential python3 && rm -rf /var/lib/apt/lists/*

COPY package.json pnpm-lock.yaml ./
RUN pnpm install --frozen-lockfile --prod

COPY . ./

FROM node:22-bookworm-slim

ENV NODE_ENV=production
WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends iputils-ping && rm -rf /var/lib/apt/lists/*

COPY --from=build --chown=node:node /app /app

USER node
EXPOSE 3000
CMD ["node", "src/app.js"]
