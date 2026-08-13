# syntax=docker/dockerfile:1.7
FROM node:22-alpine AS dependencies
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci

FROM node:22-alpine AS builder
WORKDIR /app
ARG APP_VERSION=development
ARG NEXT_PUBLIC_APP_VERSION=development
ARG NEXT_PUBLIC_API_URL=https://app.hushvoting.com
ARG NEXT_PUBLIC_APP_BASE_URL=https://app.hushvoting.com
ARG NEXT_PUBLIC_MARKETING_BASE_URL=https://www.hushvoting.com
ARG NEXT_PUBLIC_DEBUG_LOGGING=false
ENV APP_VERSION=${APP_VERSION} \
    NEXT_PUBLIC_APP_VERSION=${NEXT_PUBLIC_APP_VERSION} \
    NEXT_PUBLIC_API_URL=${NEXT_PUBLIC_API_URL} \
    NEXT_PUBLIC_APP_BASE_URL=${NEXT_PUBLIC_APP_BASE_URL} \
    NEXT_PUBLIC_MARKETING_BASE_URL=${NEXT_PUBLIC_MARKETING_BASE_URL} \
    NEXT_PUBLIC_DEBUG_LOGGING=${NEXT_PUBLIC_DEBUG_LOGGING} \
    NEXT_TELEMETRY_DISABLED=1 \
    STANDALONE_BUILD=true
COPY --from=dependencies /app/node_modules ./node_modules
COPY . .
RUN npm run build:web

FROM node:22-alpine AS runner
WORKDIR /app
ENV NODE_ENV=production \
    NEXT_TELEMETRY_DISABLED=1 \
    PORT=3000 \
    HOSTNAME=0.0.0.0
RUN addgroup --system --gid 1001 nodejs \
    && adduser --system --uid 1001 nextjs
COPY --chown=nextjs:nodejs --from=builder /app/public ./public
COPY --chown=nextjs:nodejs --from=builder /app/.next-web/standalone ./
COPY --chown=nextjs:nodejs --from=builder /app/.next-web/static ./.next-web/static
# The server-side binary gRPC loader resolves these digest-pinned files at
# runtime. Next.js cannot statically trace the computed proto directory.
COPY --chown=nextjs:nodejs --from=builder /app/src/app/api/protos ./src/app/api/protos
USER nextjs
EXPOSE 3000
CMD ["node", "server.js"]
