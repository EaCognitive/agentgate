# AgentGate Dashboard - Production-Ready Multi-Stage Build
# Security: Non-root user, health checks, minimal attack surface
# Build arguments for metadata
ARG NODE_ENV=production
ARG BUILD_DATE
ARG VERSION=1.0.0

# Stage 1: Base image with security updates
FROM node:20-alpine AS base

# Install security updates and required runtime dependencies
RUN apk update && apk upgrade --no-cache && \
    apk add --no-cache libc6-compat dumb-init && \
    rm -rf /var/cache/apk/*

WORKDIR /app

# Stage 2: Install dependencies
FROM base AS deps

# Copy package files
COPY package.json package-lock.json* ./

# Install production dependencies
RUN npm ci --omit=dev --legacy-peer-deps && \
    npm cache clean --force

# Install all dependencies (including dev) for building
FROM base AS deps-build

COPY package.json package-lock.json* ./

RUN npm ci --legacy-peer-deps && \
    npm cache clean --force

# Stage 3: Build the application
FROM base AS builder

ARG NODE_ENV
ENV NODE_ENV=${NODE_ENV}
ENV NEXT_TELEMETRY_DISABLED=1

# Copy dependencies
COPY --from=deps-build /app/node_modules ./node_modules

# Copy application source
COPY . .

# Build Next.js application (standalone mode configured in next.config.mjs)
RUN npm run build

# Stage 4: Production runtime
FROM base AS runner

ARG BUILD_DATE
ARG VERSION
ARG NODE_ENV=production

# Add image metadata (OCI labels)
LABEL org.opencontainers.image.created="${BUILD_DATE}" \
      org.opencontainers.image.authors="Erick Aleman" \
      org.opencontainers.image.url="https://github.com/EaCognitive/agentgate" \
      org.opencontainers.image.documentation="https://github.com/EaCognitive/agentgate#readme" \
      org.opencontainers.image.source="https://github.com/EaCognitive/agentgate" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.vendor="AgentGate" \
      org.opencontainers.image.title="AgentGate Dashboard" \
      org.opencontainers.image.description="Web dashboard for AgentGate"

WORKDIR /app

ENV NODE_ENV=${NODE_ENV}
ENV NEXT_TELEMETRY_DISABLED=1
ENV PORT=3000
ENV HOSTNAME="0.0.0.0"

# Create non-root user with no login shell
RUN addgroup --system --gid 1001 nodejs && \
    adduser --system --uid 1001 --ingroup nodejs --shell /sbin/nologin nextjs

# Copy only production dependencies
COPY --from=deps --chown=nextjs:nodejs /app/node_modules ./node_modules

# Copy built application from builder
COPY --from=builder --chown=nextjs:nodejs /app/public ./public
COPY --from=builder --chown=nextjs:nodejs /app/.next/standalone ./standalone
COPY --from=builder --chown=nextjs:nodejs /app/.next/static ./.next/static

# Next.js standalone output path differs by project layout (e.g. standalone/server.js,
# standalone/app/server.js, standalone/app/dashboard/server.js).
# Locate server.js dynamically and normalize it to /app/server.js layout.
RUN set -eu; \
    SERVER_PATH="$(find /app/standalone -path '*/node_modules/*' -prune -o -type f -name server.js -print | head -n 1)"; \
    if [ -z "${SERVER_PATH}" ]; then \
      echo "ERROR: standalone server.js not found"; \
      find /app/standalone -maxdepth 6 -type f | sort || true; \
      exit 1; \
    fi; \
    SERVER_DIR="$(dirname "${SERVER_PATH}")"; \
    cp -a "${SERVER_DIR}"/. /app/; \
    rm -rf /app/standalone

# Create cache directory with proper permissions
RUN mkdir -p /app/.next/cache /tmp && \
    chown -R nextjs:nodejs /app/.next/cache /tmp && \
    chmod 700 /app/.next/cache /tmp

# Switch to non-root user
USER nextjs

# Expose port
EXPOSE 3000

# Health check with proper error handling
HEALTHCHECK --interval=30s --timeout=10s --start-period=60s --retries=3 \
    CMD node -e "require('http').get('http://localhost:3000/', (r) => {if(r.statusCode >= 400) throw new Error('Status: ' + r.statusCode)}).on('error', (e) => {throw e})"

# Use dumb-init to handle signals properly
ENTRYPOINT ["/usr/bin/dumb-init", "--"]

# Start the server
CMD ["node", "server.js"]
