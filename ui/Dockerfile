# NDR UI - Next.js standalone build
FROM node:22-alpine AS builder
WORKDIR /app

# v0.13.0: reproducible installs - npm ci + the lockfile (npm install
# drifted versions between builds and broke the production image once)
COPY package.json package-lock.json ./
RUN npm ci --no-audit --no-fund

COPY . .
# NEXT_PUBLIC_DEMO_MODE is baked at build time; production default is false.
ARG NEXT_PUBLIC_DEMO_MODE=false
ENV NEXT_PUBLIC_DEMO_MODE=${NEXT_PUBLIC_DEMO_MODE} \
    NEXT_TELEMETRY_DISABLED=1
RUN npm run build

FROM node:22-alpine AS runner
WORKDIR /app
ENV NODE_ENV=production \
    PORT=3000 \
    HOSTNAME=0.0.0.0 \
    NEXT_TELEMETRY_DISABLED=1

RUN addgroup -S ndr && adduser -S ndr -G ndr

COPY --from=builder /app/.next/standalone ./
COPY --from=builder /app/.next/static ./.next/static
COPY --from=builder /app/public ./public

USER ndr
EXPOSE 3000
CMD ["node", "server.js"]
