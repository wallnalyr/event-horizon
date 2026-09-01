# syntax=docker/dockerfile:1

# ---- Frontend build (runs natively on the builder arch) ----
FROM --platform=$BUILDPLATFORM node:20-alpine AS frontend-build
WORKDIR /app/frontend
COPY frontend/package*.json ./
RUN npm ci
COPY frontend/ ./
RUN npm run build

# ---- Backend build (cross-compiled from the builder arch to the target arch) ----
# CGO is disabled, so we can cross-compile natively for any target without QEMU.
FROM --platform=$BUILDPLATFORM golang:1.22-alpine AS backend-build
WORKDIR /app
COPY go.mod go.sum* ./
RUN go mod download
COPY cmd/ ./cmd/
COPY internal/ ./internal/
ARG TARGETOS
ARG TARGETARCH
RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
    go build -trimpath -ldflags="-s -w" -o /event-horizon ./cmd/server

# ---- Final image (target arch; base is pulled per-platform by the builder) ----
FROM alpine:3.19

# CA certs (for outbound TLS if ever needed) and wget for the healthcheck.
RUN apk add --no-cache ca-certificates wget && \
    addgroup -g 1000 app && \
    adduser -u 1000 -G app -s /bin/sh -D app

WORKDIR /app
COPY --from=backend-build /event-horizon /app/event-horizon
COPY --from=frontend-build /app/frontend/dist /app/frontend/dist
RUN chown -R app:app /app

USER app

# Defaults (override via docker-compose / -e). Home-network oriented.
ENV PORT=9000 \
    HOST=0.0.0.0 \
    MAX_FILE_SIZE=104857600 \
    MAX_MEMORY=536870912 \
    FILE_EXPIRY=24h \
    CLIPBOARD_EXPIRY=1h \
    RATE_LIMIT=600 \
    UPLOAD_RATE_LIMIT=20 \
    ENABLE_CORS=true \
    ENABLE_CLIPBOARD=true \
    ENABLE_CLIPBOARD_IMAGE=true \
    ENABLE_FILE_SHARING=true \
    FRONTEND_DIR=/app/frontend/dist

EXPOSE 9000

# Works whether the server runs plain HTTP or HTTPS (TLS_ENABLED=true).
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
  CMD wget -q -O /dev/null http://localhost:9000/api/ping \
   || wget -q --no-check-certificate -O /dev/null https://localhost:9000/api/ping \
   || exit 1

CMD ["/app/event-horizon"]
