# Build stage for frontend
FROM node:20-alpine AS frontend-build
WORKDIR /app/frontend
COPY frontend/package*.json ./
RUN npm install
COPY frontend/ ./
RUN npm run build

# Build stage for Go backend
FROM golang:1.22-alpine AS backend-build
WORKDIR /app

# Install build dependencies
RUN apk add --no-cache gcc musl-dev

# Copy go mod files
COPY go.mod go.sum* ./
RUN go mod download

# Copy source code
COPY cmd/ ./cmd/
COPY internal/ ./internal/

# Build with security flags
RUN CGO_ENABLED=1 GOOS=linux go build \
    -ldflags="-s -w -extldflags '-static'" \
    -o /fileez \
    ./cmd/server

# Production stage - minimal secure image
FROM alpine:3.19

# Install CA certificates for HTTPS and wget for health checks
RUN apk add --no-cache ca-certificates wget

# Create non-root user
RUN addgroup -g 1000 fileez && \
    adduser -u 1000 -G fileez -s /bin/sh -D fileez

WORKDIR /app

# Copy binary
COPY --from=backend-build /fileez /app/fileez

# Copy frontend build
COPY --from=frontend-build /app/frontend/dist /app/frontend/dist

# Set ownership
RUN chown -R fileez:fileez /app

# Switch to non-root user
USER fileez

# Environment variables
ENV PORT=9000
ENV HOST=0.0.0.0
ENV MAX_FILE_SIZE=104857600
ENV MAX_MEMORY=536870912
ENV FILE_EXPIRY=24h
ENV CLIPBOARD_EXPIRY=1h
ENV RATE_LIMIT=600
ENV UPLOAD_RATE_LIMIT=20
ENV ENABLE_CORS=true
ENV ENABLE_CLIPBOARD=true
ENV ENABLE_CLIPBOARD_IMAGE=true
ENV ENABLE_FILE_SHARING=true
ENV FRONTEND_DIR=/app/frontend/dist

EXPOSE 9000

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
  CMD wget -q -O /dev/null http://localhost:9000/api/ping || exit 1

CMD ["/app/fileez"]
