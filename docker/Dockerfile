# Stage 1: Build C++ backend (frontend is pre-built on host into web/dist/)
FROM debian:bookworm AS builder
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential cmake pkg-config libssl-dev && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY . .

RUN cmake -S . -B build \
    -DCMAKE_BUILD_TYPE=Release \
    -DBUILD_TESTING=OFF && \
    cmake --build build -j

# Stage 2: Runtime
FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
    libssl3 ca-certificates curl && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY --from=builder /app/build/openscanproxy .
COPY --from=builder /app/web/dist web/dist
COPY configs/ configs/

EXPOSE 8080 9090

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -sf http://127.0.0.1:9090/healthz || exit 1

CMD ["./openscanproxy", "configs/config.docker.json"]
