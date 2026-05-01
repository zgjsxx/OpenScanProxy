# Stage 1: Build C++ backend (frontend is pre-built on host into web/dist/)
FROM debian:bookworm AS builder
RUN sed -i 's|http://deb.debian.org|http://mirrors.tuna.tsinghua.edu.cn|g' /etc/apt/sources.list.d/debian.sources && \
    apt-get update && apt-get install -y --no-install-recommends \
    build-essential cmake pkg-config libssl-dev libpq-dev && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY . .

RUN cmake -S . -B build \
    -DCMAKE_BUILD_TYPE=Release \
    -DBUILD_TESTING=OFF && \
    cmake --build build -j

# Stage 2: Runtime
FROM debian:bookworm-slim
RUN sed -i 's|http://deb.debian.org|http://mirrors.tuna.tsinghua.edu.cn|g' /etc/apt/sources.list.d/debian.sources && \
    apt-get update && apt-get install -y --no-install-recommends \
    libssl3 libpq5 ca-certificates curl openssl && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY --from=builder /app/build/openscanproxy .
COPY --from=builder /app/web/dist web/dist
COPY configs/ configs/
COPY docker/entrypoint.sh .

EXPOSE 8080 9090 9091

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -sf http://127.0.0.1:9090/healthz || exit 1

ENTRYPOINT ["/bin/sh", "./entrypoint.sh"]
CMD ["configs/config.docker.json"]
