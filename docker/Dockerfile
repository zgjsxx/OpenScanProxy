FROM ubuntu:24.04

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential cmake pkg-config libssl-dev ca-certificates && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY . /app
RUN cmake -S . -B build && cmake --build build -j

EXPOSE 8080 9090
CMD ["/app/build/openscanproxy", "/app/configs/config.json"]
