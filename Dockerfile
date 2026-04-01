# PQLite Docker Image
# Copyright (c) 2025-2026 Dyber, Inc.
#
# Build:  docker build -t pqlite3 .
# Run:    docker run -it pqlite3
# Mount:  docker run -it -v /path/to/data:/data pqlite3 /data/mydb.db
#
# Multi-stage build: builder stage compiles everything,
# runtime stage contains only the pqlite3 binary + libs.

# ==============================================================
# Stage 1: Build
# ==============================================================
FROM ubuntu:22.04 AS builder

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential cmake ninja-build libssl-dev pkg-config \
    tcl tclsh git ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Install liboqs
RUN git clone --depth 1 --branch 0.12.0 \
    https://github.com/open-quantum-safe/liboqs.git /tmp/liboqs \
    && cmake -S /tmp/liboqs -B /tmp/liboqs/build -GNinja \
       -DCMAKE_INSTALL_PREFIX=/usr/local \
       -DBUILD_SHARED_LIBS=ON \
       -DOQS_BUILD_ONLY_LIB=ON \
    && ninja -C /tmp/liboqs/build \
    && ninja -C /tmp/liboqs/build install \
    && ldconfig \
    && rm -rf /tmp/liboqs

# Copy PQLite source
WORKDIR /build
COPY . .

# Generate amalgamation
RUN chmod +x configure autosetup/autosetup-find-tclsh autosetup/autosetup \
    autosetup/autosetup-test-tclsh autosetup/autosetup-config.guess \
    autosetup/autosetup-config.sub 2>/dev/null || true \
    && ./configure \
    && make sqlite3.c \
    && make shell.c

# Build PQLite
RUN cmake -S . -B build -GNinja \
    -DPQLITE_PQC=ON \
    -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_INSTALL_PREFIX=/usr/local \
    -DCMAKE_INSTALL_RPATH=/usr/local/lib \
    && cmake --build build \
    && cmake --install build

# ==============================================================
# Stage 2: Runtime (minimal image)
# ==============================================================
FROM ubuntu:22.04 AS runtime

RUN apt-get update && apt-get install -y --no-install-recommends \
    libssl3 \
    && rm -rf /var/lib/apt/lists/*

# Copy liboqs and pqlite3
COPY --from=builder /usr/local/lib/liboqs* /usr/local/lib/
COPY --from=builder /usr/local/bin/pqlite3 /usr/local/bin/pqlite3
COPY --from=builder /usr/local/lib/libpqlite3* /usr/local/lib/
COPY --from=builder /usr/local/include/pqlite3.h /usr/local/include/

RUN ldconfig

# Labels
LABEL org.opencontainers.image.title="PQLite"
LABEL org.opencontainers.image.description="Post-Quantum SQLite - Quantum-resistant database encryption"
LABEL org.opencontainers.image.vendor="Dyber, Inc."
LABEL org.opencontainers.image.source="https://github.com/dyber-pqc/PQLite"
LABEL org.opencontainers.image.licenses="MIT"
LABEL org.opencontainers.image.version="1.0.0"

# Default: interactive pqlite3 shell
WORKDIR /data
ENTRYPOINT ["pqlite3"]
