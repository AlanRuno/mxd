# Multi-stage Dockerfile for MXD Library
FROM ubuntu:22.04 AS builder

# Install build dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    cmake \
    git \
    pkg-config \
    libssl-dev \
    libsodium-dev \
    librocksdb-dev \
    libcjson-dev \
    libgmp-dev \
    libc-bin \
    libcurl4-openssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Install custom dependencies (wasm3, libuv, uvwasi) as root
WORKDIR /tmp

# Install libuv
RUN git clone https://github.com/libuv/libuv && \
    cd libuv && mkdir -p build && cd build && \
    cmake -DBUILD_SHARED_LIBS=ON -DCMAKE_POSITION_INDEPENDENT_CODE=ON \
          -DCMAKE_C_FLAGS="-fPIC -fvisibility=default" \
          -DCMAKE_INSTALL_RPATH="/usr/local/lib" \
          -DCMAKE_BUILD_WITH_INSTALL_RPATH=ON \
          -DCMAKE_INSTALL_RPATH_USE_LINK_PATH=ON \
          -DLIBUV_BUILD_SHARED=ON .. && \
    make && make install && \
    cd /tmp && rm -rf libuv

# Install uvwasi
RUN git clone https://github.com/nodejs/uvwasi && \
    cd uvwasi && mkdir -p build && cd build && \
    cmake -DBUILD_SHARED_LIBS=ON -DCMAKE_POSITION_INDEPENDENT_CODE=ON \
          -DCMAKE_C_FLAGS="-fPIC -fvisibility=default" \
          -DCMAKE_INSTALL_RPATH="/usr/local/lib" \
          -DCMAKE_BUILD_WITH_INSTALL_RPATH=ON \
          -DCMAKE_INSTALL_RPATH_USE_LINK_PATH=ON \
          -DUVWASI_BUILD_SHARED=ON .. && \
    make && make install && \
    cd /tmp && rm -rf uvwasi

# Install wasm3 with simplified build
RUN git clone https://github.com/wasm3/wasm3 && \
    cd wasm3 && \
    echo 'cmake_minimum_required(VERSION 3.12)' > CMakeLists.txt && \
    echo 'project(wasm3)' >> CMakeLists.txt && \
    echo 'file(GLOB M3_SOURCES source/*.c)' >> CMakeLists.txt && \
    echo 'file(GLOB M3_HEADERS source/*.h)' >> CMakeLists.txt && \
    echo 'add_library(m3 SHARED ${M3_SOURCES})' >> CMakeLists.txt && \
    echo 'target_link_libraries(m3 PUBLIC uvwasi uv m pthread dl)' >> CMakeLists.txt && \
    echo 'target_include_directories(m3 PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/source> $<INSTALL_INTERFACE:include>)' >> CMakeLists.txt && \
    echo 'install(FILES ${M3_HEADERS} DESTINATION include/wasm3)' >> CMakeLists.txt && \
    echo 'install(TARGETS m3 LIBRARY DESTINATION lib)' >> CMakeLists.txt && \
    mkdir -p build && cd build && \
    cmake .. && make && make install && \
    echo 'prefix=/usr/local' > /usr/local/lib/pkgconfig/wasm3.pc && \
    echo 'exec_prefix=${prefix}' >> /usr/local/lib/pkgconfig/wasm3.pc && \
    echo 'libdir=${exec_prefix}/lib' >> /usr/local/lib/pkgconfig/wasm3.pc && \
    echo 'includedir=${prefix}/include' >> /usr/local/lib/pkgconfig/wasm3.pc && \
    echo '' >> /usr/local/lib/pkgconfig/wasm3.pc && \
    echo 'Name: wasm3' >> /usr/local/lib/pkgconfig/wasm3.pc && \
    echo 'Description: WebAssembly runtime' >> /usr/local/lib/pkgconfig/wasm3.pc && \
    echo 'Version: 0.5.0' >> /usr/local/lib/pkgconfig/wasm3.pc && \
    echo 'Libs: -L${libdir} -lm3' >> /usr/local/lib/pkgconfig/wasm3.pc && \
    echo 'Cflags: -I${includedir}/wasm3' >> /usr/local/lib/pkgconfig/wasm3.pc && \
    cd /tmp && rm -rf wasm3

# Run ldconfig to update library cache
RUN ldconfig

# Create non-root user for building
RUN useradd -m -u 1000 builder
USER builder
WORKDIR /home/builder

# Copy source code
COPY --chown=builder:builder . /home/builder/mxdlib/

# Build the library (no dependency installation needed)
WORKDIR /home/builder/mxdlib
RUN mkdir -p build && \
    cd build && \
    cmake .. && \
    make -j$(nproc)

# Production stage
FROM ubuntu:22.04

# Install runtime dependencies only
RUN apt-get update && apt-get install -y \
    libssl3 \
    libsodium23 \
    librocksdb6.11 \
    libcjson1 \
    libcurl4 \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && apt-get clean

# Create non-root user for runtime
RUN useradd -m -u 1001 mxdnode && \
    mkdir -p /opt/mxd/data /opt/mxd/config /opt/mxd/logs && \
    chown -R mxdnode:mxdnode /opt/mxd

# Copy runtime libraries from builder stage
COPY --from=builder /usr/local/lib/libuv.so* /usr/local/lib/
COPY --from=builder /usr/local/lib/libuvwasi.so* /usr/local/lib/
COPY --from=builder /usr/local/lib/libm3.so* /usr/local/lib/

# Copy built binaries and libraries
COPY --from=builder --chown=mxdnode:mxdnode /home/builder/mxdlib/build/lib/libmxd.so /opt/mxd/lib/
COPY --from=builder --chown=mxdnode:mxdnode /home/builder/mxdlib/build/lib/mxd_node /opt/mxd/bin/
COPY --from=builder --chown=mxdnode:mxdnode /home/builder/mxdlib/src/node/default_config.json /opt/mxd/config/

# Update library cache
RUN ldconfig

# Set up environment
USER mxdnode
WORKDIR /opt/mxd
ENV PATH="/opt/mxd/bin:$PATH"
ENV LD_LIBRARY_PATH="/opt/mxd/lib:/usr/local/lib"

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8080/health || exit 1

# Expose ports
EXPOSE 8000 8080

# Default command
CMD ["mxd_node", "--config", "/opt/mxd/config/default_config.json"]
