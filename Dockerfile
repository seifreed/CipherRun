FROM rust:1.85-bookworm

LABEL maintainer="Marc Rivero @seifreed"
LABEL description="CipherRun Testing Environment with Network Analysis Tools"

# Install system dependencies and network analysis tools
RUN apt-get update && apt-get install -y \
    # Network analysis tools
    tcpdump \
    tshark \
    wireshark-common \
    nmap \
    # SSL/TLS tools
    openssl \
    libssl-dev \
    pkg-config \
    # Build tools
    git \
    cmake \
    build-essential \
    # Utilities
    vim \
    curl \
    wget \
    net-tools \
    iputils-ping \
    dnsutils \
    && rm -rf /var/lib/apt/lists/*

# Install sslscan from source (for latest version)
WORKDIR /tmp
RUN git clone https://github.com/rbsec/sslscan.git && \
    cd sslscan && \
    make static && \
    make install && \
    cd .. && \
    rm -rf sslscan

# Install testssl.sh
RUN git clone https://github.com/drwetter/testssl.sh.git /opt/testssl.sh && \
    chmod +x /opt/testssl.sh/testssl.sh && \
    ln -s /opt/testssl.sh/testssl.sh /usr/local/bin/testssl.sh

# Create working directory
WORKDIR /cipherrun

# Copy CipherRun source code
COPY . .

# Build CipherRun in release mode
RUN cargo build --release

# Create directories for captures and results
RUN mkdir -p /captures /results /scripts

# Copy helper scripts
COPY docker/scripts/* /scripts/
RUN chmod +x /scripts/*.sh

# Set environment variables
ENV PATH="/cipherrun/target/release:${PATH}"
ENV RUST_LOG=info
ENV PCAP_DIR=/captures
ENV RESULTS_DIR=/results

# Create a non-root user for running captures (optional)
RUN useradd -m -s /bin/bash tester && \
    chown -R tester:tester /cipherrun /captures /results /scripts

# Expose no ports (client-side tool)

# Default command
CMD ["/bin/bash"]
