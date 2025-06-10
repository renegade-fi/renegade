FROM --platform=arm64 rust:latest

# Install system dependencies needed for the project
RUN apt-get update && \
    apt-get install -y \
    pkg-config \
    protobuf-compiler \
    libssl-dev \
    libclang-dev \
    ca-certificates \
    git \
    curl \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Install the specific Rust toolchain used by the project
RUN rustup toolchain install nightly-2024-09-01
RUN rustup default nightly-2024-09-01

# Create a non-root user for development
RUN useradd -m -s /bin/bash ubuntu

# Set up the working directory in the user's home
USER ubuntu
WORKDIR /home/ubuntu

# Set environment variables for development
ENV RUST_BACKTRACE=1
