# Build stage
FROM rust:1-slim AS builder
WORKDIR /src
COPY Cargo.toml Cargo.lock build.rs ./
COPY src ./src
COPY examples ./examples
RUN cargo build --release --locked

# Runtime stage: small image with CA certificates
FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --create-home --uid 10001 rustradar
COPY --from=builder /src/target/release/rustradar /usr/local/bin/rustradar
USER rustradar
WORKDIR /home/rustradar
ENTRYPOINT ["rustradar"]
