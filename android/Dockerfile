# Pin the builder to bookworm so its glibc matches the runtime image
# below — the same trap onym-relayer documents: `rust:1` now resolves to
# trixie (glibc 2.39) and the binary then fails to start on
# bookworm-slim (glibc 2.36) with `GLIBC_2.39 not found`.
FROM rust:1-bookworm AS builder
WORKDIR /build
# Cargo.lock is committed and copied, so the droplet builds the same
# dependency versions that were tested here.
COPY Cargo.toml Cargo.lock ./
COPY src ./src
RUN cargo build --release --locked

FROM debian:bookworm-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# SQLite is compiled in (rusqlite `bundled`), so nothing else is needed
# at runtime beyond the TLS trust store.
COPY --from=builder /build/target/release/onym-moderation-android /usr/local/bin/onym-moderation-android

# The store lives on a volume; the Google service-account key is mounted read-only.
VOLUME ["/data"]
EXPOSE 8080
CMD ["onym-moderation-android"]
