# Multi-stage build for the flow service (sirosid-dev + deployment).
#
# TLS is terminated upstream (the family convention): the binary binds
# plain HTTP behind a proxy/ingress.

FROM rust:slim AS build
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
COPY testdata ./testdata
COPY flows ./flows
RUN cargo build --release --locked -p siros-flow-service --bin siros-flow-service

FROM debian:trixie-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl \
    && rm -rf /var/lib/apt/lists/*
COPY --from=build /src/target/release/siros-flow-service /usr/local/bin/
# The flow definitions ship IN the image (the reviewed set — the
# deployment's config selects the directory; mounting over it installs
# another set).
COPY flows /etc/siros-flow/flows
EXPOSE 8080
HEALTHCHECK --interval=5s --timeout=5s --retries=20 --start-period=10s \
    CMD curl -sf http://localhost:8080/healthz || exit 1
ENTRYPOINT ["siros-flow-service"]
CMD ["/etc/siros-flow/config.toml"]