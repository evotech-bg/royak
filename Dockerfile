# ─── Build stage ───
FROM rust:1-alpine AS builder
RUN apk add --no-cache musl-dev
WORKDIR /build
COPY Cargo.toml Cargo.lock ./
COPY src/ src/
RUN cargo build --release

# ─── Runtime stage ───
FROM alpine:3.21
RUN apk add --no-cache curl tar
COPY --from=builder /build/target/release/royak /usr/local/bin/royak
ENV HOSTNAME=royak-node
EXPOSE 6443
ENTRYPOINT ["royak"]
CMD ["watch"]
