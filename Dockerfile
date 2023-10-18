# Use a base image with the latest version of Rust installed
FROM rust:latest as builder

WORKDIR /usr/src/myapp

# Build and install the application

# Build from this repo
#COPY . .
#RUN cargo install --path .

# build from the crates server
RUN cargo install totp-qr

# Copy only the compiled binary from the builder stage to this image
FROM debian:bookworm-slim as runtime
COPY --from=builder /usr/local/cargo/bin/totp-qr /usr/local/bin/totp-qr

# Specify the command to run when the container starts
ENTRYPOINT ["totp-qr"]
