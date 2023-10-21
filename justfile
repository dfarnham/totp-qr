docker-build:
    docker build -t totp-qr .

doc:
    cargo rustdoc --open

test:
    cargo test -r
