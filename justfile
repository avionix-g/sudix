set unstable

prep: format lint machete build test

format:
    cargo fmt
    tombi format **/Cargo.toml
    just --fmt

check-format:
    cargo fmt --check
    tombi format --check **/Cargo.toml

build:
    cargo build --all-targets

lint:
    cargo clippy --all-targets

machete:
    cargo machete

test:
    cargo test

build-release:
    cargo build --all-targets --release
