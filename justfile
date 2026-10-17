# Run `just` to list recipes. CI runs `just ci` inside `nix develop`.

default:
    @just --list

# Format all code and TOML.
fmt:
    cargo fmt --all
    taplo fmt

# Check formatting without changing files.
fmt-check:
    cargo fmt --all --check
    taplo fmt --check

# Lints for every feature combination; warnings are errors.
clippy:
    cargo clippy --locked --all-targets -- -D warnings
    cargo clippy --locked --all-targets --features p256 -- -D warnings

# Tests for every feature combination.
test:
    cargo test --locked
    cargo test --locked --features p256

# Prove the crate builds without std on a bare-metal target.
nostd:
    cargo build --locked --target thumbv7em-none-eabihf
    cargo build --locked --target thumbv7em-none-eabihf --features p256

# Licences, advisories, banned crates, allowed sources.
deny:
    cargo deny --all-features check

# Spelling.
typos:
    typos

# API docs; broken links are errors.
doc:
    RUSTDOCFLAGS="-D warnings" cargo doc --locked --no-deps --all-features

# Everything CI checks.
ci: fmt-check clippy test nostd deny typos doc
