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

# Prove the crate builds without std on every bare-metal target (with and without p256).
nostd: (nostd-target "thumbv6m-none-eabi") (nostd-target "thumbv7em-none-eabihf") (nostd-target "thumbv8m.main-none-eabihf") (nostd-target "riscv32imc-unknown-none-elf") (nostd-target "riscv32imac-unknown-none-elf")

[private]
nostd-target target:
    cargo build --locked --target {{target}}
    cargo build --locked --target {{target}} --features p256

# Builds the library for the Linux targets (no linker needed for a library).
targets: (lib-target "x86_64-unknown-linux-gnu") (lib-target "aarch64-unknown-linux-gnu") (lib-target "riscv64gc-unknown-linux-gnu")

[private]
lib-target target:
    cargo build --locked --lib --target {{target}} --all-features

# Licences, advisories, banned crates, allowed sources.
deny:
    cargo deny --all-features check

# Spelling.
typos:
    typos

# Licence and copyright: REUSE compliance, plus an SPDX header in every Rust file.
licenses:
    reuse lint
    @missing=$(git ls-files '*.rs' | while read -r f; do head -2 "$f" | grep -q 'SPDX-''License-Identifier: MIT' || echo "$f"; done); \
    if [ -n "$missing" ]; then echo "missing SPDX header:"; echo "$missing"; exit 1; fi

# API docs; broken links are errors.
doc:
    RUSTDOCFLAGS="-D warnings" cargo doc --locked --no-deps --all-features

# Everything CI checks.
# Validates requirements/*.sdoc and renders requirements, traceability and ReqIF to target/requirements.
# The coverage gate itself runs as a test (tests/requirements.rs).
requirements:
    strictdoc export . --formats=html,reqif-sdoc --output-dir target/requirements

ci: fmt-check clippy test nostd targets deny licenses typos doc requirements
