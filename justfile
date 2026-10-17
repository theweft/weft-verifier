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

# Licence and copyright: REUSE compliance, plus an SPDX header in every Rust file.
licenses:
    reuse lint
    @missing=$(git ls-files '*.rs' | while read -r f; do head -2 "$f" | grep -q 'SPDX-''License-Identifier: MIT' || echo "$f"; done); \
    if [ -n "$missing" ]; then echo "missing SPDX header:"; echo "$missing"; exit 1; fi

# API docs; broken links are errors.
doc:
    RUSTDOCFLAGS="-D warnings" cargo doc --locked --no-deps --all-features

# Everything CI checks.
ci: fmt-check clippy test nostd deny licenses typos doc
