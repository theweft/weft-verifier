# weft-verifier

The trusted core of [weft](https://theweft.org): a small, pure, deterministic state-transition
function that verifies signed documents and delegations and decides what a device should run and
how it should be configured.

```text
step(state, trust anchors, device facts, raw inputs) -> (new state, decisions)
```

- **No I/O.** No network, files, clock, randomness or global state. The shell feeds bytes in and
  executes the returned instructions.
- **`no_std` + `alloc`.** The same code runs on Linux and microcontrollers (CI builds it for
  `thumbv7em-none-eabihf`).
- **Deny by default.** Malformed, unsigned, unauthorized, expired, rolled-back or equivocating
  documents have no effect.
- **Order independent.** Inputs are deduplicated and sorted by digest; tests check all
  permutations.
- **Never panics.** `unwrap`, `expect`, `panic`, indexing and unchecked arithmetic are denied by lints.

In classic terms this is weft's *reference monitor* / *policy decision point*.

## What it does (v0.1)

| Input | Effect |
|---|---|
| Delegation | Grants a key a subset of the issuer's rights. Effective rights are the **intersection** along the chain, so a delegation can never widen rights. |
| Revocation | Trust anchors revoke keys. Permanent (stored in state). |
| Config fragment | Scoped (`fleet` → `group` → `site` → `device` → `local`), versioned, partial config. Merged with JSON Merge Patch semantics; locks stop other scopes; conflicts are reported. |
| Deployment | Which artifact (SHA-256) a component runs. Highest scope wins. |

Output: `Install` / `ApplyConfig` instructions, plus accepted, superseded, ignored and rejected
documents (with reasons), lock conflicts, and components withheld because an accepted document is
missing (fail safe).

## Formats

- Deterministic CBOR (RFC 8949 §4.2) only: re-encoding must reproduce the input byte for byte.
  No floats, tags, indefinite lengths or integers outside `i64`.
- `COSE_Sign1` (RFC 9052) with all headers protected (`alg`, `kid`), implemented directly on the
  strict CBOR layer so there is one CBOR implementation in the trusted path.
- Algorithms: Ed25519 (default), ECDSA P-256 with `--features p256`. Post-quantum (ML-DSA) and
  hybrid signatures are planned.
- Key ids are computed from the key (SHA-256, 16 bytes), never taken from documents.

## Development

Everything runs in a pinned environment:

```sh
nix develop          # or: direnv allow (uses .envrc)
just                 # list tasks
just ci              # everything CI runs: fmt, clippy, tests, no_std build, cargo-deny, REUSE, typos, docs
```

Without Nix: install the toolchain from `rust-toolchain.toml` with rustup, plus `just`,
`cargo-deny`, `taplo` and `typos`.

Dependencies are pinned exactly in `Cargo.toml` and `Cargo.lock`; every update is a reviewed PR.

## Roadmap

- `authorize()` for commands and local API calls
- ML-DSA and hybrid (Ed25519 + ML-DSA) signatures, threshold rules
- Desired-state snapshots (TUF-style) against mix-and-match
- Fuzzing (cargo-fuzz) and proofs of key properties (Kani)
- Compact integer keys for constrained links

## License

MIT. See [LICENSE](LICENSE). The repository follows the [REUSE](https://reuse.software) specification
(`REUSE.toml`, `LICENSES/`), and every Rust file carries an SPDX header; `just licenses` checks both. Security issues: see [SECURITY.md](SECURITY.md).
