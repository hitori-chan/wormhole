# AGENTS.md

`wormhole`: a fast, minimal, stateless TCP tunnel for NAT traversal. Single binary, pure Rust (tokio, edition 2024).

## Build / test

```sh
cargo build --release
cargo test --release        # must pass
cargo clippy --all-targets  # must stay clean
```

## Conventions

- Keep it concise. Docs, CLI help, error messages, and commits state the fact once; no filler, no marketing prose.
- Commits: imperative, scoped subject; body lists the concrete changes.
- Wire protocol changes require a version bump in `docs/protocol.md` **and** a coordinated swap of both ends.
- Keep the repo publishable: never commit secrets, keys, or personal infrastructure; use generic example values in docs and tests.
- Docs: README.md (user-facing), docs/protocol.md (wire + lifecycle), docs/benchmark.md (methodology). Keep them in sync with behavior.
