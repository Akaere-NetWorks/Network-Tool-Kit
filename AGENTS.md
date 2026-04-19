# AGENTS.md

## Commands

```sh
cargo build --workspace
cargo test --workspace                       # unit tests only (integration tests are #[ignore])
cargo test --workspace -- --include-ignored  # includes network-dependent integration tests
cargo test -p bgpq4                          # single package
cargo test -p dig
```

## Architecture

Cargo workspace with two crates. Both follow the same pattern: a `[[bin]]` for the CLI and a `[lib]` (named `bgpq4_lib` / `dig_lib`) exposed for integration tests.

- **bgpq4** — queries IRR databases (IRRD protocol), expands AS-SETs into prefix lists, outputs vendor BGP configs. Modules: `irrd`, `expander`, `prefix`, `printer`.
- **dig** — DNS query tool over UDP/TCP, parses wire-format messages. Modules: `dns` (wire format), `resolver` (transport), `printer`.

## Testing

- All integration tests (`tests/integration.rs`) are `#[ignore]` because they hit real network services (`rr.ntt.net:43` for bgpq4, `8.8.8.8:53` for dig).
- Run `cargo test --workspace` for fast offline unit tests; add `-- --include-ignored` only when network is available.
