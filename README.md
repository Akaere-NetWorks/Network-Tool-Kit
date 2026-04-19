# Network Tool Kit

Rust reimplementations of two classic UNIX network tools, built as a learning project using TDD.

## Tools

### bgpq4

Queries IRR (Internet Routing Registry) databases via the IRRD protocol, expands AS-SET objects into prefix lists, and outputs vendor-specific BGP filter configurations.

**Supported output formats:** Cisco IOS, Juniper JunOS, JSON, BIRD, OpenBGPD

```
bgpq4 -4 -l MY_LIST AS112
bgpq4 -6 -J -l MY_LIST AS-AS112
bgpq4 -4 -j -l MY_LIST AS112        # JSON output
```

### dig

Sends DNS queries over UDP/TCP, parses wire-format DNS messages, and prints human-readable output.

**Supported record types:** A, AAAA, MX, NS, TXT, CNAME, PTR, SOA, ANY

```
dig google.com A @8.8.8.8
dig google.com MX @8.8.8.8 +short
dig -x 8.8.8.8
dig google.com A @8.8.8.8 +tcp
```

## Build

```
cargo build --workspace
cargo test --workspace
```

Integration tests (requires network access):

```
cargo test --workspace -- --include-ignored
```

## Code Quality

All pull requests and commits to `main` must pass the following checks (enforced by CI):

### Formatting

Code must be formatted with `rustfmt` using the default stable style:

```
cargo fmt --all -- --check
```

To auto-fix before committing:

```
cargo fmt --all
```

### Linting

Code must pass `clippy` with no warnings treated as errors:

```
cargo clippy --workspace --all-targets -- -D warnings
```

Key rules enforced (non-exhaustive):

| Rule | What it catches |
|------|----------------|
| `dead_code` | Unused fields, functions, types |
| `clippy::manual_range_contains` | `x < 1 \|\| x > N` → `!(1..=N).contains(&x)` |
| `clippy::should_implement_trait` | Methods named `from_str` that shadow `FromStr` |
| `clippy::collapsible_if` / `collapsible_else_if` | Nested `if` blocks that can be merged |
| `clippy::single_match` | `match` with one arm → `if let` |
| `clippy::useless_format` | `format!("literal")` → `"literal".to_string()` |
| `clippy::field_reassign_with_default` | Post-`default()` field assignment → struct literal |
| `clippy::overly_complex_bool_expr` | Logic always true/false at compile time |

## License

MIT — Copyright (c) 2026 Liu HaoRan — see [LICENSE](LICENSE)
