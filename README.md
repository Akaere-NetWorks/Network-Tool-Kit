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

## License

MIT — Copyright (c) 2026 Liu HaoRan — see [LICENSE](LICENSE)
