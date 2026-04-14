# Network Tool Kit — Design Spec

**Date:** 2026-04-14  
**Status:** Approved

---

## Context

Reimplement two UNIX network tools in Rust as a learning/tooling project:

1. **bgpq4** — queries IRR (Internet Routing Registry) databases via the IRRD text protocol, expands AS-SET objects into prefix lists, and outputs vendor-specific BGP filter configs.
2. **dig** — sends DNS queries over UDP/TCP, parses wire-format DNS messages, and prints human-readable output.

The developer is on Windows. The C reference implementations (`bgpq4-src/`, `bind9/`) cannot be executed locally, so tests validate against live remote servers (`rr.ntt.net:43` for IRRd, `8.8.8.8` for DNS).

**Goal:** MVP working CLI tools built test-first (TDD). Tests are written before implementation; code is written to make tests pass.

---

## Scope (MVP)

### bgpq4
- Output formats: Cisco IOS, Juniper JunOS, JSON, BIRD, OpenBGPD
- IP families: IPv4 (`-4`) and IPv6 (`-6`)
- Generation modes: prefix list (default), AS-path access-list (`-f ASN`)
- AS-SET expansion: recursive via `!i` IRRD command
- Prefix aggregation: `-A` flag
- IRR source filter: `-S sources`
- CLI flags: `-4`, `-6`, `-h host[:port]`, `-S sources`, `-l name`, `-m maxlen`, `-A`, `-J`, `-j`, `-b`, `-B`, `-f ASN`

### dig
- Query types: A, AAAA, MX, NS, TXT, CNAME, PTR, SOA, ANY
- Transport: UDP (default, 512 byte limit), TCP (`+tcp`), automatic TCP fallback on truncation
- Output: standard dig format (sections + stats), `+short` (answers only)
- CLI: `@server`, `-t type`, `-p port`, `-4`, `-6`, `-x addr` (reverse), `+tcp`, `+short`, `+norecurse`, `+time=N`, `+tries=N`

---

## Architecture

### Approach: Layered Library + Thin CLI

Each tool follows the same layered pattern:

```
protocol layer  →  logic layer  →  printer layer  →  CLI (main.rs)
```

Each layer is independently testable. CLI is thin — just arg parsing + wiring.

---

## Project Structure

```
Network-Tool-Kit/
├── Cargo.toml               # workspace: members = ["bgpq4", "dig"]
├── bgpq4/
│   ├── Cargo.toml
│   └── src/
│       ├── lib.rs           # public API re-exports
│       ├── irrd.rs          # IRRd TCP protocol: connect, pipeline, parse responses
│       ├── expander.rs      # AS-SET recursive expansion + prefix collection
│       ├── prefix.rs        # IpPrefix type, radix-tree aggregation
│       ├── printer.rs       # format_cisco / format_juniper / format_json / format_bird / format_openbgpd
│       └── main.rs          # clap CLI, wires layers together
├── dig/
│   ├── Cargo.toml
│   └── src/
│       ├── lib.rs           # public API re-exports
│       ├── dns.rs           # DNS wire format: Message, Header, Question, ResourceRecord, Rdata
│       ├── resolver.rs      # send_query(): UDP send/recv, TCP fallback, retry/timeout
│       ├── printer.rs       # print_message(), print_short()
│       └── main.rs          # clap CLI
├── bgpq4-src/               # C source reference (read-only)
└── bind9/                   # C source reference (read-only)
```

---

## Dependencies

```toml
# shared across both crates
tokio = { version = "1", features = ["net", "io-util", "time", "rt-multi-thread", "macros"] }
thiserror = "1"

# bgpq4
clap = { version = "4", features = ["derive"] }
ipnetwork = "0.20"
serde = { version = "1", features = ["derive"] }
serde_json = "1"

# dig
clap = { version = "4", features = ["derive"] }
```

No external DNS library — DNS wire format is implemented from scratch in `dig/src/dns.rs` to match the learning goal.

---

## Component Design

### bgpq4: `irrd.rs`

Responsibilities:
- Open TCP connection to IRRd server (default `rr.ntt.net:43`)
- Send `!!` to enable pipelining mode
- Send `!i<object>` queries, read `A<N>\n<data>\nC\n` responses
- Parse response codes: `A` (success+data), `C` (success+empty), `D` (not found), `E` (multiple), `F` (error)

Key types:
```rust
pub struct IrrdClient { /* tokio TcpStream */ }
pub enum IrrdResponse { Data(Vec<String>), NotFound, Error(String) }
impl IrrdClient {
    pub async fn connect(host: &str, port: u16) -> Result<Self>
    pub async fn query(&mut self, object: &str) -> Result<IrrdResponse>
}
```

### bgpq4: `expander.rs`

Responsibilities:
- Accept an AS-SET name or ASN, recursively expand via IRRd
- Track already-visited objects (prevent cycles)
- Collect resulting `IpPrefix` list
- Respect `maxdepth` to limit recursion

### bgpq4: `prefix.rs`

Responsibilities:
- `IpPrefix` type wrapping `ipnetwork::IpNetwork`
- `aggregate(prefixes: Vec<IpPrefix>) -> Vec<IpPrefix>` — merge adjacent/contained prefixes

### bgpq4: `printer.rs`

Each function takes `(name: &str, prefixes: &[IpPrefix]) -> String`:
- `format_cisco` — `ip prefix-list NN permit X.X.X.X/Y`
- `format_juniper` — `policy-options { prefix-list NN { ... } }`
- `format_json` — `{ "NN": [{"prefix": "...","exact": true}] }`
- `format_bird` — `NN = [ X.X.X.X/Y, ... ];`
- `format_openbgpd` — `prefix { X.X.X.X/Y ... }`

Reference outputs: `bgpq4-src/tests/reference/` (e.g. `ios--4.txt`, `bird--4.txt`, `junos--4.txt`)

---

### dig: `dns.rs`

Responsibilities:
- Build DNS query message (wire format bytes)
- Parse DNS response message from bytes
- Support record types: A, AAAA, MX, NS, TXT, CNAME, PTR, SOA, ANY

Key types:
```rust
pub struct Message { pub header: Header, pub questions: Vec<Question>, pub answers: Vec<ResourceRecord>, pub authority: Vec<ResourceRecord>, pub additional: Vec<ResourceRecord> }
pub struct Header { pub id: u16, pub flags: u16, pub /* counts */ }
pub struct ResourceRecord { pub name: String, pub rtype: RecordType, pub class: u16, pub ttl: u32, pub rdata: Rdata }
pub enum Rdata { A(Ipv4Addr), Aaaa(Ipv6Addr), Cname(String), Mx { priority: u16, exchange: String }, Ns(String), Ptr(String), Txt(Vec<Vec<u8>>), Soa { ... }, Unknown(Vec<u8>) }

pub fn build_query(name: &str, qtype: RecordType, id: u16, recurse: bool) -> Vec<u8>
pub fn parse_message(buf: &[u8]) -> Result<Message>
```

### dig: `resolver.rs`

```rust
pub async fn send_query(server: SocketAddr, query: &[u8], use_tcp: bool, timeout_secs: u64, tries: u32) -> Result<Message>
```

- UDP: send query, receive up to 512 bytes, if TC flag set → retry via TCP
- TCP: 2-byte length prefix framing

### dig: `printer.rs`

```rust
pub fn print_message(msg: &Message, opts: &PrintOpts) -> String
pub fn print_short(msg: &Message) -> String
```

`PrintOpts` controls: `show_comments`, `show_stats`, `show_question`, `show_authority`, `show_additional`.

---

## Testing Strategy

### TDD Flow
1. Write failing test that describes expected behavior
2. Write minimum code to make it pass
3. Refactor

### bgpq4 Tests

**Unit tests (in-module, no network):**

| Module | Test | Method |
|--------|------|--------|
| `irrd.rs` | Parse `A5\nAS1 AS2 AS3 AS4 AS5\nC\n` | hardcoded bytes |
| `irrd.rs` | Parse `D\n` (not found) | hardcoded bytes |
| `prefix.rs` | Aggregate `192.168.0.0/25` + `192.168.0.128/25` → `192.168.0.0/24` | pure function |
| `prefix.rs` | Parse `2001:db8::/32` | pure function |
| `printer.rs` | Cisco format matches `bgpq4-src/tests/reference/ios--4.txt` | string compare |
| `printer.rs` | JSON output is valid JSON | serde_json::from_str |
| `printer.rs` | BIRD format matches `bgpq4-src/tests/reference/bird--4.txt` | string compare |

**Integration tests (`bgpq4/tests/integration.rs`, `#[ignore]` by default):**
- Connect to `rr.ntt.net:43`, query `AS112` IPv4 → verify non-empty prefix list
- Query `AS-AS112` AS-SET expansion → verify multiple ASNs returned
- Full pipeline: expand `AS-AS112` → Cisco output → non-empty, valid prefix-list format

Run with: `cargo test -- --include-ignored`

### dig Tests

**Unit tests (in-module, no network):**

| Module | Test | Method |
|--------|------|--------|
| `dns.rs` | Build query for `google.com A` → correct wire format bytes | byte compare |
| `dns.rs` | Parse known A response bytes → `Rdata::A(8.8.8.8)` | hardcoded hex capture |
| `dns.rs` | Parse MX response → priority + exchange fields | hardcoded bytes |
| `dns.rs` | Name decompression (pointer labels) | hardcoded bytes |
| `printer.rs` | `+short` for A record → `"1.2.3.4"` | string compare |
| `printer.rs` | Full output contains `;; ANSWER SECTION:` | string contains |

**Integration tests (`dig/tests/integration.rs`, `#[ignore]` by default):**
- Query `google.com A @8.8.8.8` → response has at least one A record
- Query `google.com AAAA @8.8.8.8` → at least one AAAA record
- Query `google.com MX @8.8.8.8` → at least one MX record
- Reverse lookup `-x 8.8.8.8` → PTR record contains `google`
- `+tcp` flag → response received via TCP

Run with: `cargo test -- --include-ignored`

---

## Reference Files Used

- `bgpq4-src/tests/reference/ios--4.txt` — Cisco IOS IPv4 prefix list for AS112
- `bgpq4-src/tests/reference/ios--6.txt` — Cisco IOS IPv6
- `bgpq4-src/tests/reference/bird--4.txt` — BIRD IPv4
- `bgpq4-src/tests/reference/junos--4.txt` — Juniper JunOS IPv4
- `bgpq4-src/tests/reference/json--4.txt` — JSON IPv4
- `bgpq4-src/tests/reference/openbgpd--4.txt` — OpenBGPD IPv4
- `bgpq4-src/tests/generate_outputs.sh` — shows exact flags used to generate each reference file

---

## Verification

End-to-end verification steps after implementation:

1. `cargo build --workspace` — builds cleanly with no warnings
2. `cargo test --workspace` — all unit tests pass (no network required)
3. `cargo test --workspace -- --include-ignored` — integration tests pass (requires network)
4. `./target/debug/bgpq4 -4 -l NN AS112` → output matches `bgpq4-src/tests/reference/ios--4.txt`
5. `./target/debug/bgpq4 -6 -J -l NN AS-AS112` → valid Juniper JunOS output
6. `./target/debug/dig google.com A @8.8.8.8` → output resembles standard dig format
7. `./target/debug/dig google.com MX @8.8.8.8 +short` → one line per MX record
