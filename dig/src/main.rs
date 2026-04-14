use dig_lib::{
    dns::{build_query, RecordType},
    printer::{print_message, print_short, PrintOpts},
    resolver::send_query,
};
use clap::Parser;
use std::net::SocketAddr;
use std::time::Instant;

#[derive(Parser)]
#[command(name = "dig", about = "DNS lookup tool")]
struct Cli {
    name: Option<String>,

    #[arg(short = 't')]
    record_type: Option<String>,

    #[arg(short = 'p', default_value = "53")]
    port: u16,

    #[arg(short = '4')]
    ipv4: bool,

    #[arg(short = 'x')]
    reverse: Option<String>,

    #[arg(long = "tcp", default_value_t = false)]
    tcp: bool,

    #[arg(long = "short", default_value_t = false)]
    short: bool,

    #[arg(long = "norecurse", default_value_t = false)]
    no_recurse: bool,

    #[arg(long = "time", default_value_t = 5)]
    timeout: u64,

    #[arg(long = "tries", default_value_t = 3)]
    tries: u32,
}

#[tokio::main]
async fn main() {
    let raw: Vec<String> = std::env::args().collect();
    let server_str = raw.iter().find(|a| a.starts_with('@'))
        .map(|s| s.trim_start_matches('@').to_string());

    let filtered: Vec<String> = raw.into_iter()
        .filter(|a| !a.starts_with('@'))
        .collect();

    let cli = match Cli::try_parse_from(&filtered) {
        Ok(c) => c,
        Err(e) => { eprintln!("{e}"); std::process::exit(1); }
    };

    let server_host = server_str.as_deref().unwrap_or("8.8.8.8");
    let server: SocketAddr = format!("{server_host}:{}", cli.port)
        .parse()
        .unwrap_or_else(|_| {
            eprintln!("Invalid server address: {server_host}");
            std::process::exit(1);
        });

    let (qname, qtype) = if let Some(rev) = &cli.reverse {
        let rev_name = build_reverse_name(rev);
        (rev_name, RecordType::Ptr)
    } else {
        let name = cli.name.as_deref().unwrap_or(".");
        let qtype = cli.record_type.as_deref()
            .and_then(RecordType::from_str)
            .unwrap_or(RecordType::A);
        (name.to_string(), qtype)
    };

    let recurse = !cli.no_recurse;
    let id: u16 = rand_id();
    let query = build_query(&qname, qtype, id, recurse);

    let start = Instant::now();
    let msg = match send_query(server, &query, cli.tcp, cli.timeout, cli.tries).await {
        Ok(m) => m,
        Err(e) => { eprintln!(";; connection timeout: {e}"); std::process::exit(1); }
    };
    let elapsed_ms = start.elapsed().as_millis() as u64;

    if cli.short {
        print!("{}", print_short(&msg));
    } else {
        let opts = PrintOpts::default();
        print!("{}", print_message(&msg, &opts, server_host, Some(elapsed_ms)));
    }
}

fn build_reverse_name(addr: &str) -> String {
    if addr.contains(':') {
        format!("{addr}.ip6.arpa")
    } else {
        let parts: Vec<&str> = addr.split('.').collect();
        format!("{}.{}.{}.{}.in-addr.arpa",
            parts.get(3).unwrap_or(&"0"),
            parts.get(2).unwrap_or(&"0"),
            parts.get(1).unwrap_or(&"0"),
            parts.get(0).unwrap_or(&"0"),
        )
    }
}

fn rand_id() -> u16 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.subsec_nanos() as u16)
        .unwrap_or(0x1234)
}
