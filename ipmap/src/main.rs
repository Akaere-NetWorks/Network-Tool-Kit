mod display;
mod scanner;

use scanner::scan;

struct Args {
    cidr: String,
    timeout_ms: u32,
    count: u32,
    concurrency: usize,
    quiet: bool,
}

fn usage() -> ! {
    eprintln!("Usage: ipmap <CIDR> [-t <timeout_ms>] [-r <retries>] [-c <concurrency>] [-q]");
    eprintln!();
    eprintln!("Options:");
    eprintln!("  -t <ms>   ping timeout per packet in milliseconds (default: 500)");
    eprintln!("  -r <n>    number of ping packets per host (default: 3)");
    eprintln!("  -c <n>    max concurrent pings (default: 64)");
    eprintln!("  -q        quiet mode, only print the final matrix");
    eprintln!();
    eprintln!("Example:");
    eprintln!("  ipmap 192.168.1.0/24");
    eprintln!("  ipmap 10.0.0.0/16 -t 200 -r 5 -c 128");
    std::process::exit(1);
}

fn parse_args() -> Args {
    let raw: Vec<String> = std::env::args().collect();
    let mut cidr: Option<String> = None;
    let mut timeout_ms: u32 = 500;
    let mut count: u32 = 3;
    let mut concurrency: usize = 64;
    let mut quiet = false;

    let mut i = 1;
    while i < raw.len() {
        match raw[i].as_str() {
            "-t" => {
                i += 1;
                if i >= raw.len() {
                    eprintln!("error: -t requires a value");
                    usage();
                }
                timeout_ms = raw[i].parse().unwrap_or_else(|_| {
                    eprintln!("error: invalid timeout: {}", raw[i]);
                    std::process::exit(1);
                });
            }
            "-r" => {
                i += 1;
                if i >= raw.len() {
                    eprintln!("error: -r requires a value");
                    usage();
                }
                count = raw[i].parse().unwrap_or_else(|_| {
                    eprintln!("error: invalid count: {}", raw[i]);
                    std::process::exit(1);
                });
                if count == 0 {
                    eprintln!("error: -r must be at least 1");
                    std::process::exit(1);
                }
            }
            "-c" => {
                i += 1;
                if i >= raw.len() {
                    eprintln!("error: -c requires a value");
                    usage();
                }
                concurrency = raw[i].parse().unwrap_or_else(|_| {
                    eprintln!("error: invalid concurrency: {}", raw[i]);
                    std::process::exit(1);
                });
            }
            "-q" => quiet = true,
            arg if arg.starts_with('-') => {
                eprintln!("error: unknown option: {arg}");
                usage();
            }
            arg => {
                if cidr.is_some() {
                    eprintln!("error: unexpected argument: {arg}");
                    usage();
                }
                cidr = Some(arg.to_string());
            }
        }
        i += 1;
    }

    let cidr = cidr.unwrap_or_else(|| {
        eprintln!("error: CIDR argument required");
        usage();
    });

    Args {
        cidr,
        timeout_ms,
        count,
        concurrency,
        quiet,
    }
}

#[tokio::main]
async fn main() {
    let args = parse_args();

    let ips = scanner::parse_cidr(&args.cidr).unwrap_or_else(|e| {
        eprintln!("error: {e}");
        std::process::exit(1);
    });

    if !args.quiet {
        println!(
            "Scanning {} ({} hosts, {} ping(s) each)...",
            args.cidr,
            ips.len(),
            args.count
        );
        println!();
    }

    let results = scan(
        ips,
        args.timeout_ms,
        args.count,
        args.concurrency,
        args.quiet,
    )
    .await;

    if !args.quiet {
        for r in &results {
            if r.alive {
                match r.latency_ms {
                    Some(ms) => println!("{:<16} up   {}ms", r.ip.to_string(), ms),
                    None => println!("{:<16} up", r.ip.to_string()),
                }
            }
        }
        println!();
    }

    display::render(&results);
}
