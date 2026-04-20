mod display;
mod scanner;

use scanner::scan;

struct Args {
    cidr: String,
    timeout_ms: u32,
    count: u32,
    concurrency: usize,
    quiet: bool,
    debug: bool,
    dump: Option<String>,
}

fn usage() -> ! {
    eprintln!(
        "Usage: ipmap <CIDR> [-t <timeout_ms>] [-r <retries>] [-c <concurrency>] [-q] [--debug] [--dump <path>]"
    );
    eprintln!();
    eprintln!("Options:");
    eprintln!("  -t <ms>        ping timeout per packet in milliseconds (default: 500)");
    eprintln!("  -r <n>         number of ping packets per host (default: 3)");
    eprintln!("  -c <n>         max concurrent pings (default: 64)");
    eprintln!("  -q             quiet mode, only print the final matrix");
    eprintln!("  --debug        print raw ping output and per-host details to stderr");
    eprintln!("  --dump <path>  write a full debug dump file to <path>");
    eprintln!();
    eprintln!("Example:");
    eprintln!("  ipmap 192.168.1.0/24");
    eprintln!("  ipmap 10.0.0.0/16 -t 200 -r 5 -c 128");
    eprintln!("  ipmap 192.168.1.0/24 --debug --dump /tmp/ipmap.dump");
    std::process::exit(1);
}

fn parse_args() -> Args {
    let raw: Vec<String> = std::env::args().collect();
    let mut cidr: Option<String> = None;
    let mut timeout_ms: u32 = 500;
    let mut count: u32 = 3;
    let mut concurrency: usize = 64;
    let mut quiet = false;
    let mut debug = false;
    let mut dump: Option<String> = None;

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
            "--debug" => debug = true,
            "--dump" => {
                i += 1;
                if i >= raw.len() {
                    eprintln!("error: --dump requires a path");
                    usage();
                }
                dump = Some(raw[i].clone());
            }
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
        debug,
        dump,
    }
}

fn write_dump(path: &str, args: &Args, results: &[scanner::PingResult]) -> std::io::Result<()> {
    use std::fmt::Write as FmtWrite;
    let mut buf = String::new();

    writeln!(buf, "=== ipmap debug dump ===").unwrap();
    writeln!(buf, "date: {}", chrono_now()).unwrap();
    writeln!(buf, "os: {}", std::env::consts::OS).unwrap();
    writeln!(buf, "arch: {}", std::env::consts::ARCH).unwrap();
    writeln!(buf).unwrap();
    writeln!(buf, "--- args ---").unwrap();
    writeln!(buf, "cidr:        {}", args.cidr).unwrap();
    writeln!(buf, "timeout_ms:  {}", args.timeout_ms).unwrap();
    writeln!(buf, "count:       {}", args.count).unwrap();
    writeln!(buf, "concurrency: {}", args.concurrency).unwrap();
    writeln!(buf, "quiet:       {}", args.quiet).unwrap();
    writeln!(buf, "debug:       {}", args.debug).unwrap();
    writeln!(buf).unwrap();
    writeln!(buf, "--- results ({} hosts) ---", results.len()).unwrap();

    let alive_count = results.iter().filter(|r| r.alive).count();
    writeln!(
        buf,
        "alive: {}  dead: {}",
        alive_count,
        results.len() - alive_count
    )
    .unwrap();
    writeln!(buf).unwrap();

    for r in results {
        writeln!(
            buf,
            "[{}] alive={} latency={:?} exit={:?}",
            r.ip, r.alive, r.latency_ms, r.exit_code
        )
        .unwrap();
        for line in r.raw_output.lines() {
            writeln!(buf, "  {line}").unwrap();
        }
        writeln!(buf).unwrap();
    }

    std::fs::write(path, buf)
}

fn chrono_now() -> String {
    // Use SystemTime since we have no chrono dep
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    format!("unix timestamp {secs}")
}

#[tokio::main]
async fn main() {
    let args = parse_args();

    let ips = scanner::parse_cidr(&args.cidr).unwrap_or_else(|e| {
        eprintln!("error: {e}");
        std::process::exit(1);
    });

    if args.debug {
        eprintln!(
            "[DEBUG] cidr={} hosts={} timeout_ms={} count={} concurrency={}",
            args.cidr,
            ips.len(),
            args.timeout_ms,
            args.count,
            args.concurrency
        );
        eprintln!(
            "[DEBUG] os={} arch={}",
            std::env::consts::OS,
            std::env::consts::ARCH
        );
        eprintln!(
            "[DEBUG] cmd args: {:?}",
            std::env::args().collect::<Vec<_>>()
        );
        eprintln!();
    }

    if !args.quiet && !args.debug {
        println!(
            "Scanning {} ({} hosts, {} ping(s) each)...",
            args.cidr,
            ips.len(),
            args.count
        );
        println!();
    } else if !args.quiet {
        eprintln!(
            "[DEBUG] Scanning {} ({} hosts, {} ping(s) each)...",
            args.cidr,
            ips.len(),
            args.count
        );
        eprintln!();
    }

    let results = scan(
        ips,
        args.timeout_ms,
        args.count,
        args.concurrency,
        args.quiet,
        args.debug,
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

    if let Some(ref path) = args.dump {
        match write_dump(path, &args, &results) {
            Ok(()) => eprintln!("dump written to: {path}"),
            Err(e) => eprintln!("error writing dump to {path}: {e}"),
        }
    }
}
