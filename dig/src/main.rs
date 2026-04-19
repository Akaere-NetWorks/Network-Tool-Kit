use dig_lib::{
    dns::{build_query, QueryConfig, RecordType},
    printer::{self, PrintContext, PrintOpts},
    resolver::{self, parse_server, ResolverConfig, ServerAddr},
};
use std::time::Instant;

const VERSION: &str = "dig 0.1.0 (Network Tool Kit)";

struct DigArgs {
    server: Option<String>,
    names: Vec<(String, RecordType, u16)>,
    reverse: Option<String>,
    port: u16,
    config: QueryConfig,
    resolver_config: ResolverConfig,
    print_opts: PrintOpts,
    trace: bool,
    use_usec: bool,
    batch_file: Option<String>,
    class: u16,
}

fn parse_args(raw: &[String]) -> Result<DigArgs, String> {
    let mut args = DigArgs {
        server: None,
        names: Vec::new(),
        reverse: None,
        port: 53,
        config: QueryConfig::default(),
        resolver_config: ResolverConfig::default(),
        print_opts: PrintOpts::default(),
        trace: false,
        use_usec: false,
        batch_file: None,
        class: 1,
    };

    let mut i = 1usize;
    let mut current_name: Option<String> = None;
    let mut current_type: Option<RecordType> = None;

    while i < raw.len() {
        let arg = &raw[i];

        if let Some(addr) = arg.strip_prefix('@') {
            args.server = Some(addr.to_string());
        } else if let Some(opt) = arg.strip_prefix('+') {
            parse_plus_option(&mut args, opt)?;
        } else if arg == "-4" || arg == "-6" {
            // address-family flag, currently ignored
        } else if arg == "-p" {
            i += 1;
            if i >= raw.len() {
                return Err("-p requires an argument".into());
            }
            args.port = raw[i].parse().map_err(|_| "invalid port")?;
        } else if arg == "-t" {
            i += 1;
            if i >= raw.len() {
                return Err("-t requires an argument".into());
            }
            let t = raw[i].to_uppercase();
            if t == "IXFR" {
                current_type = Some(RecordType::Ixfr);
            } else {
                current_type = Some(
                    RecordType::from_name(&t).ok_or_else(|| format!("unknown type: {}", raw[i]))?,
                );
            }
        } else if arg == "-c" {
            i += 1;
            if i >= raw.len() {
                return Err("-c requires an argument".into());
            }
            args.class = parse_class(&raw[i].to_uppercase())
                .ok_or_else(|| format!("unknown class: {}", raw[i]))?;
        } else if arg == "-x" {
            i += 1;
            if i >= raw.len() {
                return Err("-x requires an argument".into());
            }
            args.reverse = Some(raw[i].clone());
        } else if arg == "-b" {
            i += 1;
            if i >= raw.len() {
                return Err("-b requires an argument".into());
            }
        } else if arg == "-q" {
            i += 1;
            if i >= raw.len() {
                return Err("-q requires an argument".into());
            }
            current_name = Some(raw[i].clone());
        } else if arg == "-f" {
            i += 1;
            if i >= raw.len() {
                return Err("-f requires an argument".into());
            }
            args.batch_file = Some(raw[i].clone());
        } else if arg == "-k" || arg == "-y" {
            i += 1;
            if i >= raw.len() {
                return Err(format!("{arg} requires an argument"));
            }
        } else if arg == "-u" {
            args.use_usec = true;
        } else if arg == "-v" || arg == "--version" {
            println!("{VERSION}");
            std::process::exit(0);
        } else if arg == "-h" || arg == "--help" {
            print_help();
            std::process::exit(0);
        } else if !arg.starts_with('-') {
            let maybe_type = RecordType::from_name(arg);
            if let Some(rt) = maybe_type {
                if let Some(name) = current_name.take() {
                    args.names.push((name, rt, args.class));
                } else if current_type.is_none() {
                    current_type = Some(rt);
                } else if let Some(ref mut _rt) = current_type {
                } else {
                    current_name = Some(arg.clone());
                }
            } else if let Some(name) = current_name.take() {
                if let Some(rt) = current_type.take() {
                    args.names.push((name, rt, args.class));
                } else {
                    args.names.push((name, RecordType::A, args.class));
                }
                current_name = Some(arg.clone());
            } else {
                current_name = Some(arg.clone());
            }
        }
        i += 1;
    }

    if let Some(name) = current_name.take() {
        if let Some(rt) = current_type.take() {
            args.names.push((name, rt, args.class));
        } else {
            args.names.push((name, RecordType::A, args.class));
        }
    } else if let Some(rt) = current_type.take() {
        args.names.push((".".to_string(), rt, args.class));
    }

    if args.names.is_empty() && args.reverse.is_none() && args.batch_file.is_none() {
        return Err("no query specified".into());
    }

    Ok(args)
}

fn parse_plus_option(args: &mut DigArgs, flag: &str) -> Result<(), String> {
    let (name, val) = if let Some((n, v)) = flag.split_once('=') {
        (n, Some(v))
    } else {
        (flag, None)
    };

    let no = name.starts_with("no");
    let bare = if no { &name[2..] } else { name };

    match bare {
        "short" => args.print_opts.short = !no,
        "comments" => args.print_opts.show_comments = !no,
        "question" => args.print_opts.show_question = !no,
        "answer" => args.print_opts.show_answer = !no,
        "authority" => args.print_opts.show_authority = !no,
        "additional" => args.print_opts.show_additional = !no,
        "stats" => args.print_opts.show_stats = !no,
        "cmd" => args.print_opts.show_cmd = !no,
        "qr" => args.print_opts.show_qr = !no,
        "identify" => args.print_opts.show_identify = !no,
        "multiline" => args.print_opts.multiline = !no,
        "ttlid" | "ttl" => args.print_opts.show_ttl = !no,
        "ttlunits" => args.print_opts.ttl_units = !no,
        "class" => args.print_opts.show_class = !no,
        "rrcomments" => args.print_opts.show_rrcomments = !no,
        "unknownformat" => args.print_opts.unknown_format = !no,
        "yaml" => args.print_opts.yaml = !no,
        "all" => {
            args.print_opts.show_comments = !no;
            args.print_opts.show_question = !no;
            args.print_opts.show_answer = !no;
            args.print_opts.show_authority = !no;
            args.print_opts.show_additional = !no;
            args.print_opts.show_stats = !no;
            args.print_opts.show_cmd = !no;
        }
        "dnssec" | "do" => {
            args.config.dnssec_ok = !no;
            args.config.edns = true;
        }
        "cdflag" | "cd" => args.config.cd = !no,
        "adflag" => args.config.ad = !no,
        "aaflag" | "aaonly" => args.config.aa = !no,
        "raflag" => args.config.ra_flag = !no,
        "tcflag" => args.config.tc = !no,
        "zflag" => args.config.z_flag = !no,
        "recurse" | "rdflag" => args.config.rd = !no,
        "tcp" | "vc" => args.resolver_config.use_tcp = !no,
        "ignore" => args.resolver_config.ignore_tc = !no,
        "header-only" => args.config.header_only = !no,
        "edns" => {
            if no {
                args.config.edns = false;
            } else if let Some(v) = val {
                args.config.edns = true;
                args.config.edns_version = v.parse().map_err(|_| "invalid EDNS version")?;
            } else {
                args.config.edns = true;
            }
        }
        "bufsize" => {
            if let Some(v) = val {
                args.config.udp_bufsize = v.parse().map_err(|_| "invalid bufsize")?;
            }
            args.config.edns = true;
        }
        "ednsflags" => {
            if let Some(v) = val {
                args.config.edns_flags = u16::from_str_radix(v.trim_start_matches("0x"), 16)
                    .unwrap_or(v.parse().unwrap_or(0));
            }
            args.config.edns = true;
        }
        "retry" | "retries" => {
            if let Some(v) = val {
                args.resolver_config.retry = v.parse().map_err(|_| "invalid retry")?;
            }
        }
        "tries" => {
            if let Some(v) = val {
                args.resolver_config.tries = v.parse().map_err(|_| "invalid tries")?;
                if args.resolver_config.tries == 0 {
                    args.resolver_config.tries = 1;
                }
            }
        }
        "timeout" | "time" => {
            if let Some(v) = val {
                args.resolver_config.timeout_secs = v.parse().map_err(|_| "invalid timeout")?;
            }
        }
        "trace" => {
            args.trace = !no;
            if !no {
                args.config.dnssec_ok = true;
                args.config.rd = false;
            }
        }
        "opcode" => {
            if let Some(v) = val {
                args.config.opcode = match v {
                    "QUERY" | "query" | "0" => 0,
                    "IQUERY" | "1" => 1,
                    "STATUS" | "2" => 2,
                    "NOTIFY" | "4" => 4,
                    "UPDATE" | "5" => 5,
                    s => s.parse().map_err(|_| format!("invalid opcode: {s}"))?,
                };
            }
        }
        "qid" => {
            if let Some(v) = val {
                args.config.id = v.parse().map_err(|_| "invalid qid")?;
            }
        }
        "split" => {
            if no {
                args.print_opts.split_width = None;
            } else {
                let w = val.and_then(|v| v.parse().ok()).unwrap_or(56);
                args.print_opts.split_width = Some(w);
            }
        }
        "keepopen" | "keepalive" | "besteffort" | "fail" | "nssearch" | "showsearch" | "search"
        | "defname" | "onesoa" | "nsid" | "cookie" | "subnet" | "expire" | "padding"
        | "ednsnegotiation" | "badcookie" | "showbadcookie" | "showbadvers" | "showtruncated"
        | "showallmessages" | "dns64prefix" | "idn" | "idnin" | "idnout" | "mapped"
        | "expandaaaa" | "zoneversion" | "svcparamkeycompat" => {
            // acknowledged but not implemented in this version
        }
        _ => return Err(format!("unknown option: +{flag}")),
    }
    Ok(())
}

fn parse_class(s: &str) -> Option<u16> {
    match s {
        "IN" => Some(1),
        "CH" | "CHAOS" => Some(3),
        "HS" | "HESIOD" => Some(4),
        "NONE" => Some(254),
        "ANY" => Some(255),
        _ => None,
    }
}

fn build_reverse_name(addr: &str) -> String {
    if addr.contains(':') {
        let clean = addr.replace(":", "");
        let full: String = clean.chars().rev().collect();
        let mut labels = Vec::new();
        for ch in full.chars() {
            labels.push(ch.to_string());
        }
        format!("{}.ip6.arpa", labels.join("."))
    } else {
        let parts: Vec<&str> = addr.split('.').collect();
        if parts.len() == 4 {
            format!(
                "{}.{}.{}.{}.in-addr.arpa",
                parts[3], parts[2], parts[1], parts[0]
            )
        } else {
            format!("{addr}.in-addr.arpa")
        }
    }
}

fn rand_id() -> u16 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| (d.subsec_nanos() % 65536) as u16)
        .unwrap_or(0x1234)
}

#[tokio::main]
async fn main() {
    let raw: Vec<String> = std::env::args().collect();
    let cmdline = raw.join(" ");

    let args = match parse_args(&raw) {
        Ok(a) => a,
        Err(e) => {
            eprintln!(";; Error: {e}");
            std::process::exit(1);
        }
    };

    let server_str = args.server.as_deref().unwrap_or("8.8.8.8");
    let server = parse_server(server_str, args.port).unwrap_or_else(|e| {
        eprintln!(";; {e}");
        std::process::exit(1);
    });
    let server_host = match &server {
        ServerAddr::UdpTcp(a) => a.to_string(),
        ServerAddr::Doh(u) => u.clone(),
    };

    if args.trace {
        run_trace(&args, &server_host, &server, &cmdline).await;
        return;
    }

    let queries: Vec<(String, RecordType, u16)> = if let Some(ref rev) = args.reverse {
        vec![(build_reverse_name(rev), RecordType::Ptr, args.class)]
    } else {
        args.names.clone()
    };

    for (name, qtype, qclass) in &queries {
        let mut cfg = args.config.clone();
        cfg.qclass = *qclass;
        if cfg.id == 0x1234 {
            cfg.id = rand_id();
        }

        let query = build_query(name, *qtype, &cfg);

        if args.print_opts.show_qr {
            println!(";; Sending:");
            let tmp_opts = PrintOpts::default();
            let tmp_ctx = PrintContext {
                opts: &tmp_opts,
                server: &server_host,
                query_time_ms: None,
                query_bytes: None,
                response_bytes: None,
                server_addr: None,
                cmdline: None,
            };
            let tmp_msg =
                dig_lib::dns::parse_message(&query).unwrap_or_else(|_| dig_lib::dns::Message {
                    header: dig_lib::dns::Header {
                        id: 0,
                        flags: 0,
                        qd_count: 0,
                        an_count: 0,
                        ns_count: 0,
                        ar_count: 0,
                    },
                    questions: vec![],
                    answers: vec![],
                    authority: vec![],
                    additional: vec![],
                });
            print!("{}", printer::print_message(&tmp_ctx, &tmp_msg));
        }

        let start = Instant::now();
        let result = match resolver::send_query(&server, &query, &args.resolver_config).await {
            Ok(r) => r,
            Err(e) => {
                eprintln!(";; {e}");
                std::process::exit(1);
            }
        };
        let elapsed = if args.use_usec {
            start.elapsed().as_micros() as u64
        } else {
            start.elapsed().as_millis() as u64
        };

        let ctx = PrintContext {
            opts: &args.print_opts,
            server: &server_host,
            query_time_ms: Some(elapsed),
            query_bytes: Some(result.query_bytes),
            response_bytes: Some(result.response_bytes),
            server_addr: Some(server_host.clone()),
            cmdline: if args.print_opts.show_cmd {
                Some(cmdline.clone())
            } else {
                None
            },
        };

        if args.print_opts.short {
            print!("{}", printer::print_short(&ctx, &result.message));
        } else {
            print!("{}", printer::print_message(&ctx, &result.message));
        }

        if queries.len() > 1 {
            println!();
        }
    }
}

async fn run_trace(args: &DigArgs, _server_host: &str, _server: &ServerAddr, cmdline: &str) {
    let queries: Vec<(String, RecordType, u16)> = if let Some(ref rev) = args.reverse {
        vec![(build_reverse_name(rev), RecordType::Ptr, args.class)]
    } else {
        args.names.clone()
    };

    for (name, qtype, qclass) in &queries {
        let mut cfg = args.config.clone();
        cfg.qclass = *qclass;
        cfg.rd = false;
        if cfg.id == 0x1234 {
            cfg.id = rand_id();
        }

        let results = match resolver::trace_query(name, *qtype, &cfg, &args.resolver_config).await {
            Ok(r) => r,
            Err(e) => {
                eprintln!(";; {e}");
                std::process::exit(1);
            }
        };

        for (idx, result) in results.iter().enumerate() {
            let server_str = if idx == 0 {
                "root server"
            } else {
                "referred server"
            };
            let ctx = PrintContext {
                opts: &args.print_opts,
                server: server_str,
                query_time_ms: None,
                query_bytes: Some(result.query_bytes),
                response_bytes: Some(result.response_bytes),
                server_addr: None,
                cmdline: if idx == 0 && args.print_opts.show_cmd {
                    Some(cmdline.to_string())
                } else {
                    None
                },
            };

            if !args.print_opts.short {
                println!(
                    ";; Received {} bytes from {server_str}",
                    result.response_bytes
                );
            }
            if args.print_opts.short {
                let ctx_short = PrintContext {
                    opts: &PrintOpts {
                        short: true,
                        ..args.print_opts.clone()
                    },
                    ..ctx
                };
                print!("{}", printer::print_short(&ctx_short, &result.message));
            } else {
                print!("{}", printer::print_message(&ctx, &result.message));
            }
            println!();
        }
    }
}

fn print_help() {
    println!("{VERSION}");
    println!("Usage: dig [@server] name [type] [class] [+opts] [-flags]");
    println!();
    println!("Options:");
    println!("  @server       Server to query (default: 8.8.8.8)");
    println!("  -t type       Query type (A, AAAA, MX, NS, TXT, ANY, etc.)");
    println!("  -c class      Query class (IN, CH, HS, ANY)");
    println!("  -p port       Port number (default: 53)");
    println!("  -x addr       Reverse lookup");
    println!("  -q name       Query name");
    println!("  -f file       Batch mode: read queries from file");
    println!("  -4            Use IPv4 only");
    println!("  -6            Use IPv6 only");
    println!("  -b addr       Bind to source address");
    println!("  -u            Display times in microseconds");
    println!("  -v            Print version");
    println!("  -h            Print help");
    println!();
    println!("Plus options (+[no]flag[=value]):");
    println!("  +[no]short           Short output");
    println!("  +[no]dnssec / +do    Set DNSSEC OK bit");
    println!("  +[no]trace           Trace delegation from root");
    println!("  +[no]tcp / +vc       Use TCP");
    println!("  +[no]multiline       Verbose multi-line output");
    println!("  +[no]comments        Show comments");
    println!("  +[no]stats           Show statistics");
    println!("  +[no]cmd             Show command line");
    println!("  +[no]question        Show question section");
    println!("  +[no]answer          Show answer section");
    println!("  +[no]authority       Show authority section");
    println!("  +[no]additional      Show additional section");
    println!("  +[no]identify        Show responder in short output");
    println!("  +[no]qr              Print question before sending");
    println!("  +[no]ttlid           Show TTL in records");
    println!("  +[no]ttlunits        Display TTLs in human-readable units");
    println!("  +[no]class           Show CLASS in records");
    println!("  +[no]rrcomments      Show per-record comments");
    println!("  +[no]unknownformat   RFC 3597 format for RDATA");
    println!("  +[no]yaml            YAML output");
    println!("  +[no]all             Set/clear all display flags");
    println!("  +[no]recurse         Set RD flag");
    println!("  +[no]aaflag          Set AA flag");
    println!("  +[no]adflag          Set AD flag");
    println!("  +[no]cdflag          Set CD flag");
    println!("  +[no]ignore          Don't revert to TCP on TC");
    println!("  +[no]header-only     Send query without question");
    println!("  +[no]edns[=N]        Enable EDNS / set version");
    println!("  +bufsize=N           Set EDNS UDP buffer size (default: 1232)");
    println!("  +ednsflags=N         Set EDNS Z flags");
    println!("  +opcode=N            Set DNS opcode");
    println!("  +qid=N               Set query ID");
    println!("  +timeout=N / +time=N Query timeout (default: 5)");
    println!("  +tries=N             Total UDP attempts (default: 3)");
    println!("  +retry=N             Extra UDP retries (default: 0)");
    println!("  +split[=W]           Split hex fields (default: 56)");
}
