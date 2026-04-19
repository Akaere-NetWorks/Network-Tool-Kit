use bgpq4_lib::config::{ExpanderConfig, Generation, Vendor};
use bgpq4_lib::expander::Expander;
use bgpq4_lib::printer;
use bgpq4_lib::report;

fn usage(ecode: i32) -> ! {
    println!("\nUsage: bgpq4 [-h host[:port]] [-S sources] [-E|G|H <num>|f <num>|t] [-46ABbdJjKNnpwXz] [-R len] <OBJECTS> ... [EXCEPT <OBJECTS> ...]\n");
    println!("\nVendor targets:");
    println!(" no option : Cisco IOS Classic (default)");
    println!(" -X        : Cisco IOS XR");
    println!(" -U        : Huawei");
    println!(" -u        : Huawei XPL");
    println!(" -j        : JSON");
    println!(" -J        : Juniper Junos");
    println!(" -K        : MikroTik RouterOSv6");
    println!(" -K7       : MikroTik RouterOSv7");
    println!(" -b        : NIC.CZ BIRD");
    println!(" -N        : Nokia SR OS (Classic CLI)");
    println!(" -n        : Nokia SR OS (MD-CLI)");
    println!(" -n2       : Nokia SR Linux");
    println!(" -B        : OpenBSD OpenBGPD");
    println!(" -e        : Arista EOS");
    println!(" -F fmt    : User defined format (example: '-F %n/%l')");

    println!("\nInput filters:");
    println!(" -4        : generate IPv4 prefix-lists (default)");
    println!(" -6        : generate IPv6 prefix-lists");
    println!(" -m len    : maximum prefix length (default: 32 for IPv4, 128 for IPv6)");
    println!(" -L depth  : limit recursion depth (default: unlimited)");
    println!(
        " -S sources: only use specified IRR sources, in the specified order (comma separated)"
    );
    println!(" -w        : 'validate' AS numbers: only accept ones with registered routes");

    println!("\nOutput modifiers:");
    println!(" -3        : assume that your device is asn32-safe (default)");
    println!(" -A        : try to aggregate prefix-lists/route-filters");
    println!(" -E        : generate extended access-list (Cisco), route-filter (Juniper)");
    println!(" -f number : generate input as-path access-list");
    println!(" -G number : generate output as-path access-list");
    println!(" -H number : generate origin as-lists (JunOS only)");
    println!(" -M match  : extra match conditions for JunOS route-filters");
    println!(" -l name   : use specified name for generated access/prefix/.. list");
    println!(" -p        : allow special ASNs like 23456 or in the private range");
    println!(" -R len    : allow more specific routes up to specified masklen");
    println!(" -r len    : allow more specific routes from masklen specified");
    println!(" -s        : generate sequence numbers in prefix-lists (IOS only)");
    println!(" -t        : generate as-sets for OpenBGPD (OpenBGPD 6.4+), BIRD and JSON formats");
    println!(" -z        : generate route-filter-list (Junos only)");
    println!(" -W len    : specify max-entries on as-path/as-list line (use 0 for infinity)");

    println!("\nUtility operations:");
    println!(" -d        : generate some debugging output");
    println!(" -h host   : host running IRRD software (default: rr.ntt.net)");
    println!("             use 'host:port' to specify alternate port");
    println!(" -T        : disable pipelining (not recommended)");
    println!(" -v        : print version and exit");
    println!("\nbgpq4-rs version: 0.1.0\n");
    std::process::exit(ecode)
}

fn version() -> ! {
    println!("bgpq4-rs - a versatile utility to generate BGP filters");
    println!("version: 0.1.0");
    println!("website: https://github.com/bgp/bgpq4");
    std::process::exit(0)
}

fn parse_asnumber(s: &str) -> u32 {
    let asn: u32;
    if let Some(dot_pos) = s.find('.') {
        let hi: u32 = s[..dot_pos].parse().unwrap_or(0);
        let lo: u32 = s[dot_pos + 1..].parse().unwrap_or(0);
        if !(1..=65535).contains(&hi) || !(1..=65535).contains(&lo) {
            report::fatal(&format!("Invalid AS number: {s}"));
        }
        asn = (hi << 16) + lo;
    } else {
        asn = s.parse().unwrap_or_else(|_| {
            report::fatal(&format!("Invalid AS number: {s}"));
        });
    }
    if !(1..=65535u32 * 65535).contains(&asn) {
        report::fatal(&format!("Invalid AS number: {s}"));
    }
    asn
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let mut i = 1usize;

    let mut config = ExpanderConfig::default();
    config.init(2);

    let mut aggregate = 0;
    let mut width_set = false;
    #[allow(unused_assignments)]
    let mut refine: u32 = 0;
    let mut refine_low: u32 = 0;
    let mut generation_set = false;
    let mut af_set = false;

    let mut objects: Vec<String> = Vec::new();

    while i < args.len() {
        let arg = &args[i];
        if arg == "--" {
            i += 1;
            break;
        } else if arg == "-3" {
            // do nothing, 32-bit ASN support assumed
        } else if arg == "-4" {
            if af_set && config.family == 10 {
                report::fatal("-4 and -6 are mutually exclusive");
            }
            af_set = true;
        } else if arg == "-6" {
            if af_set && config.family == 2 {
                report::fatal("-4 and -6 are mutually exclusive");
            }
            config.family = 10;
            config.maxlen = 128;
            af_set = true;
        } else if arg == "-a" {
            i += 1;
            if i >= args.len() {
                report::fatal("Missing argument for -a");
            }
            config.asnumber = parse_asnumber(&args[i]);
        } else if arg == "-A" {
            if aggregate > 0 {
                config.debug_aggregation += 1;
            }
            aggregate = 1;
        } else if arg == "-b" {
            if config.vendor != Vendor::Cisco {
                vendor_exclusive();
            }
            config.vendor = Vendor::Bird;
        } else if arg == "-B" {
            if config.vendor != Vendor::Cisco {
                vendor_exclusive();
            }
            config.vendor = Vendor::OpenBgpd;
        } else if arg == "-d" {
            config.debug_expander += 1;
        } else if arg == "-E" {
            if generation_set {
                exclusive();
            }
            config.generation = Generation::Eacl;
            generation_set = true;
        } else if arg == "-e" {
            if config.vendor != Vendor::Cisco {
                vendor_exclusive();
            }
            config.vendor = Vendor::Arista;
            config.sequence = 1;
        } else if arg == "-F" {
            if generation_set {
                exclusive();
            }
            i += 1;
            if i >= args.len() {
                report::fatal("-F requires an argument");
            }
            config.vendor = Vendor::Format;
            config.format = Some(args[i].clone());
        } else if arg == "-f" {
            if generation_set {
                exclusive();
            }
            i += 1;
            if i >= args.len() {
                report::fatal("-f requires an argument");
            }
            config.generation = Generation::AsPath;
            generation_set = true;
            config.asnumber = parse_asnumber(&args[i]);
        } else if arg == "-G" {
            if generation_set {
                exclusive();
            }
            i += 1;
            if i >= args.len() {
                report::fatal("-G requires an argument");
            }
            config.generation = Generation::OasPath;
            generation_set = true;
            config.asnumber = parse_asnumber(&args[i]);
        } else if arg == "-H" {
            if generation_set {
                exclusive();
            }
            i += 1;
            if i >= args.len() {
                report::fatal("-H requires an argument");
            }
            config.generation = Generation::AsList;
            generation_set = true;
            config.asnumber = parse_asnumber(&args[i]);
        } else if arg == "-h" {
            i += 1;
            if i >= args.len() {
                report::fatal("-h requires an argument");
            }
            let host_arg = &args[i];
            if let Some(colon_pos) = host_arg.find(':') {
                config.server = host_arg[..colon_pos].to_string();
                config.port = host_arg[colon_pos + 1..].parse().unwrap_or_else(|_| {
                    report::fatal(&format!("Invalid port: {}", &host_arg[colon_pos + 1..]));
                });
            } else {
                config.server = host_arg.clone();
            }
        } else if arg == "-J" {
            if config.vendor != Vendor::Cisco {
                vendor_exclusive();
            }
            config.vendor = Vendor::Juniper;
        } else if arg == "-j" {
            if config.vendor != Vendor::Cisco {
                vendor_exclusive();
            }
            config.vendor = Vendor::Json;
        } else if arg == "-K" || arg == "-K7" {
            if config.vendor != Vendor::Cisco {
                vendor_exclusive();
            }
            config.vendor = if arg == "-K7" {
                Vendor::Mikrotik7
            } else {
                Vendor::Mikrotik6
            };
        } else if arg == "-r" {
            i += 1;
            if i >= args.len() {
                report::fatal("Missing argument for -r");
            }
            refine_low = args[i].parse().unwrap_or_else(|_| {
                report::fatal(&format!("Invalid refineLow value: {}", args[i]));
            });
            if refine_low == 0 {
                report::fatal(&format!("Invalid refineLow value: {}", args[i]));
            }
        } else if arg == "-R" {
            i += 1;
            if i >= args.len() {
                report::fatal("Missing argument for -R");
            }
            refine = args[i].parse().unwrap_or_else(|_| {
                report::fatal(&format!("Invalid refine length: {}", args[i]));
            });
            if refine == 0 {
                report::fatal(&format!("Invalid refine length: {}", args[i]));
            }
        } else if arg == "-l" {
            i += 1;
            if i >= args.len() {
                report::fatal("-l requires an argument");
            }
            config.name = args[i].clone();
        } else if let Some(rest) = arg.strip_prefix("-L") {
            config.maxdepth = rest.parse().unwrap_or_else(|_| {
                report::fatal(&format!("Invalid maximum recursion (-L): {rest}"));
            });
            if config.maxdepth < 1 {
                report::fatal(&format!("Invalid maximum recursion (-L): {rest}"));
            }
        } else if let Some(rest) = arg.strip_prefix("-m") {
            let maxlen: u32 = rest.parse().unwrap_or_else(|_| {
                report::fatal(&format!("Invalid maxlen (-m): {rest}"));
            });
            if maxlen == 0 {
                report::fatal(&format!("Invalid maxlen (-m): {rest}"));
            }
            config.maxlen = maxlen;
        } else if arg == "-M" {
            i += 1;
            if i >= args.len() {
                report::fatal("-M requires an argument");
            }
            let match_val = process_match_string(&args[i]);
            config.r#match = Some(match_val);
        } else if arg == "-N" {
            if config.vendor != Vendor::Cisco {
                vendor_exclusive();
            }
            config.vendor = Vendor::Nokia;
        } else if arg == "-n" || arg == "-n2" {
            if config.vendor != Vendor::Cisco {
                vendor_exclusive();
            }
            config.vendor = if arg == "-n2" {
                Vendor::NokiaSrl
            } else {
                Vendor::NokiaMd
            };
        } else if arg == "-p" {
            config.expand_special_asn = true;
        } else if arg == "-t" {
            if generation_set {
                exclusive();
            }
            config.generation = Generation::Asset;
            generation_set = true;
        } else if arg == "-T" {
            config.pipelining = false;
        } else if arg == "-s" {
            config.sequence = 1;
        } else if arg == "-S" {
            i += 1;
            if i >= args.len() {
                report::fatal("-S requires an argument");
            }
            config.sources = args[i].clone();
        } else if arg == "-U" {
            if config.vendor != Vendor::Cisco {
                vendor_exclusive();
            }
            config.vendor = Vendor::Huawei;
        } else if arg == "-u" {
            if config.vendor != Vendor::Cisco {
                vendor_exclusive();
            }
            config.vendor = Vendor::HuaweiXpl;
        } else if let Some(rest) = arg.strip_prefix("-W") {
            let w: i32 = rest.parse().unwrap_or(0);
            if w < 0 {
                report::fatal(&format!("Invalid as-width: {rest}"));
            }
            config.aswidth = w;
            width_set = true;
        } else if arg == "-w" {
            config.validate_asns = true;
        } else if arg == "-X" {
            if config.vendor != Vendor::Cisco {
                vendor_exclusive();
            }
            config.vendor = Vendor::CiscoXr;
        } else if arg == "-v" {
            version();
        } else if arg == "-z" {
            if generation_set {
                exclusive();
            }
            config.generation = Generation::RouteFilterList;
            generation_set = true;
        } else {
            objects.push(arg.clone());
        }
        i += 1;
    }

    while i < args.len() {
        objects.push(args[i].clone());
        i += 1;
    }

    if !width_set {
        match config.generation {
            Generation::AsPath => match config.vendor {
                Vendor::Arista | Vendor::Cisco | Vendor::Mikrotik6 | Vendor::Mikrotik7 => {
                    config.aswidth = 4;
                }
                Vendor::CiscoXr => {
                    config.aswidth = 6;
                }
                Vendor::Juniper | Vendor::Nokia | Vendor::NokiaMd | Vendor::NokiaSrl => {
                    config.aswidth = 8;
                }
                Vendor::Bird => {
                    config.aswidth = 10;
                }
                _ => {}
            },
            Generation::OasPath => match config.vendor {
                Vendor::Arista | Vendor::Cisco => {
                    config.aswidth = 5;
                }
                Vendor::CiscoXr => {
                    config.aswidth = 7;
                }
                Vendor::Juniper | Vendor::Nokia | Vendor::NokiaMd | Vendor::NokiaSrl => {
                    config.aswidth = 8;
                }
                _ => {}
            },
            Generation::AsList => {
                if config.vendor == Vendor::Juniper {
                    config.aswidth = 8;
                }
            }
            _ => {}
        }
    }

    if objects.is_empty() {
        usage(1);
    }

    let mut exp = Expander::new(config);
    let mut exceptmode = false;

    for obj in &objects {
        if obj == "EXCEPT" {
            exceptmode = true;
        } else if exceptmode {
            exp.add_stop(obj);
        } else {
            exp.add_object(obj);
        }
    }

    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        if !exp.expand().await {
            std::process::exit(1);
        }

        if refine > 0 {
            exp.tree.refine(refine);
        }
        if refine_low > 0 {
            exp.tree.refine_low(refine_low);
        }
        if aggregate > 0 {
            exp.tree.aggregate();
        }

        let mut out = String::new();
        match exp.config.generation {
            Generation::AsPath => printer::print_aspath(&mut out, &exp),
            Generation::OasPath => printer::print_oaspath(&mut out, &exp),
            Generation::AsList => printer::print_aslist(&mut out, &exp),
            Generation::Asset => printer::print_asset(&mut out, &exp),
            Generation::PrefixList => printer::print_prefixlist(&mut out, &exp),
            Generation::Eacl => printer::print_eacl(&mut out, &exp),
            Generation::RouteFilterList => printer::print_route_filter_list(&mut out, &exp),
            Generation::None => report::fatal("Unreachable point"),
        }

        print!("{out}");
    });
}

fn exclusive() -> ! {
    eprintln!("-E, -F, -K , -f <asnum>, -G <asnum>, and -t are mutually exclusive");
    std::process::exit(1)
}

fn vendor_exclusive() -> ! {
    eprintln!(
        "-b (BIRD), -B (OpenBGPD), -F (formatted), -J (Junos), \
        -j (JSON), -K[7] (Microtik ROS), -N (Nokia SR OS Classic), \
        -n (Nokia SR OS MD-CLI), -U (Huawei), -u (Huawei XPL), \
        -e (Arista) and -X (IOS XR) options are mutually exclusive"
    );
    std::process::exit(1)
}

fn process_match_string(s: &str) -> String {
    let mut result = Vec::new();
    let chars: Vec<char> = s.chars().collect();
    let mut i = 0;
    while i < chars.len() {
        if chars[i] == '\\' && i + 1 < chars.len() {
            match chars[i + 1] {
                '\n' => {
                    result.push('\n');
                    i += 2;
                }
                'r' => {
                    result.push('\r');
                    i += 2;
                }
                't' => {
                    result.push('\t');
                    i += 2;
                }
                '\\' => {
                    result.push('\\');
                    i += 2;
                }
                c => {
                    report::fatal(&format!(
                        "Unsupported escape \\{} (0x{:02x}) in '{}'",
                        c, c as u8, s
                    ));
                }
            }
        } else {
            result.push(chars[i]);
            i += 1;
        }
    }
    result.into_iter().collect()
}
