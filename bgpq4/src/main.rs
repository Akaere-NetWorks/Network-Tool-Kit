use bgpq4_lib::{
    expander::{Expander, IpFamily},
    prefix::aggregate,
    printer,
};
use clap::Parser;

#[derive(Parser)]
#[command(
    name = "bgpq4",
    about = "Generate BGP filters from IRR data",
    disable_help_flag = true,
)]
struct Cli {
    #[arg(short = '4', conflicts_with = "ipv6")]
    ipv4: bool,

    #[arg(short = '6', conflicts_with = "ipv4")]
    ipv6: bool,

    #[arg(short = 'H', default_value = "rr.ntt.net")]
    host: String,

    #[arg(short = 'l', default_value = "NN")]
    name: String,

    #[arg(short = 'A')]
    aggregate_flag: bool,

    #[arg(short = 'J', conflicts_with_all = ["json", "bird", "openbgpd"])]
    juniper: bool,

    #[arg(short = 'j', conflicts_with_all = ["juniper", "bird", "openbgpd"])]
    json: bool,

    #[arg(short = 'b', conflicts_with_all = ["juniper", "json", "openbgpd"])]
    bird: bool,

    #[arg(short = 'B', conflicts_with_all = ["juniper", "json", "bird"])]
    openbgpd: bool,

    objects: Vec<String>,
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    let family = if cli.ipv6 { IpFamily::V6 } else { IpFamily::V4 };

    let (host, port) = if let Some((h, p)) = cli.host.split_once(':') {
        (h.to_string(), p.parse::<u16>().unwrap_or(43))
    } else {
        (cli.host.clone(), 43)
    };

    let expander = Expander::new(host, port, family);
    let mut all_prefixes = Vec::new();
    for obj in &cli.objects {
        match expander.expand(obj).await {
            Ok(mut pfxs) => all_prefixes.append(&mut pfxs),
            Err(e) => {
                eprintln!("Error expanding {obj}: {e}");
                std::process::exit(1);
            }
        }
    }

    if cli.aggregate_flag {
        all_prefixes = aggregate(all_prefixes);
    }

    let output = if cli.juniper {
        printer::format_juniper(&cli.name, &all_prefixes)
    } else if cli.json {
        printer::format_json(&cli.name, &all_prefixes)
    } else if cli.bird {
        printer::format_bird(&cli.name, &all_prefixes)
    } else if cli.openbgpd {
        printer::format_openbgpd(&cli.name, &all_prefixes)
    } else {
        printer::format_cisco(&cli.name, &all_prefixes)
    };

    print!("{output}");
}
