use super::common::*;
use super::format::*;
use crate::dns::Message;
use std::time::SystemTime;

const _VERSION: &str = "0.1.0";

#[derive(Debug, Clone)]
pub struct PrintOpts {
    pub short: bool,
    pub show_comments: bool,
    pub show_question: bool,
    pub show_answer: bool,
    pub show_authority: bool,
    pub show_additional: bool,
    pub show_stats: bool,
    pub show_cmd: bool,
    pub show_identify: bool,
    pub show_qr: bool,
    pub multiline: bool,
    pub show_ttl: bool,
    pub ttl_units: bool,
    pub show_class: bool,
    pub show_rrcomments: bool,
    pub unknown_format: bool,
    pub yaml: bool,
    pub split_width: Option<usize>,
}

impl Default for PrintOpts {
    fn default() -> Self {
        PrintOpts {
            short: false,
            show_comments: true,
            show_question: true,
            show_answer: true,
            show_authority: true,
            show_additional: true,
            show_stats: true,
            show_cmd: true,
            show_identify: false,
            show_qr: false,
            multiline: false,
            show_ttl: true,
            ttl_units: false,
            show_class: true,
            show_rrcomments: false,
            unknown_format: false,
            yaml: false,
            split_width: None,
        }
    }
}

pub struct PrintContext<'a> {
    pub opts: &'a PrintOpts,
    pub server: &'a str,
    pub query_time_us: Option<u64>,
    pub query_bytes: Option<usize>,
    pub response_bytes: Option<usize>,
    pub server_addr: Option<String>,
    pub cmdline: Option<String>,
    pub is_query: bool,
    pub use_tcp: bool,
    pub user_arg: Option<&'a str>,
    pub address_count: usize,
}

pub fn print_message(ctx: &PrintContext, msg: &Message) -> String {
    if ctx.opts.yaml {
        return print_yaml(ctx, msg);
    }
    if ctx.opts.short {
        return print_short(ctx, msg);
    }
    let mut out = String::new();

    if ctx.opts.show_cmd {
        if let Some(ref cmd) = ctx.cmdline {
            out.push('\n');
            out.push_str("; <<>> DiG ");
            out.push_str(_VERSION);
            out.push_str(" <<>> ");
            out.push_str(cmd);
            out.push_str(" <<>>\n");
            if ctx.address_count > 0 {
                let s = if ctx.address_count > 1 { "s" } else { "" };
                out.push_str(&format!("; ({} server{s} found)\n", ctx.address_count));
            }
            out.push_str(";; global options: +cmd\n");
        }
    }

    if ctx.opts.show_comments {
        if !ctx.is_query {
            out.push_str(";; Got answer:\n");
        }
        let rcode = crate::dns::rcode_name(msg.header.rcode());
        let opcode = crate::dns::opcode_name(msg.header.opcode());
        out.push_str(&format!(
            ";; ->>HEADER<<- opcode: {opcode}, status: {rcode}, id: {:6}\n",
            msg.header.id
        ));

        out.push_str(";; flags:");
        let mut flags = Vec::new();
        if msg.header.is_response() {
            flags.push("qr");
        }
        if msg.header.is_authoritative() {
            flags.push("aa");
        }
        if msg.header.is_truncated() {
            flags.push("tc");
        }
        if msg.header.recursion_desired() {
            flags.push("rd");
        }
        if msg.header.recursion_available() {
            flags.push("ra");
        }
        if msg.header.ad_flag() {
            flags.push("ad");
        }
        if msg.header.cd_flag() {
            flags.push("cd");
        }
        if flags.is_empty() {
            out.push(' ');
        } else {
            for f in &flags {
                out.push(' ');
                out.push_str(f);
            }
        }
        out.push_str(&format!(
            "; QUERY: {}, ANSWER: {}, AUTHORITY: {}, ADDITIONAL: {}\n",
            msg.header.qd_count, msg.header.an_count, msg.header.ns_count, msg.header.ar_count
        ));

        if let Some(opt) = msg.opt_record() {
            out.push_str(";; OPT PSEUDOSECTION:\n");
            out.push_str(&format!("; EDNS: version: {}, flags:", opt.edns_version));
            if opt.dnssec_ok {
                out.push_str(" do");
            }
            if opt.z_flags & 0x4000 != 0 {
                out.push_str(" co");
            }
            if opt.z_flags & 0x3FFF != 0 {
                out.push_str(&format!(" 0x{:04x}", opt.z_flags & 0x3FFF));
            }
            out.push_str(&format!("; udp: {}", opt.udp_size));
            if opt.extended_rcode != 0 {
                out.push_str(&format!(
                    "; rc: {}",
                    crate::dns::rcode_name(opt.extended_rcode)
                ));
            }
            out.push('\n');
            for edns_opt in &opt.options {
                print_edns_option(&mut out, edns_opt);
            }
        }
    }

    if ctx.opts.show_question && !msg.questions.is_empty() {
        out.push_str("\n;; QUESTION SECTION:\n");
        for q in &msg.questions {
            let cstr = if ctx.opts.show_class {
                class_name(q.qclass)
            } else {
                ""
            };
            add_question(
                &mut out,
                &q.name,
                cstr,
                q.qtype.as_str(),
                !ctx.opts.show_class,
            );
        }
    }

    print_section(&mut out, "ANSWER", &msg.answers, ctx);
    print_section(&mut out, "AUTHORITY", &msg.authority, ctx);
    print_section(&mut out, "ADDITIONAL", &msg.additional, ctx);

    if ctx.opts.show_comments {
        let tsig_records: Vec<_> = msg
            .additional
            .iter()
            .filter(|rr| rr.rtype == crate::dns::RecordType::Tsig)
            .collect();
        if !tsig_records.is_empty() {
            out.push_str("\n;; TSIG PSEUDOSECTION:\n");
            let fmt_opts = FormatOpts {
                ttl_units: ctx.opts.ttl_units,
                unknown_format: ctx.opts.unknown_format,
                rrcomments: ctx.opts.show_rrcomments,
            };
            for rr in &tsig_records {
                let rdata_str = format_rdata(&rr.rdata, &fmt_opts);
                add_rr_start(
                    &mut out,
                    &rr.name,
                    rr.ttl,
                    &rr.ttl.to_string(),
                    class_name(rr.class),
                    rr.rtype.as_str(),
                    false,
                    false,
                );
                out.push_str(&rdata_str);
                out.push('\n');
            }
            out.push('\n');
        }
    }

    if ctx.opts.show_comments
        && !ctx.is_query
        && msg.header.recursion_desired()
        && !msg.header.recursion_available()
    {
        out.push_str(";; WARNING: recursion requested but not available\n");
    }

    if ctx.opts.show_comments && !ctx.is_query {
        let rcode = msg.header.rcode();
        if (rcode == 1 || rcode == 4) && msg.opt_record().is_some() {
            out.push_str(";; WARNING: EDNS query returned status ");
            out.push_str(&crate::dns::rcode_name(rcode));
            out.push_str(" - retry with '+noedns'\n");
        }
    }

    if ctx.opts.show_stats {
        if let Some(us) = ctx.query_time_us {
            if us >= 1000 {
                out.push_str(&format!(";; Query time: {} msec\n", us / 1000));
            } else {
                out.push_str(&format!(";; Query time: {} usec\n", us));
            }
        }
        let proto = if ctx.use_tcp { "TCP" } else { "UDP" };
        let user_arg = ctx.user_arg.unwrap_or(ctx.server);
        out.push_str(&format!(
            ";; SERVER: {}#53({}) ({})\n",
            ctx.server, user_arg, proto
        ));
        out.push_str(";; WHEN: ");
        if let Ok(dur) = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH) {
            let secs = dur.as_secs();
            let tm = epoch_secs_to_tm(secs);
            out.push_str(format_weekday(tm.tm_wday));
            out.push(' ');
            out.push_str(format_month(tm.tm_mon));
            out.push(' ');
            out.push_str(&format!(
                "{:02} {:02}:{:02}:{:02}",
                tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec
            ));
            out.push_str(" UTC ");
            out.push_str(&format!("{}", 1970 + tm.tm_year));
        } else {
            out.push_str("unknown");
        }
        out.push('\n');
        if let Some(rb) = ctx.response_bytes {
            out.push_str(&format!(";; MSG SIZE  rcvd: {rb}\n"));
        }
        out.push('\n');
    }

    out
}

struct Tm {
    tm_wday: usize,
    tm_mon: usize,
    tm_mday: usize,
    tm_hour: usize,
    tm_min: usize,
    tm_sec: usize,
    tm_year: usize,
}

fn epoch_secs_to_tm(secs: u64) -> Tm {
    let mut days = secs / 86400;
    let time_of_day = secs % 86400;
    let hours = time_of_day / 3600;
    let mins = (time_of_day % 3600) / 60;
    let secs = time_of_day % 60;

    let mut year = 1970i32;
    loop {
        let days_in_year = if is_leap(year) { 366 } else { 365 };
        if days < days_in_year as u64 {
            break;
        }
        days -= days_in_year as u64;
        year += 1;
    }

    let leap = is_leap(year);
    let cum_days: [u64; 12] = if leap {
        [0, 31, 60, 91, 121, 152, 182, 213, 244, 274, 305, 335]
    } else {
        [0, 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334]
    };

    let mut month = 0usize;
    for (i, _cd) in cum_days.iter().enumerate() {
        let next = if i + 1 < 12 { cum_days[i + 1] } else { 366 };
        if days < next {
            month = i;
            break;
        }
    }
    let day_of_month = days - cum_days[month] + 1;

    let day_of_week = ((4 + (secs / 86400) % 7) as usize) % 7;

    Tm {
        tm_wday: day_of_week,
        tm_mon: month,
        tm_mday: day_of_month as usize,
        tm_hour: hours as usize,
        tm_min: mins as usize,
        tm_sec: secs as usize,
        tm_year: (year - 1970) as usize,
    }
}

fn is_leap(y: i32) -> bool {
    (y % 4 == 0 && y % 100 != 0) || (y % 400 == 0)
}

fn format_weekday(d: usize) -> &'static str {
    match d {
        0 => "Sun",
        1 => "Mon",
        2 => "Tue",
        3 => "Wed",
        4 => "Thu",
        5 => "Fri",
        6 => "Sat",
        _ => "???",
    }
}

fn format_month(m: usize) -> &'static str {
    match m {
        0 => "Jan",
        1 => "Feb",
        2 => "Mar",
        3 => "Apr",
        4 => "May",
        5 => "Jun",
        6 => "Jul",
        7 => "Aug",
        8 => "Sep",
        9 => "Oct",
        10 => "Nov",
        11 => "Dec",
        _ => "???",
    }
}

fn print_edns_option(out: &mut String, opt: &crate::dns::EdnsOption) {
    match opt.code {
        3 => {
            out.push_str("; NSID: ");
            out.push_str(&hex::encode(&opt.data));
            out.push('\n');
        }
        10 => {
            out.push_str("; COOKIE: ");
            out.push_str(&hex::encode(&opt.data));
            out.push('\n');
        }
        15 => {
            out.push_str("; EDE: ");
            if opt.data.len() >= 2 {
                let code = u16::from_be_bytes([opt.data[0], opt.data[1]]);
                let desc = ede_text(code);
                out.push_str(&format!("{code} ({desc})"));
                if opt.data.len() > 2 {
                    out.push_str(": ");
                    if let Ok(s) = std::str::from_utf8(&opt.data[2..]) {
                        out.push_str(s);
                    } else {
                        out.push_str(&hex::encode(&opt.data[2..]));
                    }
                }
            } else {
                out.push_str(&hex::encode(&opt.data));
            }
            out.push('\n');
        }
        8 => {
            out.push_str("; CLIENT-SUBNET: ");
            out.push_str(&hex::encode(&opt.data));
            out.push('\n');
        }
        11 => {
            out.push_str("; TCP-KEEPALIVE: ");
            if opt.data.len() >= 2 {
                let timeout = u16::from_be_bytes([opt.data[0], opt.data[1]]);
                out.push_str(&format!("{timeout}"));
                if opt.data.len() >= 4 {
                    let idle = u16::from_be_bytes([opt.data[2], opt.data[3]]);
                    out.push_str(&format!(" {}", idle));
                }
            }
            out.push('\n');
        }
        12 => {
            out.push_str(&format!("; PADDING: {} bytes\n", opt.data.len()));
        }
        _ => {
            out.push_str(&format!("; OPTION{}: ", opt.code));
            out.push_str(&hex::encode(&opt.data));
            out.push('\n');
        }
    }
}

fn ede_text(code: u16) -> &'static str {
    match code {
        0 => "Other",
        1 => "Unsupported DNSKEY Algorithm",
        2 => "Unsupported DS Digest Type",
        3 => "Stale Answer",
        4 => "Forged Answer",
        5 => "DNSSEC Indeterminate",
        6 => "DNSSEC Bogus",
        7 => "Signature Expired",
        8 => "Signature Not Yet Valid",
        9 => "DNSKEY Missing",
        10 => "RRSIGs Missing",
        11 => "No Zone Key Bit Set",
        12 => "NSEC Missing",
        13 => "Cached Error",
        14 => "Not Ready",
        15 => "Blocked",
        16 => "Censored",
        17 => "Filtered",
        18 => "Prohibited",
        19 => "Stale NXDOMAIN Answer",
        20 => "Bogus NXDOMAIN",
        21 => "Not Authoritative",
        22 => "Not Supported",
        23 => "No Reachable Authority",
        24 => "Network Error",
        25 => "Invalid Data",
        _ => "Unknown",
    }
}

fn print_section(
    out: &mut String,
    name: &str,
    records: &[crate::dns::ResourceRecord],
    ctx: &PrintContext,
) {
    let show = match name {
        "ANSWER" => ctx.opts.show_answer,
        "AUTHORITY" => ctx.opts.show_authority,
        "ADDITIONAL" => ctx.opts.show_additional,
        _ => true,
    };
    if !show {
        return;
    }
    if !has_visible_records(records) {
        return;
    }

    out.push_str(&format!("\n;; {name} SECTION:\n"));

    let fmt_opts = FormatOpts {
        ttl_units: ctx.opts.ttl_units,
        unknown_format: ctx.opts.unknown_format,
        rrcomments: ctx.opts.show_rrcomments,
    };

    for rr in records {
        if should_skip_opt(rr.rtype) {
            continue;
        }
        let ttl_str = if ctx.opts.show_ttl {
            if ctx.opts.ttl_units {
                format_ttl_units(rr.ttl)
            } else {
                rr.ttl.to_string()
            }
        } else {
            String::new()
        };
        let class_str = if ctx.opts.show_class {
            class_name(rr.class).to_string()
        } else {
            String::new()
        };
        let rdata_str = format_rdata(&rr.rdata, &fmt_opts);
        let rr_comment = if ctx.opts.show_rrcomments {
            format_rrcomment(&rr.rdata)
        } else {
            None
        };
        let max_rdata = ctx.opts.split_width.unwrap_or(80).saturating_sub(RDATA_COL);

        if ctx.opts.multiline {
            out.push_str(&rr.name);
            out.push_str("        ");
            out.push_str(&ttl_str);
            out.push_str("        IN        ");
            out.push_str(rr.rtype.as_str());
            out.push_str(" ( ");
            out.push_str(&rdata_str);
            out.push_str(" )\n");
            if let Some(ref comment) = rr_comment {
                out.push(';');
                out.push_str(comment);
                out.push('\n');
            }
        } else {
            let no_ttl = !ctx.opts.show_ttl;
            let no_class = !ctx.opts.show_class;
            add_rr_start(
                out,
                &rr.name,
                rr.ttl,
                &ttl_str,
                &class_str,
                rr.rtype.as_str(),
                no_ttl,
                no_class,
            );
            if max_rdata > 0 && rdata_str.len() > max_rdata {
                let mut pos = 0;
                out.push_str(&rdata_str[pos..(pos + max_rdata).min(rdata_str.len())]);
                pos = max_rdata;
                while pos < rdata_str.len() {
                    out.push('\n');
                    indent_to(out, 0, RDATA_COL);
                    let end = (pos + max_rdata).min(rdata_str.len());
                    out.push_str(&rdata_str[pos..end]);
                    pos = end;
                }
                if let Some(ref comment) = rr_comment {
                    out.push(' ');
                    out.push_str(comment);
                }
                out.push('\n');
            } else {
                out.push_str(&rdata_str);
                if let Some(ref comment) = rr_comment {
                    out.push_str(comment);
                }
                out.push('\n');
            }
        }
    }
}

pub fn print_short(ctx: &PrintContext, msg: &Message) -> String {
    let fmt_opts = FormatOpts {
        ttl_units: ctx.opts.ttl_units,
        unknown_format: ctx.opts.unknown_format,
        rrcomments: false,
    };
    let lines: Vec<String> = msg
        .answers
        .iter()
        .filter(|rr| !should_skip_opt(rr.rtype))
        .map(|rr| {
            let mut s = format_rdata(&rr.rdata, &fmt_opts);
            if ctx.opts.show_identify {
                if let Some(ref addr) = ctx.server_addr {
                    s.push_str(&format!(" from {}", addr));
                    if let Some(us) = ctx.query_time_us {
                        if us >= 1000 {
                            s.push_str(&format!(" in {} ms", us / 1000));
                        } else {
                            s.push_str(&format!(" in {} us", us));
                        }
                    }
                }
            }
            s
        })
        .collect();
    lines.join("\n") + "\n"
}

fn print_yaml(ctx: &PrintContext, msg: &Message) -> String {
    let mut out = String::new();

    let msg_type = if ctx.is_query {
        "RECURSIVE_QUERY"
    } else {
        "RECURSIVE_RESPONSE"
    };

    out.push_str("- type: MESSAGE\n");
    out.push_str("  message:\n");
    out.push_str(&format!("    type: {msg_type}\n"));

    if let Some(us) = ctx.query_time_us {
        let frac = us % 1_000_000;
        let tm = epoch_secs_to_tm(
            SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
        );
        let month = format!("{:02}", tm.tm_mon + 1);
        let day = format!("{:02}", tm.tm_mday);
        let hour = format!("{:02}", tm.tm_hour);
        let min = format!("{:02}", tm.tm_min);
        let sec = format!("{:02}", tm.tm_sec);
        let year = 1970 + tm.tm_year;
        let ts = format!("{year}-{month}-{day}T{hour}:{min}:{sec}.{frac:06}Z");
        let key = if ctx.is_query {
            "query_time"
        } else {
            "response_time"
        };
        out.push_str(&format!("    {key}: !!timestamp {ts}\n"));
    }

    if let Some(rb) = ctx.response_bytes {
        out.push_str(&format!("    message_size: {rb}b\n"));
    }

    let proto = if ctx.use_tcp { "TCP" } else { "UDP" };
    out.push_str(&format!("    socket_protocol: {proto}\n"));
    out.push_str(&format!("    response_address: \"{}\"\n", ctx.server));

    let data_key = if ctx.is_query {
        "query_message_data"
    } else {
        "response_message_data"
    };
    out.push_str(&format!("    {data_key}:\n"));

    let opcode = crate::dns::opcode_name(msg.header.opcode());
    let status = crate::dns::rcode_name(msg.header.rcode());
    out.push_str(&format!("      opcode: {opcode}\n"));
    out.push_str(&format!("      status: {status}\n"));
    out.push_str(&format!("      id: {}\n", msg.header.id));

    let mut flags = String::new();
    if msg.header.is_response() {
        flags.push_str(" qr");
    }
    if msg.header.is_authoritative() {
        flags.push_str(" aa");
    }
    if msg.header.is_truncated() {
        flags.push_str(" tc");
    }
    if msg.header.recursion_desired() {
        flags.push_str(" rd");
    }
    if msg.header.recursion_available() {
        flags.push_str(" ra");
    }
    if msg.header.ad_flag() {
        flags.push_str(" ad");
    }
    if msg.header.cd_flag() {
        flags.push_str(" cd");
    }
    out.push_str(&format!("      flags:{flags}\n"));

    out.push_str(&format!("      QUESTION: {}\n", msg.header.qd_count));
    out.push_str(&format!("      ANSWER: {}\n", msg.header.an_count));
    out.push_str(&format!("      AUTHORITY: {}\n", msg.header.ns_count));
    out.push_str(&format!("      ADDITIONAL: {}\n", msg.header.ar_count));

    if let Some(opt) = msg.opt_record() {
        out.push_str("      OPT_PSEUDOSECTION:\n");
        out.push_str("        EDNS:\n");
        out.push_str(&format!("          version: {}\n", opt.edns_version));
        out.push_str("          flags:");
        if opt.dnssec_ok {
            out.push_str(" do");
        }
        if opt.z_flags & 0x4000 != 0 {
            out.push_str(" co");
        }
        out.push('\n');
        out.push_str(&format!("          udp: {}\n", opt.udp_size));
    }

    if !msg.questions.is_empty() {
        out.push_str("      QUESTION_SECTION:\n");
        let fmt_opts = FormatOpts {
            ttl_units: false,
            unknown_format: false,
            rrcomments: false,
        };
        for q in &msg.questions {
            let rdata_line = format!("{}. {} {}", q.name, class_name(q.qclass), q.qtype);
            let escaped = yaml_single_quote_escape(&rdata_line);
            out.push_str(&format!("        - '{escaped}'\n"));
            let _ = fmt_opts;
        }
    }

    for (section_name, records) in [
        ("ANSWER", &msg.answers),
        ("AUTHORITY", &msg.authority),
        ("ADDITIONAL", &msg.additional),
    ] {
        let visible: Vec<_> = records
            .iter()
            .filter(|rr| !should_skip_opt(rr.rtype))
            .collect();
        if visible.is_empty() {
            continue;
        }
        out.push_str(&format!("      {section_name}_SECTION:\n"));
        let fmt_opts = FormatOpts {
            ttl_units: false,
            unknown_format: false,
            rrcomments: false,
        };
        for rr in &visible {
            let rdata_str = format_rdata(&rr.rdata, &fmt_opts);
            let line = format!(
                "{}. {} {} {} {}",
                rr.name,
                rr.ttl,
                class_name(rr.class),
                rr.rtype.as_str(),
                rdata_str
            );
            let escaped = yaml_single_quote_escape(&line);
            out.push_str(&format!("        - '{escaped}'\n"));
        }
    }

    out
}

fn yaml_single_quote_escape(s: &str) -> String {
    let mut out = String::new();
    for c in s.chars() {
        if c == '\'' {
            out.push_str("''");
        } else {
            out.push(c);
        }
    }
    out
}
