use crate::dns::{opcode_name, rcode_name, Message, Rdata, RecordType, ResourceRecord};

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
    pub query_time_ms: Option<u64>,
    pub query_bytes: Option<usize>,
    pub response_bytes: Option<usize>,
    pub server_addr: Option<String>,
    pub cmdline: Option<String>,
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
            out.push_str(&format!(";; <<>> {cmd} <<>>\n"));
        }
    }

    if ctx.opts.show_comments {
        let rcode = rcode_name(msg.header.rcode());
        let opcode = opcode_name(msg.header.opcode());
        let mut flags = Vec::new();
        flags.push("qr".to_string());
        if msg.header.is_authoritative() {
            flags.push("aa".into());
        }
        if msg.header.is_truncated() {
            flags.push("tc".into());
        }
        if msg.header.recursion_desired() {
            flags.push("rd".into());
        }
        if msg.header.recursion_available() {
            flags.push("ra".into());
        }
        if msg.header.ad_flag() {
            flags.push("ad".into());
        }
        if msg.header.cd_flag() {
            flags.push("cd".into());
        }

        let mut opt_str = String::new();
        if let Some(opt) = msg.opt_record() {
            opt_str = format!(
                "\n;; OPT PSEUDOSECTION:\n; EDNS: version: {}, flags: {}; udp: {}",
                opt.edns_version,
                if opt.dnssec_ok { "do" } else { "" },
                opt.udp_size
            );
            if opt.extended_rcode != 0 {
                opt_str.push_str(&format!("; rc: {}", rcode_name(opt.extended_rcode)));
            }
        }

        out.push_str(&format!(
            ";; ->>HEADER<<- opcode: {opcode}, status: {rcode}, id: {}\n",
            msg.header.id
        ));
        out.push_str(&format!(
            ";; flags: {}; QUERY: {}, ANSWER: {}, AUTHORITY: {}, ADDITIONAL: {}{}\n",
            flags.join(" "),
            msg.header.qd_count,
            msg.header.an_count,
            msg.header.ns_count,
            msg.header.ar_count,
            opt_str
        ));
    }

    if ctx.opts.show_question && !msg.questions.is_empty() {
        out.push_str("\n;; QUESTION SECTION:\n");
        for q in &msg.questions {
            let class_name = class_name(q.qclass);
            if ctx.opts.show_class {
                out.push_str(&format!(";{}\t\t\t{class_name}\t{}\n", q.name, q.qtype));
            } else {
                out.push_str(&format!(";{}\t\t\t{}\n", q.name, q.qtype));
            }
        }
    }

    print_section(&mut out, "ANSWER", &msg.answers, ctx);
    print_section(&mut out, "AUTHORITY", &msg.authority, ctx);
    print_section(&mut out, "ADDITIONAL", &msg.additional, ctx);

    if ctx.opts.show_stats {
        out.push('\n');
        if let Some(ms) = ctx.query_time_ms {
            out.push_str(&format!(";; Query time: {ms} msec\n"));
        }
        out.push_str(&format!(";; SERVER: {}#53\n", ctx.server));
        if let (Some(_qb), Some(rb)) = (ctx.query_bytes, ctx.response_bytes) {
            out.push_str(&format!(";; MSG SIZE  rcvd: {rb}\n"));
        }
    }

    out
}

fn print_section(out: &mut String, name: &str, records: &[ResourceRecord], ctx: &PrintContext) {
    let show = match name {
        "ANSWER" => ctx.opts.show_answer,
        "AUTHORITY" => ctx.opts.show_authority,
        "ADDITIONAL" => ctx.opts.show_additional,
        _ => true,
    };
    if !show || records.is_empty() {
        return;
    }

    out.push_str(&format!("\n;; {name} SECTION:\n"));
    for rr in records {
        if rr.rtype == RecordType::Opt {
            continue;
        }
        let rdata_str = format_rdata(&rr.rdata, ctx.opts);
        if ctx.opts.multiline {
            out.push_str(&format!("{}\t", rr.name));
            if ctx.opts.show_ttl {
                if ctx.opts.ttl_units {
                    out.push_str(&format!("{}\t", format_ttl_units(rr.ttl)));
                } else {
                    out.push_str(&format!("{}\t", rr.ttl));
                }
            }
            if ctx.opts.show_class {
                out.push_str(&format!("{}\t", class_name(rr.class)));
            }
            out.push_str(&format!("{}\t{}\n", rr.rtype, rdata_str));
        } else {
            out.push_str(&format!("{}\t", rr.name));
            if ctx.opts.show_ttl {
                if ctx.opts.ttl_units {
                    out.push_str(&format!("{}\t", format_ttl_units(rr.ttl)));
                } else {
                    out.push_str(&format!("{}\t", rr.ttl));
                }
            }
            if ctx.opts.show_class {
                out.push_str(&format!("{}\t", class_name(rr.class)));
            }
            out.push_str(&format!("{}\t{}\n", rr.rtype, rdata_str));
        }
    }
}

pub fn print_short(ctx: &PrintContext, msg: &Message) -> String {
    let lines: Vec<String> = msg
        .answers
        .iter()
        .map(|rr| {
            let mut s = format_rdata(&rr.rdata, ctx.opts);
            if ctx.opts.show_identify {
                if let Some(ref addr) = ctx.server_addr {
                    s.push_str(&format!(" from {}", addr));
                }
            }
            s
        })
        .collect();
    lines.join("\n") + "\n"
}

fn print_yaml(_ctx: &PrintContext, msg: &Message) -> String {
    let mut out = String::from("---\n");
    out.push_str(&format!("id: {}\n", msg.header.id));
    out.push_str(&format!("opcode: {}\n", opcode_name(msg.header.opcode())));
    out.push_str(&format!("status: {}\n", rcode_name(msg.header.rcode())));
    out.push_str(&format!("qr: {}\n", msg.header.is_response()));
    out.push_str(&format!("rd: {}\n", msg.header.recursion_desired()));
    out.push_str(&format!("ra: {}\n", msg.header.recursion_available()));
    out.push_str(&format!("qdcount: {}\n", msg.header.qd_count));
    out.push_str(&format!("ancount: {}\n", msg.header.an_count));
    out.push_str(&format!("nscount: {}\n", msg.header.ns_count));
    out.push_str(&format!("arcount: {}\n", msg.header.ar_count));

    out.push_str("question:\n");
    for q in &msg.questions {
        out.push_str(&format!("  - name: \"{}\"\n", q.name));
        out.push_str(&format!("    type: {}\n", q.qtype));
        out.push_str(&format!("    class: {}\n", q.qclass));
    }

    for (label, records) in [
        ("answer", &msg.answers),
        ("authority", &msg.authority),
        ("additional", &msg.additional),
    ] {
        out.push_str(&format!("{label}:\n"));
        for rr in records {
            out.push_str(&format!("  - name: \"{}\"\n", rr.name));
            out.push_str(&format!("    type: {}\n", rr.rtype));
            out.push_str(&format!("    class: {}\n", rr.class));
            out.push_str(&format!("    ttl: {}\n", rr.ttl));
            out.push_str(&format!(
                "    rdata: \"{}\"\n",
                format_rdata(&rr.rdata, &PrintOpts::default())
            ));
        }
    }
    out.push_str("...\n");
    out
}

pub fn format_rdata(rdata: &Rdata, opts: &PrintOpts) -> String {
    if opts.unknown_format {
        let bytes = rdata_to_bytes(rdata);
        return format!("\\# {} {}", bytes.len(), hex::encode(&bytes));
    }
    match rdata {
        Rdata::A(addr) => addr.to_string(),
        Rdata::Aaaa(addr) => addr.to_string(),
        Rdata::Cname(s) => format!("{s}."),
        Rdata::Ns(s) => format!("{s}."),
        Rdata::Ptr(s) => format!("{s}."),
        Rdata::Dname(s) => format!("{s}."),
        Rdata::Mx { priority, exchange } => format!("{priority} {exchange}."),
        Rdata::Txt(parts) => parts
            .iter()
            .map(|p| format!("\"{}\"", String::from_utf8_lossy(p)))
            .collect::<Vec<_>>()
            .join(" "),
        Rdata::Soa {
            mname,
            rname,
            serial,
            refresh,
            retry,
            expire,
            minimum,
        } => format!("{mname}. {rname}. {serial} {refresh} {retry} {expire} {minimum}"),
        Rdata::Srv {
            priority,
            weight,
            port,
            target,
        } => format!("{priority} {weight} {port} {target}."),
        Rdata::Caa { flags, tag, value } => {
            format!("{flags} {tag} \"{}\"", String::from_utf8_lossy(value))
        }
        Rdata::Ds {
            key_tag,
            algorithm,
            digest_type,
            digest,
        } => format!(
            "{key_tag} {algorithm} {digest_type} {}",
            hex::encode(digest)
        ),
        Rdata::Dnskey {
            flags,
            protocol,
            algorithm,
            public_key,
        } => format!(
            "{flags} {protocol} {algorithm} {}",
            base64_encode(public_key)
        ),
        Rdata::Rrsig {
            type_covered,
            algorithm,
            labels,
            original_ttl,
            signature_expiration,
            signature_inception,
            key_tag,
            signer_name,
            signature,
        } => {
            let tc = RecordType::from_u16(*type_covered);
            format!(
                "{} {} {} {} {} {} {} {}. {}",
                tc,
                algorithm,
                labels,
                original_ttl,
                signature_expiration,
                signature_inception,
                key_tag,
                signer_name,
                base64_encode(signature)
            )
        }
        Rdata::Nsec {
            next_name,
            type_bitmap,
        } => {
            let types = decode_type_bitmap(type_bitmap);
            format!("{}. {}", next_name, types.join(" "))
        }
        Rdata::Nsec3 {
            hash_algorithm,
            flags,
            iterations,
            salt,
            next_hash,
            type_bitmap,
        } => {
            let types = decode_type_bitmap(type_bitmap);
            format!(
                "{} {} {} {} {} {}",
                hash_algorithm,
                flags,
                iterations,
                if salt.is_empty() {
                    "-".into()
                } else {
                    hex::encode(salt)
                },
                base32hex_encode(next_hash),
                types.join(" ")
            )
        }
        Rdata::Nsec3param {
            hash_algorithm,
            flags,
            iterations,
            salt,
        } => format!(
            "{} {} {} {}",
            hash_algorithm,
            flags,
            iterations,
            if salt.is_empty() {
                "-".into()
            } else {
                hex::encode(salt)
            }
        ),
        Rdata::Loc {
            version: _,
            siz,
            horiz,
            vert,
            latitude,
            longitude,
            altitude,
        } => format!("{siz} {horiz} {vert} {latitude} {longitude} {altitude}"),
        Rdata::Sshfp {
            algorithm,
            fp_type,
            fingerprint,
        } => format!("{algorithm} {fp_type} {}", hex::encode(fingerprint)),
        Rdata::Tlsa {
            usage,
            selector,
            matching_type,
            data,
        } => format!("{usage} {selector} {matching_type} {}", hex::encode(data)),
        Rdata::Hinfo { cpu, os } => format!("\"{cpu}\" \"{os}\""),
        Rdata::Naptr {
            order,
            preference,
            flags,
            service,
            regexp,
            replacement,
        } => format!("{order} {preference} \"{flags}\" \"{service}\" \"{regexp}\" {replacement}."),
        Rdata::Opt(opt) => format!(
            "; EDNS: version: {}, flags: {}; udp: {}",
            opt.edns_version,
            if opt.dnssec_ok { "do" } else { "" },
            opt.udp_size
        ),
        Rdata::Unknown(b) => format!("\\# {} {}", b.len(), hex::encode(b)),
    }
}

fn rdata_to_bytes(rdata: &Rdata) -> Vec<u8> {
    match rdata {
        Rdata::A(addr) => addr.octets().to_vec(),
        Rdata::Aaaa(addr) => addr.octets().to_vec(),
        Rdata::Unknown(b) => b.clone(),
        Rdata::Txt(parts) => {
            let mut v = Vec::new();
            for p in parts {
                v.push(p.len() as u8);
                v.extend_from_slice(p);
            }
            v
        }
        _ => vec![],
    }
}

fn format_ttl_units(ttl: u32) -> String {
    if ttl == 0 {
        return "0s".into();
    }
    let weeks = ttl / 604800;
    let days = (ttl % 604800) / 86400;
    let hours = (ttl % 86400) / 3600;
    let mins = (ttl % 3600) / 60;
    let secs = ttl % 60;
    let mut s = String::new();
    if weeks > 0 {
        s.push_str(&format!("{weeks}w"));
    }
    if days > 0 {
        s.push_str(&format!("{days}d"));
    }
    if hours > 0 {
        s.push_str(&format!("{hours}h"));
    }
    if mins > 0 {
        s.push_str(&format!("{mins}m"));
    }
    if secs > 0 {
        s.push_str(&format!("{secs}s"));
    }
    s
}

fn class_name(class: u16) -> &'static str {
    match class {
        1 => "IN",
        3 => "CH",
        4 => "HS",
        255 => "ANY",
        _ => "CLASS?",
    }
}

fn decode_type_bitmap(bitmap: &[u8]) -> Vec<String> {
    let mut types = Vec::new();
    let mut i = 0;
    while i + 2 <= bitmap.len() {
        let _window = bitmap[i];
        let bm_len = bitmap[i + 1] as usize;
        i += 2;
        if i + bm_len > bitmap.len() {
            break;
        }
        for (bit_idx, &byte) in bitmap[i..i + bm_len].iter().enumerate() {
            for bit in (0..8).rev() {
                if byte & (1 << bit) != 0 {
                    let rtype_num = (bit_idx as u16) * 8 + (7 - bit) as u16;
                    let rt = RecordType::from_u16(rtype_num);
                    types.push(rt.display_str());
                }
            }
        }
        i += bm_len;
    }
    types
}

fn base64_encode(data: &[u8]) -> String {
    const CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut s = String::with_capacity((data.len() + 2) / 3 * 4);
    let chunks = data.chunks(3);
    for chunk in chunks {
        let b0 = chunk[0] as u32;
        let b1 = if chunk.len() > 1 { chunk[1] as u32 } else { 0 };
        let b2 = if chunk.len() > 2 { chunk[2] as u32 } else { 0 };
        let triple = (b0 << 16) | (b1 << 8) | b2;
        s.push(CHARS[((triple >> 18) & 0x3F) as usize] as char);
        s.push(CHARS[((triple >> 12) & 0x3F) as usize] as char);
        if chunk.len() > 1 {
            s.push(CHARS[((triple >> 6) & 0x3F) as usize] as char);
        } else {
            s.push('=');
        }
        if chunk.len() > 2 {
            s.push(CHARS[(triple & 0x3F) as usize] as char);
        } else {
            s.push('=');
        }
    }
    s
}

fn base32hex_encode(data: &[u8]) -> String {
    const CHARS: &[u8] = b"0123456789ABCDEFGHIJKLMNOPQRSTUV";
    let mut s = String::new();
    let mut bits = 0u64;
    let mut n_bits = 0u32;
    for &byte in data {
        bits = (bits << 8) | byte as u64;
        n_bits += 8;
        while n_bits >= 5 {
            n_bits -= 5;
            s.push(CHARS[((bits >> n_bits) & 0x1F) as usize] as char);
        }
    }
    if n_bits > 0 {
        s.push(CHARS[((bits << (5 - n_bits)) & 0x1F) as usize] as char);
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns::{Header, Question, RecordType, ResourceRecord};
    use std::net::Ipv4Addr;

    fn a_response() -> Message {
        Message {
            header: Header {
                id: 0x1234,
                flags: 0x8180,
                qd_count: 1,
                an_count: 1,
                ns_count: 0,
                ar_count: 0,
            },
            questions: vec![Question {
                name: "google.com".into(),
                qtype: RecordType::A,
                qclass: 1,
            }],
            answers: vec![ResourceRecord {
                name: "google.com".into(),
                rtype: RecordType::A,
                class: 1,
                ttl: 300,
                rdata: Rdata::A(Ipv4Addr::new(142, 250, 80, 46)),
            }],
            authority: vec![],
            additional: vec![],
        }
    }

    #[test]
    fn short_output() {
        let msg = a_response();
        let ctx = PrintContext {
            opts: &PrintOpts {
                short: true,
                ..PrintOpts::default()
            },
            server: "8.8.8.8",
            query_time_ms: None,
            query_bytes: None,
            response_bytes: None,
            server_addr: None,
            cmdline: None,
        };
        assert_eq!(print_short(&ctx, &msg).trim(), "142.250.80.46");
    }

    #[test]
    fn full_output_contains_sections() {
        let msg = a_response();
        let opts = PrintOpts::default();
        let ctx = PrintContext {
            opts: &opts,
            server: "8.8.8.8",
            query_time_ms: Some(12),
            query_bytes: Some(28),
            response_bytes: Some(44),
            server_addr: None,
            cmdline: Some("dig google.com A".into()),
        };
        let out = print_message(&ctx, &msg);
        assert!(out.contains("ANSWER SECTION"));
        assert!(out.contains("142.250.80.46"));
        assert!(out.contains("QUESTION SECTION"));
        assert!(out.contains("Query time:"));
        assert!(out.contains("MSG SIZE"));
    }

    #[test]
    fn ttl_units_format() {
        assert_eq!(format_ttl_units(0), "0s");
        assert_eq!(format_ttl_units(300), "5m");
        assert_eq!(format_ttl_units(3600), "1h");
        assert_eq!(format_ttl_units(86400), "1d");
        assert_eq!(format_ttl_units(604800), "1w");
    }
}
