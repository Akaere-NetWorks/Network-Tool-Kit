use crate::dns::{Message, Rdata};

pub struct PrintOpts {
    pub short: bool,
    pub show_question: bool,
    pub show_answer: bool,
    pub show_authority: bool,
    pub show_additional: bool,
    pub show_stats: bool,
    pub show_comments: bool,
}

impl Default for PrintOpts {
    fn default() -> Self {
        PrintOpts {
            short: false,
            show_question: true,
            show_answer: true,
            show_authority: true,
            show_additional: true,
            show_stats: true,
            show_comments: true,
        }
    }
}

pub fn print_message(
    msg: &Message,
    opts: &PrintOpts,
    server: &str,
    query_time_ms: Option<u64>,
) -> String {
    if opts.short {
        return print_short(msg);
    }

    let mut out = String::new();

    if opts.show_comments {
        let rcode_str = match msg.header.rcode() {
            0 => "NOERROR",
            1 => "FORMERR",
            2 => "SERVFAIL",
            3 => "NXDOMAIN",
            _ => "UNKNOWN",
        };
        let mut flag_str = String::from("qr");
        if msg.header.recursion_desired() {
            flag_str.push_str(" rd");
        }
        if msg.header.recursion_available() {
            flag_str.push_str(" ra");
        }

        out.push_str(&format!(
            ";; Got answer:\n;; ->>HEADER<<- opcode: QUERY, status: {rcode_str}, id: {}\n",
            msg.header.id
        ));
        out.push_str(&format!(
            ";; flags: {flag_str}; QUERY: {}, ANSWER: {}, AUTHORITY: {}, ADDITIONAL: {}\n\n",
            msg.header.qd_count, msg.header.an_count, msg.header.ns_count, msg.header.ar_count
        ));
    }

    if opts.show_question && !msg.questions.is_empty() {
        out.push_str(";; QUESTION SECTION:\n");
        for q in &msg.questions {
            out.push_str(&format!(";{}.\t\t\tIN\t{}\n", q.name, q.qtype.as_str()));
        }
        out.push('\n');
    }

    if opts.show_answer && !msg.answers.is_empty() {
        out.push_str(";; ANSWER SECTION:\n");
        for rr in &msg.answers {
            out.push_str(&format!(
                "{}.\t\t{}\tIN\t{}\t{}\n",
                rr.name,
                rr.ttl,
                rr.rtype.as_str(),
                rdata_to_string(&rr.rdata)
            ));
        }
        out.push('\n');
    }

    if opts.show_authority && !msg.authority.is_empty() {
        out.push_str(";; AUTHORITY SECTION:\n");
        for rr in &msg.authority {
            out.push_str(&format!(
                "{}.\t\t{}\tIN\t{}\t{}\n",
                rr.name,
                rr.ttl,
                rr.rtype.as_str(),
                rdata_to_string(&rr.rdata)
            ));
        }
        out.push('\n');
    }

    if opts.show_additional && !msg.additional.is_empty() {
        out.push_str(";; ADDITIONAL SECTION:\n");
        for rr in &msg.additional {
            out.push_str(&format!(
                "{}.\t\t{}\tIN\t{}\t{}\n",
                rr.name,
                rr.ttl,
                rr.rtype.as_str(),
                rdata_to_string(&rr.rdata)
            ));
        }
        out.push('\n');
    }

    if opts.show_stats {
        if let Some(ms) = query_time_ms {
            out.push_str(&format!(";; Query time: {ms} msec\n"));
        }
        out.push_str(&format!(";; SERVER: {server}#53({server})\n"));
    }

    out
}

pub fn print_short(msg: &Message) -> String {
    msg.answers
        .iter()
        .map(|rr| rdata_to_string(&rr.rdata))
        .collect::<Vec<_>>()
        .join("\n")
        + "\n"
}

fn rdata_to_string(rdata: &Rdata) -> String {
    match rdata {
        Rdata::A(addr) => addr.to_string(),
        Rdata::Aaaa(addr) => addr.to_string(),
        Rdata::Cname(s) => format!("{s}."),
        Rdata::Ns(s) => format!("{s}."),
        Rdata::Ptr(s) => format!("{s}."),
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
        Rdata::Unknown(b) => format!("\\# {} {}", b.len(), hex::encode(b)),
    }
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
        let out = print_short(&msg);
        assert_eq!(out.trim(), "142.250.80.46");
    }

    #[test]
    fn full_output_contains_sections() {
        let msg = a_response();
        let out = print_message(&msg, &PrintOpts::default(), "8.8.8.8", Some(12));
        assert!(
            out.contains(";; ANSWER SECTION:"),
            "missing ANSWER section header"
        );
        assert!(out.contains("142.250.80.46"), "missing answer IP");
        assert!(
            out.contains(";; QUESTION SECTION:"),
            "missing QUESTION section header"
        );
        assert!(out.contains("Query time:"), "missing stats");
    }

    #[test]
    fn full_output_short_suppresses_sections() {
        let msg = a_response();
        let opts = PrintOpts {
            short: true,
            ..PrintOpts::default()
        };
        let out = print_message(&msg, &opts, "8.8.8.8", None);
        assert!(!out.contains(";; ANSWER SECTION:"));
        assert!(out.contains("142.250.80.46"));
    }
}
