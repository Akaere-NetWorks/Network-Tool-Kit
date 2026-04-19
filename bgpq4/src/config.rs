use crate::report;
use std::collections::BTreeSet;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Vendor {
    Cisco = 0,
    Juniper,
    CiscoXr,
    Json,
    Bird,
    OpenBgpd,
    Format,
    Nokia,
    Huawei,
    HuaweiXpl,
    Mikrotik6,
    Mikrotik7,
    NokiaMd,
    Arista,
    NokiaSrl,
}

impl Vendor {
    pub fn is_cisco_like(self) -> bool {
        matches!(self, Vendor::Cisco | Vendor::Arista)
    }

    pub fn is_nokia_variant(self) -> bool {
        matches!(self, Vendor::Nokia | Vendor::NokiaMd | Vendor::NokiaSrl)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Generation {
    None = 0,
    AsPath,
    OasPath,
    AsList,
    Asset,
    PrefixList,
    Eacl,
    RouteFilterList,
}

pub struct ExpanderConfig {
    pub family: u8,
    pub sources: String,
    pub defaultsources: String,
    pub usesource: bool,
    pub asnumber: u32,
    pub aswidth: i32,
    pub name: String,
    pub vendor: Vendor,
    pub generation: Generation,
    pub identify: bool,
    pub sequence: i32,
    pub maxdepth: u32,
    pub validate_asns: bool,
    pub r#match: Option<String>,
    pub server: String,
    pub port: u16,
    pub format: Option<String>,
    pub maxlen: u32,
    pub pipelining: bool,
    pub expand_special_asn: bool,
    pub debug_expander: i32,
    pub debug_aggregation: i32,
}

impl Default for ExpanderConfig {
    fn default() -> Self {
        ExpanderConfig {
            family: 2,
            sources: String::new(),
            defaultsources: String::new(),
            usesource: false,
            asnumber: 0,
            aswidth: 8,
            name: "NN".to_string(),
            vendor: Vendor::Cisco,
            generation: Generation::PrefixList,
            identify: true,
            sequence: 0,
            maxdepth: 0,
            validate_asns: false,
            r#match: None,
            server: "rr.ntt.net".to_string(),
            port: 43,
            format: None,
            maxlen: 32,
            pipelining: true,
            expand_special_asn: false,
            debug_expander: 0,
            debug_aggregation: 0,
        }
    }
}

impl ExpanderConfig {
    pub fn init(&mut self, family: u8) {
        self.family = family;
        self.maxlen = if family == 10 { 128 } else { 32 };
    }

    pub fn effective_name(&self) -> &str {
        if self.name.is_empty() {
            "NN"
        } else {
            &self.name
        }
    }
}

#[derive(Debug, Clone)]
pub struct AsnEntry {
    pub asn: u32,
}

pub type AsnTree = BTreeSet<u32>;

pub fn asn_add(tree: &mut AsnTree, asn_str: &str, expand_special: bool) -> bool {
    let s = asn_str.strip_prefix("AS").unwrap_or(asn_str);
    let (num_str, rest) = match s.find(|c: char| !c.is_ascii_digit()) {
        Some(pos) => (&s[..pos], Some(&s[pos..])),
        None => (s, None),
    };

    let asn: u32 = match num_str.parse() {
        Ok(n) => n,
        Err(_) => {
            report::error(&format!("Invalid symbol in AS number: '{}'", asn_str));
            return false;
        }
    };

    if let Some(r) = rest {
        if !r.is_empty() {
            report::error(&format!("Invalid symbol in AS number: '{r}' in {asn_str}"));
            return false;
        }
    }

    if !expand_special && (asn == 23456 || asn >= 4200000000 || (64496..=65551).contains(&asn)) {
        report::error(&format!("Invalid AS number: {asn}"));
        return false;
    }

    tree.insert(asn)
}

pub fn parse_asnumber(s: &str) -> u32 {
    let asn: u32;
    if let Some(dot_pos) = s.find('.') {
        let hi: u32 = s[..dot_pos].parse().unwrap_or(0);
        let lo: u32 = s[dot_pos + 1..].parse().unwrap_or(0);
        if hi < 1 || hi > 65535 || lo < 1 || lo > 65535 {
            report::fatal(&format!("Invalid AS number: {s}"));
        }
        asn = (hi << 16) + lo;
    } else {
        asn = s.parse().unwrap_or_else(|_| {
            report::fatal(&format!("Invalid AS number: {s}"));
        });
    }
    if asn < 1 || asn > 65535 * 65535 {
        report::fatal(&format!("Invalid AS number: {s}"));
    }
    asn
}
