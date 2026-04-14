use std::fmt;
use std::net::{Ipv4Addr, Ipv6Addr};
use thiserror::Error;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum RecordType {
    A = 1,
    Ns = 2,
    Cname = 5,
    Soa = 6,
    Ptr = 12,
    Hinfo = 13,
    Mx = 15,
    Txt = 16,
    Rp = 17,
    Afsdb = 18,
    Sig = 24,
    Key = 25,
    Aaaa = 28,
    Loc = 29,
    Srv = 33,
    Naptr = 35,
    Kx = 36,
    Cert = 37,
    Dname = 39,
    Opt = 41,
    Ds = 43,
    Sshfp = 44,
    Ipseckey = 45,
    Rrsig = 46,
    Nsec = 47,
    Dnskey = 48,
    Dhcid = 49,
    Nsec3 = 50,
    Nsec3param = 51,
    Tlsa = 52,
    Smimea = 53,
    Hip = 55,
    Cds = 59,
    Cdnskey = 60,
    Openpgpkey = 61,
    Svcb = 64,
    Https = 65,
    Spf = 99,
    Tkey = 249,
    Tsig = 250,
    Ixfr = 251,
    Axfr = 252,
    Any = 255,
    Uri = 256,
    Caa = 257,
    Other(u16),
}

impl RecordType {
    pub fn from_u16(v: u16) -> Self {
        match v {
            1 => Self::A,
            2 => Self::Ns,
            5 => Self::Cname,
            6 => Self::Soa,
            12 => Self::Ptr,
            13 => Self::Hinfo,
            15 => Self::Mx,
            16 => Self::Txt,
            17 => Self::Rp,
            18 => Self::Afsdb,
            24 => Self::Sig,
            25 => Self::Key,
            28 => Self::Aaaa,
            29 => Self::Loc,
            33 => Self::Srv,
            35 => Self::Naptr,
            36 => Self::Kx,
            37 => Self::Cert,
            39 => Self::Dname,
            41 => Self::Opt,
            43 => Self::Ds,
            44 => Self::Sshfp,
            45 => Self::Ipseckey,
            46 => Self::Rrsig,
            47 => Self::Nsec,
            48 => Self::Dnskey,
            49 => Self::Dhcid,
            50 => Self::Nsec3,
            51 => Self::Nsec3param,
            52 => Self::Tlsa,
            53 => Self::Smimea,
            55 => Self::Hip,
            59 => Self::Cds,
            60 => Self::Cdnskey,
            61 => Self::Openpgpkey,
            64 => Self::Svcb,
            65 => Self::Https,
            99 => Self::Spf,
            249 => Self::Tkey,
            250 => Self::Tsig,
            251 => Self::Ixfr,
            252 => Self::Axfr,
            255 => Self::Any,
            256 => Self::Uri,
            257 => Self::Caa,
            _ => Self::Other(v),
        }
    }

    pub fn to_u16(self) -> u16 {
        match self {
            Self::A => 1,
            Self::Ns => 2,
            Self::Cname => 5,
            Self::Soa => 6,
            Self::Ptr => 12,
            Self::Hinfo => 13,
            Self::Mx => 15,
            Self::Txt => 16,
            Self::Rp => 17,
            Self::Afsdb => 18,
            Self::Sig => 24,
            Self::Key => 25,
            Self::Aaaa => 28,
            Self::Loc => 29,
            Self::Srv => 33,
            Self::Naptr => 35,
            Self::Kx => 36,
            Self::Cert => 37,
            Self::Dname => 39,
            Self::Opt => 41,
            Self::Ds => 43,
            Self::Sshfp => 44,
            Self::Ipseckey => 45,
            Self::Rrsig => 46,
            Self::Nsec => 47,
            Self::Dnskey => 48,
            Self::Dhcid => 49,
            Self::Nsec3 => 50,
            Self::Nsec3param => 51,
            Self::Tlsa => 52,
            Self::Smimea => 53,
            Self::Hip => 55,
            Self::Cds => 59,
            Self::Cdnskey => 60,
            Self::Openpgpkey => 61,
            Self::Svcb => 64,
            Self::Https => 65,
            Self::Spf => 99,
            Self::Tkey => 249,
            Self::Tsig => 250,
            Self::Ixfr => 251,
            Self::Axfr => 252,
            Self::Any => 255,
            Self::Uri => 256,
            Self::Caa => 257,
            Self::Other(v) => v,
        }
    }

    pub fn from_str(s: &str) -> Option<Self> {
        let upper = s.to_uppercase();
        let s = upper.as_str();
        if let Some(rest) = s.strip_prefix("TYPE") {
            if let Ok(n) = rest.parse::<u16>() {
                return Some(Self::from_u16(n));
            }
        }
        Some(match s {
            "A" => Self::A,
            "NS" => Self::Ns,
            "CNAME" => Self::Cname,
            "SOA" => Self::Soa,
            "PTR" => Self::Ptr,
            "HINFO" => Self::Hinfo,
            "MX" => Self::Mx,
            "TXT" => Self::Txt,
            "RP" => Self::Rp,
            "AFSDB" => Self::Afsdb,
            "SIG" => Self::Sig,
            "KEY" => Self::Key,
            "AAAA" => Self::Aaaa,
            "LOC" => Self::Loc,
            "SRV" => Self::Srv,
            "NAPTR" => Self::Naptr,
            "KX" => Self::Kx,
            "CERT" => Self::Cert,
            "DNAME" => Self::Dname,
            "OPT" => Self::Opt,
            "DS" => Self::Ds,
            "SSHFP" => Self::Sshfp,
            "IPSECKEY" => Self::Ipseckey,
            "RRSIG" => Self::Rrsig,
            "NSEC" => Self::Nsec,
            "DNSKEY" => Self::Dnskey,
            "DHCID" => Self::Dhcid,
            "NSEC3" => Self::Nsec3,
            "NSEC3PARAM" => Self::Nsec3param,
            "TLSA" => Self::Tlsa,
            "SMIMEA" => Self::Smimea,
            "HIP" => Self::Hip,
            "CDS" => Self::Cds,
            "CDNSKEY" => Self::Cdnskey,
            "OPENPGPKEY" => Self::Openpgpkey,
            "SVCB" => Self::Svcb,
            "HTTPS" => Self::Https,
            "SPF" => Self::Spf,
            "TKEY" => Self::Tkey,
            "TSIG" => Self::Tsig,
            "IXFR" => Self::Ixfr,
            "AXFR" => Self::Axfr,
            "ANY" => Self::Any,
            "URI" => Self::Uri,
            "CAA" => Self::Caa,
            _ => return None,
        })
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::A => "A",
            Self::Ns => "NS",
            Self::Cname => "CNAME",
            Self::Soa => "SOA",
            Self::Ptr => "PTR",
            Self::Hinfo => "HINFO",
            Self::Mx => "MX",
            Self::Txt => "TXT",
            Self::Rp => "RP",
            Self::Afsdb => "AFSDB",
            Self::Sig => "SIG",
            Self::Key => "KEY",
            Self::Aaaa => "AAAA",
            Self::Loc => "LOC",
            Self::Srv => "SRV",
            Self::Naptr => "NAPTR",
            Self::Kx => "KX",
            Self::Cert => "CERT",
            Self::Dname => "DNAME",
            Self::Opt => "OPT",
            Self::Ds => "DS",
            Self::Sshfp => "SSHFP",
            Self::Ipseckey => "IPSECKEY",
            Self::Rrsig => "RRSIG",
            Self::Nsec => "NSEC",
            Self::Dnskey => "DNSKEY",
            Self::Dhcid => "DHCID",
            Self::Nsec3 => "NSEC3",
            Self::Nsec3param => "NSEC3PARAM",
            Self::Tlsa => "TLSA",
            Self::Smimea => "SMIMEA",
            Self::Hip => "HIP",
            Self::Cds => "CDS",
            Self::Cdnskey => "CDNSKEY",
            Self::Openpgpkey => "OPENPGPKEY",
            Self::Svcb => "SVCB",
            Self::Https => "HTTPS",
            Self::Spf => "SPF",
            Self::Tkey => "TKEY",
            Self::Tsig => "TSIG",
            Self::Ixfr => "IXFR",
            Self::Axfr => "AXFR",
            Self::Any => "ANY",
            Self::Uri => "URI",
            Self::Caa => "CAA",
            Self::Other(_) => "TYPE",
        }
    }

    pub fn display_str(self) -> String {
        match self {
            Self::Other(v) => format!("TYPE{v}"),
            _ => self.as_str().to_string(),
        }
    }
}

impl fmt::Display for RecordType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.display_str())
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum Rdata {
    A(Ipv4Addr),
    Aaaa(Ipv6Addr),
    Cname(String),
    Mx {
        priority: u16,
        exchange: String,
    },
    Ns(String),
    Ptr(String),
    Txt(Vec<Vec<u8>>),
    Soa {
        mname: String,
        rname: String,
        serial: u32,
        refresh: u32,
        retry: u32,
        expire: u32,
        minimum: u32,
    },
    Srv {
        priority: u16,
        weight: u16,
        port: u16,
        target: String,
    },
    Caa {
        flags: u8,
        tag: String,
        value: Vec<u8>,
    },
    Ds {
        key_tag: u16,
        algorithm: u8,
        digest_type: u8,
        digest: Vec<u8>,
    },
    Dnskey {
        flags: u16,
        protocol: u8,
        algorithm: u8,
        public_key: Vec<u8>,
    },
    Rrsig {
        type_covered: u16,
        algorithm: u8,
        labels: u8,
        original_ttl: u32,
        signature_expiration: u32,
        signature_inception: u32,
        key_tag: u16,
        signer_name: String,
        signature: Vec<u8>,
    },
    Nsec {
        next_name: String,
        type_bitmap: Vec<u8>,
    },
    Nsec3 {
        hash_algorithm: u8,
        flags: u8,
        iterations: u16,
        salt: Vec<u8>,
        next_hash: Vec<u8>,
        type_bitmap: Vec<u8>,
    },
    Nsec3param {
        hash_algorithm: u8,
        flags: u8,
        iterations: u16,
        salt: Vec<u8>,
    },
    Loc {
        version: u8,
        siz: u8,
        horiz: u8,
        vert: u8,
        latitude: i32,
        longitude: i32,
        altitude: i32,
    },
    Dname(String),
    Sshfp {
        algorithm: u8,
        fp_type: u8,
        fingerprint: Vec<u8>,
    },
    Tlsa {
        usage: u8,
        selector: u8,
        matching_type: u8,
        data: Vec<u8>,
    },
    Hinfo {
        cpu: String,
        os: String,
    },
    Naptr {
        order: u16,
        preference: u16,
        flags: String,
        service: String,
        regexp: String,
        replacement: String,
    },
    Opt(EdnsOpt),
    Unknown(Vec<u8>),
}

#[derive(Debug, Clone, PartialEq)]
pub struct EdnsOpt {
    pub udp_size: u16,
    pub extended_rcode: u8,
    pub edns_version: u8,
    pub dnssec_ok: bool,
    pub z_flags: u16,
    pub options: Vec<EdnsOption>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct EdnsOption {
    pub code: u16,
    pub data: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Header {
    pub id: u16,
    pub flags: u16,
    pub qd_count: u16,
    pub an_count: u16,
    pub ns_count: u16,
    pub ar_count: u16,
}

impl Header {
    pub fn is_response(&self) -> bool {
        self.flags & 0x8000 != 0
    }
    pub fn opcode(&self) -> u8 {
        ((self.flags >> 11) & 0xF) as u8
    }
    pub fn is_authoritative(&self) -> bool {
        self.flags & 0x0400 != 0
    }
    pub fn is_truncated(&self) -> bool {
        self.flags & 0x0200 != 0
    }
    pub fn recursion_desired(&self) -> bool {
        self.flags & 0x0100 != 0
    }
    pub fn recursion_available(&self) -> bool {
        self.flags & 0x0080 != 0
    }
    pub fn ad_flag(&self) -> bool {
        self.flags & 0x0020 != 0
    }
    pub fn cd_flag(&self) -> bool {
        self.flags & 0x0010 != 0
    }
    pub fn rcode(&self) -> u8 {
        (self.flags & 0x000F) as u8
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct Question {
    pub name: String,
    pub qtype: RecordType,
    pub qclass: u16,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ResourceRecord {
    pub name: String,
    pub rtype: RecordType,
    pub class: u16,
    pub ttl: u32,
    pub rdata: Rdata,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Message {
    pub header: Header,
    pub questions: Vec<Question>,
    pub answers: Vec<ResourceRecord>,
    pub authority: Vec<ResourceRecord>,
    pub additional: Vec<ResourceRecord>,
}

impl Message {
    pub fn opt_record(&self) -> Option<&EdnsOpt> {
        self.additional
            .iter()
            .find(|rr| rr.rtype == RecordType::Opt)
            .and_then(|rr| match &rr.rdata {
                Rdata::Opt(opt) => Some(opt),
                _ => None,
            })
    }
}

#[derive(Error, Debug)]
pub enum DnsError {
    #[error("buffer too short at offset {0}")]
    Short(usize),
    #[error("invalid name at offset {0}: {1}")]
    BadName(usize, String),
    #[error("unknown record type {0}")]
    UnknownType(u16),
    #[error("invalid UTF-8 in label")]
    Utf8,
}

#[derive(Clone)]
pub struct QueryConfig {
    pub id: u16,
    pub opcode: u8,
    pub rd: bool,
    pub aa: bool,
    pub ad: bool,
    pub cd: bool,
    pub tc: bool,
    pub z_flag: bool,
    pub ra_flag: bool,
    pub edns: bool,
    pub edns_version: u8,
    pub dnssec_ok: bool,
    pub udp_bufsize: u16,
    pub edns_flags: u16,
    pub edns_options: Vec<EdnsOption>,
    pub header_only: bool,
    pub qclass: u16,
}

impl Default for QueryConfig {
    fn default() -> Self {
        QueryConfig {
            id: 0x1234,
            opcode: 0,
            rd: true,
            aa: false,
            ad: true,
            cd: false,
            tc: false,
            z_flag: false,
            ra_flag: false,
            edns: true,
            edns_version: 0,
            dnssec_ok: false,
            udp_bufsize: 1232,
            edns_flags: 0,
            edns_options: Vec::new(),
            header_only: false,
            qclass: 1,
        }
    }
}

pub fn build_query(name: &str, qtype: RecordType, cfg: &QueryConfig) -> Vec<u8> {
    let mut flags: u16 = 0;
    if cfg.rd {
        flags |= 0x0100;
    }
    if cfg.aa {
        flags |= 0x0400;
    }
    if cfg.ad {
        flags |= 0x0020;
    }
    if cfg.cd {
        flags |= 0x0010;
    }
    if cfg.tc {
        flags |= 0x0200;
    }
    if cfg.z_flag {
        flags |= 0x0040;
    }
    if cfg.ra_flag {
        flags |= 0x0080;
    }
    flags |= (cfg.opcode as u16 & 0xF) << 11;

    let mut buf = Vec::with_capacity(512);

    buf.extend_from_slice(&cfg.id.to_be_bytes());
    buf.extend_from_slice(&flags.to_be_bytes());
    buf.extend_from_slice(&1u16.to_be_bytes());
    buf.extend_from_slice(&0u16.to_be_bytes());
    buf.extend_from_slice(&0u16.to_be_bytes());
    let ar_offset = buf.len();
    buf.extend_from_slice(&0u16.to_be_bytes());

    if !cfg.header_only {
        encode_name(&mut buf, name);
        buf.extend_from_slice(&qtype.to_u16().to_be_bytes());
        buf.extend_from_slice(&cfg.qclass.to_be_bytes());
    }

    if cfg.edns {
        let opt_rdlen_pos;
        buf.push(0x00);
        buf.extend_from_slice(&41u16.to_be_bytes());
        buf.extend_from_slice(&cfg.udp_bufsize.to_be_bytes());
        let ext_rcode_and_version = ((0u8 as u16) << 8) | (cfg.edns_version as u16);
        buf.extend_from_slice(&ext_rcode_and_version.to_be_bytes());
        let mut z: u16 = cfg.edns_flags;
        if cfg.dnssec_ok {
            z |= 0x8000;
        }
        buf.extend_from_slice(&z.to_be_bytes());
        opt_rdlen_pos = buf.len();
        buf.extend_from_slice(&0u16.to_be_bytes());

        for opt in &cfg.edns_options {
            buf.extend_from_slice(&opt.code.to_be_bytes());
            buf.extend_from_slice(&(opt.data.len() as u16).to_be_bytes());
            buf.extend_from_slice(&opt.data);
        }

        let rdlen = buf.len() - opt_rdlen_pos - 2;
        buf[opt_rdlen_pos] = ((rdlen >> 8) & 0xFF) as u8;
        buf[opt_rdlen_pos + 1] = (rdlen & 0xFF) as u8;

        let ar_count: u16 = 1;
        buf[ar_offset] = ((ar_count >> 8) & 0xFF) as u8;
        buf[ar_offset + 1] = (ar_count & 0xFF) as u8;
    }

    buf
}

fn encode_name(buf: &mut Vec<u8>, name: &str) {
    if name == "." {
        buf.push(0x00);
        return;
    }
    for label in name.trim_end_matches('.').split('.') {
        let bytes = label.as_bytes();
        buf.push(bytes.len() as u8);
        buf.extend_from_slice(bytes);
    }
    buf.push(0x00);
}

pub fn parse_message(buf: &[u8]) -> Result<Message, DnsError> {
    if buf.len() < 12 {
        return Err(DnsError::Short(0));
    }

    let id = u16::from_be_bytes([buf[0], buf[1]]);
    let flags = u16::from_be_bytes([buf[2], buf[3]]);
    let qd_count = u16::from_be_bytes([buf[4], buf[5]]);
    let an_count = u16::from_be_bytes([buf[6], buf[7]]);
    let ns_count = u16::from_be_bytes([buf[8], buf[9]]);
    let ar_count = u16::from_be_bytes([buf[10], buf[11]]);

    let header = Header {
        id,
        flags,
        qd_count,
        an_count,
        ns_count,
        ar_count,
    };
    let mut pos = 12usize;

    let mut questions = Vec::with_capacity(qd_count as usize);
    let mut answers = Vec::with_capacity(an_count as usize);
    let mut authority = Vec::with_capacity(ns_count as usize);
    let mut additional = Vec::with_capacity(ar_count as usize);

    for _ in 0..qd_count {
        let (name, end) = parse_name(buf, pos)?;
        pos = end;
        if pos + 4 > buf.len() {
            return Err(DnsError::Short(pos));
        }
        let qtype_raw = u16::from_be_bytes([buf[pos], buf[pos + 1]]);
        let qtype = RecordType::from_u16(qtype_raw);
        let qclass = u16::from_be_bytes([buf[pos + 2], buf[pos + 3]]);
        pos += 4;
        questions.push(Question {
            name,
            qtype,
            qclass,
        });
    }

    for (section, count) in [
        (&mut answers as &mut Vec<ResourceRecord>, an_count),
        (&mut authority as &mut Vec<ResourceRecord>, ns_count),
        (&mut additional as &mut Vec<ResourceRecord>, ar_count),
    ] {
        for _ in 0..count {
            let (name, end) = parse_name(buf, pos)?;
            pos = end;
            if pos + 10 > buf.len() {
                return Err(DnsError::Short(pos));
            }
            let rtype_raw = u16::from_be_bytes([buf[pos], buf[pos + 1]]);
            let class = u16::from_be_bytes([buf[pos + 2], buf[pos + 3]]);
            let ttl = u32::from_be_bytes([buf[pos + 4], buf[pos + 5], buf[pos + 6], buf[pos + 7]]);
            let rdlen = u16::from_be_bytes([buf[pos + 8], buf[pos + 9]]) as usize;
            pos += 10;
            if pos + rdlen > buf.len() {
                return Err(DnsError::Short(pos));
            }
            let rtype = RecordType::from_u16(rtype_raw);
            let rdata = parse_rdata(buf, pos, rdlen, rtype, class)?;
            pos += rdlen;
            section.push(ResourceRecord {
                name,
                rtype,
                class,
                ttl,
                rdata,
            });
        }
    }

    Ok(Message {
        header,
        questions,
        answers,
        authority,
        additional,
    })
}

fn parse_name(buf: &[u8], start: usize) -> Result<(String, usize), DnsError> {
    let mut labels: Vec<String> = Vec::new();
    let mut pos = start;
    let mut end_pos = start;
    let mut jumped = false;

    loop {
        if pos >= buf.len() {
            return Err(DnsError::Short(pos));
        }
        let len = buf[pos] as usize;
        if len == 0 {
            if !jumped {
                end_pos = pos + 1;
            }
            break;
        }
        if (len & 0xC0) == 0xC0 {
            if pos + 1 >= buf.len() {
                return Err(DnsError::Short(pos));
            }
            let ptr = ((len & 0x3F) << 8) | buf[pos + 1] as usize;
            if !jumped {
                end_pos = pos + 2;
            }
            jumped = true;
            pos = ptr;
        } else {
            pos += 1;
            if pos + len > buf.len() {
                return Err(DnsError::Short(pos));
            }
            let label = std::str::from_utf8(&buf[pos..pos + len])
                .map_err(|_| DnsError::Utf8)?
                .to_string();
            labels.push(label);
            pos += len;
        }
    }

    let name = if labels.is_empty() {
        ".".into()
    } else {
        labels.join(".")
    };
    Ok((name, end_pos))
}

fn parse_rdata(
    buf: &[u8],
    offset: usize,
    rdlen: usize,
    rtype: RecordType,
    class: u16,
) -> Result<Rdata, DnsError> {
    let rd = &buf[offset..offset + rdlen];

    if rtype == RecordType::Opt {
        let udp_size = class;
        let extended_rcode = rd.get(0).copied().unwrap_or(0);
        let edns_version = rd.get(1).copied().unwrap_or(0);
        let z = if rd.len() >= 4 {
            u16::from_be_bytes([rd[2], rd[3]])
        } else {
            0
        };
        let dnssec_ok = z & 0x8000 != 0;

        let mut options = Vec::new();
        let mut i = 4usize;
        while i + 4 <= rd.len() {
            let code = u16::from_be_bytes([rd[i], rd[i + 1]]);
            let olen = u16::from_be_bytes([rd[i + 2], rd[i + 3]]) as usize;
            i += 4;
            if i + olen > rd.len() {
                break;
            }
            options.push(EdnsOption {
                code,
                data: rd[i..i + olen].to_vec(),
            });
            i += olen;
        }

        return Ok(Rdata::Opt(EdnsOpt {
            udp_size,
            extended_rcode,
            edns_version,
            dnssec_ok,
            z_flags: z & !0x8000,
            options,
        }));
    }

    match rtype {
        RecordType::A => {
            if rd.len() < 4 {
                return Err(DnsError::Short(offset));
            }
            Ok(Rdata::A(Ipv4Addr::new(rd[0], rd[1], rd[2], rd[3])))
        }
        RecordType::Aaaa => {
            if rd.len() < 16 {
                return Err(DnsError::Short(offset));
            }
            let mut bytes = [0u8; 16];
            bytes.copy_from_slice(&rd[..16]);
            Ok(Rdata::Aaaa(Ipv6Addr::from(bytes)))
        }
        RecordType::Cname | RecordType::Dname => {
            let (name, _) = parse_name(buf, offset)?;
            if rtype == RecordType::Cname {
                Ok(Rdata::Cname(name))
            } else {
                Ok(Rdata::Dname(name))
            }
        }
        RecordType::Ns => {
            let (n, _) = parse_name(buf, offset)?;
            Ok(Rdata::Ns(n))
        }
        RecordType::Ptr => {
            let (n, _) = parse_name(buf, offset)?;
            Ok(Rdata::Ptr(n))
        }
        RecordType::Mx => {
            if rd.len() < 2 {
                return Err(DnsError::Short(offset));
            }
            let priority = u16::from_be_bytes([rd[0], rd[1]]);
            let (exchange, _) = parse_name(buf, offset + 2)?;
            Ok(Rdata::Mx { priority, exchange })
        }
        RecordType::Txt => {
            let mut strings = Vec::new();
            let mut i = 0;
            while i < rd.len() {
                let slen = rd[i] as usize;
                i += 1;
                if i + slen > rd.len() {
                    break;
                }
                strings.push(rd[i..i + slen].to_vec());
                i += slen;
            }
            Ok(Rdata::Txt(strings))
        }
        RecordType::Soa => {
            let (mname, pos1) = parse_name(buf, offset)?;
            let (rname, pos2) = parse_name(buf, pos1)?;
            let rest = &buf[pos2..offset + rdlen];
            if rest.len() < 20 {
                return Err(DnsError::Short(pos2));
            }
            let serial = u32::from_be_bytes([rest[0], rest[1], rest[2], rest[3]]);
            let refresh = u32::from_be_bytes([rest[4], rest[5], rest[6], rest[7]]);
            let retry = u32::from_be_bytes([rest[8], rest[9], rest[10], rest[11]]);
            let expire = u32::from_be_bytes([rest[12], rest[13], rest[14], rest[15]]);
            let minimum = u32::from_be_bytes([rest[16], rest[17], rest[18], rest[19]]);
            Ok(Rdata::Soa {
                mname,
                rname,
                serial,
                refresh,
                retry,
                expire,
                minimum,
            })
        }
        RecordType::Srv => {
            if rd.len() < 6 {
                return Err(DnsError::Short(offset));
            }
            let priority = u16::from_be_bytes([rd[0], rd[1]]);
            let weight = u16::from_be_bytes([rd[2], rd[3]]);
            let port = u16::from_be_bytes([rd[4], rd[5]]);
            let (target, _) = parse_name(buf, offset + 6)?;
            Ok(Rdata::Srv {
                priority,
                weight,
                port,
                target,
            })
        }
        RecordType::Caa => {
            if rd.len() < 2 {
                return Err(DnsError::Short(offset));
            }
            let flags = rd[0];
            let tag_len = rd[1] as usize;
            if 2 + tag_len > rd.len() {
                return Err(DnsError::Short(offset));
            }
            let tag = std::str::from_utf8(&rd[2..2 + tag_len])
                .map_err(|_| DnsError::Utf8)?
                .to_string();
            let value = rd[2 + tag_len..].to_vec();
            Ok(Rdata::Caa { flags, tag, value })
        }
        RecordType::Ds => {
            if rd.len() < 4 {
                return Err(DnsError::Short(offset));
            }
            let key_tag = u16::from_be_bytes([rd[0], rd[1]]);
            let algorithm = rd[2];
            let digest_type = rd[3];
            let digest = rd[4..].to_vec();
            Ok(Rdata::Ds {
                key_tag,
                algorithm,
                digest_type,
                digest,
            })
        }
        RecordType::Dnskey => {
            if rd.len() < 4 {
                return Err(DnsError::Short(offset));
            }
            let flags = u16::from_be_bytes([rd[0], rd[1]]);
            let protocol = rd[2];
            let algorithm = rd[3];
            let public_key = rd[4..].to_vec();
            Ok(Rdata::Dnskey {
                flags,
                protocol,
                algorithm,
                public_key,
            })
        }
        RecordType::Rrsig => {
            if rd.len() < 18 {
                return Err(DnsError::Short(offset));
            }
            let type_covered = u16::from_be_bytes([rd[0], rd[1]]);
            let algorithm = rd[2];
            let labels = rd[3];
            let original_ttl = u32::from_be_bytes([rd[4], rd[5], rd[6], rd[7]]);
            let signature_expiration = u32::from_be_bytes([rd[8], rd[9], rd[10], rd[11]]);
            let signature_inception = u32::from_be_bytes([rd[12], rd[13], rd[14], rd[15]]);
            let key_tag = u16::from_be_bytes([rd[16], rd[17]]);
            let (signer_name, pos1) = parse_name(buf, offset + 18)?;
            let signature = buf[pos1..offset + rdlen].to_vec();
            Ok(Rdata::Rrsig {
                type_covered,
                algorithm,
                labels,
                original_ttl,
                signature_expiration,
                signature_inception,
                key_tag,
                signer_name,
                signature,
            })
        }
        RecordType::Nsec => {
            let (next_name, pos1) = parse_name(buf, offset)?;
            let type_bitmap = buf[pos1..offset + rdlen].to_vec();
            Ok(Rdata::Nsec {
                next_name,
                type_bitmap,
            })
        }
        RecordType::Nsec3 => {
            if rd.len() < 6 {
                return Err(DnsError::Short(offset));
            }
            let hash_algorithm = rd[0];
            let flags = rd[1];
            let iterations = u16::from_be_bytes([rd[2], rd[3]]);
            let salt_len = rd[4] as usize;
            let mut i = 5 + salt_len;
            if i >= rd.len() {
                return Err(DnsError::Short(offset));
            }
            let hash_len = rd[i] as usize;
            i += 1;
            if i + hash_len > rd.len() {
                return Err(DnsError::Short(offset));
            }
            let salt = rd[5..5 + salt_len].to_vec();
            let next_hash = rd[i..i + hash_len].to_vec();
            i += hash_len;
            let type_bitmap = rd[i..].to_vec();
            Ok(Rdata::Nsec3 {
                hash_algorithm,
                flags,
                iterations,
                salt,
                next_hash,
                type_bitmap,
            })
        }
        RecordType::Nsec3param => {
            if rd.len() < 5 {
                return Err(DnsError::Short(offset));
            }
            let hash_algorithm = rd[0];
            let flags = rd[1];
            let iterations = u16::from_be_bytes([rd[2], rd[3]]);
            let salt_len = rd[4] as usize;
            let salt = if salt_len > 0 && 5 + salt_len <= rd.len() {
                rd[5..5 + salt_len].to_vec()
            } else {
                vec![]
            };
            Ok(Rdata::Nsec3param {
                hash_algorithm,
                flags,
                iterations,
                salt,
            })
        }
        RecordType::Sshfp => {
            if rd.len() < 2 {
                return Err(DnsError::Short(offset));
            }
            let algorithm = rd[0];
            let fp_type = rd[1];
            let fingerprint = rd[2..].to_vec();
            Ok(Rdata::Sshfp {
                algorithm,
                fp_type,
                fingerprint,
            })
        }
        RecordType::Tlsa => {
            if rd.len() < 3 {
                return Err(DnsError::Short(offset));
            }
            let usage = rd[0];
            let selector = rd[1];
            let matching_type = rd[2];
            let data = rd[3..].to_vec();
            Ok(Rdata::Tlsa {
                usage,
                selector,
                matching_type,
                data,
            })
        }
        RecordType::Hinfo => {
            if rd.is_empty() {
                return Ok(Rdata::Hinfo {
                    cpu: String::new(),
                    os: String::new(),
                });
            }
            let cpu_len = rd[0] as usize;
            if 1 + cpu_len > rd.len() {
                return Err(DnsError::Short(offset));
            }
            let cpu = std::str::from_utf8(&rd[1..1 + cpu_len])
                .unwrap_or("")
                .to_string();
            let os_start = 1 + cpu_len;
            if os_start >= rd.len() {
                return Ok(Rdata::Hinfo {
                    cpu,
                    os: String::new(),
                });
            }
            let os_len = rd[os_start] as usize;
            let os = if os_start + 1 + os_len <= rd.len() {
                std::str::from_utf8(&rd[os_start + 1..os_start + 1 + os_len])
                    .unwrap_or("")
                    .to_string()
            } else {
                String::new()
            };
            Ok(Rdata::Hinfo { cpu, os })
        }
        RecordType::Naptr => {
            if rd.len() < 4 {
                return Err(DnsError::Short(offset));
            }
            let order = u16::from_be_bytes([rd[0], rd[1]]);
            let preference = u16::from_be_bytes([rd[2], rd[3]]);
            let mut i = 4usize;
            let flags_str = parse_char_string(rd, &mut i);
            let service = parse_char_string(rd, &mut i);
            let regexp = parse_char_string(rd, &mut i);
            let (replacement, _) = parse_name(buf, offset + i)?;
            Ok(Rdata::Naptr {
                order,
                preference,
                flags: flags_str,
                service,
                regexp,
                replacement,
            })
        }
        RecordType::Loc => {
            if rd.len() < 16 {
                return Ok(Rdata::Unknown(rd.to_vec()));
            }
            let version = rd[0];
            let siz = rd[1];
            let horiz = rd[2];
            let vert = rd[3];
            let latitude = i32::from_be_bytes([rd[4], rd[5], rd[6], rd[7]]);
            let longitude = i32::from_be_bytes([rd[8], rd[9], rd[10], rd[11]]);
            let altitude = i32::from_be_bytes([rd[12], rd[13], rd[14], rd[15]]);
            Ok(Rdata::Loc {
                version,
                siz,
                horiz,
                vert,
                latitude,
                longitude,
                altitude,
            })
        }
        _ => Ok(Rdata::Unknown(rd.to_vec())),
    }
}

fn parse_char_string(rd: &[u8], i: &mut usize) -> String {
    if *i >= rd.len() {
        return String::new();
    }
    let len = rd[*i] as usize;
    *i += 1;
    if *i + len > rd.len() {
        return String::new();
    }
    let s = std::str::from_utf8(&rd[*i..*i + len])
        .unwrap_or("")
        .to_string();
    *i += len;
    s
}

pub fn rcode_name(rcode: u8) -> &'static str {
    match rcode {
        0 => "NOERROR",
        1 => "FORMERR",
        2 => "SERVFAIL",
        3 => "NXDOMAIN",
        4 => "NOTIMP",
        5 => "REFUSED",
        6 => "YXDOMAIN",
        7 => "YXRRSET",
        8 => "NXRRSET",
        9 => "NOTAUTH",
        10 => "NOTZONE",
        16 => "BADVERS",
        17 => "BADKEY",
        18 => "BADTIME",
        19 => "BADMODE",
        20 => "BADNAME",
        21 => "BADALG",
        22 => "BADTRUNC",
        23 => "BADCOOKIE",
        _ => "UNKNOWN",
    }
}

pub fn opcode_name(opcode: u8) -> &'static str {
    match opcode {
        0 => "QUERY",
        1 => "IQUERY",
        2 => "STATUS",
        4 => "NOTIFY",
        5 => "UPDATE",
        _ => "UNKNOWN",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const QUERY_XY_A: &[u8] = &[
        0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, b'x', 0x01,
        b'y', 0x00, 0x00, 0x01, 0x00, 0x01,
    ];

    const RESPONSE_XY_A: &[u8] = &[
        0x12, 0x34, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x01, b'x', 0x01,
        b'y', 0x00, 0x00, 0x01, 0x00, 0x01, 0xC0, 0x0C, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x01,
        0x2C, 0x00, 0x04, 0x01, 0x02, 0x03, 0x04,
    ];

    #[test]
    fn build_query_simple() {
        let mut cfg = QueryConfig::default();
        cfg.id = 0x1234;
        cfg.ad = false;
        cfg.edns = false;
        let q = build_query("x.y", RecordType::A, &cfg);
        assert_eq!(q, QUERY_XY_A);
    }

    #[test]
    fn build_query_no_recursion() {
        let mut cfg = QueryConfig::default();
        cfg.id = 0x1234;
        cfg.rd = false;
        cfg.edns = false;
        let q = build_query("x.y", RecordType::A, &cfg);
        assert_eq!(q[2], 0x00, "flags high byte should have RD=0");
    }

    #[test]
    fn build_query_multipart_name() {
        let mut cfg = QueryConfig::default();
        cfg.id = 0x0001;
        cfg.edns = false;
        let q = build_query("a.b.c", RecordType::A, &cfg);
        let s = 12;
        assert_eq!(&q[s..s + 7], &[0x01, b'a', 0x01, b'b', 0x01, b'c', 0x00]);
    }

    #[test]
    fn build_query_with_edns() {
        let cfg = QueryConfig::default();
        let q = build_query("x.y", RecordType::A, &cfg);
        let ar_count = u16::from_be_bytes([q[10], q[11]]);
        assert_eq!(ar_count, 1);
        assert!(q.len() > 24);
    }

    #[test]
    fn build_query_dnssec() {
        let mut cfg = QueryConfig::default();
        cfg.dnssec_ok = true;
        let q = build_query("x.y", RecordType::A, &cfg);
        assert!(q.len() > 24);
        let ar_count = u16::from_be_bytes([q[10], q[11]]);
        assert_eq!(ar_count, 1);
    }

    #[test]
    fn record_type_roundtrip() {
        assert_eq!(RecordType::from_u16(1), RecordType::A);
        assert_eq!(RecordType::A.to_u16(), 1);
        assert_eq!(RecordType::from_str("AAAA"), Some(RecordType::Aaaa));
        assert_eq!(RecordType::Aaaa.as_str(), "AAAA");
        assert_eq!(RecordType::from_str("SRV"), Some(RecordType::Srv));
        assert_eq!(RecordType::from_str("CAA"), Some(RecordType::Caa));
        assert_eq!(
            RecordType::from_str("TYPE65432"),
            Some(RecordType::Other(65432))
        );
        assert_eq!(RecordType::Other(65432).to_u16(), 65432);
    }

    #[test]
    fn parse_a_response() {
        let msg = parse_message(RESPONSE_XY_A).unwrap();
        assert_eq!(msg.header.id, 0x1234);
        assert!(msg.header.is_response());
        assert_eq!(msg.header.qd_count, 1);
        assert_eq!(msg.header.an_count, 1);
        assert_eq!(msg.questions[0].name, "x.y");
        assert_eq!(msg.questions[0].qtype, RecordType::A);
        let rr = &msg.answers[0];
        assert_eq!(rr.name, "x.y");
        assert_eq!(rr.rtype, RecordType::A);
        assert_eq!(rr.ttl, 300);
        assert_eq!(rr.rdata, Rdata::A(Ipv4Addr::new(1, 2, 3, 4)));
    }

    #[test]
    fn parse_name_with_pointer() {
        let msg = parse_message(RESPONSE_XY_A).unwrap();
        assert_eq!(msg.answers[0].name, "x.y");
    }

    #[test]
    fn parse_error_on_short_buffer() {
        assert!(parse_message(&[0u8; 11]).is_err());
    }

    #[test]
    fn rcode_and_opcode_names() {
        assert_eq!(rcode_name(0), "NOERROR");
        assert_eq!(rcode_name(3), "NXDOMAIN");
        assert_eq!(opcode_name(0), "QUERY");
    }
}
