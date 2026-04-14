use std::net::{Ipv4Addr, Ipv6Addr};
use thiserror::Error;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecordType {
    A = 1,
    Ns = 2,
    Cname = 5,
    Soa = 6,
    Ptr = 12,
    Mx = 15,
    Txt = 16,
    Aaaa = 28,
    Any = 255,
}

impl RecordType {
    pub fn from_u16(v: u16) -> Option<Self> {
        match v {
            1 => Some(Self::A),
            2 => Some(Self::Ns),
            5 => Some(Self::Cname),
            6 => Some(Self::Soa),
            12 => Some(Self::Ptr),
            15 => Some(Self::Mx),
            16 => Some(Self::Txt),
            28 => Some(Self::Aaaa),
            255 => Some(Self::Any),
            _ => None,
        }
    }

    pub fn to_u16(self) -> u16 {
        self as u16
    }

    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_uppercase().as_str() {
            "A" => Some(Self::A),
            "NS" => Some(Self::Ns),
            "CNAME" => Some(Self::Cname),
            "SOA" => Some(Self::Soa),
            "PTR" => Some(Self::Ptr),
            "MX" => Some(Self::Mx),
            "TXT" => Some(Self::Txt),
            "AAAA" => Some(Self::Aaaa),
            "ANY" => Some(Self::Any),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::A => "A",
            Self::Ns => "NS",
            Self::Cname => "CNAME",
            Self::Soa => "SOA",
            Self::Ptr => "PTR",
            Self::Mx => "MX",
            Self::Txt => "TXT",
            Self::Aaaa => "AAAA",
            Self::Any => "ANY",
        }
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
    Unknown(Vec<u8>),
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
    pub fn is_truncated(&self) -> bool {
        self.flags & 0x0200 != 0
    }
    pub fn rcode(&self) -> u8 {
        (self.flags & 0x000F) as u8
    }
    pub fn recursion_desired(&self) -> bool {
        self.flags & 0x0100 != 0
    }
    pub fn recursion_available(&self) -> bool {
        self.flags & 0x0080 != 0
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

pub fn build_query(name: &str, qtype: RecordType, id: u16, recurse: bool) -> Vec<u8> {
    let flags: u16 = if recurse { 0x0100 } else { 0x0000 };
    let mut buf = Vec::with_capacity(512);

    buf.extend_from_slice(&id.to_be_bytes());
    buf.extend_from_slice(&flags.to_be_bytes());
    buf.extend_from_slice(&1u16.to_be_bytes());
    buf.extend_from_slice(&0u16.to_be_bytes());
    buf.extend_from_slice(&0u16.to_be_bytes());
    buf.extend_from_slice(&0u16.to_be_bytes());

    for label in name.split('.') {
        let bytes = label.as_bytes();
        buf.push(bytes.len() as u8);
        buf.extend_from_slice(bytes);
    }
    buf.push(0x00);

    buf.extend_from_slice(&qtype.to_u16().to_be_bytes());
    buf.extend_from_slice(&1u16.to_be_bytes());
    buf
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
        let qtype = RecordType::from_u16(qtype_raw).unwrap_or(RecordType::Any);
        let qclass = u16::from_be_bytes([buf[pos + 2], buf[pos + 3]]);
        pos += 4;
        questions.push(Question {
            name,
            qtype,
            qclass,
        });
    }

    for (section, count) in [
        (&mut answers, an_count),
        (&mut authority, ns_count),
        (&mut additional, ar_count),
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
            let rtype = RecordType::from_u16(rtype_raw).unwrap_or(RecordType::A);
            let rdata = parse_rdata(buf, pos, rdlen, rtype)?;
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
) -> Result<Rdata, DnsError> {
    let rd = &buf[offset..offset + rdlen];
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
        RecordType::Cname => {
            let (name, _) = parse_name(buf, offset)?;
            Ok(Rdata::Cname(name))
        }
        RecordType::Ns => {
            let (name, _) = parse_name(buf, offset)?;
            Ok(Rdata::Ns(name))
        }
        RecordType::Ptr => {
            let (name, _) = parse_name(buf, offset)?;
            Ok(Rdata::Ptr(name))
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
        _ => Ok(Rdata::Unknown(rd.to_vec())),
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
    fn build_query_bytes() {
        let q = build_query("x.y", RecordType::A, 0x1234, true);
        assert_eq!(q, QUERY_XY_A);
    }

    #[test]
    fn build_query_no_recursion() {
        let q = build_query("x.y", RecordType::A, 0x1234, false);
        assert_eq!(q[2], 0x00, "flags high byte should have RD=0");
    }

    #[test]
    fn build_query_multipart_name() {
        let q = build_query("a.b.c", RecordType::A, 0x0001, false);
        let name_start = 12;
        assert_eq!(q[name_start], 0x01);
        assert_eq!(q[name_start + 1], b'a');
        assert_eq!(q[name_start + 2], 0x01);
        assert_eq!(q[name_start + 3], b'b');
        assert_eq!(q[name_start + 4], 0x01);
        assert_eq!(q[name_start + 5], b'c');
        assert_eq!(q[name_start + 6], 0x00);
    }

    #[test]
    fn record_type_roundtrip() {
        assert_eq!(RecordType::from_u16(1), Some(RecordType::A));
        assert_eq!(RecordType::A.to_u16(), 1);
        assert_eq!(RecordType::from_str("AAAA"), Some(RecordType::Aaaa));
        assert_eq!(RecordType::Aaaa.as_str(), "AAAA");
        assert_eq!(RecordType::from_u16(999), None);
    }

    #[test]
    fn parse_a_response() {
        let msg = parse_message(RESPONSE_XY_A).unwrap();
        assert_eq!(msg.header.id, 0x1234);
        assert!(msg.header.is_response());
        assert_eq!(msg.header.qd_count, 1);
        assert_eq!(msg.header.an_count, 1);
        assert_eq!(msg.questions.len(), 1);
        assert_eq!(msg.questions[0].name, "x.y");
        assert_eq!(msg.questions[0].qtype, RecordType::A);
        assert_eq!(msg.answers.len(), 1);
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
        let result = parse_message(&[0u8; 11]);
        assert!(result.is_err());
    }
}
