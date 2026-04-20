use crate::dns::Rdata;

pub fn format_rdata(rdata: &Rdata, opts: &FormatOpts) -> String {
    if opts.unknown_format {
        let bytes = rdata_to_bytes(rdata);
        return format!("\\# {} {}", bytes.len(), hex::encode(&bytes));
    }
    match rdata {
        Rdata::A(addr) => addr.to_string(),
        Rdata::Aaaa(addr) => format_aaaa(addr),
        Rdata::Cname(s) => format!("{s}."),
        Rdata::Ns(s) => format!("{s}."),
        Rdata::Ptr(s) => format!("{s}."),
        Rdata::Dname(s) => format!("{s}."),
        Rdata::Mx { priority, exchange } => format!("{priority} {exchange}."),
        Rdata::Txt(parts) => format_txt(parts),
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
            use crate::dns::RecordType;
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
        Rdata::Svcb {
            priority,
            target,
            params,
        } => format_svcb(*priority, target, params),
        Rdata::Unknown(b) => format!("\\# {} {}", b.len(), hex::encode(b)),
        Rdata::Opt(_) => String::new(),
    }
}

fn format_svcb(priority: u16, target: &str, params: &[crate::dns::SvcParam]) -> String {
    let mut s = format!("{priority} {target}.");
    for p in params {
        s.push(' ');
        s.push_str(&svcparam_key_name(p.key));
        let has_value = !matches!(&p.value, crate::dns::SvcParamValue::NoDefaultAlpn);
        if has_value {
            s.push('=');
            s.push_str(&format_svcparam_value(&p.value));
        }
    }
    s
}

fn svcparam_key_name(key: u16) -> String {
    match key {
        0 => "mandatory".to_string(),
        1 => "alpn".to_string(),
        2 => "no-default-alpn".to_string(),
        3 => "port".to_string(),
        4 => "ipv4hint".to_string(),
        5 => "ech".to_string(),
        6 => "ipv6hint".to_string(),
        7 => "dohpath".to_string(),
        _ => format!("key{key}"),
    }
}

fn format_svcparam_value(v: &crate::dns::SvcParamValue) -> String {
    use crate::dns::SvcParamValue;
    match v {
        SvcParamValue::Mandatory(keys) => keys
            .iter()
            .map(|k| svcparam_key_name(*k))
            .collect::<Vec<_>>()
            .join(","),
        SvcParamValue::Alpn(protos) => {
            let inner: Vec<String> = protos
                .iter()
                .map(|p| String::from_utf8_lossy(p).to_string())
                .collect();
            format!("\"{}\"", inner.join(","))
        }
        SvcParamValue::NoDefaultAlpn => String::new(),
        SvcParamValue::Port(port) => port.to_string(),
        SvcParamValue::Ipv4Hint(addrs) => addrs
            .iter()
            .map(|a| a.to_string())
            .collect::<Vec<_>>()
            .join(","),
        SvcParamValue::Ipv6Hint(addrs) => {
            addrs.iter().map(format_aaaa).collect::<Vec<_>>().join(",")
        }
        SvcParamValue::Ech(data) => base64_encode(data),
        SvcParamValue::DohPath(data) => {
            let s = String::from_utf8_lossy(data).to_string();
            escape_dohpath(&s)
        }
        SvcParamValue::Other(_key, data) => {
            let s = String::from_utf8_lossy(data).to_string();
            s
        }
    }
}

fn escape_dohpath(s: &str) -> String {
    let mut out = String::new();
    for ch in s.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c.is_control() => {
                out.push_str(&format!("\\{:03o}", c as u32));
            }
            c => out.push(c),
        }
    }
    out
}

pub fn format_aaaa(addr: &std::net::Ipv6Addr) -> String {
    let segments = addr.segments();
    let mut runs: Vec<(usize, usize)> = Vec::new();
    let mut current_run: Option<(usize, usize)> = None;
    for (i, &s) in segments.iter().enumerate() {
        if s == 0 {
            if let Some(ref mut run) = current_run {
                run.1 = i + 1;
            } else {
                current_run = Some((i, i + 1));
            }
        } else {
            current_run = None;
        }
    }
    if let Some(run) = current_run {
        if run.1 - run.0 >= 2 {
            runs.push(run);
        }
    }
    if let Some(best) = runs.iter().max_by_key(|r| r.1 - r.0) {
        if best.1 - best.0 >= 2 {
            let mut parts = Vec::new();
            for seg in segments.iter().take(best.0) {
                parts.push(format!("{seg:x}"));
            }
            parts.push(String::new());
            for seg in segments.iter().skip(best.1) {
                parts.push(format!("{seg:x}"));
            }
            return parts.join(":");
        }
    }
    segments
        .iter()
        .map(|s| format!("{s:x}"))
        .collect::<Vec<_>>()
        .join(":")
}

fn format_txt(parts: &[Vec<u8>]) -> String {
    parts
        .iter()
        .map(|p| format!("\"{}\"", escape_txt_string(p)))
        .collect::<Vec<_>>()
        .join(" ")
}

fn escape_txt_string(data: &[u8]) -> String {
    let mut s = String::with_capacity(data.len());
    for &b in data {
        match b {
            b'\\' => s.push_str("\\\\"),
            b'"' => s.push_str("\\\""),
            b'\n' => s.push_str("\\n"),
            b'\r' => s.push_str("\\r"),
            b'\t' => s.push_str("\\t"),
            c if c < 0x20 || c == 0x7f => s.push_str(&format!("\\{:03o}", c)),
            c => {
                if let Some(ch) = char::from_u32(c as u32) {
                    s.push(ch);
                }
            }
        }
    }
    s
}

pub fn rdata_to_bytes(rdata: &Rdata) -> Vec<u8> {
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

pub fn format_ttl_units(ttl: u32) -> String {
    if ttl == 0 {
        return "0".into();
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
    if secs > 0 || s.is_empty() {
        s.push_str(&format!("{secs}s"));
    }
    s
}

pub fn class_name(class: u16) -> &'static str {
    match class {
        1 => "IN",
        3 => "CH",
        4 => "HS",
        255 => "ANY",
        254 => "NONE",
        _ => "CLASS?",
    }
}

pub fn decode_type_bitmap(bitmap: &[u8]) -> Vec<String> {
    let mut types = Vec::new();
    let mut i = 0;
    while i + 2 <= bitmap.len() {
        let window = bitmap[i];
        let bm_len = bitmap[i + 1] as usize;
        i += 2;
        if i + bm_len > bitmap.len() {
            break;
        }
        for (bit_idx, &byte) in bitmap[i..i + bm_len].iter().enumerate() {
            for bit in (0..8).rev() {
                if byte & (1 << bit) != 0 {
                    let rtype_num = window as u16 * 256 + (bit_idx as u16) * 8 + (7 - bit) as u16;
                    use crate::dns::RecordType;
                    let rt = RecordType::from_u16(rtype_num);
                    types.push(rt.display_str());
                }
            }
        }
        i += bm_len;
    }
    types
}

pub fn base64_encode(data: &[u8]) -> String {
    const CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut s = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
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

pub fn base32hex_encode(data: &[u8]) -> String {
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

pub struct FormatOpts {
    #[allow(dead_code)]
    pub ttl_units: bool,
    pub unknown_format: bool,
    #[allow(dead_code)]
    pub rrcomments: bool,
}

pub fn format_rrcomment(rdata: &Rdata) -> Option<String> {
    match rdata {
        Rdata::Dnskey {
            flags,
            algorithm,
            public_key,
            ..
        } => {
            let key_info = if (*flags & 0x0001) != 0 {
                if (*flags & 0x0080) != 0 {
                    "revoked KSK"
                } else {
                    "KSK"
                }
            } else {
                "ZSK"
            };
            let alg_name = secalg_name(*algorithm);
            let key_tag = compute_key_tag(*flags, 3, *algorithm, public_key);
            Some(format!(
                " ; {key_info} ; alg = {alg_name} ; key id = {key_tag}"
            ))
        }
        Rdata::Ds {
            key_tag,
            algorithm,
            digest_type,
            ..
        } => {
            let alg_name = secalg_name(*algorithm);
            let dt_name = digest_type_name(*digest_type);
            Some(format!(
                " ; zsk = no ; alg = {alg_name} ; digest type = {dt_name} ; tag = {key_tag}"
            ))
        }
        _ => None,
    }
}

fn secalg_name(alg: u8) -> &'static str {
    match alg {
        1 => "RSAMD5",
        2 => "DH",
        3 => "DSA",
        5 => "RSASHA1",
        6 => "DSA-NSEC3-SHA1",
        7 => "RSASHA1-NSEC3-SHA1",
        8 => "RSASHA256",
        10 => "RSASHA512",
        12 => "ECC-GOST",
        13 => "ECDSAP256SHA256",
        14 => "ECDSAP384SHA384",
        15 => "ED25519",
        16 => "ED448",
        _ => "UNKNOWN",
    }
}

fn digest_type_name(dt: u8) -> String {
    match dt {
        1 => "SHA-1".to_string(),
        2 => "SHA-256".to_string(),
        4 => "SHA-384".to_string(),
        _ => format!("{dt}"),
    }
}

fn compute_key_tag(flags: u16, protocol: u8, algorithm: u8, public_key: &[u8]) -> u16 {
    let mut ac: u32 = 0;
    let data: Vec<u8> = {
        let mut d = Vec::with_capacity(4 + public_key.len());
        d.extend_from_slice(&flags.to_be_bytes());
        d.push(protocol);
        d.push(algorithm);
        d.extend_from_slice(public_key);
        d
    };
    let mut size = data.len();
    let mut p = 0usize;
    while size > 1 {
        ac += (data[p] as u32) << 8 | data[p + 1] as u32;
        p += 2;
        size -= 2;
    }
    if size > 0 {
        ac += (data[p] as u32) << 8;
    }
    ac += (ac >> 16) & 0xffff;
    (ac & 0xffff) as u16
}
