use crate::report;
use std::fmt;
use std::net::{Ipv4Addr, Ipv6Addr};

const ADDR_BYTES: usize = 16;

#[derive(Clone)]
pub struct SxPrefix {
    pub family: u8,
    pub masklen: u32,
    pub addrs: [u8; ADDR_BYTES],
}

impl SxPrefix {
    pub fn new() -> Self {
        SxPrefix {
            family: 0,
            masklen: 0,
            addrs: [0u8; ADDR_BYTES],
        }
    }

    pub fn parse(&mut self, af: u8, text: &str) -> bool {
        let mut mtext = text.to_string();
        let masklen;

        if let Some(pos) = mtext.find('/') {
            let rest = mtext[pos + 1..].trim_end().to_string();
            mtext.truncate(pos);
            masklen = match rest.parse::<i32>() {
                Ok(n) => n,
                Err(_) => {
                    report::error(&format!("Invalid masklen in prefix {text}"));
                    return false;
                }
            };
        } else {
            masklen = -1;
        }

        let effective_af = if af == 0 {
            if mtext.contains(':') {
                10
            } else {
                2
            }
        } else {
            af
        };

        let max_bits = if effective_af == 2 { 32u32 } else { 128u32 };
        self.addrs = [0u8; ADDR_BYTES];

        if let Ok(addr) = mtext.parse::<Ipv4Addr>() {
            if effective_af == 2 {
                let octets = addr.octets();
                self.addrs[0] = octets[0];
                self.addrs[1] = octets[1];
                self.addrs[2] = octets[2];
                self.addrs[3] = octets[3];
            }
        } else if let Ok(addr) = mtext.parse::<Ipv6Addr>() {
            if effective_af == 10 {
                let octets = addr.octets();
                self.addrs.copy_from_slice(&octets);
            }
        } else if effective_af == 2 {
            let parts: Vec<&str> = mtext.split('.').collect();
            if parts.len() == 4 {
                let mut nums = [0u8; 4];
                let mut valid = true;
                for (i, p) in parts.iter().enumerate() {
                    match u8::from_str_radix(p, 0) {
                        Ok(n) if n < 255u8 => nums[i] = n,
                        _ => valid = false,
                    }
                }
                if valid {
                    self.addrs[0] = nums[0];
                    self.addrs[1] = nums[1];
                    self.addrs[2] = nums[2];
                    self.addrs[3] = nums[3];
                } else {
                    report::error(&format!("Unable to parse prefix '{text}'"));
                    return false;
                }
            } else {
                report::error(&format!("Unable to parse prefix '{text}'"));
                return false;
            }
        } else {
            report::error(&format!("Unable to parse prefix '{text}'"));
            return false;
        }

        self.family = effective_af;
        self.masklen = if masklen < 0 || masklen as u32 > max_bits {
            max_bits
        } else {
            masklen as u32
        };

        self.adjust_masklen();
        true
    }

    pub fn adjust_masklen(&mut self) {
        let nbytes = if self.family == 2 { 4usize } else { 16usize };
        if self.masklen == (nbytes * 8) as u32 {
            return;
        }
        let mut i: usize = nbytes;
        while i > ((self.masklen / 8) as usize + 1) {
            i -= 1;
            self.addrs[i] = 0;
        }
        let bit_off = self.masklen % 8;
        if bit_off != 0 {
            for j in 1..=8 - bit_off {
                self.addrs[self.masklen as usize / 8] &= 0xff << j;
            }
        }
    }

    pub fn is_bit_set(&self, n: u32) -> bool {
        let max = if self.family == 2 { 32u32 } else { 128u32 };
        if n == 0 || n > max {
            return false;
        }
        let idx = ((n - 1) / 8) as usize;
        let bit = (n - 1) % 8;
        (self.addrs[idx] & (0x80 >> bit)) != 0
    }

    fn set_bit(&mut self, n: u32) {
        let max = if self.family == 2 { 32u32 } else { 128u32 };
        if n == 0 || n > max {
            return;
        }
        let idx = ((n - 1) / 8) as usize;
        let bit = (n - 1) % 8;
        self.addrs[idx] |= 0x80 >> bit;
    }

    pub fn format_str(&self) -> String {
        let addr_str = self.format_addr();
        format!("{addr_str}/{}", self.masklen)
    }

    pub fn format_sep(&self, sep: &str) -> String {
        let addr_str = self.format_addr();
        format!("{addr_str}{sep}{}", self.masklen)
    }

    pub fn format_json(&self) -> String {
        let addr_str = self.format_addr();
        format!("{addr_str}\\/{}", self.masklen)
    }

    pub fn format_addr(&self) -> String {
        if self.family == 2 {
            let ip = Ipv4Addr::new(self.addrs[0], self.addrs[1], self.addrs[2], self.addrs[3]);
            ip.to_string()
        } else {
            let mut bytes = [0u8; 16];
            bytes.copy_from_slice(&self.addrs);
            let ip = Ipv6Addr::from(bytes);
            ip.to_string()
        }
    }

    pub fn compute_mask(&self) -> SxPrefix {
        let mut q = SxPrefix::new();
        q.family = self.family;
        q.masklen = self.masklen;
        for i in 0..(self.masklen / 8) as usize {
            q.addrs[i] = 0xff;
        }
        for i in 1..=(self.masklen % 8) {
            q.addrs[self.masklen as usize / 8] |= 1 << (8 - i);
        }
        q
    }

    pub fn compute_imask(&self) -> SxPrefix {
        let mut q = SxPrefix::new();
        q.family = self.family;
        q.masklen = self.masklen;
        for i in 0..ADDR_BYTES {
            q.addrs[i] = 0xff;
        }
        for i in 0..(self.masklen / 8) as usize {
            q.addrs[i] = 0;
        }
        for i in 1..=(self.masklen % 8) {
            q.addrs[self.masklen as usize / 8] &= !(1 << (8 - i));
        }
        q
    }
}

impl fmt::Display for SxPrefix {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.format_str())
    }
}

pub struct RadixNode {
    pub prefix: SxPrefix,
    pub parent: Option<usize>,
    pub left: Option<usize>,
    pub right: Option<usize>,
    pub son: Option<usize>,
    pub is_glue: bool,
    pub is_aggregate: bool,
    pub aggregate_low: u32,
    pub aggregate_hi: u32,
}

impl RadixNode {
    fn new(prefix: &SxPrefix) -> Self {
        RadixNode {
            prefix: prefix.clone(),
            parent: None,
            left: None,
            right: None,
            son: None,
            is_glue: false,
            is_aggregate: false,
            aggregate_low: 0,
            aggregate_hi: 0,
        }
    }
}

pub struct RadixTree {
    pub family: u8,
    pub head: Option<usize>,
    nodes: Vec<RadixNode>,
}

impl RadixTree {
    pub fn new(family: u8) -> Self {
        RadixTree {
            family,
            head: None,
            nodes: Vec::new(),
        }
    }

    fn alloc_node(&mut self, prefix: &SxPrefix) -> usize {
        let idx = self.nodes.len();
        self.nodes.push(RadixNode::new(prefix));
        idx
    }

    pub fn is_empty(&self) -> bool {
        self.head.is_none()
    }

    pub fn foreach<F: FnMut(&RadixNode)>(&self, mut func: F) {
        if let Some(h) = self.head {
            self.foreach_inner(h, &mut func);
        }
    }

    fn foreach_inner<F: FnMut(&RadixNode)>(&self, idx: usize, func: &mut F) {
        func(&self.nodes[idx]);
        if let Some(l) = self.nodes[idx].left {
            self.foreach_inner(l, func);
        }
        if let Some(r) = self.nodes[idx].right {
            self.foreach_inner(r, func);
        }
    }

    pub fn insert(&mut self, prefix: &SxPrefix) -> Option<usize> {
        if prefix.family != self.family {
            return None;
        }
        if self.head.is_none() {
            let idx = self.alloc_node(prefix);
            self.head = Some(idx);
            return Some(idx);
        }

        let new_idx = self.alloc_node(prefix);
        let mut chead = self.head.unwrap();
        loop {
            let eb = eq_bits(prefix, &self.nodes[chead].prefix);
            let head_ml = self.nodes[chead].prefix.masklen;
            let new_ml = prefix.masklen;

            if eb < new_ml && eb < head_ml {
                let mut neo = prefix.clone();
                neo.masklen = eb;
                neo.adjust_masklen();
                let glue = self.alloc_node(&neo);
                self.nodes[glue].is_glue = true;

                if prefix.is_bit_set(eb + 1) {
                    self.nodes[glue].left = Some(chead);
                    self.nodes[glue].right = Some(new_idx);
                } else {
                    self.nodes[glue].left = Some(new_idx);
                    self.nodes[glue].right = Some(chead);
                }

                let orig_parent = self.nodes[chead].parent;
                self.nodes[glue].parent = orig_parent;
                self.nodes[chead].parent = Some(glue);
                self.nodes[new_idx].parent = Some(glue);

                if let Some(p) = orig_parent {
                    if self.nodes[p].left == Some(chead) {
                        self.nodes[p].left = Some(glue);
                    } else if self.nodes[p].right == Some(chead) {
                        self.nodes[p].right = Some(glue);
                    }
                } else {
                    self.head = Some(glue);
                }
                return Some(new_idx);
            } else if eb == new_ml && eb < head_ml {
                if self.nodes[chead].prefix.is_bit_set(eb + 1) {
                    self.nodes[new_idx].right = Some(chead);
                } else {
                    self.nodes[new_idx].left = Some(chead);
                }
                let orig_parent = self.nodes[chead].parent;
                self.nodes[new_idx].parent = orig_parent;
                self.nodes[chead].parent = Some(new_idx);

                if let Some(p) = orig_parent {
                    if self.nodes[p].left == Some(chead) {
                        self.nodes[p].left = Some(new_idx);
                    } else if self.nodes[p].right == Some(chead) {
                        self.nodes[p].right = Some(new_idx);
                    }
                } else {
                    self.head = Some(new_idx);
                }
                return Some(new_idx);
            } else if eb == head_ml && eb < new_ml {
                if prefix.is_bit_set(eb + 1) {
                    if self.nodes[chead].right.is_some() {
                        chead = self.nodes[chead].right.unwrap();
                        continue;
                    } else {
                        let child = self.alloc_node(prefix);
                        self.nodes[chead].right = Some(child);
                        self.nodes[child].parent = Some(chead);
                        return Some(child);
                    }
                } else {
                    if self.nodes[chead].left.is_some() {
                        chead = self.nodes[chead].left.unwrap();
                        continue;
                    } else {
                        let child = self.alloc_node(prefix);
                        self.nodes[chead].left = Some(child);
                        self.nodes[child].parent = Some(chead);
                        return Some(child);
                    }
                }
            } else if eb == head_ml && eb == new_ml {
                if self.nodes[chead].is_glue {
                    self.nodes[chead].is_glue = false;
                }
                return Some(chead);
            } else {
                report::fatal(&format!(
                    "Unreachable point... eb={eb}, prefix={}, chead={}",
                    prefix, self.nodes[chead].prefix
                ));
            }
        }
    }

    pub fn aggregate(&mut self) {
        if let Some(h) = self.head {
            self.aggregate_node(h);
        }
    }

    fn aggregate_node(&mut self, idx: usize) {
        let left = self.nodes[idx].left;
        let right = self.nodes[idx].right;
        if let Some(l) = left {
            self.aggregate_node(l);
        }
        if let Some(r) = right {
            self.aggregate_node(r);
        }

        let node_ml = self.nodes[idx].prefix.masklen;
        let node_is_glue = self.nodes[idx].is_glue;

        if let (Some(l), Some(r)) = (left, right) {
            let l_glue = self.nodes[l].is_glue;
            let r_glue = self.nodes[r].is_glue;
            let l_agg = self.nodes[l].is_aggregate;
            let r_agg = self.nodes[r].is_aggregate;
            let l_ml = self.nodes[l].prefix.masklen;
            let r_ml = self.nodes[r].prefix.masklen;
            let l_hi = self.nodes[l].aggregate_hi;
            let l_lo = self.nodes[l].aggregate_low;
            let r_hi = self.nodes[r].aggregate_hi;
            let r_lo = self.nodes[r].aggregate_low;

            if !r_agg && !l_agg && !r_glue && !l_glue && r_ml == l_ml {
                if r_ml == node_ml + 1 {
                    self.nodes[idx].is_aggregate = true;
                    self.nodes[r].is_glue = true;
                    self.nodes[l].is_glue = true;
                    self.nodes[idx].aggregate_hi = r_ml;
                    if node_is_glue {
                        self.nodes[idx].is_glue = false;
                        self.nodes[idx].aggregate_low = r_ml;
                    } else {
                        self.nodes[idx].aggregate_low = node_ml;
                    }
                }
                let l_son = self.nodes[l].son;
                let r_son = self.nodes[r].son;
                if let (Some(ls), Some(rs)) = (l_son, r_son) {
                    if self.nodes[ls].is_aggregate
                        && self.nodes[rs].is_aggregate
                        && self.nodes[ls].aggregate_hi == self.nodes[rs].aggregate_hi
                        && self.nodes[ls].aggregate_low == self.nodes[rs].aggregate_low
                        && r_ml == node_ml + 1
                        && l_ml == node_ml + 1
                    {
                        let prefix = self.nodes[idx].prefix.clone();
                        let son = self.alloc_node(&prefix);
                        self.nodes[son].is_glue = false;
                        self.nodes[son].is_aggregate = true;
                        self.nodes[son].aggregate_hi = self.nodes[rs].aggregate_hi;
                        self.nodes[son].aggregate_low = self.nodes[rs].aggregate_low;
                        self.nodes[r].son = Some(son);
                        self.nodes[l].son = Some(son);
                        self.nodes[r].is_glue = true;
                        self.nodes[l].is_glue = true;
                    }
                }
            } else if r_agg && l_agg && r_hi == l_hi && r_lo == l_lo {
                if r_ml == node_ml + 1 && l_ml == node_ml + 1 {
                    if node_is_glue {
                        self.nodes[r].is_glue = true;
                        self.nodes[l].is_glue = true;
                        self.nodes[idx].is_aggregate = true;
                        self.nodes[idx].is_glue = false;
                        self.nodes[idx].aggregate_hi = r_hi;
                        self.nodes[idx].aggregate_low = r_lo;
                    } else if r_ml == r_lo {
                        self.nodes[r].is_glue = true;
                        self.nodes[l].is_glue = true;
                        self.nodes[idx].is_aggregate = true;
                        self.nodes[idx].aggregate_hi = r_hi;
                        self.nodes[idx].aggregate_low = node_ml;
                    } else {
                        let prefix = self.nodes[idx].prefix.clone();
                        let son = self.alloc_node(&prefix);
                        self.nodes[son].is_glue = false;
                        self.nodes[son].is_aggregate = true;
                        self.nodes[son].aggregate_hi = r_hi;
                        self.nodes[son].aggregate_low = r_lo;
                        self.nodes[idx].son = Some(son);
                        self.nodes[r].is_glue = true;
                        self.nodes[l].is_glue = true;
                    }
                }
            }
        }
    }

    pub fn refine(&mut self, refine: u32) {
        if let Some(h) = self.head {
            self.refine_node(h, refine);
        }
    }

    fn refine_node(&mut self, idx: usize, refine: u32) {
        let ml = self.nodes[idx].prefix.masklen;
        let is_glue = self.nodes[idx].is_glue;

        if !is_glue && ml < refine {
            self.nodes[idx].is_aggregate = true;
            self.nodes[idx].aggregate_low = ml;
            self.nodes[idx].aggregate_hi = refine;
            if let Some(l) = self.nodes[idx].left {
                self.set_glue_up_to(l, refine);
                self.refine_node(l, refine);
            }
            if let Some(r) = self.nodes[idx].right {
                self.set_glue_up_to(r, refine);
                self.refine_node(r, refine);
            }
        } else if !is_glue && ml == refine {
            if let Some(l) = self.nodes[idx].left {
                self.refine_node(l, refine);
            }
            if let Some(r) = self.nodes[idx].right {
                self.refine_node(r, refine);
            }
        } else if is_glue {
            if let Some(r) = self.nodes[idx].right {
                self.refine_node(r, refine);
            }
            if let Some(l) = self.nodes[idx].left {
                self.refine_node(l, refine);
            }
        }
    }

    fn set_glue_up_to(&mut self, idx: usize, refine: u32) {
        if self.nodes[idx].prefix.masklen <= refine {
            self.nodes[idx].is_glue = true;
        }
    }

    pub fn refine_low(&mut self, refine_low: u32) {
        if let Some(h) = self.head {
            self.refine_low_node(h, refine_low);
        }
    }

    fn refine_low_node(&mut self, idx: usize, refine_low: u32) {
        let ml = self.nodes[idx].prefix.masklen;
        let is_glue = self.nodes[idx].is_glue;

        if !is_glue && ml <= refine_low {
            if !self.nodes[idx].is_aggregate {
                self.nodes[idx].is_aggregate = true;
                self.nodes[idx].aggregate_low = refine_low;
                self.nodes[idx].aggregate_hi = if self.nodes[idx].prefix.family == 2 {
                    32
                } else {
                    128
                };
            } else {
                self.nodes[idx].aggregate_low = refine_low;
            }
            if let Some(l) = self.nodes[idx].left {
                self.set_glue_from(l, refine_low);
                self.refine_low_node(l, refine_low);
            }
            if let Some(r) = self.nodes[idx].right {
                self.set_glue_from(r, refine_low);
                self.refine_low_node(r, refine_low);
            }
        } else if !is_glue && ml == refine_low {
            if let Some(l) = self.nodes[idx].left {
                self.refine_low_node(l, refine_low);
            }
            if let Some(r) = self.nodes[idx].right {
                self.refine_low_node(r, refine_low);
            }
        } else if is_glue {
            if let Some(r) = self.nodes[idx].right {
                self.refine_low_node(r, refine_low);
            }
            if let Some(l) = self.nodes[idx].left {
                self.refine_low_node(l, refine_low);
            }
        }
    }

    fn set_glue_from(&mut self, idx: usize, refine_low: u32) {
        if self.nodes[idx].prefix.masklen <= refine_low {
            self.nodes[idx].is_glue = true;
        }
    }

    pub fn insert_specifics(&mut self, mut p: SxPrefix, min: u32, max: u32) {
        if p.masklen >= min {
            self.insert(&p);
        }
        if p.masklen + 1 > max {
            return;
        }
        p.masklen += 1;
        self.insert_specifics(p.clone(), min, max);
        p.set_bit(p.masklen);
        self.insert_specifics(p, min, max);
    }

    pub fn insert_prefix(&mut self, prefix: &SxPrefix, maxlen: u32) -> bool {
        if prefix.family != self.family {
            return false;
        }
        if maxlen > 0 && prefix.masklen > maxlen {
            return false;
        }
        self.insert(prefix);
        true
    }

    pub fn parse_range(&mut self, af: u8, maxlen: u32, text: &str) -> bool {
        let d_pos = match text.find('^') {
            Some(p) => p,
            None => return false,
        };

        let mut p = SxPrefix::new();
        let prefix_part = &text[..d_pos];
        if !p.parse(af, prefix_part) {
            report::error(&format!("Unable to parse prefix {text}"));
            return false;
        }

        if af != 0 && p.family != af {
            return false;
        }
        if maxlen > 0 && p.masklen > maxlen {
            return false;
        }

        let range_part = &text[d_pos + 1..];
        if range_part.is_empty() {
            return false;
        }

        let (min, max) = if range_part.starts_with('-') {
            (
                p.masklen + 1,
                if maxlen > 0 {
                    maxlen
                } else {
                    if af == 2 {
                        32
                    } else {
                        128
                    }
                },
            )
        } else if range_part.starts_with('+') {
            (
                p.masklen,
                if maxlen > 0 {
                    maxlen
                } else {
                    if af == 2 {
                        32
                    } else {
                        128
                    }
                },
            )
        } else if range_part.as_bytes()[0].is_ascii_digit() {
            let mut _end = range_part.len();
            let mut min_val: u32 = 0;
            let mut max_val: u32 = 0;
            let mut found_dash = false;

            for (i, c) in range_part.char_indices() {
                if c == '-' {
                    min_val = range_part[..i].parse().unwrap_or(0);
                    found_dash = true;
                    if i + 1 < range_part.len() {
                        max_val = range_part[i + 1..].parse().unwrap_or(0);
                    }
                    _end = i;
                    break;
                } else if !c.is_ascii_digit() {
                    report::error(&format!("Unable to parse prefix-range {text}"));
                    return false;
                }
            }
            if !found_dash {
                min_val = range_part.parse().unwrap_or(0);
                max_val = if maxlen > 0 {
                    maxlen
                } else {
                    if af == 2 {
                        32
                    } else {
                        128
                    }
                };
            }
            (min_val, max_val)
        } else {
            report::error(&format!("Invalid prefix-range {text}"));
            return false;
        };

        if min < p.masklen {
            report::error(&format!(
                "Invalid prefix-range {text}: min {min} < masklen {}",
                p.masklen
            ));
            return false;
        }
        let abs_max = if af == 2 || p.family == 2 {
            32u32
        } else {
            128u32
        };
        if max > abs_max {
            report::error(&format!(
                "Invalid prefix-range {text}: max {max} > {abs_max}"
            ));
            return false;
        }
        let eff_max = if max > maxlen && maxlen > 0 {
            maxlen
        } else {
            max
        };

        self.insert_specifics(p, min, eff_max);
        true
    }

    pub fn format_prefix_fmt(
        &self,
        prefix: &SxPrefix,
        name: &str,
        fmt: &str,
        agg_low: u32,
        agg_hi: u32,
    ) -> String {
        let mut out = String::new();
        let mut i = 0;
        let bytes = fmt.as_bytes();
        while i < bytes.len() {
            if bytes[i] == b'%' && i + 1 < bytes.len() {
                match bytes[i + 1] {
                    b'r' | b'n' => out.push_str(&prefix.format_addr()),
                    b'l' => out.push_str(&prefix.masklen.to_string()),
                    b'a' => out.push_str(&agg_low.to_string()),
                    b'A' => out.push_str(&agg_hi.to_string()),
                    b'%' => out.push('%'),
                    b'N' => out.push_str(name),
                    b'm' => out.push_str(&prefix.compute_mask().format_addr()),
                    b'i' => out.push_str(&prefix.compute_imask().format_addr()),
                    _ => {
                        report::error(&format!("Unknown format char '{}'", bytes[i + 1] as char));
                        return out;
                    }
                }
                i += 2;
            } else if bytes[i] == b'\\' && i + 1 < bytes.len() {
                match bytes[i + 1] {
                    b'n' => out.push('\n'),
                    b't' => out.push('\t'),
                    b'\\' => out.push('\\'),
                    c => out.push(c as char),
                }
                i += 2;
            } else {
                out.push(bytes[i] as char);
                i += 1;
            }
        }
        out
    }
}

fn eq_bits(a: &SxPrefix, b: &SxPrefix) -> u32 {
    let nbytes = if a.family == 2 { 4 } else { 16 };
    for i in 0..nbytes {
        if a.addrs[i] == b.addrs[i] {
            continue;
        }
        let pos_base = i as u32 * 8;
        for j in 0..8u32 {
            let pos = pos_base + j;
            if pos > a.masklen || pos > b.masklen {
                break;
            }
            if (a.addrs[i] & (0x80 >> j)) != (b.addrs[i] & (0x80 >> j)) {
                return pos;
            }
        }
        break;
    }
    a.masklen.min(b.masklen)
}
