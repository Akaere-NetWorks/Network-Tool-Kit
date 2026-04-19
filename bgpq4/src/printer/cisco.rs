use crate::expander::Expander;
use super::common::{self, FormatCtx};

pub fn print_prefixlist(out: &mut String, exp: &Expander) {
    let name = exp.config.effective_name();

    let ip_str = common::format_ip_family(exp.config.family);
    out.push_str(&format!("no {ip_str} prefix-list {name}\n"));

    if exp.tree.is_empty() {
        out.push_str(&format!("! generated prefix-list {name} is empty\n"));
        let seq_str = if exp.config.sequence > 0 { " seq 1" } else { "" };
        let default = if exp.config.family == 2 { "0.0.0.0/0" } else { "::/0" };
        out.push_str(&format!(
            "{ip_str} prefix-list {name}{seq_str} deny {default}\n"
        ));
    } else {
        let mut ctx = FormatCtx::new(name);
        ctx.seq = if exp.config.sequence > 0 { 1 } else { 0 };
        let seq = ctx.seq;
        exp.tree.foreach(|node| {
            if node.is_glue {
                return;
            }
            let prefix = node.prefix.format_str();
            let ip_str = common::format_ip_family(node.prefix.family);
            let seq_str = if seq > 0 {
                let s = format!(" seq {}", ctx.seq);
                ctx.seq += 1;
                s
            } else {
                String::new()
            };

            if node.is_aggregate {
                if node.aggregate_low > node.prefix.masklen {
                    out.push_str(&format!(
                        "{ip_str} prefix-list {name}{seq_str} permit {prefix} ge {} le {}\n",
                        node.aggregate_low, node.aggregate_hi
                    ));
                } else {
                    out.push_str(&format!(
                        "{ip_str} prefix-list {name}{seq_str} permit {prefix} le {}\n",
                        node.aggregate_hi
                    ));
                }
            } else {
                out.push_str(&format!(
                    "{ip_str} prefix-list {name}{seq_str} permit {prefix}\n"
                ));
            }
        });
    }
}

pub fn print_xr_prefixlist(out: &mut String, exp: &Expander) {
    let name = exp.config.effective_name();
    out.push_str(&format!("no prefix-set {name}\n"));
    out.push_str(&format!("prefix-set {name}\n"));

    let mut needs_comma = false;
    exp.tree.foreach(|node| {
        if node.is_glue {
            return;
        }
        let prefix = node.prefix.format_str();
        let sep = if needs_comma { ",\n " } else { " " };
        if node.is_aggregate {
            if node.aggregate_low > node.prefix.masklen {
                out.push_str(&format!("{sep}{prefix} ge {} le {}", node.aggregate_low, node.aggregate_hi));
            } else {
                out.push_str(&format!("{sep}{prefix} le {}", node.aggregate_hi));
            }
        } else {
            out.push_str(&format!("{sep}{prefix}"));
        }
        needs_comma = true;
    });

    out.push_str("\nend-set\n");
}

pub fn print_arista_prefixlist(out: &mut String, exp: &Expander) {
    let name = exp.config.effective_name();
    let ip_str = common::format_ip_family(exp.config.family);

    out.push_str(&format!("no {ip_str} prefix-list {name}\n"));

    if exp.tree.is_empty() {
        out.push_str(&format!("! generated prefix-list {name} is empty\n"));
        let default = if exp.config.family == 2 { "0.0.0.0/0" } else { "::/0" };
        out.push_str(&format!(
            "{ip_str} prefix-list {name}\n   seq {} deny {default}\n",
            exp.config.sequence
        ));
    } else {
        out.push_str(&format!("{ip_str} prefix-list {name}\n"));
        let mut seq: i32 = exp.config.sequence;
        exp.tree.foreach(|node| {
            if node.is_glue {
                return;
            }
            let prefix = node.prefix.format_str();
            if node.is_aggregate {
                if node.aggregate_low > node.prefix.masklen {
                    out.push_str(&format!(
                        "   seq {seq} permit {prefix} ge {} le {}\n",
                        node.aggregate_low, node.aggregate_hi
                    ));
                } else {
                    out.push_str(&format!(
                        "   seq {seq} permit {prefix} le {}\n",
                        node.aggregate_hi
                    ));
                }
            } else {
                out.push_str(&format!("   seq {seq} permit {prefix}\n"));
            }
            seq += 1;
        });
    }
}

pub fn print_eacl(out: &mut String, exp: &Expander) {
    let name = exp.config.effective_name();
    out.push_str(&format!("no ip access-list extended {name}\n"));

    if exp.tree.is_empty() {
        out.push_str(&format!("! generated access-list {name} is empty\n"));
        out.push_str(&format!("ip access-list extended {name} deny any any\n"));
    } else {
        out.push_str(&format!("ip access-list extended {name}\n"));
        exp.tree.foreach(|node| {
            if node.is_glue {
                return;
            }
            let prefix = node.prefix.format_str();
            let mut addr_str = prefix.clone();
            if let Some(slash_pos) = addr_str.find('/') {
                addr_str.truncate(slash_pos);
            }

            if !node.is_aggregate {
                use std::net::Ipv4Addr;
                let mask_val = if node.prefix.masklen == 32 {
                    Ipv4Addr::new(0, 0, 0, 0)
                } else {
                    let mut m = 0xffffffffu32;
                    m <<= 32 - node.prefix.masklen;
                    m = m.to_be();
                    Ipv4Addr::from(m)
                };
                out.push_str(&format!(
                    " permit ip host {addr_str} host {mask}\n",
                    mask = mask_val
                ));
            } else {
                let addr = node.prefix.format_addr();
                let wild_addr = 0xffffffffu32 >> node.prefix.masklen;
                let wild_addr_be = wild_addr.to_be();

                let mask_hi = 0xffffffffu32 & (0xffffffffu32 << (32 - node.aggregate_low));
                let wild_mask = (0xffffffffu32 >> node.aggregate_low)
                    & !(0xffffffffu32 >> node.aggregate_hi);

                let wild_addr_ip = std::net::Ipv4Addr::from(wild_addr_be);
                let mask_ip = std::net::Ipv4Addr::from(mask_hi.to_be());
                let wildmask_ip = std::net::Ipv4Addr::from(wild_mask.to_be());

                if wild_addr != 0 {
                    out.push_str(&format!(" permit ip {addr} {wild_addr_ip} "));
                    if wild_mask != 0 {
                        out.push_str(&format!("{mask_ip} {wildmask_ip}\n"));
                    } else {
                        out.push_str(&format!("host {mask_ip}\n"));
                    }
                } else {
                    out.push_str(&format!(" permit ip host {addr} "));
                    if wild_mask != 0 {
                        out.push_str(&format!("{mask_ip} {wildmask_ip}\n"));
                    } else {
                        out.push_str(&format!("host {mask_ip}\n"));
                    }
                }
            }
        });
    }
}
