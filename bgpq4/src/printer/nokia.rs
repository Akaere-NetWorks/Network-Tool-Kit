use crate::expander::Expander;

pub fn print_prefixlist(out: &mut String, exp: &Expander) {
    let name = exp.config.effective_name();
    out.push_str(&format!(
        "configure router policy-options\nbegin\nno prefix-list \"{name}\"\n"
    ));
    out.push_str(&format!("prefix-list \"{name}\"\n"));

    exp.tree.foreach(|node| {
        if node.is_glue {
            return;
        }
        let prefix = node.prefix.format_str();
        if !node.is_aggregate {
            out.push_str(&format!("    prefix {prefix} exact\n"));
        } else if node.aggregate_low > node.prefix.masklen {
            out.push_str(&format!(
                "    prefix {prefix} prefix-length-range {}-{}\n",
                node.aggregate_low, node.aggregate_hi
            ));
        } else {
            out.push_str(&format!(
                "    prefix {prefix} prefix-length-range {}-{}\n",
                node.prefix.masklen, node.aggregate_hi
            ));
        }
    });

    out.push_str("exit\ncommit\n");
}

pub fn print_ipprefixlist(out: &mut String, exp: &Expander) {
    let name = exp.config.effective_name();
    let ip_str = if exp.config.family == 2 { "ip" } else { "ipv6" };
    out.push_str(&format!(
        "configure filter match-list\nno {ip_str}-prefix-list \"{name}\"\n"
    ));
    out.push_str(&format!("{ip_str}-prefix-list \"{name}\" create\n"));

    if exp.tree.is_empty() {
        out.push_str(&format!("# generated ip-prefix-list {name} is empty\n"));
    } else {
        exp.tree.foreach(|node| {
            if node.is_glue {
                return;
            }
            let prefix = node.prefix.format_str();
            out.push_str(&format!("    prefix {prefix}\n"));
        });
    }

    out.push_str("exit\n");
}

pub fn print_md_prefixlist(out: &mut String, exp: &Expander) {
    let name = exp.config.effective_name();
    let ip_str = if exp.config.family == 2 { "ip" } else { "ipv6" };
    out.push_str(&format!(
        "/configure filter match-list\ndelete {ip_str}-prefix-list \"{name}\"\n"
    ));
    out.push_str(&format!("{ip_str}-prefix-list \"{name}\" {{\n"));

    if exp.tree.is_empty() {
        out.push_str(&format!(
            "# generated {ip_str}-prefix-list {name} is empty\n"
        ));
    } else {
        exp.tree.foreach(|node| {
            if node.is_glue {
                return;
            }
            let prefix = node.prefix.format_str();
            out.push_str(&format!("    prefix {prefix} {{ }}\n"));
        });
    }

    out.push_str("}\n");
}

pub fn print_md_ipprefixlist(out: &mut String, exp: &Expander) {
    let name = exp.config.effective_name();
    out.push_str(&format!(
        "/configure policy-options\ndelete prefix-list \"{name}\"\n"
    ));
    out.push_str(&format!("prefix-list \"{name}\" {{\n"));

    exp.tree.foreach(|node| {
        if node.is_glue {
            return;
        }
        let prefix = node.prefix.format_str();
        if !node.is_aggregate {
            out.push_str(&format!("    prefix {prefix} type exact {{\n    }}\n"));
        } else if node.aggregate_low > node.prefix.masklen {
            out.push_str(&format!(
                "    prefix {prefix} type range {{\n        start-length {}\n        end-length {}\n    }}\n",
                node.aggregate_low, node.aggregate_hi
            ));
        } else {
            out.push_str(&format!(
                "    prefix {prefix} type through {{\n        through-length {}\n    }}\n",
                node.aggregate_hi
            ));
        }
    });

    out.push_str("}\n");
}

pub fn print_srl_prefixset(out: &mut String, exp: &Expander) {
    let name = exp.config.effective_name();
    out.push_str(&format!("/routing-policy\ndelete prefix-set \"{name}\"\n"));
    out.push_str(&format!("prefix-set \"{name}\" {{\n"));

    exp.tree.foreach(|node| {
        if node.is_glue {
            return;
        }
        let prefix = node.prefix.format_str();
        if !node.is_aggregate {
            out.push_str(&format!(
                "    prefix {prefix} mask-length-range exact {{ }}\n"
            ));
        } else {
            let lo = node.aggregate_low.max(node.prefix.masklen);
            out.push_str(&format!(
                "    prefix {prefix} mask-length-range {}..{} {{ }}\n",
                lo, node.aggregate_hi
            ));
        }
    });

    out.push_str("}\n");
}

pub fn print_srl_aclipfilter(out: &mut String, exp: &Expander) {
    let name = exp.config.effective_name();
    let v = if exp.config.family == 2 { '4' } else { '6' };
    out.push_str(&format!("/acl \ndelete ipv{v}-filter \"{name}\"\n"));
    out.push_str(&format!("ipv{v}-filter \"{name}\" {{\n"));

    if exp.tree.is_empty() {
        out.push_str(&format!("# generated ipv{v}-filter '{name}' is empty\n"));
    } else {
        let mut seq: i32 = 10;
        exp.tree.foreach(|node| {
            if node.is_glue {
                return;
            }
            let prefix = node.prefix.format_str();
            out.push_str(&format!(
                " entry {seq} {{\n  action {{ accept {{ }} }}\n  match {{ source-ip {{ prefix {prefix} }} }} }}\n"
            ));
            seq += 10;
        });
    }

    out.push_str("}\n");
}
