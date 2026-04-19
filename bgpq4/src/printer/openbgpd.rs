use crate::expander::Expander;

pub fn print_prefixlist(out: &mut String, exp: &Expander) {
    if exp.tree.is_empty() {
        out.push_str(&format!(
            "# generated prefix-list {} (AS {}) is empty\n",
            exp.config.effective_name(),
            exp.config.asnumber
        ));
        if exp.config.asnumber == 0 {
            out.push_str(
                "# use -a <asn> to generate \"deny from ASN <asn>\" instead of this list\n",
            );
        }
    }

    if !exp.tree.is_empty() || exp.config.asnumber == 0 {
        let name = exp.config.effective_name();
        let use_name = name != "NN";
        if use_name {
            out.push_str(&format!("{name}=\""));
        }
        out.push_str("prefix { ");

        exp.tree.foreach(|node| {
            if node.is_glue {
                return;
            }
            let prefix = node.prefix.format_str();

            if !node.is_aggregate {
                out.push_str(&format!("\n\t{prefix}"));
            } else if node.aggregate_low == node.aggregate_hi {
                out.push_str(&format!("\n\t{prefix} prefixlen = {}", node.aggregate_hi));
            } else if node.aggregate_low > node.prefix.masklen {
                out.push_str(&format!(
                    "\n\t{prefix} prefixlen {} - {}",
                    node.aggregate_low, node.aggregate_hi
                ));
            } else {
                out.push_str(&format!(
                    "\n\t{prefix} prefixlen {} - {}",
                    node.prefix.masklen, node.aggregate_hi
                ));
            }
        });

        out.push_str("\n\t}");
        if use_name {
            out.push_str("\"");
        }
        out.push('\n');
    } else {
        out.push_str(&format!("deny from AS {}\n", exp.config.asnumber));
    }
}

pub fn print_prefixset(out: &mut String, exp: &Expander) {
    let name = exp.config.effective_name();
    out.push_str(&format!("prefix-set {name} {{"));

    exp.tree.foreach(|node| {
        if node.is_glue {
            return;
        }
        let prefix = node.prefix.format_str();

        if !node.is_aggregate {
            out.push_str(&format!("\n\t{prefix}"));
        } else if node.aggregate_low == node.aggregate_hi {
            out.push_str(&format!("\n\t{prefix} prefixlen = {}", node.aggregate_hi));
        } else if node.aggregate_low > node.prefix.masklen {
            out.push_str(&format!(
                "\n\t{prefix} prefixlen {} - {}",
                node.aggregate_low, node.aggregate_hi
            ));
        } else {
            out.push_str(&format!(
                "\n\t{prefix} prefixlen {} - {}",
                node.prefix.masklen, node.aggregate_hi
            ));
        }
    });

    out.push_str("\n}\n");
}
