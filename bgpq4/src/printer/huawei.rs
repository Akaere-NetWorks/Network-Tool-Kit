use crate::expander::Expander;
use super::common;

pub fn print_prefixlist(out: &mut String, exp: &Expander) {
    let name = exp.config.effective_name();
    let ip_str = common::format_ip_family(exp.config.family);
    out.push_str(&format!("undo ip {ip_str}-prefix {name}\n"));

    if exp.tree.is_empty() {
        let default = if exp.config.family == 2 { "0.0.0.0/0" } else { "::/0" };
        let seq_str = if exp.config.sequence > 0 { " seq 1" } else { "" };
        out.push_str(&format!(
            "ip {ip_str}-prefix {name}{seq_str} deny {default}\n"
        ));
    } else {
        exp.tree.foreach(|node| {
            if node.is_glue {
                return;
            }
            let prefix_sep = node.prefix.format_sep(" ");
            if node.is_aggregate {
                if node.aggregate_low > node.prefix.masklen {
                    out.push_str(&format!(
                        "ip {ip_str}-prefix {name} permit {prefix_sep} greater-equal {} less-equal {}\n",
                        node.aggregate_low, node.aggregate_hi
                    ));
                } else {
                    out.push_str(&format!(
                        "ip {ip_str}-prefix {name} permit {prefix_sep} less-equal {}\n",
                        node.aggregate_hi
                    ));
                }
            } else {
                out.push_str(&format!(
                    "ip {ip_str}-prefix {name} permit {prefix_sep}\n"
                ));
            }
        });
    }
}

pub fn print_xpl_prefixlist(out: &mut String, exp: &Expander) {
    let name = exp.config.effective_name();
    let ip_str = common::format_ip_family(exp.config.family);
    out.push_str(&format!(
        "no xpl {ip_str}-prefix-list {name}\nxpl {ip_str}-prefix-list {name}\n"
    ));

    let mut needs_comma = false;
    exp.tree.foreach(|node| {
        if node.is_glue {
            return;
        }
        let prefix_sep = node.prefix.format_sep(" ");
        let sep = if needs_comma { ",\n  " } else { "  " };

        if node.is_aggregate {
            if node.aggregate_low > node.prefix.masklen {
                out.push_str(&format!(
                    "{sep}{prefix_sep} ge {} le {}",
                    node.aggregate_low, node.aggregate_hi
                ));
            } else {
                out.push_str(&format!(
                    "{sep}{prefix_sep} le {}",
                    node.aggregate_hi
                ));
            }
        } else {
            out.push_str(&format!("{sep}{prefix_sep}"));
        }
        needs_comma = true;
    });

    out.push_str("\nend-list\n");
}
