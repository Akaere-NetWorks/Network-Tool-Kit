use crate::config::Vendor;
use crate::expander::Expander;

pub fn print_prefixlist(out: &mut String, exp: &Expander) {
    let name = exp.config.effective_name();

    if exp.tree.is_empty() {
        out.push_str(&format!("# generated prefix-list {name} is empty\n"));
        return;
    }

    exp.tree.foreach(|node| {
        if node.is_glue {
            return;
        }
        let prefix_sep = node.prefix.format_sep("/");
        let v = if node.prefix.family == 2 { "V4" } else { "V6" };

        if node.is_aggregate {
            if exp.config.vendor == Vendor::Mikrotik7 {
                out.push_str(&format!(
                    "/routing filter rule add chain=\"{name}-{v}\" rule=\"if (dst in {prefix_sep} && dst-len in {}-{}) {{accept}}\"\n",
                    node.aggregate_low, node.aggregate_hi
                ));
            } else {
                out.push_str(&format!(
                    "/routing filter add action=accept chain=\"{name}-{v}\" prefix={prefix_sep} prefix-length={}-{}\n",
                    node.aggregate_low, node.aggregate_hi
                ));
            }
        } else {
            if exp.config.vendor == Vendor::Mikrotik7 {
                out.push_str(&format!(
                    "/routing filter rule add chain=\"{name}-{v}\" rule=\"if (dst=={prefix_sep}) {{accept}}\"\n"
                ));
            } else {
                out.push_str(&format!(
                    "/routing filter add action=accept chain=\"{name}-{v}\" prefix={prefix_sep}\n"
                ));
            }
        }
    });
}
