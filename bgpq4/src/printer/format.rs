use crate::expander::Expander;

pub fn print_prefixlist(out: &mut String, exp: &Expander) {
    let name = exp.config.effective_name();
    let fmt = match &exp.config.format {
        Some(f) => f.clone(),
        None => return,
    };

    exp.tree.foreach(|node| {
        if node.is_glue {
            return;
        }
        let agg_low = if node.is_aggregate && node.aggregate_low > node.prefix.masklen {
            node.aggregate_low
        } else {
            node.prefix.masklen
        };
        let agg_hi = if node.is_aggregate {
            node.aggregate_hi
        } else {
            node.prefix.masklen
        };

        let s = exp
            .tree
            .format_prefix_fmt(&node.prefix, name, &fmt, agg_low, agg_hi);
        out.push_str(&s);
    });

    let bytes = fmt.as_bytes();
    let len = bytes.len();
    if len < 2 || !(bytes[len - 2] == b'\\' && bytes[len - 1] == b'n') {
        out.push('\n');
    }
}
