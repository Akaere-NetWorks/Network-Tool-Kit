use crate::expander::Expander;

pub fn print_prefixlist(out: &mut String, exp: &Expander) {
    let name = exp.config.effective_name();

    if exp.tree.is_empty() {
        return;
    }

    out.push_str(&format!("{name} = ["));

    let mut needs_comma = false;
    exp.tree.foreach(|node| {
        if node.is_glue {
            return;
        }
        let prefix = node.prefix.format_str();

        if !node.is_aggregate {
            out.push_str(&format!(
                "{}\n    {prefix}",
                if needs_comma { "," } else { "" }
            ));
        } else if node.aggregate_low > node.prefix.masklen {
            out.push_str(&format!(
                "{}\n    {prefix}{{{},{}}}",
                if needs_comma { "," } else { "" },
                node.aggregate_low,
                node.aggregate_hi
            ));
        } else {
            out.push_str(&format!(
                "{}\n    {prefix}{{{},{}}}",
                if needs_comma { "," } else { "" },
                node.prefix.masklen,
                node.aggregate_hi
            ));
        }
        needs_comma = true;
    });

    out.push_str("\n];\n");
}
