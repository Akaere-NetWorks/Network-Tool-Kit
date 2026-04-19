use crate::expander::Expander;

pub fn print_prefixlist(out: &mut String, exp: &Expander) {
    let name = exp.config.effective_name();
    out.push_str(&format!("policy-options {{\nreplace:\n prefix-list {name} {{\n"));

    exp.tree.foreach(|node| {
        if node.is_glue {
            return;
        }
        let prefix = node.prefix.format_str();
        out.push_str(&format!("    {prefix};\n"));
    });

    out.push_str(" }\n}\n");
}

pub fn print_routefilter(out: &mut String, exp: &Expander) {
    let name = exp.config.effective_name().to_string();
    let mut c: Option<&str> = None;

    if let Some(slash_pos) = name.find('/') {
        c = Some(&name[slash_pos + 1..]);
        let real_name = &name[..slash_pos];
        out.push_str(&format!(
            "policy-options {{\n policy-statement {real_name} {{\n  term {} {{\nreplace:\n   from {{\n",
            &name[slash_pos + 1..]
        ));
        if let Some(ref m) = exp.config.r#match {
            out.push_str(&format!("    {m};\n"));
        }
    } else {
        out.push_str(&format!(
            "policy-options {{\n policy-statement {name} {{ \nreplace:\n  from {{\n"
        ));
        if let Some(ref m) = exp.config.r#match {
            out.push_str(&format!("    {m};\n"));
        }
    }

    let prefixed = true;
    if exp.tree.is_empty() {
        let default = if exp.config.family == 2 { "0.0.0.0" } else { "::" };
        out.push_str(&format!("    route-filter {default}/0 orlonger reject;\n"));
    } else {
        exp.tree.foreach(|node| {
            if node.is_glue {
                return;
            }
            let prefix = node.prefix.format_str();
            let pfx = if prefixed { "route-filter " } else { "" };

            if !node.is_aggregate {
                out.push_str(&format!("    {pfx}{prefix} exact;\n"));
            } else {
                if node.aggregate_low > node.prefix.masklen {
                    out.push_str(&format!(
                        "    {pfx}{prefix} prefix-length-range /{}-/{};\n",
                        node.aggregate_low, node.aggregate_hi
                    ));
                } else {
                    out.push_str(&format!("    {pfx}{prefix} upto /{};\n", node.aggregate_hi));
                }
            }
        });
    }

    if c.is_some() {
        out.push_str("   }\n  }\n }\n}\n");
    } else {
        out.push_str("  }\n }\n}\n");
    }
}

pub fn print_route_filter_list(out: &mut String, exp: &Expander) {
    let name = exp.config.effective_name();
    out.push_str(&format!("policy-options {{\nreplace:\n  route-filter-list {name} {{\n"));

    if exp.tree.is_empty() {
        let default = if exp.config.family == 2 { "0.0.0.0" } else { "::" };
        out.push_str(&format!("    {default}/0 orlonger reject;\n"));
    } else {
        exp.tree.foreach(|node| {
            if node.is_glue {
                return;
            }
            let prefix = node.prefix.format_str();

            if !node.is_aggregate {
                out.push_str(&format!("    {prefix} exact;\n"));
            } else {
                if node.aggregate_low > node.prefix.masklen {
                    out.push_str(&format!(
                        "    {prefix} prefix-length-range /{}-/{};\n",
                        node.aggregate_low, node.aggregate_hi
                    ));
                } else {
                    out.push_str(&format!("    {prefix} upto /{};\n", node.aggregate_hi));
                }
            }
        });
    }

    out.push_str("  }\n}\n");
}
