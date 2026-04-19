use crate::expander::Expander;

pub fn print_cisco_aspath(out: &mut String, exp: &Expander) {
    let name = exp.config.effective_name();
    out.push_str(&format!("no ip as-path access-list {name}\n"));

    if exp.asn_list.is_empty() {
        out.push_str(&format!("ip as-path access-list {name} deny .*\n"));
        return;
    }

    let mut nc = 0i32;
    let mut printed_self = false;

    for &asn in &exp.asn_list {
        if !printed_self && asn == exp.config.asnumber && exp.config.asnumber > 0 {
            out.push_str(&format!(
                "ip as-path access-list {name} permit ^{asn}(_{asn})*$\n"
            ));
            printed_self = true;
            continue;
        }

        if nc == 0 {
            out.push_str(&format!(
                "ip as-path access-list {name} permit ^{}(_[0-9]+)*_({}",
                exp.config.asnumber, asn
            ));
        } else {
            out.push_str(&format!("|{}", asn));
        }

        nc += 1;
        if nc == exp.config.aswidth {
            out.push_str(")$\n");
            nc = 0;
        }
    }

    if nc > 0 {
        out.push_str(")$\n");
    }
}

pub fn print_cisco_xr_aspath(out: &mut String, exp: &Expander) {
    let name = exp.config.effective_name();
    out.push_str(&format!("as-path-set {name}"));

    let mut nc = 0i32;
    let mut comma = false;
    let mut printed_self = false;

    for &asn in &exp.asn_list {
        if !printed_self && asn == exp.config.asnumber && exp.config.asnumber > 0 {
            out.push_str(&format!("\n  ios-regex '^{}(_{})*$'", asn, asn));
            printed_self = true;
            comma = true;
            continue;
        }

        if nc == 0 {
            out.push_str(&format!(
                "{}\n  ios-regex '^{}(_[0-9]+)*_({}",
                if comma { "," } else { "" },
                exp.config.asnumber,
                asn
            ));
            comma = true;
        } else {
            out.push_str(&format!("|{}", asn));
        }

        nc += 1;
        if nc == exp.config.aswidth {
            out.push_str(")$'");
            nc = 0;
        }
    }

    if nc > 0 {
        out.push_str(")$'");
    }

    out.push_str("\nend-set\n");
}

pub fn print_cisco_oaspath(out: &mut String, exp: &Expander) {
    let name = exp.config.effective_name();
    out.push_str(&format!("no ip as-path access-list {name}\n"));

    if exp.asn_list.is_empty() {
        out.push_str(&format!("ip as-path access-list {name} deny .*\n"));
        return;
    }

    let mut nc = 0i32;
    let mut printed_self = false;

    for &asn in &exp.asn_list {
        if !printed_self && asn == exp.config.asnumber && exp.config.asnumber > 0 {
            out.push_str(&format!(
                "ip as-path access-list {name} permit ^(_{})*$\n",
                asn
            ));
            printed_self = true;
            continue;
        }

        if nc == 0 {
            out.push_str(&format!(
                "ip as-path access-list {name} permit ^(_[0-9]+)*_({}",
                asn
            ));
        } else {
            out.push_str(&format!("|{}", asn));
        }

        nc += 1;
        if nc == exp.config.aswidth {
            out.push_str(")$\n");
            nc = 0;
        }
    }

    if nc > 0 {
        out.push_str(")$\n");
    }
}

pub fn print_cisco_xr_oaspath(out: &mut String, exp: &Expander) {
    let name = exp.config.effective_name();
    out.push_str(&format!("as-path-set {name}"));

    let mut nc = 0i32;
    let mut comma = false;
    let mut printed_self = false;

    for &asn in &exp.asn_list {
        if !printed_self && asn == exp.config.asnumber && exp.config.asnumber > 0 {
            out.push_str(&format!("\n  ios-regex '^(_{})*$'", asn));
            printed_self = true;
            comma = true;
            continue;
        }

        if nc == 0 {
            out.push_str(&format!(
                "{}\n  ios-regex '^(_[0-9]+)*_({}",
                if comma { "," } else { "" },
                asn
            ));
            comma = true;
        } else {
            out.push_str(&format!("|{}", asn));
        }

        nc += 1;
        if nc == exp.config.aswidth {
            out.push_str(")$'");
            nc = 0;
        }
    }

    if nc > 0 {
        out.push_str(")$'");
    }

    out.push_str("\nend-set\n");
}

pub fn print_juniper_aspath(out: &mut String, exp: &Expander) {
    let name = exp.config.effective_name();
    out.push_str(&format!(
        "policy-options {{\nreplace:\n as-path-group {name} {{\n"
    ));

    let mut nc = 0i32;
    let mut line_no = 0u32;
    let mut printed_self = false;

    for &asn in &exp.asn_list {
        if !printed_self && asn == exp.config.asnumber && exp.config.asnumber > 0 {
            out.push_str(&format!(
                "  as-path a{} \"^{}({})*$\";\n",
                line_no, asn, asn
            ));
            printed_self = true;
            line_no += 1;
            continue;
        }

        if nc == 0 {
            out.push_str(&format!(
                "  as-path a{} \"^{}(.)*({}",
                line_no, exp.config.asnumber, asn
            ));
        } else {
            out.push_str(&format!("|{}", asn));
        }

        nc += 1;
        if nc == exp.config.aswidth {
            out.push_str(")$\";\n");
            nc = 0;
            line_no += 1;
        }
    }

    if nc > 0 {
        out.push_str(")$\";\n");
    } else if line_no == 0 {
        out.push_str("  as-path aNone \"!.*\";\n");
    }

    out.push_str(" }\n}\n");
}

pub fn print_juniper_oaspath(out: &mut String, exp: &Expander) {
    let name = exp.config.effective_name();
    out.push_str(&format!(
        "policy-options {{\nreplace:\n as-path-group {name} {{\n"
    ));

    let mut nc = 0i32;
    let mut line_no = 0u32;
    let mut printed_self = false;

    for &asn in &exp.asn_list {
        if !printed_self && asn == exp.config.asnumber && exp.config.asnumber > 0 {
            out.push_str(&format!(
                "  as-path a{} \"^{}({})*$\";\n",
                line_no, asn, asn
            ));
            printed_self = true;
            line_no += 1;
            continue;
        }

        if nc == 0 {
            out.push_str(&format!("  as-path a{} \"^(.)*({}", line_no, asn));
        } else {
            out.push_str(&format!("|{}", asn));
        }

        nc += 1;
        if nc == exp.config.aswidth {
            out.push_str(")$\";\n");
            nc = 0;
            line_no += 1;
        }
    }

    if nc > 0 {
        out.push_str(")$\";\n");
    } else if line_no == 0 {
        out.push_str(" as-path aNone \"!.*\";\n");
    }

    out.push_str(" }\n}\n");
}

pub fn print_juniper_aslist(out: &mut String, exp: &Expander) {
    let name = exp.config.effective_name();
    out.push_str(&format!(
        "policy-options {{\nreplace:\n as-list-group {name} {{\n"
    ));

    let mut nc = 0i32;
    let mut line_no = 0u32;
    let mut printed_self = false;

    for &asn in &exp.asn_list {
        if !printed_self && asn == exp.config.asnumber && exp.config.asnumber > 0 {
            out.push_str(&format!("  as-list a{line_no} members {asn};\n"));
            printed_self = true;
            line_no += 1;
            continue;
        }

        if nc == 0 {
            out.push_str(&format!("  as-list a{line_no} members ["));
        }

        if asn != 0 {
            out.push_str(&format!(" {asn}"));
        }

        nc += 1;
        if nc == exp.config.aswidth {
            out.push_str(" ];\n");
            nc = 0;
            line_no += 1;
        }
    }

    if nc > 0 {
        out.push_str(" ];\n");
    }

    out.push_str(" }\n}\n");
}

pub fn print_bird_aspath(out: &mut String, exp: &Expander) {
    let name = exp.config.effective_name();
    out.push_str(&format!("{name} = ["));

    if exp.asn_list.is_empty() {
        out.push_str("];\n");
        return;
    }

    let mut nc = 0i32;
    let mut needs_comma = false;

    for &asn in &exp.asn_list {
        if nc == 0 {
            out.push_str(&format!(
                "{}\n    {}",
                if needs_comma { "," } else { "" },
                asn
            ));
            needs_comma = true;
        } else {
            out.push_str(&format!(", {}", asn));
            needs_comma = true;
        }

        nc += 1;
        if nc == exp.config.aswidth {
            nc = 0;
        }
    }

    out.push_str("\n];\n");
}

pub fn print_json_aspath(out: &mut String, exp: &Expander) {
    let name = exp.config.effective_name();
    out.push_str(&format!("{{\"{name}\": ["));

    let mut nc = 0i32;
    let mut needs_comma = false;

    for &asn in &exp.asn_list {
        if nc == 0 {
            out.push_str(&format!(
                "{}\n  {}",
                if needs_comma { "," } else { "" },
                asn
            ));
            needs_comma = true;
        } else {
            out.push_str(&format!("{}{}", if needs_comma { "," } else { "" }, asn));
            needs_comma = true;
        }

        nc += 1;
        if nc == exp.config.aswidth {
            nc = 0;
        }
    }

    out.push_str("\n]}\n");
}

pub fn print_openbgpd_aspath(out: &mut String, exp: &Expander) {
    if exp.asn_list.is_empty() {
        out.push_str(&format!("deny from AS {}\n", exp.config.asnumber));
        return;
    }

    for &asn in &exp.asn_list {
        out.push_str(&format!(
            "allow from AS {} AS {}\n",
            exp.config.asnumber, asn
        ));
    }
}

pub fn print_openbgpd_oaspath(out: &mut String, exp: &Expander) {
    if exp.asn_list.is_empty() {
        out.push_str(&format!("deny to AS {}\n", exp.config.asnumber));
        return;
    }

    for &asn in &exp.asn_list {
        out.push_str(&format!("allow to AS {} AS {}\n", exp.config.asnumber, asn));
    }
}

pub fn print_openbgpd_asset(out: &mut String, exp: &Expander) {
    let name = exp.config.effective_name();
    out.push_str(&format!("as-set {name} {{"));

    let mut nc = 0i32;
    for &asn in &exp.asn_list {
        if nc == 0 {
            out.push_str(&format!("\n\t{asn}"));
        } else {
            out.push_str(&format!(" {asn}"));
        }
        nc += 1;
        if nc == exp.config.aswidth {
            nc = 0;
        }
    }

    out.push_str("\n}\n");
}

pub fn print_nokia_aspath(out: &mut String, exp: &Expander) {
    let name = exp.config.effective_name();
    out.push_str(&format!(
        "configure router policy-options\nbegin\nno as-path-group \"{name}\"\n"
    ));
    out.push_str(&format!("as-path-group \"{name}\"\n"));

    let mut nc = 0i32;
    let mut line_no = 1u32;
    let mut printed_self = false;

    for &asn in &exp.asn_list {
        if !printed_self && asn == exp.config.asnumber && exp.config.asnumber > 0 {
            out.push_str(&format!("  entry {} expression \"{}+\"\n", line_no, asn));
            printed_self = true;
            line_no += 1;
            continue;
        }

        if nc == 0 {
            out.push_str(&format!(
                "  entry {} expression \"{}.*[{}",
                line_no, exp.config.asnumber, asn
            ));
        } else {
            out.push_str(&format!(" {}", asn));
        }

        nc += 1;
        if nc == exp.config.aswidth {
            out.push_str("]\"\n");
            nc = 0;
            line_no += 1;
        }
    }

    if nc > 0 {
        out.push_str("]\"\n");
    }

    out.push_str("exit\ncommit\n");
}

pub fn print_nokia_oaspath(out: &mut String, exp: &Expander) {
    let name = exp.config.effective_name();
    out.push_str(&format!(
        "configure router policy-options\nbegin\nno as-path-group\"{name}\"\n"
    ));
    out.push_str(&format!("as-path-group \"{name}\"\n"));

    let mut nc = 0i32;
    let mut line_no = 1u32;
    let mut printed_self = false;

    for &asn in &exp.asn_list {
        if !printed_self && asn == exp.config.asnumber && exp.config.asnumber > 0 {
            out.push_str(&format!(
                "  entry {} expression \"{}+\"\n",
                line_no, exp.config.asnumber
            ));
            printed_self = true;
            line_no += 1;
            continue;
        }

        if nc == 0 {
            out.push_str(&format!("  entry {} expression \".*[{}", line_no, asn));
        } else {
            out.push_str(&format!(" {}", asn));
        }

        nc += 1;
        if nc == exp.config.aswidth {
            out.push_str("]\"\n");
            nc = 0;
            line_no += 1;
        }
    }

    if nc > 0 {
        out.push_str("]\"\n");
    }

    out.push_str("exit\ncommit\n");
}

pub fn print_nokia_md_aspath(out: &mut String, exp: &Expander) {
    let name = exp.config.effective_name();
    out.push_str(&format!(
        "/configure policy-options\ndelete as-path-group \"{name}\"\n"
    ));
    out.push_str(&format!("as-path-group \"{name}\" {{\n"));

    let mut nc = 0i32;
    let mut line_no = 1u32;
    let mut printed_self = false;

    for &asn in &exp.asn_list {
        if !printed_self && asn == exp.config.asnumber && exp.config.asnumber > 0 {
            out.push_str(&format!(
                "  entry {} {{\n    expression \"{}+\"\n  }}\n",
                line_no, asn
            ));
            printed_self = true;
            line_no += 1;
            continue;
        }

        if nc == 0 {
            out.push_str(&format!(
                "  entry {} {{\n    expression \"{}.*[{}\"",
                line_no, exp.config.asnumber, asn
            ));
        } else {
            out.push_str(&format!(" {}", asn));
        }

        nc += 1;
        if nc == exp.config.aswidth {
            out.push_str("]\"\n  }}\n");
            nc = 0;
            line_no += 1;
        }
    }

    if nc > 0 {
        out.push_str("]\"\n  }}\n");
    }

    out.push_str("}\n");
}

pub fn print_nokia_md_oaspath(out: &mut String, exp: &Expander) {
    let name = exp.config.effective_name();
    out.push_str(&format!(
        "/configure policy-options\ndelete as-path-group \"{name}\"\n"
    ));
    out.push_str(&format!("as-path-group \"{name}\" {{\n"));

    let mut nc = 0i32;
    let mut line_no = 1u32;
    let mut printed_self = false;

    for &asn in &exp.asn_list {
        if !printed_self && asn == exp.config.asnumber && exp.config.asnumber > 0 {
            out.push_str(&format!(
                "  entry {} {{\n    expression \"{}+\"\n  }}\n",
                line_no, asn
            ));
            printed_self = true;
            line_no += 1;
            continue;
        }

        if nc == 0 {
            out.push_str(&format!(
                "  entry {} {{\n    expression \".*[{}",
                line_no, asn
            ));
        } else {
            out.push_str(&format!(" {}", asn));
        }

        nc += 1;
        if nc == exp.config.aswidth {
            out.push_str("]\"\n  }}\n");
            nc = 0;
            line_no += 1;
        }
    }

    if nc > 0 {
        out.push_str("]\"\n  }}\n");
    }

    out.push_str("}\n");
}

pub fn print_huawei_aspath(out: &mut String, exp: &Expander) {
    let name = exp.config.effective_name();
    out.push_str(&format!("undo ip as-path-filter {name}\n"));

    if exp.asn_list.is_empty() {
        out.push_str(&format!("ip as-path-filter {name} deny .*\n"));
        return;
    }

    let mut nc = 0i32;
    let mut printed_self = false;

    for &asn in &exp.asn_list {
        if !printed_self && asn == exp.config.asnumber && exp.config.asnumber > 0 {
            out.push_str(&format!(
                "ip as-path-filter {name} permit ^{asn}(_{asn})*$\n"
            ));
            printed_self = true;
            continue;
        }

        if nc == 0 {
            out.push_str(&format!(
                "ip as-path-filter {name} permit ^{asn}(_[0-9]+)*_({}",
                exp.config.asnumber
            ));
        } else {
            out.push_str(&format!("|{}", asn));
        }

        nc += 1;
        if nc == exp.config.aswidth {
            out.push_str(")$\n");
            nc = 0;
        }
    }

    if nc > 0 {
        out.push_str(")$\n");
    }
}

pub fn print_huawei_xpl_aspath(out: &mut String, exp: &Expander) {
    let name = exp.config.effective_name();
    out.push_str(&format!("xpl as-path-list {name}"));

    let mut nc = 0i32;
    let mut comma = true;
    let mut printed_self = false;

    for &asn in &exp.asn_list {
        if !printed_self && asn == exp.config.asnumber && exp.config.asnumber > 0 {
            out.push_str(&format!("\n  regular ^{asn}(_{asn})*$"));
            printed_self = true;
            continue;
        }

        if nc == 0 {
            out.push_str(&format!(
                "{}\n  regular ^{asn}(_[0-9]+)*_({}",
                if comma { "," } else { "" },
                exp.config.asnumber
            ));
            comma = true;
        } else {
            out.push_str(&format!("|{}", asn));
        }

        nc += 1;
        if nc == exp.config.aswidth {
            out.push_str(")$");
            nc = 0;
        }
    }

    if nc > 0 {
        out.push_str(")$");
    }

    out.push_str("\nend-list\n");
}

pub fn print_huawei_oaspath(out: &mut String, exp: &Expander) {
    let name = exp.config.effective_name();
    out.push_str(&format!("undo ip as-path-filter {name}\n"));

    let mut nc = 0i32;
    let mut printed_self = false;

    if !printed_self && exp.config.asnumber > 0 && exp.asn_list.contains(&exp.config.asnumber) {
        out.push_str(&format!(
            "ip as-path-filter {name} permit ^(_{})*$\n",
            exp.config.asnumber
        ));
        printed_self = true;
    }

    if exp.asn_list.is_empty() && !printed_self {
        out.push_str(&format!("ip as-path-filter {name} deny .*\n"));
        return;
    }

    let skip_self = exp.config.asnumber > 0;

    for &asn in &exp.asn_list {
        if skip_self && asn == exp.config.asnumber {
            continue;
        }

        if nc == 0 {
            out.push_str(&format!(
                "ip as-path-filter {name} permit ^(_[0-9]+)*_({}",
                asn
            ));
        } else {
            out.push_str(&format!("|{}", asn));
        }

        nc += 1;
        if nc == exp.config.aswidth {
            out.push_str(")$\n");
            nc = 0;
        }
    }

    if nc > 0 {
        out.push_str(")$\n");
    }
}

pub fn print_huawei_xpl_oaspath(out: &mut String, exp: &Expander) {
    let name = exp.config.effective_name();
    out.push_str(&format!("xpl as-path-list {name}"));

    let mut nc = 0i32;
    let mut comma = false;

    if exp.config.asnumber > 0 && exp.asn_list.contains(&exp.config.asnumber) {
        out.push_str(&format!("\n  regular ^(_{})*$", exp.config.asnumber));
        comma = true;
    }

    let skip_self = exp.config.asnumber > 0;

    for &asn in &exp.asn_list {
        if skip_self && asn == exp.config.asnumber {
            continue;
        }

        if nc == 0 {
            out.push_str(&format!(
                "{}\n  regular ^(_[0-9]+)*_({}",
                if comma { "," } else { "" },
                asn
            ));
            comma = true;
        } else {
            out.push_str(&format!("|{}", asn));
        }

        nc += 1;
        if nc == exp.config.aswidth {
            out.push_str(")$");
            nc = 0;
        }
    }

    if nc > 0 {
        out.push_str(")$");
    }

    out.push_str("\nend-list\n");
}
