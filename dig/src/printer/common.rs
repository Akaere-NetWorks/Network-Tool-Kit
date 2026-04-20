use crate::dns::{Message, RecordType};

pub(crate) const TAB_WIDTH: usize = 8;
pub(crate) const TTL_COL: usize = 24;
pub(crate) const CLASS_COL: usize = 32;
pub(crate) const TYPE_COL: usize = 40;
pub(crate) const RDATA_COL: usize = 48;
pub(crate) const LINE_LEN: usize = 80;

pub fn indent(out: &mut String, from: usize, to: usize) {
    if to <= from {
        return;
    }
    let ntabs = (to / TAB_WIDTH).saturating_sub(from / TAB_WIDTH);
    for _ in 0..ntabs {
        out.push('\t');
    }
    let tabs_end = (from / TAB_WIDTH + ntabs) * TAB_WIDTH;
    if to > tabs_end {
        out.push_str(&" ".repeat(to - tabs_end));
    }
}

pub fn indent_to(out: &mut String, current_len: usize, col: usize) {
    indent(out, current_len, col);
}

pub fn current_column(s: &str) -> usize {
    let mut col = 0;
    for ch in s.chars() {
        if ch == '\n' {
            col = 0;
        } else if ch == '\t' {
            col = (col / TAB_WIDTH + 1) * TAB_WIDTH;
        } else {
            col += 1;
        }
    }
    col
}

pub fn add_owner(out: &mut String, name: &str) {
    out.push_str(name);
    indent_to(out, current_column(out), RDATA_COL);
}

#[allow(clippy::too_many_arguments)]
pub fn add_rdata_line(
    out: &mut String,
    first: bool,
    omit_owner: bool,
    name: &str,
    ttl_str: &str,
    class_str: &str,
    _type_str: &str,
    rdata: &str,
    split_width: Option<usize>,
) {
    if !omit_owner {
        out.push_str(name);
        indent_to(out, current_column(out), TTL_COL);
    }
    out.push_str(ttl_str);
    indent_to(out, current_column(out), CLASS_COL);
    out.push_str(class_str);
    indent_to(out, current_column(out), TYPE_COL);
    indent_to(out, current_column(out), RDATA_COL);

    let max_line = if let Some(sw) = split_width {
        sw
    } else {
        LINE_LEN
    };
    if first && rdata.len() > max_line {
        let mut pos = 0;
        let mut is_first = true;
        while pos < rdata.len() {
            let end = (pos + max_line).min(rdata.len());
            let chunk = &rdata[pos..end];
            if !is_first {
                indent_to(out, 0, RDATA_COL);
            }
            out.push_str(chunk);
            out.push('\n');
            pos = end;
            is_first = false;
        }
    } else {
        out.push_str(rdata);
        out.push('\n');
    }
}

#[allow(clippy::too_many_arguments)]
pub fn add_rr_start(
    out: &mut String,
    name: &str,
    _ttl: u32,
    ttl_str: &str,
    class_str: &str,
    type_str: &str,
    no_ttl: bool,
    no_class: bool,
) {
    out.push_str(name);
    let name_col = current_column(out);
    if !no_ttl {
        indent_to(out, name_col, TTL_COL);
        out.push_str(ttl_str);
    }
    let ttl_col = current_column(out);
    if !no_class {
        indent_to(out, ttl_col, CLASS_COL);
        out.push_str(class_str);
    }
    let class_col = current_column(out);
    indent_to(out, class_col, TYPE_COL);
    out.push_str(type_str);
    indent_to(out, current_column(out), RDATA_COL);
}

pub fn add_question(out: &mut String, name: &str, class_str: &str, type_str: &str, no_class: bool) {
    out.push(';');
    out.push_str(name);
    let name_col = current_column(out);
    if !no_class {
        indent_to(out, name_col, CLASS_COL);
        out.push_str(class_str);
    }
    let class_col = current_column(out);
    indent_to(out, class_col, TYPE_COL);
    out.push_str(type_str);
    out.push('\n');
}

pub fn should_skip_opt(rr_type: RecordType) -> bool {
    rr_type == RecordType::Opt
}

pub fn has_visible_records(records: &[crate::dns::ResourceRecord]) -> bool {
    records.iter().any(|rr| !should_skip_opt(rr.rtype))
}

pub fn has_non_opt_additional(msg: &Message) -> bool {
    msg.additional.iter().any(|rr| rr.rtype != RecordType::Opt)
}
