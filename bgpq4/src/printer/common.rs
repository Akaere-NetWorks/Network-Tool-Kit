use crate::prefix::RadixNode;

pub fn format_ip_family(family: u8) -> &'static str {
    if family == 2 { "ip" } else { "ipv6" }
}

pub struct NodeWalkState {
    pub needs_comma: bool,
    pub seq: u32,
}

impl NodeWalkState {
    pub fn new() -> Self {
        NodeWalkState {
            needs_comma: false,
            seq: 0,
        }
    }
}

pub struct FormatCtx {
    pub bname: String,
    pub seq: u32,
    pub needs_comma: bool,
    pub jrfilter_prefixed: bool,
}

impl FormatCtx {
    pub fn new(name: &str) -> Self {
        FormatCtx {
            bname: if name.is_empty() { "NN".to_string() } else { name.to_string() },
            seq: 0,
            needs_comma: false,
            jrfilter_prefixed: true,
        }
    }
}

pub fn is_output_node(node: &RadixNode) -> bool {
    !node.is_glue
}
