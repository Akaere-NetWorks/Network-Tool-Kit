pub mod aspath;
pub mod bird;
pub mod cisco;
pub mod common;
pub mod format;
pub mod huawei;
pub mod json;
pub mod juniper;
pub mod mikrotik;
pub mod nokia;
pub mod openbgpd;

use crate::config::Vendor;
use crate::expander::Expander;
use crate::report;

pub fn print_prefixlist(out: &mut String, exp: &Expander) {
    match exp.config.vendor {
        Vendor::Juniper => juniper::print_prefixlist(out, exp),
        Vendor::Cisco => cisco::print_prefixlist(out, exp),
        Vendor::CiscoXr => cisco::print_xr_prefixlist(out, exp),
        Vendor::Json => json::print_prefixlist(out, exp),
        Vendor::Bird => bird::print_prefixlist(out, exp),
        Vendor::OpenBgpd => openbgpd::print_prefixlist(out, exp),
        Vendor::Format => format::print_prefixlist(out, exp),
        Vendor::Nokia => nokia::print_prefixlist(out, exp),
        Vendor::NokiaMd => nokia::print_md_ipprefixlist(out, exp),
        Vendor::NokiaSrl => nokia::print_srl_prefixset(out, exp),
        Vendor::Huawei => huawei::print_prefixlist(out, exp),
        Vendor::HuaweiXpl => huawei::print_xpl_prefixlist(out, exp),
        Vendor::Mikrotik6 | Vendor::Mikrotik7 => mikrotik::print_prefixlist(out, exp),
        Vendor::Arista => cisco::print_arista_prefixlist(out, exp),
    }
}

pub fn print_eacl(out: &mut String, exp: &Expander) {
    match exp.config.vendor {
        Vendor::Juniper => juniper::print_routefilter(out, exp),
        Vendor::Cisco | Vendor::Arista => cisco::print_eacl(out, exp),
        Vendor::OpenBgpd => openbgpd::print_prefixset(out, exp),
        Vendor::Nokia => nokia::print_ipprefixlist(out, exp),
        Vendor::NokiaMd => nokia::print_md_prefixlist(out, exp),
        Vendor::NokiaSrl => nokia::print_srl_aclipfilter(out, exp),
        _ => report::fatal("unreachable point"),
    }
}

pub fn print_aspath(out: &mut String, exp: &Expander) {
    match exp.config.vendor {
        Vendor::Juniper => aspath::print_juniper_aspath(out, exp),
        Vendor::Cisco | Vendor::Arista => aspath::print_cisco_aspath(out, exp),
        Vendor::CiscoXr => aspath::print_cisco_xr_aspath(out, exp),
        Vendor::Json => aspath::print_json_aspath(out, exp),
        Vendor::Bird => aspath::print_bird_aspath(out, exp),
        Vendor::OpenBgpd => aspath::print_openbgpd_aspath(out, exp),
        Vendor::Nokia => aspath::print_nokia_aspath(out, exp),
        Vendor::NokiaMd => aspath::print_nokia_md_aspath(out, exp),
        Vendor::Huawei => aspath::print_huawei_aspath(out, exp),
        Vendor::HuaweiXpl => aspath::print_huawei_xpl_aspath(out, exp),
        _ => report::fatal("Unknown vendor for aspath"),
    }
}

pub fn print_oaspath(out: &mut String, exp: &Expander) {
    match exp.config.vendor {
        Vendor::Juniper => aspath::print_juniper_oaspath(out, exp),
        Vendor::Cisco | Vendor::Arista => aspath::print_cisco_oaspath(out, exp),
        Vendor::CiscoXr => aspath::print_cisco_xr_oaspath(out, exp),
        Vendor::OpenBgpd => aspath::print_openbgpd_oaspath(out, exp),
        Vendor::Nokia => aspath::print_nokia_oaspath(out, exp),
        Vendor::NokiaMd => aspath::print_nokia_md_oaspath(out, exp),
        Vendor::Huawei => aspath::print_huawei_oaspath(out, exp),
        Vendor::HuaweiXpl => aspath::print_huawei_xpl_oaspath(out, exp),
        _ => report::fatal("Unknown vendor for oaspath"),
    }
}

pub fn print_aslist(out: &mut String, exp: &Expander) {
    aspath::print_juniper_aslist(out, exp);
}

pub fn print_asset(out: &mut String, exp: &Expander) {
    match exp.config.vendor {
        Vendor::Json => aspath::print_json_aspath(out, exp),
        Vendor::OpenBgpd => aspath::print_openbgpd_asset(out, exp),
        Vendor::Bird => aspath::print_bird_aspath(out, exp),
        _ => report::fatal("as-sets (-t) supported for JSON, OpenBGPD, and BIRD only"),
    }
}

pub fn print_route_filter_list(out: &mut String, exp: &Expander) {
    juniper::print_route_filter_list(out, exp);
}
