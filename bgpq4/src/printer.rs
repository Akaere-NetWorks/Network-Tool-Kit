use crate::prefix::IpPrefix;

pub fn format_cisco(name: &str, prefixes: &[IpPrefix]) -> String {
    let mut out = format!("no ip prefix-list {name}\n");
    for p in prefixes {
        out.push_str(&format!("ip prefix-list {name} permit {p}\n"));
    }
    out
}

pub fn format_juniper(name: &str, prefixes: &[IpPrefix]) -> String {
    let mut out = format!("policy-options {{\nreplace:\n prefix-list {name} {{\n");
    for p in prefixes {
        out.push_str(&format!("    {p};\n"));
    }
    out.push_str(" }\n}\n");
    out
}

pub fn format_json(name: &str, prefixes: &[IpPrefix]) -> String {
    let entries: Vec<String> = prefixes
        .iter()
        .map(|p| {
            let ps = p.to_string().replace('/', "\\/");
            format!(r#"    {{ "prefix": "{ps}", "exact": true }}"#)
        })
        .collect();
    format!("{{ \"{name}\": [\n{}\n] }}\n", entries.join(",\n"))
}

pub fn format_bird(name: &str, prefixes: &[IpPrefix]) -> String {
    let mut out = format!("{name} = [\n");
    let last = prefixes.len();
    for (i, p) in prefixes.iter().enumerate() {
        if i + 1 < last {
            out.push_str(&format!("    {p},\n"));
        } else {
            out.push_str(&format!("    {p}\n"));
        }
    }
    out.push_str("];\n");
    out
}

pub fn format_openbgpd(_name: &str, prefixes: &[IpPrefix]) -> String {
    let mut out = String::from("prefix { \n");
    for p in prefixes {
        out.push_str(&format!("\t{p}\n"));
    }
    out.push_str("\t}\n");
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::prefix::IpPrefix;

    fn two_prefixes() -> Vec<IpPrefix> {
        vec![
            IpPrefix::parse("192.31.196.0/24").unwrap(),
            IpPrefix::parse("192.175.48.0/24").unwrap(),
        ]
    }

    #[test]
    fn cisco_format() {
        let out = format_cisco("NN", &two_prefixes());
        let expected = "no ip prefix-list NN\nip prefix-list NN permit 192.31.196.0/24\nip prefix-list NN permit 192.175.48.0/24\n";
        assert_eq!(out, expected);
    }

    #[test]
    fn bird_format() {
        let out = format_bird("NN", &two_prefixes());
        let expected = "NN = [\n    192.31.196.0/24,\n    192.175.48.0/24\n];\n";
        assert_eq!(out, expected);
    }

    #[test]
    fn juniper_format() {
        let out = format_juniper("NN", &two_prefixes());
        let expected = "policy-options {\nreplace:\n prefix-list NN {\n    192.31.196.0/24;\n    192.175.48.0/24;\n }\n}\n";
        assert_eq!(out, expected);
    }

    #[test]
    fn json_format_valid() {
        let out = format_json("NN", &two_prefixes());
        let v: serde_json::Value = serde_json::from_str(&out).expect("invalid JSON");
        let arr = v["NN"].as_array().expect("NN must be array");
        assert_eq!(arr.len(), 2);
        assert_eq!(arr[0]["prefix"].as_str().unwrap(), "192.31.196.0/24");
        assert_eq!(arr[0]["exact"].as_bool().unwrap(), true);
    }

    #[test]
    fn openbgpd_format() {
        let out = format_openbgpd("NN", &two_prefixes());
        assert!(out.starts_with("prefix { \n"));
        assert!(out.contains("\t192.31.196.0/24\n"));
        assert!(out.contains("\t192.175.48.0/24\n"));
    }

    #[test]
    fn cisco_matches_reference() {
        let reference = std::fs::read_to_string("../bgpq4-src/tests/reference/ios--4.txt")
            .expect("reference file not found");
        assert_eq!(format_cisco("NN", &two_prefixes()), reference);
    }

    #[test]
    fn bird_matches_reference() {
        let reference = std::fs::read_to_string("../bgpq4-src/tests/reference/bird--4.txt")
            .expect("reference file not found");
        assert_eq!(format_bird("NN", &two_prefixes()), reference);
    }

    #[test]
    fn juniper_matches_reference() {
        let reference = std::fs::read_to_string("../bgpq4-src/tests/reference/junos--4.txt")
            .expect("reference file not found");
        assert_eq!(format_juniper("NN", &two_prefixes()), reference);
    }

    #[test]
    fn json_matches_reference() {
        let reference = std::fs::read_to_string("../bgpq4-src/tests/reference/json--4.txt")
            .expect("reference file not found");
        assert_eq!(format_json("NN", &two_prefixes()), reference);
    }

    #[test]
    fn openbgpd_matches_reference() {
        let reference = std::fs::read_to_string("../bgpq4-src/tests/reference/openbgpd--4.txt")
            .expect("reference file not found");
        assert_eq!(format_openbgpd("NN", &two_prefixes()), reference);
    }
}
