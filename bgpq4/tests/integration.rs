use bgpq4_lib::irrd::{IrrdClient, IrrdResponse};
use bgpq4_lib::expander::{Expander, IpFamily};

#[tokio::test]
#[ignore]
async fn query_as112_ipv4_routes() {
    let client = IrrdClient::new("rr.ntt.net", 43);
    let resp = client.query("!gAS112").await.expect("IRRD query failed");
    match resp {
        IrrdResponse::Data(items) => {
            assert!(!items.is_empty(), "AS112 should have IPv4 routes");
            for item in &items {
                assert!(item.contains('/'), "expected CIDR notation, got: {item}");
            }
        }
        other => panic!("expected Data, got {:?}", other),
    }
}

#[tokio::test]
#[ignore]
async fn query_as_as112_set_members() {
    let client = IrrdClient::new("rr.ntt.net", 43);
    let resp = client.query("!iAS-AS112").await.expect("IRRD query failed");
    match resp {
        IrrdResponse::Data(items) => {
            assert!(!items.is_empty(), "AS-AS112 should have members");
        }
        other => panic!("expected Data, got {:?}", other),
    }
}

#[tokio::test]
#[ignore]
async fn expand_as112_ipv4() {
    let exp = Expander::new("rr.ntt.net", 43, IpFamily::V4);
    let prefixes = exp.expand("AS112").await.expect("expand failed");
    assert!(!prefixes.is_empty(), "AS112 should yield IPv4 prefixes");
    for p in &prefixes {
        assert!(p.is_ipv4(), "expected IPv4 prefix, got: {p}");
    }
}

#[tokio::test]
#[ignore]
async fn expand_as_as112_set() {
    let exp = Expander::new("rr.ntt.net", 43, IpFamily::V4);
    let prefixes = exp.expand("AS-AS112").await.expect("expand failed");
    assert!(!prefixes.is_empty(), "AS-AS112 should yield IPv4 prefixes");
}
