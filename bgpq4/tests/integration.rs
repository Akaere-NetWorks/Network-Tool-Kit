use bgpq4_lib::config::ExpanderConfig;
use bgpq4_lib::expander::Expander;
use bgpq4_lib::irrd::{IrrdClient, IrrdResponse};

#[tokio::test]
#[ignore]
async fn query_as112_ipv4_routes() {
    let mut client = IrrdClient::connect("rr.ntt.net", 43)
        .await
        .expect("connect failed");
    let resp = client
        .query_sync("!gAS112\n")
        .await
        .expect("IRRD query failed");
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
    let mut client = IrrdClient::connect("rr.ntt.net", 43)
        .await
        .expect("connect failed");
    let resp = client
        .query_sync("!iAS-AS112,1\n")
        .await
        .expect("IRRD query failed");
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
    let mut config = ExpanderConfig::default();
    config.init(2);
    let mut exp = Expander::new(config);
    exp.add_object("AS112");
    let ok = exp.expand().await;
    assert!(ok, "expand failed");
    assert!(!exp.tree.is_empty(), "AS112 should yield IPv4 prefixes");
}

#[tokio::test]
#[ignore]
async fn expand_as_as112_set() {
    let mut config = ExpanderConfig::default();
    config.init(2);
    let mut exp = Expander::new(config);
    exp.add_object("AS-AS112");
    let ok = exp.expand().await;
    assert!(ok, "expand failed");
    assert!(!exp.tree.is_empty(), "AS-AS112 should yield IPv4 prefixes");
}
