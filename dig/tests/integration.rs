use dig_lib::{
    dns::{build_query, QueryConfig, RecordType, Rdata},
    resolver::{send_query, ResolverConfig},
};
use std::net::SocketAddr;

fn google_dns() -> SocketAddr { "8.8.8.8:53".parse().unwrap() }

fn make_query(name: &str, qtype: RecordType, id: u16) -> Vec<u8> {
    let cfg = QueryConfig { id, rd: true, edns: true, ..QueryConfig::default() };
    build_query(name, qtype, &cfg)
}

fn resolver_cfg(tcp: bool) -> ResolverConfig {
    ResolverConfig { use_tcp: tcp, ..ResolverConfig::default() }
}

#[tokio::test]
#[ignore]
async fn query_google_com_a() {
    let q = make_query("google.com", RecordType::A, 0xAB01);
    let result = send_query(google_dns(), &q, &resolver_cfg(false)).await.unwrap();
    assert!(result.message.header.is_response());
    assert!(result.message.header.rcode() == 0, "NOERROR expected");
    let has_a = result.message.answers.iter().any(|rr| matches!(rr.rdata, Rdata::A(_)));
    assert!(has_a, "expected at least one A record");
}

#[tokio::test]
#[ignore]
async fn query_google_com_aaaa() {
    let q = make_query("google.com", RecordType::Aaaa, 0xAB02);
    let result = send_query(google_dns(), &q, &resolver_cfg(false)).await.unwrap();
    assert!(result.message.header.is_response());
    let has_aaaa = result.message.answers.iter().any(|rr| matches!(rr.rdata, Rdata::Aaaa(_)));
    assert!(has_aaaa, "expected at least one AAAA record");
}

#[tokio::test]
#[ignore]
async fn query_google_com_mx() {
    let q = make_query("google.com", RecordType::Mx, 0xAB03);
    let result = send_query(google_dns(), &q, &resolver_cfg(false)).await.unwrap();
    assert!(result.message.header.is_response());
    let has_mx = result.message.answers.iter().any(|rr| matches!(rr.rdata, Rdata::Mx { .. }));
    assert!(has_mx, "expected at least one MX record");
}

#[tokio::test]
#[ignore]
async fn query_reverse_google_dns() {
    let q = make_query("8.8.8.8.in-addr.arpa", RecordType::Ptr, 0xAB04);
    let result = send_query(google_dns(), &q, &resolver_cfg(false)).await.unwrap();
    assert!(result.message.header.is_response());
    let has_ptr = result.message.answers.iter().any(|rr| matches!(rr.rdata, Rdata::Ptr(_)));
    assert!(has_ptr, "expected PTR record for 8.8.8.8");
}

#[tokio::test]
#[ignore]
async fn query_via_tcp() {
    let q = make_query("google.com", RecordType::A, 0xAB05);
    let result = send_query(google_dns(), &q, &resolver_cfg(true)).await.unwrap();
    assert!(result.message.header.is_response());
}
