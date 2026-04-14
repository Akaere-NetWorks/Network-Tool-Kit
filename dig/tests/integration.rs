use dig_lib::{
    dns::{build_query, RecordType, Rdata},
    resolver::send_query,
};
use std::net::SocketAddr;

fn google_dns() -> SocketAddr { "8.8.8.8:53".parse().unwrap() }

#[tokio::test]
#[ignore]
async fn query_google_com_a() {
    let q = build_query("google.com", RecordType::A, 0xAB01, true);
    let msg = send_query(google_dns(), &q, false, 5, 3).await.unwrap();
    assert!(msg.header.is_response());
    assert!(msg.header.rcode() == 0, "NOERROR expected");
    let has_a = msg.answers.iter().any(|rr| matches!(rr.rdata, Rdata::A(_)));
    assert!(has_a, "expected at least one A record");
}

#[tokio::test]
#[ignore]
async fn query_google_com_aaaa() {
    let q = build_query("google.com", RecordType::Aaaa, 0xAB02, true);
    let msg = send_query(google_dns(), &q, false, 5, 3).await.unwrap();
    assert!(msg.header.is_response());
    let has_aaaa = msg.answers.iter().any(|rr| matches!(rr.rdata, Rdata::Aaaa(_)));
    assert!(has_aaaa, "expected at least one AAAA record");
}

#[tokio::test]
#[ignore]
async fn query_google_com_mx() {
    let q = build_query("google.com", RecordType::Mx, 0xAB03, true);
    let msg = send_query(google_dns(), &q, false, 5, 3).await.unwrap();
    assert!(msg.header.is_response());
    let has_mx = msg.answers.iter().any(|rr| matches!(rr.rdata, Rdata::Mx { .. }));
    assert!(has_mx, "expected at least one MX record");
}

#[tokio::test]
#[ignore]
async fn query_reverse_google_dns() {
    let q = build_query("8.8.8.8.in-addr.arpa", RecordType::Ptr, 0xAB04, true);
    let msg = send_query(google_dns(), &q, false, 5, 3).await.unwrap();
    assert!(msg.header.is_response());
    let has_ptr = msg.answers.iter().any(|rr| matches!(rr.rdata, Rdata::Ptr(_)));
    assert!(has_ptr, "expected PTR record for 8.8.8.8");
}

#[tokio::test]
#[ignore]
async fn query_via_tcp() {
    let q = build_query("google.com", RecordType::A, 0xAB05, true);
    let msg = send_query(google_dns(), &q, true, 5, 1).await.unwrap();
    assert!(msg.header.is_response());
}
