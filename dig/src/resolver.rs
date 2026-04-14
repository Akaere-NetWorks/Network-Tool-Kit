use std::net::SocketAddr;
use std::time::Duration;
use crate::dns::{self, DnsError, Message, QueryConfig, RecordType, build_query};
use thiserror::Error;
use tokio::net::{TcpStream, UdpSocket};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::timeout;

#[derive(Error, Debug)]
pub enum ResolverError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("DNS parse error: {0}")]
    Dns(#[from] DnsError),
    #[error("query timed out after {0} tries")]
    Timeout(u32),
}

pub struct QueryResult {
    pub message: Message,
    pub response_bytes: usize,
    pub query_bytes: usize,
}

pub struct ResolverConfig {
    pub use_tcp: bool,
    pub ignore_tc: bool,
    pub timeout_secs: u64,
    pub tries: u32,
    pub retry: u32,
    pub udp_bufsize: u16,
}

impl Default for ResolverConfig {
    fn default() -> Self {
        ResolverConfig {
            use_tcp: false,
            ignore_tc: false,
            timeout_secs: 5,
            tries: 3,
            retry: 0,
            udp_bufsize: 1232,
        }
    }
}

pub async fn send_query(
    server: SocketAddr,
    query: &[u8],
    config: &ResolverConfig,
) -> Result<QueryResult, ResolverError> {
    let total_tries = if config.retry > 0 { config.retry + 1 } else { config.tries };
    let effective_tcp = config.use_tcp;

    if effective_tcp {
        return send_tcp(server, query, config.timeout_secs).await;
    }

    for _attempt in 0..total_tries {
        match timeout(
            Duration::from_secs(config.timeout_secs),
            send_udp(server, query, config.udp_bufsize),
        ).await {
            Ok(Ok(result)) => {
                if result.message.header.is_truncated() && !config.ignore_tc {
                    return send_tcp(server, query, config.timeout_secs).await;
                }
                return Ok(result);
            }
            Ok(Err(e)) => return Err(e),
            Err(_) => continue,
        }
    }
    Err(ResolverError::Timeout(total_tries))
}

async fn send_udp(
    server: SocketAddr,
    query: &[u8],
    buf_size: u16,
) -> Result<QueryResult, ResolverError> {
    let local: SocketAddr = if server.is_ipv6() {
        "[::]:0".parse().unwrap()
    } else {
        "0.0.0.0:0".parse().unwrap()
    };
    let sock = UdpSocket::bind(local).await?;
    sock.send_to(query, server).await?;
    let recv_size = buf_size.max(512) as usize;
    let mut buf = vec![0u8; recv_size];
    let n = sock.recv(&mut buf).await?;
    let msg = dns::parse_message(&buf[..n])?;
    Ok(QueryResult {
        message: msg,
        response_bytes: n,
        query_bytes: query.len(),
    })
}

async fn send_tcp(
    server: SocketAddr,
    query: &[u8],
    timeout_secs: u64,
) -> Result<QueryResult, ResolverError> {
    let mut stream = timeout(
        Duration::from_secs(timeout_secs),
        TcpStream::connect(server),
    ).await.map_err(|_| ResolverError::Timeout(1))??;

    let len = (query.len() as u16).to_be_bytes();
    stream.write_all(&len).await?;
    stream.write_all(query).await?;

    let mut resp_len_buf = [0u8; 2];
    stream.read_exact(&mut resp_len_buf).await?;
    let resp_len = u16::from_be_bytes(resp_len_buf) as usize;

    let mut resp_buf = vec![0u8; resp_len];
    stream.read_exact(&mut resp_buf).await?;
    let msg = dns::parse_message(&resp_buf)?;
    Ok(QueryResult {
        message: msg,
        response_bytes: resp_len + 2,
        query_bytes: query.len() + 2,
    })
}

const ROOT_SERVERS: &[&str] = &[
    "198.41.0.4", "199.9.14.201", "192.33.4.12", "199.7.91.13",
    "192.203.230.10", "192.5.5.241", "192.112.36.4", "198.97.190.53",
    "192.36.148.17", "192.58.128.30", "193.0.14.129", "199.7.83.42",
    "202.12.27.33",
];

pub async fn trace_query(
    name: &str,
    qtype: RecordType,
    cfg: &QueryConfig,
    resolver_cfg: &ResolverConfig,
) -> Result<Vec<QueryResult>, ResolverError> {
    let mut results = Vec::new();
    let mut servers: Vec<SocketAddr> = ROOT_SERVERS.iter()
        .map(|s| format!("{s}:53").parse().unwrap())
        .collect();
    let mut depth = 0;
    let max_depth = 30;

    loop {
        if depth >= max_depth { break; }
        depth += 1;

        let server = servers[0];
        let query = build_query(name, qtype, cfg);
        let result = send_query(server, &query, resolver_cfg).await?;
        let msg = &result.message;

        results.push(QueryResult {
            message: msg.clone(),
            response_bytes: result.response_bytes,
            query_bytes: result.query_bytes,
        });

        if msg.header.rcode() != 0 && msg.header.rcode() != 0 {
            break;
        }

        if !msg.answers.is_empty() {
            break;
        }

        let ns_records: Vec<&crate::dns::ResourceRecord> = msg.authority.iter()
            .filter(|rr| rr.rtype == RecordType::Ns)
            .collect();

        if ns_records.is_empty() {
            break;
        }

        let mut next_servers = Vec::new();
        for ns_rr in &ns_records {
            if let crate::dns::Rdata::Ns(ref ns_name) = ns_rr.rdata {
                let glue_name = ns_name;

                for add_rr in &msg.additional {
                    if add_rr.name == *glue_name {
                        match &add_rr.rdata {
                            crate::dns::Rdata::A(addr) => {
                                next_servers.push(SocketAddr::new(std::net::IpAddr::V4(*addr), 53));
                            }
                            crate::dns::Rdata::Aaaa(addr) => {
                                next_servers.push(SocketAddr::new(std::net::IpAddr::V6(*addr), 53));
                            }
                            _ => {}
                        }
                    }
                }

                if next_servers.is_empty() {
                    let mut resolve_cfg = QueryConfig::default();
                    resolve_cfg.rd = true;
                    let glue_query = build_query(glue_name, RecordType::A, &resolve_cfg);
                    if let Ok(glue_result) = send_query(
                        "8.8.8.8:53".parse().unwrap(),
                        &glue_query,
                        &ResolverConfig::default(),
                    ).await {
                        for rr in &glue_result.message.answers {
                            if let crate::dns::Rdata::A(addr) = &rr.rdata {
                                next_servers.push(SocketAddr::new(std::net::IpAddr::V4(*addr), 53));
                            }
                        }
                    }
                }
            }
        }

        if next_servers.is_empty() {
            break;
        }

        servers = next_servers;
    }

    Ok(results)
}
