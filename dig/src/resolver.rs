use std::net::SocketAddr;
use std::time::Duration;
use crate::dns::{self, DnsError, Message};
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

pub async fn send_query(
    server: SocketAddr,
    query: &[u8],
    use_tcp: bool,
    timeout_secs: u64,
    tries: u32,
) -> Result<Message, ResolverError> {
    if use_tcp {
        return send_tcp(server, query, timeout_secs).await;
    }

    for _attempt in 0..tries {
        match timeout(
            Duration::from_secs(timeout_secs),
            send_udp(server, query),
        ).await {
            Ok(Ok(msg)) => {
                if msg.header.is_truncated() {
                    return send_tcp(server, query, timeout_secs).await;
                }
                return Ok(msg);
            }
            Ok(Err(e)) => return Err(e),
            Err(_)     => continue,
        }
    }
    Err(ResolverError::Timeout(tries))
}

async fn send_udp(server: SocketAddr, query: &[u8]) -> Result<Message, ResolverError> {
    let local: SocketAddr = if server.is_ipv6() {
        "[::]:0".parse().unwrap()
    } else {
        "0.0.0.0:0".parse().unwrap()
    };
    let sock = UdpSocket::bind(local).await?;
    sock.send_to(query, server).await?;
    let mut buf = vec![0u8; 512];
    let n = sock.recv(&mut buf).await?;
    Ok(dns::parse_message(&buf[..n])?)
}

async fn send_tcp(
    server: SocketAddr,
    query: &[u8],
    timeout_secs: u64,
) -> Result<Message, ResolverError> {
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
    Ok(dns::parse_message(&resp_buf)?)
}
