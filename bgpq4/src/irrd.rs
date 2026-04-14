use thiserror::Error;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;

#[derive(Debug, PartialEq)]
pub enum IrrdResponse {
    Data(Vec<String>),
    Empty,
    NotFound,
    MultipleKeys,
    Error(String),
}

#[derive(Error, Debug)]
pub enum IrrdError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("protocol error: {0}")]
    Protocol(String),
    #[error("UTF-8 error: {0}")]
    Utf8(#[from] std::string::FromUtf8Error),
}

pub async fn read_irrd_response<R: tokio::io::AsyncRead + Unpin>(
    reader: &mut BufReader<R>,
) -> Result<IrrdResponse, IrrdError> {
    let mut first_line = String::new();
    reader.read_line(&mut first_line).await?;
    let code = first_line.trim_end_matches(|c: char| c == '\r' || c == '\n');

    match code.chars().next() {
        Some('A') => {
            let n: usize = code[1..]
                .parse()
                .map_err(|_| IrrdError::Protocol(format!("bad byte count in: {code}")))?;
            let mut data = vec![0u8; n];
            reader.read_exact(&mut data).await?;
            let mut _term = String::new();
            reader.read_line(&mut _term).await?;
            let items = String::from_utf8(data)?
                .split_whitespace()
                .map(String::from)
                .collect();
            Ok(IrrdResponse::Data(items))
        }
        Some('C') => Ok(IrrdResponse::Empty),
        Some('D') => Ok(IrrdResponse::NotFound),
        Some('E') => Ok(IrrdResponse::MultipleKeys),
        Some('F') => Ok(IrrdResponse::Error(code[1..].trim().to_string())),
        _ => Err(IrrdError::Protocol(format!("unexpected response: {}", &code[..code.len().min(20)]))),
    }
}

pub struct IrrdClient {
    host: String,
    port: u16,
}

impl IrrdClient {
    pub fn new(host: impl Into<String>, port: u16) -> Self {
        IrrdClient { host: host.into(), port }
    }

    pub async fn query(&self, cmd: &str) -> Result<IrrdResponse, IrrdError> {
        let stream = TcpStream::connect((&*self.host, self.port)).await?;
        let (read_half, mut write_half) = tokio::io::split(stream);
        let mut reader = BufReader::new(read_half);
        write_half.write_all(format!("{cmd}\n").as_bytes()).await?;
        read_irrd_response(&mut reader).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::BufReader;

    #[tokio::test]
    async fn parse_data_response() {
        let raw = b"A12\nAS1 AS2 AS3\nC\n";
        let mut reader = BufReader::new(&raw[..]);
        let resp = read_irrd_response(&mut reader).await.unwrap();
        assert_eq!(
            resp,
            IrrdResponse::Data(vec!["AS1".into(), "AS2".into(), "AS3".into()])
        );
    }

    #[tokio::test]
    async fn parse_empty_response() {
        let raw = b"C\n";
        let mut reader = BufReader::new(&raw[..]);
        assert_eq!(read_irrd_response(&mut reader).await.unwrap(), IrrdResponse::Empty);
    }

    #[tokio::test]
    async fn parse_not_found() {
        let raw = b"D\n";
        let mut reader = BufReader::new(&raw[..]);
        assert_eq!(read_irrd_response(&mut reader).await.unwrap(), IrrdResponse::NotFound);
    }

    #[tokio::test]
    async fn parse_error_response() {
        let raw = b"F Unknown key\n";
        let mut reader = BufReader::new(&raw[..]);
        assert_eq!(
            read_irrd_response(&mut reader).await.unwrap(),
            IrrdResponse::Error("Unknown key".into())
        );
    }

    #[tokio::test]
    async fn parse_prefixes_response() {
        let data = b"192.0.2.0/24 203.0.113.0/24\n";
        let header = format!("A{}\n", data.len());
        let mut raw = header.into_bytes();
        raw.extend_from_slice(data);
        raw.extend_from_slice(b"C\n");

        let mut reader = BufReader::new(&raw[..]);
        let resp = read_irrd_response(&mut reader).await.unwrap();
        assert_eq!(
            resp,
            IrrdResponse::Data(vec!["192.0.2.0/24".into(), "203.0.113.0/24".into()])
        );
    }
}
