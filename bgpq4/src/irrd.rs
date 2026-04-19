use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;

pub type CallbackFn = Box<dyn Fn(&str, &mut Vec<u32>, &str) -> bool + Send + Sync>;

pub struct IrrdClient {
    stream: Option<BufReader<tokio::io::ReadHalf<TcpStream>>>,
    writer: Option<tokio::io::WriteHalf<TcpStream>>,
}

impl IrrdClient {
    pub async fn connect(server: &str, port: u16) -> std::io::Result<Self> {
        let addr = format!("{server}:{port}");
        let stream = TcpStream::connect(&addr).await?;

        let (read_half, mut write_half) = tokio::io::split(stream);
        let reader = BufReader::new(read_half);

        write_half.write_all(b"!!\n").await?;

        Ok(IrrdClient {
            stream: Some(reader),
            writer: Some(write_half),
        })
    }

    pub async fn identify(&mut self, ident: &str) -> std::io::Result<()> {
        let cmd = format!("!n{ident}\n");
        self.send_raw(&cmd).await?;
        let mut resp = String::new();
        if let Some(ref mut reader) = self.stream {
            reader.read_line(&mut resp).await?;
        }
        Ok(())
    }

    pub async fn set_sources(&mut self, sources: &str) -> std::io::Result<bool> {
        let cmd = format!("!s{sources}\n");
        self.send_raw(&cmd).await?;
        let mut resp = String::new();
        if let Some(ref mut reader) = self.stream {
            reader.read_line(&mut resp).await?;
        }
        Ok(resp.trim().starts_with('C'))
    }

    pub async fn get_sources_list(&mut self) -> std::io::Result<String> {
        self.send_raw("!s-lc\n").await?;
        let mut response = String::new();
        if let Some(ref mut reader) = self.stream {
            reader.read_line(&mut response).await?;
            if !response.trim().starts_with('A') {
                return Err(std::io::Error::other("Invalid source list response"));
            }
            let count: usize = response.trim()[1..]
                .trim_end_matches('\n')
                .trim_end_matches('\r')
                .parse()
                .unwrap_or(0);
            let mut data = vec![0u8; count];
            reader.read_exact(&mut data).await?;
            let mut term = String::new();
            reader.read_line(&mut term).await?;
            let sources = String::from_utf8_lossy(&data).to_string();
            Ok(sources)
        } else {
            Err(std::io::Error::new(
                std::io::ErrorKind::NotConnected,
                "Not connected",
            ))
        }
    }

    pub async fn check_a_query_support(&mut self) -> std::io::Result<bool> {
        self.send_raw("!a\n").await?;
        let mut resp = String::new();
        if let Some(ref mut reader) = self.stream {
            reader.read_line(&mut resp).await?;
        }
        Ok(resp.starts_with("F Missing required set name"))
    }

    pub async fn query_sync(&mut self, cmd: &str) -> IrrdResult {
        self.send_raw(cmd).await?;
        self.read_response().await
    }

    pub async fn query_pipeline(&mut self, cmd: &str) -> IrrdResult {
        self.send_raw(cmd).await?;
        self.read_response().await
    }

    async fn send_raw(&mut self, cmd: &str) -> std::io::Result<()> {
        if let Some(ref mut w) = self.writer {
            w.write_all(cmd.as_bytes()).await?;
        }
        Ok(())
    }

    async fn read_response(&mut self) -> IrrdResult {
        if let Some(ref mut reader) = self.stream {
            let mut first_line = String::new();
            reader.read_line(&mut first_line).await?;
            let code = first_line.trim_end_matches(['\r', '\n']);

            match code.chars().next() {
                Some('A') => {
                    let n: usize = code[1..].trim().parse().map_err(|_| "bad byte count")?;
                    let mut data = vec![0u8; n];
                    reader.read_exact(&mut data).await?;
                    let mut _term = String::new();
                    reader.read_line(&mut _term).await?;
                    let items = String::from_utf8_lossy(&data)
                        .split_whitespace()
                        .map(String::from)
                        .collect();
                    Ok(IrrdResponse::Data(items))
                }
                Some('C') => Ok(IrrdResponse::Empty),
                Some('D') => Ok(IrrdResponse::NotFound),
                Some('E') => Ok(IrrdResponse::MultipleKeys),
                Some('F') => Ok(IrrdResponse::Error(code[1..].trim().to_string())),
                _ => Err("unexpected response".into()),
            }
        } else {
            Err("not connected".into())
        }
    }

    pub async fn quit(&mut self) -> std::io::Result<()> {
        if let Some(ref mut w) = self.writer {
            let _ = w.write_all(b"!q\n").await;
        }
        Ok(())
    }
}

impl Drop for IrrdClient {
    fn drop(&mut self) {}
}

#[derive(Debug, PartialEq)]
pub enum IrrdResponse {
    Data(Vec<String>),
    Empty,
    NotFound,
    MultipleKeys,
    Error(String),
}

pub type IrrdResult = Result<IrrdResponse, Box<dyn std::error::Error + Send + Sync>>;
