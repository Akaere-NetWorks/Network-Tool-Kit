use std::net::Ipv4Addr;
use std::sync::Arc;
use tokio::sync::Semaphore;

fn decode_output(bytes: &[u8]) -> String {
    #[cfg(windows)]
    {
        let (text, _, _) = encoding_rs::GBK.decode(bytes);
        text.into_owned()
    }
    #[cfg(not(windows))]
    String::from_utf8_lossy(bytes).into_owned()
}

pub struct PingResult {
    pub ip: Ipv4Addr,
    pub alive: bool,
    pub latency_ms: Option<u32>,
    pub raw_output: String,
    pub exit_code: Option<i32>,
}

pub fn parse_cidr(cidr: &str) -> Result<Vec<Ipv4Addr>, String> {
    let (addr_str, prefix_str) = cidr
        .split_once('/')
        .ok_or_else(|| format!("invalid CIDR: {cidr}"))?;

    let prefix: u32 = prefix_str
        .parse()
        .map_err(|_| format!("invalid prefix length: {prefix_str}"))?;

    if prefix > 32 {
        return Err(format!("prefix length {prefix} out of range"));
    }

    let base: u32 = addr_str
        .parse::<Ipv4Addr>()
        .map_err(|_| format!("invalid address: {addr_str}"))?
        .into();

    let mask = if prefix == 0 {
        0u32
    } else {
        !0u32 << (32 - prefix)
    };
    let network = base & mask;
    let count = 1u64 << (32 - prefix);

    Ok((0..count)
        .map(|i| Ipv4Addr::from(network + i as u32))
        .collect())
}

async fn ping_one(ip: Ipv4Addr, timeout_ms: u32, count: u32) -> PingResult {
    let count_str = count.to_string();
    let ip_str = ip.to_string();
    let output = if cfg!(target_os = "windows") {
        let timeout_str = timeout_ms.to_string();
        tokio::process::Command::new("ping")
            .args(["-n", &count_str, "-w", &timeout_str, &ip_str])
            .output()
            .await
    } else {
        let timeout_sec = timeout_ms.div_ceil(1000).max(1).to_string();
        tokio::process::Command::new("ping")
            .args(["-c", &count_str, "-W", &timeout_sec, &ip_str])
            .output()
            .await
    };

    let output = match output {
        Ok(o) => o,
        Err(e) => {
            return PingResult {
                ip,
                alive: false,
                latency_ms: None,
                raw_output: format!("failed to spawn ping: {e}"),
                exit_code: None,
            }
        }
    };

    let exit_code = output.status.code();
    let alive = output.status.success();
    let stdout = decode_output(&output.stdout);
    let stderr = decode_output(&output.stderr);

    let raw_output = if stderr.is_empty() {
        stdout.clone()
    } else {
        format!("{stdout}--- stderr ---\n{stderr}")
    };

    let latency_ms = if alive { parse_latency(&stdout) } else { None };

    PingResult {
        ip,
        alive,
        latency_ms,
        raw_output,
        exit_code,
    }
}

fn parse_latency(output: &str) -> Option<u32> {
    // Scan for patterns like "=12ms", "<1ms", "=12 ms" regardless of prefix.
    // This handles English ("time=12ms"), Chinese ("时间<1ms"), and locale variants.
    let bytes = output.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'=' || bytes[i] == b'<' {
            let start = i + 1;
            let mut end = start;
            while end < bytes.len() && bytes[end].is_ascii_digit() {
                end += 1;
            }
            if end > start {
                let mut j = end;
                while j < bytes.len() && bytes[j] == b' ' {
                    j += 1;
                }
                if bytes.get(j..j + 2) == Some(b"ms")
                    || bytes.get(j..j + 2) == Some(b"Ms")
                    || bytes.get(j..j + 2) == Some(b"MS")
                {
                    if let Ok(s) = std::str::from_utf8(&bytes[start..end]) {
                        if let Ok(n) = s.parse::<u32>() {
                            return Some(n);
                        }
                    }
                }
            } else if bytes[i] == b'<' {
                return Some(0);
            }
        }
        i += 1;
    }
    None
}

pub async fn scan(
    ips: Vec<Ipv4Addr>,
    timeout_ms: u32,
    count: u32,
    concurrency: usize,
    quiet: bool,
    debug: bool,
) -> Vec<PingResult> {
    let total = ips.len();
    let sem = Arc::new(Semaphore::new(concurrency));
    let counter = Arc::new(std::sync::atomic::AtomicUsize::new(0));

    let mut handles = Vec::with_capacity(total);

    for ip in ips {
        let sem = Arc::clone(&sem);
        let counter = Arc::clone(&counter);
        let handle = tokio::spawn(async move {
            let _permit = sem.acquire().await.unwrap();
            let result = ping_one(ip, timeout_ms, count).await;
            let done = counter.fetch_add(1, std::sync::atomic::Ordering::Relaxed) + 1;
            if debug {
                eprintln!(
                    "[DEBUG] [{done}/{total}] {} alive={} latency={:?} exit={:?}",
                    result.ip, result.alive, result.latency_ms, result.exit_code
                );
                for line in result.raw_output.lines() {
                    eprintln!("[DEBUG]   {line}");
                }
            } else if !quiet {
                eprint!("\rScanning... [{done}/{total}]");
            }
            result
        });
        handles.push(handle);
    }

    let mut results = Vec::with_capacity(total);
    for h in handles {
        if let Ok(r) = h.await {
            results.push(r);
        }
    }

    if !quiet && !debug {
        eprint!("\r{}\r", " ".repeat(30));
    }

    results.sort_by_key(|r| u32::from(r.ip));
    results
}
