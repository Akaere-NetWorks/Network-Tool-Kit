use std::collections::HashSet;
use std::pin::Pin;
use std::future::Future;
use std::sync::{Arc, Mutex};
use crate::irrd::{IrrdClient, IrrdError, IrrdResponse};
use crate::prefix::IpPrefix;

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum IpFamily { V4, V6 }

pub struct Expander {
    pub client: IrrdClient,
    pub family: IpFamily,
    pub max_depth: u32,
}

impl Expander {
    pub fn new(host: impl Into<String>, port: u16, family: IpFamily) -> Self {
        Expander {
            client: IrrdClient::new(host, port),
            family,
            max_depth: 25,
        }
    }

    pub async fn expand(&self, object: &str) -> Result<Vec<IpPrefix>, IrrdError> {
        let visited = Arc::new(Mutex::new(HashSet::new()));
        expand_recursive(self, object.to_string(), visited, 0).await
    }
}

fn expand_recursive<'a>(
    exp: &'a Expander,
    object: String,
    visited: Arc<Mutex<HashSet<String>>>,
    depth: u32,
) -> Pin<Box<dyn Future<Output = Result<Vec<IpPrefix>, IrrdError>> + Send + 'a>> {
    Box::pin(async move {
        {
            let mut guard = visited.lock().unwrap();
            if depth > exp.max_depth || !guard.insert(object.clone()) {
                return Ok(vec![]);
            }
        }

        if object.contains('-') {
            let resp = exp.client.query(&format!("!i{object}")).await?;
            let members = match resp {
                IrrdResponse::Data(items) => items,
                _ => return Ok(vec![]),
            };
            let mut prefixes = Vec::new();
            for member in members {
                let sub = expand_recursive(exp, member, visited.clone(), depth + 1).await?;
                prefixes.extend(sub);
            }
            Ok(prefixes)
        } else {
            let asn = object.strip_prefix("AS").unwrap_or(&object).to_string();
            let cmd = match exp.family {
                IpFamily::V4 => format!("!gAS{asn}"),
                IpFamily::V6 => format!("!6as{asn}"),
            };
            let resp = exp.client.query(&cmd).await?;
            match resp {
                IrrdResponse::Data(items) => Ok(
                    items.iter()
                        .filter_map(|s| IpPrefix::parse(s).ok())
                        .filter(|p| match exp.family {
                            IpFamily::V4 => p.is_ipv4(),
                            IpFamily::V6 => !p.is_ipv4(),
                        })
                        .collect()
                ),
                _ => Ok(vec![]),
            }
        }
    })
}
