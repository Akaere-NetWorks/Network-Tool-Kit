use ipnet::{IpNet, Ipv4Net, Ipv6Net};
use std::str::FromStr;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct IpPrefix(pub IpNet);

impl IpPrefix {
    pub fn parse(s: &str) -> Result<Self, ipnet::AddrParseError> {
        let net = IpNet::from_str(s)?;
        Ok(IpPrefix(match net {
            IpNet::V4(n) => IpNet::V4(n.trunc()),
            IpNet::V6(n) => IpNet::V6(n.trunc()),
        }))
    }
    pub fn is_ipv4(&self) -> bool {
        matches!(self.0, IpNet::V4(_))
    }
}

impl std::fmt::Display for IpPrefix {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

pub fn aggregate(prefixes: Vec<IpPrefix>) -> Vec<IpPrefix> {
    let (mut v4, mut v6): (Vec<Ipv4Net>, Vec<Ipv6Net>) = (Vec::new(), Vec::new());
    for p in &prefixes {
        match p.0 {
            IpNet::V4(n) => v4.push(n),
            IpNet::V6(n) => v6.push(n),
        }
    }
    let v4 = aggregate_v4(v4);
    let v6 = aggregate_v6(v6);
    v4.into_iter()
        .map(|n| IpPrefix(IpNet::V4(n)))
        .chain(v6.into_iter().map(|n| IpPrefix(IpNet::V6(n))))
        .collect()
}

fn aggregate_v4(nets: Vec<Ipv4Net>) -> Vec<Ipv4Net> {
    aggregate_nets(nets)
}

fn aggregate_v6(nets: Vec<Ipv6Net>) -> Vec<Ipv6Net> {
    aggregate_nets(nets)
}

fn aggregate_nets<N>(mut nets: Vec<N>) -> Vec<N>
where
    N: Copy + Ord + std::hash::Hash + HasSupernet<N> + ContainsNet<N>,
{
    loop {
        nets.sort();
        nets.dedup();
        let before = nets.clone();
        nets.retain(|n| !before.iter().any(|sup| sup != n && sup.contains_net(n)));

        let mut merged = false;
        let mut result: Vec<N> = Vec::new();
        let mut used = vec![false; nets.len()];
        for i in 0..nets.len() {
            if used[i] {
                continue;
            }
            let mut found = false;
            for j in (i + 1)..nets.len() {
                if used[j] {
                    continue;
                }
                if let (Some(si), Some(sj)) = (nets[i].supernet(), nets[j].supernet()) {
                    if si == sj {
                        result.push(si);
                        used[i] = true;
                        used[j] = true;
                        merged = true;
                        found = true;
                        break;
                    }
                }
            }
            if !found {
                result.push(nets[i]);
            }
        }
        nets = result;
        if !merged {
            break;
        }
    }
    nets.sort();
    nets
}

trait HasSupernet<T> {
    fn supernet(&self) -> Option<T>;
}
trait ContainsNet<T> {
    fn contains_net(&self, other: &T) -> bool;
}

impl HasSupernet<Ipv4Net> for Ipv4Net {
    fn supernet(&self) -> Option<Ipv4Net> {
        Ipv4Net::supernet(self)
    }
}
impl HasSupernet<Ipv6Net> for Ipv6Net {
    fn supernet(&self) -> Option<Ipv6Net> {
        Ipv6Net::supernet(self)
    }
}
impl ContainsNet<Ipv4Net> for Ipv4Net {
    fn contains_net(&self, other: &Ipv4Net) -> bool {
        self.contains(other)
    }
}
impl ContainsNet<Ipv6Net> for Ipv6Net {
    fn contains_net(&self, other: &Ipv6Net) -> bool {
        self.contains(other)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_ipv4() {
        let p = IpPrefix::parse("192.168.0.0/24").unwrap();
        assert_eq!(p.to_string(), "192.168.0.0/24");
        assert!(p.is_ipv4());
    }

    #[test]
    fn parse_ipv6() {
        let p = IpPrefix::parse("2001:db8::/32").unwrap();
        assert_eq!(p.to_string(), "2001:db8::/32");
        assert!(!p.is_ipv4());
    }

    #[test]
    fn parse_invalid() {
        assert!(IpPrefix::parse("192.168.0.0/33").is_err());
        assert!(IpPrefix::parse("not-a-prefix").is_err());
    }

    #[test]
    fn host_bits_zeroed() {
        let p = IpPrefix::parse("192.168.0.1/24").unwrap();
        assert_eq!(p.to_string(), "192.168.0.0/24");
    }

    #[test]
    fn aggregate_dedup() {
        let p = IpPrefix::parse("10.0.0.0/8").unwrap();
        let result = aggregate(vec![p.clone(), p.clone()]);
        assert_eq!(result, vec![IpPrefix::parse("10.0.0.0/8").unwrap()]);
    }

    #[test]
    fn aggregate_removes_subnet() {
        let supernet = IpPrefix::parse("10.0.0.0/8").unwrap();
        let subnet = IpPrefix::parse("10.1.0.0/24").unwrap();
        let result = aggregate(vec![supernet.clone(), subnet]);
        assert_eq!(result, vec![supernet]);
    }

    #[test]
    fn aggregate_merges_siblings() {
        let lo = IpPrefix::parse("192.168.0.0/25").unwrap();
        let hi = IpPrefix::parse("192.168.0.128/25").unwrap();
        let result = aggregate(vec![lo, hi]);
        assert_eq!(result, vec![IpPrefix::parse("192.168.0.0/24").unwrap()]);
    }

    #[test]
    fn aggregate_ipv6_siblings() {
        let lo = IpPrefix::parse("2001:db8::/33").unwrap();
        let hi = IpPrefix::parse("2001:db8:8000::/33").unwrap();
        let result = aggregate(vec![lo, hi]);
        assert_eq!(result, vec![IpPrefix::parse("2001:db8::/32").unwrap()]);
    }
}
