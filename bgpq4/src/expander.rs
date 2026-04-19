use crate::config::{AsnTree, ExpanderConfig, Generation};
use crate::irrd::{IrrdClient, IrrdResponse};
use crate::prefix::{RadixTree, SxPrefix};
use crate::report;
use std::collections::{BTreeSet, HashSet};

pub struct Expander {
    pub config: ExpanderConfig,
    pub tree: RadixTree,
    pub asn_list: AsnTree,
    pub macroses: Vec<String>,
    pub rsets: Vec<String>,
    pub already: HashSet<String>,
    pub stoplist: HashSet<String>,
}

impl Expander {
    pub fn new(config: ExpanderConfig) -> Self {
        let family = config.family;
        Expander {
            tree: RadixTree::new(family),
            config,
            asn_list: BTreeSet::new(),
            macroses: Vec::new(),
            rsets: Vec::new(),
            already: HashSet::new(),
            stoplist: HashSet::new(),
        }
    }

    pub fn add_asset(&mut self, name: &str) {
        self.macroses.push(name.to_string());
    }

    pub fn add_rset(&mut self, name: &str) {
        self.rsets.push(name.to_string());
    }

    pub fn add_stop(&mut self, name: &str) -> bool {
        self.stoplist.insert(name.to_lowercase())
    }

    pub fn add_as(&mut self, as_str: &str) -> bool {
        crate::config::asn_add(&mut self.asn_list, as_str, self.config.expand_special_asn)
    }

    pub fn add_prefix(&mut self, prefix_str: &str) -> bool {
        let mut p = SxPrefix::new();
        if !p.parse(0, prefix_str) {
            report::error(&format!("Unable to parse prefix {prefix_str}"));
            return false;
        }
        if p.family != self.config.family {
            return false;
        }
        if self.config.maxlen > 0 && p.masklen > self.config.maxlen {
            return false;
        }
        self.tree.insert(&p);
        true
    }

    pub fn add_prefix_range(&mut self, prefix_str: &str) -> bool {
        self.tree.parse_range(0, self.config.maxlen, prefix_str)
    }

    pub fn add_object(&mut self, obj: &str) {
        let (_source_part, effective_obj) = if let Some(pos) = obj.find("::") {
            self.config.usesource = true;
            (&obj[..pos], &obj[pos + 2..])
        } else {
            ("", obj)
        };

        if !effective_obj.is_empty() {
            let upper = effective_obj.to_uppercase();
            if upper.starts_with("AS-") || upper.contains('-') && effective_obj.contains(':') {
                self.add_asset(obj);
            } else if upper.starts_with("RS-") {
                self.add_rset(obj);
            } else if upper.starts_with("AS") {
                let effective_upper = effective_obj.to_uppercase();
                if let Some(colon_pos) = effective_upper.find(':') {
                    let after_colon = &effective_upper[colon_pos + 1..];
                    if after_colon.starts_with("AS-") {
                        self.add_asset(obj);
                    } else if after_colon.starts_with("RS-") {
                        self.add_rset(obj);
                    }
                } else {
                    self.add_as(effective_obj);
                }
            } else {
                let has_caret = effective_obj.contains('^');
                if !has_caret && !self.add_prefix(effective_obj) {
                    report::error(&format!(
                        "Unable to add prefix {effective_obj} (bad prefix or address-family)"
                    ));
                    std::process::exit(1);
                } else if has_caret && !self.add_prefix_range(effective_obj) {
                    report::error(&format!(
                        "Unable to add prefix-range {effective_obj} (bad range or address-family)"
                    ));
                    std::process::exit(1);
                }
            }
        }
    }

    pub async fn expand(&mut self) -> bool {
        let server = self.config.server.clone();
        let port = self.config.port;
        let mut client = match IrrdClient::connect(&server, port).await {
            Ok(c) => c,
            Err(e) => {
                report::fatal(&format!("Unable to connect to {server}: {e}"));
            }
        };

        if self.config.identify {
            let _ = client.identify("bgpq4-rs").await;
        }

        let mut aquery = false;
        if self.config.generation >= Generation::PrefixList
            && !self.macroses.is_empty()
            && !self.config.usesource
        {
            aquery = client.check_a_query_support().await.unwrap_or(false);
        }

        if !self.config.sources.is_empty() {
            self.config.defaultsources = self.config.sources.clone();
        } else if let Ok(s) = client.get_sources_list().await {
            self.config.defaultsources = s;
        }

        if !self.config.sources.is_empty()
            && !client
                .set_sources(&self.config.sources)
                .await
                .unwrap_or(false)
        {
            report::fatal(&format!("Invalid source(s) '{}'", self.config.sources));
        }

        let mut rval = true;

        let macroses: Vec<String> = self.macroses.clone();
        let rsets: Vec<String> = self.rsets.clone();

        for mc in &macroses {
            let source = get_source(mc);
            let asset = get_asset(mc);

            if self.config.usesource {
                if let Some(ref src) = source {
                    client.set_sources(src).await.ok();
                } else {
                    client.set_sources(&self.config.defaultsources).await.ok();
                }
            }

            if self.config.maxdepth != 0 || !self.stoplist.is_empty() {
                self.already.insert(asset.to_lowercase());
                let cmd = format!("!i{asset}\n");
                let resp = client.query_sync(&cmd).await;
                if let Ok(IrrdResponse::Data(items)) = resp {
                    for item in items.into_iter().collect::<Vec<_>>() {
                        Box::pin(self.expanded_macro_limit(&item, &mut client, 0, &mut rval)).await;
                    }
                }
            } else if aquery {
                let family_prefix = if self.config.family == 2 { "4" } else { "6" };
                let cmd = format!("!a{family_prefix}{asset}\n");
                let resp = client.query_sync(&cmd).await;
                if let Ok(IrrdResponse::Data(items)) = resp {
                    for item in &items {
                        if item.contains('^') {
                            self.add_prefix_range(item);
                        } else {
                            self.add_prefix(item);
                        }
                    }
                }
            } else {
                let cmd = format!("!i{asset},1\n");
                let resp = client.query_sync(&cmd).await;
                if let Ok(IrrdResponse::Data(items)) = resp {
                    for item in &items {
                        self.expanded_macro(item, &mut rval);
                    }
                }
            }
        }

        if !self.config.sources.is_empty() || !self.config.defaultsources.is_empty() {
            client.set_sources(&self.config.defaultsources).await.ok();
        }

        if self.config.generation >= Generation::PrefixList || self.config.validate_asns {
            let asn_list: Vec<u32> = self.asn_list.iter().copied().collect();

            for rs in &rsets {
                let source = get_source(rs);
                let _rset = get_rset(rs);

                if self.config.usesource {
                    if let Some(ref src) = source {
                        client.set_sources(src).await.ok();
                    } else {
                        client.set_sources(&self.config.defaultsources).await.ok();
                    }
                }

                let cb_name = get_asset(rs);
                let cmd = format!("!i{cb_name},1\n");
                let resp = client.query_sync(&cmd).await;
                if let Ok(IrrdResponse::Data(items)) = resp {
                    for item in &items {
                        self.add_prefix(item);
                    }
                }
            }

            for asn in &asn_list {
                let cmd = if self.config.family == 10 {
                    format!("!6as{asn}\n")
                } else {
                    format!("!gas{asn}\n")
                };
                let resp = client.query_sync(&cmd).await;
                match resp {
                    Ok(IrrdResponse::Data(items)) => {
                        for item in &items {
                            if item.contains('^') {
                                self.add_prefix_range(item);
                            } else {
                                self.add_prefix(item);
                            }
                        }
                    }
                    Ok(IrrdResponse::NotFound) | Ok(IrrdResponse::Empty) => {
                        if self.config.validate_asns {}
                    }
                    _ => {}
                }
            }
        }

        let _ = client.quit().await;
        rval
    }

    fn expanded_macro(&mut self, as_str: &str, rval: &mut bool) {
        if !self.add_as(as_str) {
            *rval = false;
        }
    }

    async fn expanded_macro_limit(
        &mut self,
        as_str: &str,
        client: &mut IrrdClient,
        depth: u32,
        rval: &mut bool,
    ) {
        let upper = as_str.to_uppercase();
        if upper.starts_with("AS-") || as_str.contains('-') || as_str.contains(':') {
            let lower = as_str.to_lowercase();
            if self.already.contains(&lower) {
                return;
            }
            if self.stoplist.contains(&lower) {
                return;
            }

            if self.config.maxdepth == 0 || (depth + 1 < self.config.maxdepth) {
                self.already.insert(lower);
                let asset = get_asset(as_str);
                let cmd = format!("!i{asset}\n");
                let resp = client.query_sync(&cmd).await;
                if let Ok(IrrdResponse::Data(items)) = resp {
                    for item in items.into_iter().collect::<Vec<_>>() {
                        Box::pin(self.expanded_macro_limit(&item, client, depth + 1, rval)).await;
                    }
                }
            }
        } else if upper.starts_with("AS") {
            let lower = as_str.to_lowercase();
            if self.stoplist.contains(&lower) {
                return;
            }
            self.add_as(as_str);
        } else if upper == "ANY" {
        } else {
            report::error(&format!(
                "unexpected object '{as_str}' in expanded_macro_limit"
            ));
        }
    }
}

pub fn get_source(object: &str) -> Option<String> {
    object.find("::").map(|pos| object[..pos].to_string())
}

pub fn get_asset(object: &str) -> String {
    if let Some(pos) = object.find("::") {
        object[pos + 2..].to_string()
    } else {
        object.to_string()
    }
}

pub fn get_rset(object: &str) -> String {
    get_asset(object)
}
