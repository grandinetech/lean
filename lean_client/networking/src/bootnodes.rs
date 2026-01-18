use std::sync::Arc;

use discv5::enr::CombinedKey;
use enr::Enr;
use libp2p::Multiaddr;
use tracing::warn;

use crate::discovery::{DiscoveryService, parse_enr};

pub trait BootnodeSource: Send + Sync {
    fn to_multiaddrs(&self) -> Vec<Multiaddr>;
}

impl BootnodeSource for Vec<Multiaddr> {
    fn to_multiaddrs(&self) -> Vec<Multiaddr> {
        self.clone()
    }
}

impl BootnodeSource for &[Multiaddr] {
    fn to_multiaddrs(&self) -> Vec<Multiaddr> {
        self.to_vec()
    }
}

impl BootnodeSource for Arc<[Multiaddr]> {
    fn to_multiaddrs(&self) -> Vec<Multiaddr> {
        self.as_ref().to_vec()
    }
}

#[derive(Debug, Clone)]
pub enum Bootnode {
    Multiaddr(Multiaddr),
    Enr(Enr<CombinedKey>),
}

impl Bootnode {
    pub fn parse(s: &str) -> Option<Self> {
        if s.starts_with("enr:") {
            match parse_enr(s) {
                Ok(enr) => Some(Bootnode::Enr(enr)),
                Err(e) => {
                    warn!(bootnode = s, error = ?e, "Failed to parse ENR bootnode");
                    None
                }
            }
        } else {
            match s.parse::<Multiaddr>() {
                Ok(addr) => Some(Bootnode::Multiaddr(addr)),
                Err(e) => {
                    warn!(bootnode = s, error = ?e, "Failed to parse Multiaddr bootnode");
                    None
                }
            }
        }
    }

    pub fn to_multiaddr(&self) -> Option<Multiaddr> {
        match self {
            Bootnode::Multiaddr(addr) => Some(addr.clone()),
            Bootnode::Enr(enr) => DiscoveryService::enr_to_multiaddr(enr),
        }
    }

    pub fn as_enr(&self) -> Option<&Enr<CombinedKey>> {
        match self {
            Bootnode::Enr(enr) => Some(enr),
            Bootnode::Multiaddr(_) => None,
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct StaticBootnodes {
    multiaddrs: Vec<Multiaddr>,
    enrs: Vec<Enr<CombinedKey>>,
}

impl StaticBootnodes {
    pub fn new(bootnodes: Vec<Bootnode>) -> Self {
        let mut multiaddrs = Vec::new();
        let mut enrs = Vec::new();

        for bootnode in bootnodes {
            match bootnode {
                Bootnode::Multiaddr(addr) => multiaddrs.push(addr),
                Bootnode::Enr(enr) => {
                    // Convert ENR to multiaddr for libp2p connection
                    if let Some(addr) = DiscoveryService::enr_to_multiaddr(&enr) {
                        multiaddrs.push(addr);
                    }
                    enrs.push(enr);
                }
            }
        }

        StaticBootnodes { multiaddrs, enrs }
    }

    pub fn parse(bootnode_strs: &[String]) -> Self {
        let bootnodes: Vec<Bootnode> = bootnode_strs
            .iter()
            .filter_map(|s| Bootnode::parse(s))
            .collect();
        Self::new(bootnodes)
    }

    pub fn enrs(&self) -> &[Enr<CombinedKey>] {
        &self.enrs
    }
}

impl BootnodeSource for StaticBootnodes {
    fn to_multiaddrs(&self) -> Vec<Multiaddr> {
        self.multiaddrs.clone()
    }
}
