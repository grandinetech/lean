use std::sync::Arc;

use libp2p::Multiaddr;

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

#[derive(Debug, Clone, Default)]
pub struct StaticBootnodes(Vec<Multiaddr>);

impl StaticBootnodes {
    pub fn new<T: Into<Vec<Multiaddr>>>(addrs: T) -> Self {
        StaticBootnodes(addrs.into())
    }
}

impl BootnodeSource for StaticBootnodes {
    fn to_multiaddrs(&self) -> Vec<Multiaddr> {
        self.0.clone()
    }
}
