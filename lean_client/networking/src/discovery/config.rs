use std::net::IpAddr;

use discv5::enr::CombinedKey;
use enr::Enr;

#[derive(Debug, Clone)]
pub struct DiscoveryConfig {
    pub enabled: bool,
    pub udp_port: u16,
    pub libp2p_port: u16,
    pub listen_address: IpAddr,
    pub bootnodes: Vec<Enr<CombinedKey>>,
}

impl DiscoveryConfig {
    pub fn new(listen_address: IpAddr, udp_port: u16, libp2p_port: u16) -> Self {
        Self {
            enabled: true,
            udp_port,
            libp2p_port,
            listen_address,
            bootnodes: Vec::new(),
        }
    }

    pub fn with_bootnodes(mut self, bootnodes: Vec<Enr<CombinedKey>>) -> Self {
        self.bootnodes = bootnodes;
        self
    }

    pub fn disabled() -> Self {
        Self {
            enabled: false,
            udp_port: 0,
            libp2p_port: 0,
            listen_address: IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED),
            bootnodes: Vec::new(),
        }
    }
}
