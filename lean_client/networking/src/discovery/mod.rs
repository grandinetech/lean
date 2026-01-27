pub mod config;

#[cfg(test)]
mod tests;

use std::net::IpAddr;
use std::sync::Arc;

use anyhow::{Result, anyhow};
use discv5::enr::{CombinedKey, NodeId};
use discv5::{ConfigBuilder, Discv5, Event as Discv5Event, ListenConfig};
use enr::{Builder as EnrBuilder, Enr};
use libp2p::Multiaddr;
use libp2p::multiaddr::Protocol;
use libp2p_identity::{Keypair, PeerId};
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

use crate::enr_ext::EnrExt;

pub use config::DiscoveryConfig;

/// Discovery service that wraps discv5 for peer discovery.
pub struct DiscoveryService {
    discv5: Arc<Discv5>,
    local_enr: Enr<CombinedKey>,
    event_receiver: mpsc::Receiver<Discv5Event>,
}

impl DiscoveryService {
    pub async fn new(config: DiscoveryConfig, keypair: &Keypair) -> Result<Self> {
        let enr_key = keypair_to_enr_key(keypair)?;

        let local_enr = build_enr(
            &enr_key,
            config.listen_address,
            config.udp_port,
            config.libp2p_port,
        )?;

        info!(
            enr = %local_enr,
            node_id = %local_enr.node_id(),
            "Built local ENR"
        );

        let listen_config = ListenConfig::from_ip(config.listen_address, config.udp_port);

        let discv5_config = ConfigBuilder::new(listen_config).build();

        let mut discv5 = Discv5::new(local_enr.clone(), enr_key, discv5_config)
            .map_err(|e| anyhow!("Failed to create discv5: {e}"))?;

        for bootnode in &config.bootnodes {
            if let Err(e) = discv5.add_enr(bootnode.clone()) {
                warn!(enr = %bootnode, error = ?e, "Failed to add bootnode ENR");
            } else {
                info!(enr = %bootnode, "Added bootnode ENR");
            }
        }

        discv5
            .start()
            .await
            .map_err(|e| anyhow!("Failed to start discv5: {e}"))?;

        let event_receiver = discv5
            .event_stream()
            .await
            .map_err(|e| anyhow!("Failed to get discv5 event stream: {e}"))?;

        info!("Discovery service started");

        Ok(Self {
            discv5: Arc::new(discv5),
            local_enr,
            event_receiver,
        })
    }

    pub fn local_enr(&self) -> &Enr<CombinedKey> {
        &self.local_enr
    }

    pub async fn recv(&mut self) -> Option<Enr<CombinedKey>> {
        loop {
            match self.event_receiver.recv().await {
                Some(event) => {
                    match event {
                        Discv5Event::Discovered(enr) => {
                            info!(
                                node_id = %enr.node_id(),
                                "Discovered peer via discv5"
                            );
                            return Some(enr);
                        }
                        Discv5Event::SocketUpdated(addr) => {
                            info!(?addr, "discv5 socket updated");
                        }
                        Discv5Event::SessionEstablished(enr, addr) => {
                            debug!(
                                node_id = %enr.node_id(),
                                ?addr,
                                "discv5 session established"
                            );
                        }
                        Discv5Event::TalkRequest(_) => {
                            // We don't handle TALKREQ for now
                        }
                        Discv5Event::NodeInserted { node_id, replaced } => {
                            debug!(
                                %node_id,
                                ?replaced,
                                "Node inserted into routing table"
                            );
                        }
                        _ => {
                            // Handle any new event types added in future versions
                        }
                    }
                }
                None => return None,
            }
        }
    }

    pub fn enr_to_multiaddr(enr: &Enr<CombinedKey>) -> Option<Multiaddr> {
        let ip = enr
            .ip4()
            .map(IpAddr::V4)
            .or_else(|| enr.ip6().map(IpAddr::V6))?;

        // Try TCP ports first (lean_client stores QUIC port in TCP field),
        // then fall back to QUIC ports (genesis tools may use quic field directly)
        let libp2p_port = enr
            .tcp4()
            .or_else(|| enr.tcp6())
            .or_else(|| enr.quic4())
            .or_else(|| enr.quic6())?;

        let peer_id = enr_to_peer_id(enr)?;

        let mut multiaddr: Multiaddr = ip.into();
        multiaddr.push(Protocol::Udp(libp2p_port));
        multiaddr.push(Protocol::QuicV1);
        multiaddr.push(Protocol::P2p(peer_id));

        Some(multiaddr)
    }

    pub fn find_random_peers(&self) {
        let random_node_id = generate_random_node_id();
        debug!(%random_node_id, "Starting random peer discovery lookup");

        let discv5 = Arc::clone(&self.discv5);
        tokio::spawn(async move {
            match discv5.find_node(random_node_id).await {
                Ok(nodes) => {
                    info!(count = nodes.len(), "Random lookup completed");
                }
                Err(e) => {
                    warn!(error = ?e, "Random lookup failed");
                }
            }
        });
    }

    pub fn connected_peers(&self) -> usize {
        self.discv5.connected_peers()
    }
}

fn keypair_to_enr_key(keypair: &Keypair) -> Result<CombinedKey> {
    match keypair.key_type() {
        libp2p_identity::KeyType::Secp256k1 => {
            let secp_keypair = keypair
                .clone()
                .try_into_secp256k1()
                .map_err(|_| anyhow!("Failed to convert to secp256k1"))?;

            let secret_bytes = secp_keypair.secret().to_bytes();
            let secret_key = k256::ecdsa::SigningKey::from_slice(&secret_bytes)
                .map_err(|e| anyhow!("Failed to create signing key: {e}"))?;

            Ok(CombinedKey::Secp256k1(secret_key))
        }
        other => Err(anyhow!("Unsupported key type for discv5: {:?}", other)),
    }
}

fn build_enr(
    key: &CombinedKey,
    ip: IpAddr,
    udp_port: u16,
    libp2p_port: u16,
) -> Result<Enr<CombinedKey>> {
    let mut builder = EnrBuilder::default();

    // libp2p port is stored in tcp field, since Enr doesn't have a field for a quic port
    match ip {
        IpAddr::V4(ipv4) => {
            builder.ip4(ipv4);
            builder.udp4(udp_port);
            builder.tcp4(libp2p_port);
        }
        IpAddr::V6(ipv6) => {
            builder.ip6(ipv6);
            builder.udp6(udp_port);
            builder.tcp6(libp2p_port);
        }
    }

    builder
        .build(key)
        .map_err(|e| anyhow!("Failed to build ENR: {e}"))
}

fn enr_to_peer_id(enr: &Enr<CombinedKey>) -> Option<PeerId> {
    let public_key = enr.public_key();

    match public_key {
        discv5::enr::CombinedPublicKey::Secp256k1(pk) => {
            let compressed = pk.to_sec1_bytes();
            let libp2p_pk =
                libp2p_identity::secp256k1::PublicKey::try_from_bytes(&compressed).ok()?;
            let public = libp2p_identity::PublicKey::from(libp2p_pk);
            Some(PeerId::from_public_key(&public))
        }
        _ => None,
    }
}

pub fn parse_enr(enr_str: &str) -> Result<Enr<CombinedKey>> {
    enr_str
        .parse()
        .map_err(|e| anyhow!("Failed to parse ENR: {e}"))
}

fn generate_random_node_id() -> NodeId {
    let random_bytes: [u8; 32] = rand::random();
    NodeId::new(&random_bytes)
}
