use std::{collections::HashMap, fmt::Display};

use anyhow::{Result, anyhow};
use async_trait::async_trait;
use containers::{SignedAttestation, SignedBlockWithAttestation};
use serde::Serialize;
use tokio::sync::mpsc;

use crate::serde_utils::quoted_u64;

pub const MESSAGE_DOMAIN_VALID_SNAPPY: &str = "0x01000000";
pub const MESSAGE_DOMAIN_INVALID_SNAPPY: &str = "0x00000000";

#[derive(Debug, Serialize, Clone, Copy, PartialEq, Eq, Hash)]
#[serde(rename_all = "lowercase")]
pub enum ConnectionState {
    Connected,
    Connecting,
    Disconnected,
    Disconnecting,
}

#[derive(Debug, Serialize, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Direction {
    Inbound,
    Outbound,
    Unknown,
}

#[derive(Default, Debug, Clone, Serialize)]
pub struct PeerCount {
    #[serde(with = "quoted_u64")]
    pub disconnected: u64,
    #[serde(with = "quoted_u64")]
    pub connecting: u64,
    #[serde(with = "quoted_u64")]
    pub connected: u64,
    #[serde(with = "quoted_u64")]
    pub disconnecting: u64,
}

impl PeerCount {
    pub fn new(states: &HashMap<libp2p_identity::PeerId, ConnectionState>) -> Self {
        let mut count = PeerCount::default();
        for state in states.values() {
            match state {
                ConnectionState::Connected => count.connected += 1,
                ConnectionState::Connecting => count.connecting += 1,
                ConnectionState::Disconnected => count.disconnected += 1,
                ConnectionState::Disconnecting => count.disconnecting += 1,
            }
        }
        count
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChainMessage {
    ProcessBlock {
        signed_block_with_attestation: SignedBlockWithAttestation,
        is_trusted: bool,
        should_gossip: bool,
    },
    ProcessAttestation {
        signed_attestation: SignedAttestation,
        is_trusted: bool,
        should_gossip: bool,
    },
}

impl ChainMessage {
    pub fn block_with_attestation(signed_block_with_attestation: SignedBlockWithAttestation) -> Self {
        ChainMessage::ProcessBlock {
            signed_block_with_attestation,
            is_trusted: false,
            should_gossip: true,
        }
    }

    pub fn attestation(signed_attestation: SignedAttestation) -> Self {
        ChainMessage::ProcessAttestation {
            signed_attestation,
            is_trusted: false,
            should_gossip: true,
        }
    }
}

impl Display for ChainMessage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ChainMessage::ProcessBlock { signed_block_with_attestation, .. } => {
                write!(f, "ProcessBlockWithAttestation(slot={})", signed_block_with_attestation.message.block.slot.0)
            }
            ChainMessage::ProcessAttestation { signed_attestation, .. } => {
                write!(f, "ProcessAttestation(slot={})", signed_attestation.message.data.slot.0)
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OutboundP2pRequest {
    GossipBlockWithAttestation(SignedBlockWithAttestation),
    GossipAttestation(SignedAttestation),
}

#[async_trait]
pub trait ChainMessageSink<M>: Send + Sync {
    async fn send(&self, message: M) -> Result<()>;
}

#[async_trait]
impl<M: Send + 'static> ChainMessageSink<M> for mpsc::UnboundedSender<M> {
    async fn send(&self, message: M) -> Result<()> {
        self.send(message)
            .map_err(|err| anyhow!("failed to send message to chain: {err}"))
    }
}

#[async_trait]
pub trait P2pRequestSource<T>: Send {
    async fn recv(&mut self) -> Option<T>;
}

#[async_trait]
impl<T: Send + 'static> P2pRequestSource<T> for mpsc::UnboundedReceiver<T> {
    async fn recv(&mut self) -> Option<T> {
        mpsc::UnboundedReceiver::recv(self).await
    }
}
