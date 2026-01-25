use std::{
    collections::HashMap,
    fs::File,
    net::IpAddr,
    num::{NonZeroU8, NonZeroUsize},
    sync::Arc,
    sync::atomic::{AtomicU64, Ordering},
};

use anyhow::{Result, anyhow};
use containers::ssz::SszWrite;
use derive_more::Display;
use discv5::Enr;
use futures::StreamExt;
use libp2p::{
    Multiaddr, SwarmBuilder,
    connection_limits::{self, ConnectionLimits},
    gossipsub::{Event, IdentTopic, MessageAuthenticity},
    identify,
    multiaddr::Protocol,
    swarm::{Config, Swarm, SwarmEvent},
};
use libp2p_identity::{Keypair, PeerId};
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use tokio::select;
use tokio::time::{Duration, MissedTickBehavior, interval};
use tracing::{debug, info, trace, warn};

use crate::{
    bootnodes::{BootnodeSource, StaticBootnodes},
    compressor::Compressor,
    enr_ext::EnrExt,
    gossipsub::{self, config::GossipsubConfig, message::GossipsubMessage, topic::GossipsubKind},
    network::behaviour::{LeanNetworkBehaviour, LeanNetworkBehaviourEvent},
    req_resp::{self, BLOCKS_BY_ROOT_PROTOCOL_V1, LeanRequest, ReqRespMessage, STATUS_PROTOCOL_V1},
    types::{
        ChainMessage, ChainMessageSink, ConnectionState, OutboundP2pRequest, P2pRequestSource,
    },
};

#[derive(Debug, Clone)]
pub struct NetworkServiceConfig {
    pub gossipsub_config: GossipsubConfig,
    pub socket_address: IpAddr,
    pub socket_port: u16,
    bootnodes: StaticBootnodes,
}

#[derive(Debug, Clone, Serialize, Deserialize, Display)]
#[serde(untagged)]
enum Bootnode {
    Multiaddr(Multiaddr),
    Enr(Enr),
}

impl Bootnode {
    fn addrs(&self) -> Vec<Multiaddr> {
        match self {
            Self::Multiaddr(addr) => vec![addr.clone()],
            Self::Enr(enr) => enr.multiaddr_quic(),
        }
    }
}

fn parse_bootnode_argument(arg: &str) -> Vec<Bootnode> {
    if let Some(value) = arg.parse::<Multiaddr>().ok() {
        return vec![Bootnode::Multiaddr(value)];
    };

    if let Some(rec) = arg.parse::<Enr>().ok() {
        return vec![Bootnode::Enr(rec)];
    }

    let Some(file) = File::open(&arg).ok() else {
        warn!(
            "value {arg:?} provided as bootnode is not recognized - it is not valid multiaddr nor valid path to file containing bootnodes."
        );

        return Vec::new();
    };

    let bootnodes: Vec<Bootnode> = match serde_yaml::from_reader(file) {
        Ok(value) => value,
        Err(err) => {
            warn!("failed to read bootnodes from {arg:?}: {err:?}");

            return Vec::new();
        }
    };

    if bootnodes.is_empty() {
        warn!("provided file with bootnodes {arg:?} is empty");
    }

    bootnodes
}

impl NetworkServiceConfig {
    pub fn new(
        gossipsub_config: GossipsubConfig,
        socket_address: IpAddr,
        socket_port: u16,
        bootnodes: Vec<String>,
    ) -> Self {
        let bootnodes = StaticBootnodes::new(
            bootnodes
                .iter()
                .flat_map(|addr_str| parse_bootnode_argument(&addr_str))
                .flat_map(|bootnode| {
                    let addrs = bootnode.addrs();
                    if addrs.is_empty() {
                        warn!("bootnode {bootnode} doesn't have valid address to dial");
                    }

                    addrs
                })
                .collect::<Vec<Multiaddr>>(),
        );

        NetworkServiceConfig {
            gossipsub_config,
            socket_address,
            socket_port,
            bootnodes,
        }
    }
}

#[derive(Debug)]
pub enum NetworkEvent {
    PeerConnectedIncoming(PeerId),
    PeerConnectedOutgoing(PeerId),
    PeerDisconnected(PeerId),
    Status(PeerId),
    Ping(PeerId),
    MetaData(PeerId),
    DisconnectPeer(PeerId),
}

pub struct NetworkService<R, S>
where
    R: P2pRequestSource<OutboundP2pRequest> + Send + 'static,
    S: ChainMessageSink<ChainMessage> + Send + 'static,
{
    network_config: Arc<NetworkServiceConfig>,
    swarm: Swarm<LeanNetworkBehaviour>,
    peer_table: Arc<Mutex<HashMap<PeerId, ConnectionState>>>,
    peer_count: Arc<AtomicU64>,
    outbound_p2p_requests: R,
    chain_message_sink: S,
}

impl<R, S> NetworkService<R, S>
where
    R: P2pRequestSource<OutboundP2pRequest> + Send + 'static,
    S: ChainMessageSink<ChainMessage> + Send + 'static,
{
    pub async fn new(
        network_config: Arc<NetworkServiceConfig>,
        outbound_p2p_requests: R,
        chain_message_sink: S,
    ) -> Result<Self> {
        Self::new_with_peer_count(
            network_config,
            outbound_p2p_requests,
            chain_message_sink,
            Arc::new(AtomicU64::new(0)),
        )
        .await
    }

    pub async fn new_with_peer_count(
        network_config: Arc<NetworkServiceConfig>,
        outbound_p2p_requests: R,
        chain_message_sink: S,
        peer_count: Arc<AtomicU64>,
    ) -> Result<Self> {
        let local_key = Keypair::generate_secp256k1();
        Self::new_with_keypair(
            network_config,
            outbound_p2p_requests,
            chain_message_sink,
            peer_count,
            local_key,
        )
        .await
    }

    pub async fn new_with_keypair(
        network_config: Arc<NetworkServiceConfig>,
        outbound_p2p_requests: R,
        chain_message_sink: S,
        peer_count: Arc<AtomicU64>,
        local_key: Keypair,
    ) -> Result<Self> {
        let behaviour = Self::build_behaviour(&local_key, &network_config)?;

        let config = Config::with_tokio_executor()
            .with_notify_handler_buffer_size(NonZeroUsize::new(7).unwrap())
            .with_per_connection_event_buffer_size(4)
            .with_dial_concurrency_factor(NonZeroU8::new(1).unwrap());

        let multiaddr = Self::multiaddr(&network_config)?;
        let swarm = SwarmBuilder::with_existing_identity(local_key.clone())
            .with_tokio()
            .with_quic()
            .with_behaviour(|_| behaviour)?
            .with_swarm_config(|_| config)
            .build();

        let mut service = Self {
            network_config,
            swarm,
            peer_table: Arc::new(Mutex::new(HashMap::new())),
            peer_count,
            outbound_p2p_requests,
            chain_message_sink,
        };

        service.listen(&multiaddr)?;
        service.subscribe_to_topics()?;

        Ok(service)
    }

    pub async fn start(&mut self) -> Result<()> {
        // Periodic reconnect attempts to bootnodes
        let mut reconnect_interval = interval(Duration::from_secs(30));
        reconnect_interval.set_missed_tick_behavior(MissedTickBehavior::Skip);
        loop {
            select! {
                _ = reconnect_interval.tick() => {
                    self.connect_to_peers(self.network_config.bootnodes.to_multiaddrs()).await;
                }
                request = self.outbound_p2p_requests.recv() => {
                    if let Some(request) = request {
                        self.dispatch_outbound_request(request).await;
                    }
                }
                event = self.swarm.select_next_some() => {
                    if let Some(event) = self.parse_swarm_event(event).await {
                        info!(?event, "Swarm event");
                    }
                }
            }
        }
    }

    async fn parse_swarm_event(
        &mut self,
        event: SwarmEvent<LeanNetworkBehaviourEvent>,
    ) -> Option<NetworkEvent> {
        match event {
            SwarmEvent::Behaviour(LeanNetworkBehaviourEvent::Gossipsub(event)) => {
                self.handle_gossipsub_event(event).await
            }
            SwarmEvent::Behaviour(LeanNetworkBehaviourEvent::ReqResp(event)) => {
                self.handle_request_response_event(event)
            }
            SwarmEvent::Behaviour(LeanNetworkBehaviourEvent::Identify(event)) => {
                self.handle_identify_event(event)
            }
            SwarmEvent::Behaviour(_) => {
                // ConnectionLimits behaviour has no events
                None
            }
            SwarmEvent::ConnectionEstablished {
                peer_id, endpoint, ..
            } => {
                self.peer_table
                    .lock()
                    .insert(peer_id, ConnectionState::Connected);

                let connected = self
                    .peer_table
                    .lock()
                    .values()
                    .filter(|s| **s == ConnectionState::Connected)
                    .count() as u64;
                self.peer_count.store(connected, Ordering::Relaxed);

                info!(peer = %peer_id, "Connected to peer (total: {})", connected);

                if endpoint.is_dialer() {
                    self.send_status_request(peer_id);
                }

                None
            }
            SwarmEvent::ConnectionClosed { peer_id, .. } => {
                self.peer_table
                    .lock()
                    .insert(peer_id, ConnectionState::Disconnected);

                let connected = self
                    .peer_table
                    .lock()
                    .values()
                    .filter(|s| **s == ConnectionState::Connected)
                    .count() as u64;
                self.peer_count.store(connected, Ordering::Relaxed);

                info!(peer = %peer_id, "Disconnected from peer (total: {})", connected);
                Some(NetworkEvent::PeerDisconnected(peer_id))
            }
            SwarmEvent::IncomingConnection { local_addr, .. } => {
                info!(?local_addr, "Incoming connection");
                None
            }
            SwarmEvent::Dialing { peer_id, .. } => {
                info!(?peer_id, "Dialing peer");
                peer_id.map(NetworkEvent::PeerConnectedOutgoing)
            }
            SwarmEvent::OutgoingConnectionError { peer_id, error, .. } => {
                warn!(?peer_id, ?error, "Failed to connect to peer");
                None
            }
            SwarmEvent::NewListenAddr {
                listener_id,
                address,
            } => {
                info!(?listener_id, ?address, "New listen address");
                None
            }
            SwarmEvent::NewExternalAddrCandidate { address } => {
                info!(?address, "New external address candidate");
                // Optionally confirm it as an external address so other peers can reach us
                self.swarm.add_external_address(address);
                None
            }
            SwarmEvent::ExternalAddrConfirmed { address } => {
                info!(?address, "External address confirmed");
                None
            }
            SwarmEvent::ExternalAddrExpired { address } => {
                info!(?address, "External address expired");
                None
            }
            _ => {
                info!(?event, "Unhandled swarm event");
                None
            }
        }
    }

    async fn handle_gossipsub_event(&mut self, event: Event) -> Option<NetworkEvent> {
        match event {
            Event::Subscribed { peer_id, topic } => {
                info!(peer = %peer_id, topic = %topic, "A peer subscribed to topic");
            }
            Event::Unsubscribed { peer_id, topic } => {
                info!(peer = %peer_id, topic = %topic, "A peer unsubscribed from topic");
            }

            Event::Message { message, .. } => {
                match GossipsubMessage::decode(&message.topic, &message.data) {
                    Ok(GossipsubMessage::Block(signed_block_with_attestation)) => {
                        let slot = signed_block_with_attestation.message.block.slot.0;

                        if let Err(err) = self
                            .chain_message_sink
                            .send(ChainMessage::ProcessBlock {
                                signed_block_with_attestation,
                                is_trusted: false,
                                should_gossip: true,
                            })
                            .await
                        {
                            warn!(
                                "failed to send block with attestation for slot {slot} to chain: {err:?}"
                            );
                        }
                    }
                    Ok(GossipsubMessage::Attestation(signed_attestation)) => {
                        let slot = signed_attestation.message.slot.0;

                        if let Err(err) = self
                            .chain_message_sink
                            .send(ChainMessage::ProcessAttestation {
                                signed_attestation: signed_attestation,
                                is_trusted: false,
                                should_gossip: true,
                            })
                            .await
                        {
                            warn!("failed to send vote for slot {slot} to chain: {err:?}");
                        }
                    }
                    Err(err) => {
                        warn!(%err, topic = %message.topic, "gossip decode failed");
                    }
                }
            }
            _ => {
                info!(?event, "Unhandled gossipsub event");
            }
        }
        None
    }

    fn handle_request_response_event(&mut self, event: ReqRespMessage) -> Option<NetworkEvent> {
        use crate::req_resp::LeanResponse;
        use libp2p::request_response::{Event, Message};

        match event {
            Event::Message { peer, message, .. } => match message {
                Message::Response { response, .. } => {
                    match response {
                        LeanResponse::BlocksByRoot(blocks) => {
                            info!(
                                peer = %peer,
                                num_blocks = blocks.len(),
                                "Received BlocksByRoot response"
                            );

                            // Feed received blocks back into chain processing
                            let chain_sink = self.chain_message_sink.clone();
                            tokio::spawn(async move {
                                for block in blocks {
                                    let slot = block.message.block.slot.0;
                                    if let Err(e) = chain_sink
                                        .send(ChainMessage::ProcessBlock {
                                            signed_block_with_attestation: block,
                                            is_trusted: false,
                                            should_gossip: false, // Don't re-gossip requested blocks
                                        })
                                        .await
                                    {
                                        warn!(
                                            slot = slot,
                                            ?e,
                                            "Failed to send requested block to chain"
                                        );
                                    } else {
                                        debug!(
                                            slot = slot,
                                            "Queued requested block for processing"
                                        );
                                    }
                                }
                            });
                        }
                        LeanResponse::Status(_) => {
                            info!(peer = %peer, "Received Status response");
                        }
                        LeanResponse::Empty => {
                            warn!(peer = %peer, "Received empty response");
                        }
                    }
                }
                Message::Request {
                    request, channel, ..
                } => {
                    use crate::req_resp::{LeanRequest, LeanResponse};

                    let response = match request {
                        LeanRequest::Status(_) => {
                            info!(peer = %peer, "Received Status request");
                            LeanResponse::Status(containers::Status::default())
                        }
                        LeanRequest::BlocksByRoot(roots) => {
                            info!(peer = %peer, num_roots = roots.len(), "Received BlocksByRoot request");
                            // TODO: Lookup blocks from our store and return them
                            // For now, return empty to prevent timeout
                            LeanResponse::BlocksByRoot(vec![])
                        }
                    };

                    if let Err(e) = self
                        .swarm
                        .behaviour_mut()
                        .req_resp
                        .send_response(channel, response)
                    {
                        warn!(peer = %peer, ?e, "Failed to send response");
                    }
                }
            },
            Event::OutboundFailure { peer, error, .. } => {
                warn!(peer = %peer, ?error, "Request failed");
            }
            Event::InboundFailure { peer, error, .. } => {
                warn!(peer = %peer, ?error, "Inbound request failed");
            }
            Event::ResponseSent { peer, .. } => {
                trace!(peer = %peer, "Response sent");
            }
        }
        None
    }

    fn handle_identify_event(&mut self, event: identify::Event) -> Option<NetworkEvent> {
        match event {
            identify::Event::Received {
                peer_id,
                info,
                connection_id: _,
            } => {
                info!(
                    peer = %peer_id,
                    agent_version = %info.agent_version,
                    protocol_version = %info.protocol_version,
                    listen_addrs = info.listen_addrs.len(),
                    protocols = info.protocols.len(),
                    "Received peer info"
                );

                None
            }
            identify::Event::Sent {
                peer_id,
                connection_id: _,
            } => {
                info!(peer = %peer_id, "Sent identify info");
                None
            }
            identify::Event::Pushed { peer_id, .. } => {
                info!(peer = %peer_id, "Pushed identify update");
                None
            }
            identify::Event::Error {
                peer_id,
                error,
                connection_id: _,
            } => {
                warn!(peer = %peer_id, ?error, "Identify error");
                None
            }
        }
    }

    async fn connect_to_peers(&mut self, peers: Vec<Multiaddr>) {
        info!(?peers, "Discovered peers");
        for peer in peers {
            if let Some(Protocol::P2p(peer_id)) = peer
                .iter()
                .find(|protocol| matches!(protocol, Protocol::P2p(_)))
                && peer_id != self.local_peer_id()
            {
                let current_state = self.peer_table.lock().get(&peer_id).cloned();
                if !matches!(
                    current_state,
                    Some(ConnectionState::Disconnected | ConnectionState::Connecting) | None
                ) {
                    trace!(?peer_id, "Already connected");
                    continue;
                }

                if let Err(err) = self.swarm.dial(peer.clone()) {
                    warn!(?err, "Failed to dial peer");
                    continue;
                }

                info!(peer = %peer_id, "Dialing peer");
                self.peer_table
                    .lock()
                    .insert(peer_id, ConnectionState::Connecting);
            }
        }
    }

    fn get_random_connected_peer(&self) -> Option<PeerId> {
        let peers: Vec<PeerId> = self
            .peer_table
            .lock()
            .iter()
            .filter(|(_, state)| **state == ConnectionState::Connected)
            .map(|(peer_id, _)| *peer_id)
            .collect();

        if peers.is_empty() {
            None
        } else {
            use rand::seq::SliceRandom;
            peers.choose(&mut rand::thread_rng()).copied()
        }
    }

    async fn dispatch_outbound_request(&mut self, request: OutboundP2pRequest) {
        match request {
            OutboundP2pRequest::GossipBlockWithAttestation(signed_block_with_attestation) => {
                let slot = signed_block_with_attestation.message.block.slot.0;
                match signed_block_with_attestation.to_ssz() {
                    Ok(bytes) => {
                        if let Err(err) = self.publish_to_topic(GossipsubKind::Block, bytes) {
                            // Duplicate errors are expected - we receive our own blocks back from peers
                            let err_str = format!("{:?}", err);
                            if !err_str.contains("Duplicate") {
                                warn!(slot = slot, ?err, "Publish block with attestation failed");
                            }
                        } else {
                            info!(slot = slot, "Broadcasted block with attestation");
                        }
                    }
                    Err(err) => {
                        warn!(slot = slot, ?err, "Serialize block with attestation failed");
                    }
                }
            }
            OutboundP2pRequest::GossipAttestation(signed_attestation) => {
                let slot = signed_attestation.message.slot.0;

                match signed_attestation.to_ssz() {
                    Ok(bytes) => {
                        if let Err(err) = self.publish_to_topic(GossipsubKind::Attestation, bytes) {
                            // Duplicate errors are expected - we receive our own attestations back from peers
                            let err_str = format!("{:?}", err);
                            if !err_str.contains("Duplicate") {
                                warn!(slot = slot, ?err, "Publish attestation failed");
                            }
                        } else {
                            info!(slot = slot, "Broadcasted attestation");
                        }
                    }
                    Err(err) => {
                        warn!(slot = slot, ?err, "Serialize attestation failed");
                    }
                }
            }
            OutboundP2pRequest::RequestBlocksByRoot(roots) => {
                if let Some(peer_id) = self.get_random_connected_peer() {
                    info!(
                        peer = %peer_id,
                        num_blocks = roots.len(),
                        "Requesting missing blocks from peer"
                    );
                    self.send_blocks_by_root_request(peer_id, roots);
                } else {
                    warn!("Cannot request blocks: no connected peers");
                }
            }
        }
    }

    fn publish_to_topic(&mut self, kind: GossipsubKind, data: Vec<u8>) -> Result<()> {
        let topic = self
            .network_config
            .gossipsub_config
            .topics
            .iter()
            .find(|topic| topic.kind == kind)
            .cloned()
            .ok_or_else(|| anyhow!("Missing gossipsub topic for kind {kind:?}"))?;

        self.swarm
            .behaviour_mut()
            .gossipsub
            .publish(IdentTopic::from(topic), data)
            .map(|_| ())
            .map_err(|err| anyhow!("publish failed: {err:?}"))
    }

    pub fn peer_table(&self) -> Arc<Mutex<HashMap<PeerId, ConnectionState>>> {
        self.peer_table.clone()
    }

    pub fn local_peer_id(&self) -> PeerId {
        *self.swarm.local_peer_id()
    }

    pub fn swarm_mut(&mut self) -> &mut Swarm<LeanNetworkBehaviour> {
        &mut self.swarm
    }

    fn send_status_request(&mut self, peer_id: PeerId) {
        let status = containers::Status::default();
        let request = LeanRequest::Status(status);

        info!(peer = %peer_id, "Sending Status request for handshake");
        let _request_id = self
            .swarm
            .behaviour_mut()
            .req_resp
            .send_request(&peer_id, request);
    }

    pub fn send_blocks_by_root_request(
        &mut self,
        peer_id: PeerId,
        roots: Vec<containers::Bytes32>,
    ) {
        if roots.is_empty() {
            return;
        }

        if roots.len() > req_resp::MAX_REQUEST_BLOCKS {
            warn!(
                peer = %peer_id,
                requested = roots.len(),
                max = req_resp::MAX_REQUEST_BLOCKS,
                "BlocksByRoot request exceeds MAX_REQUEST_BLOCKS"
            );
            return;
        }

        let request = LeanRequest::BlocksByRoot(roots.clone());
        info!(peer = %peer_id, num_roots = roots.len(), "Sending BlocksByRoot request");
        let _request_id = self
            .swarm
            .behaviour_mut()
            .req_resp
            .send_request(&peer_id, request);
    }

    fn build_behaviour(
        local_key: &Keypair,
        cfg: &NetworkServiceConfig,
    ) -> Result<LeanNetworkBehaviour> {
        let identify = Self::build_identify(local_key);
        let gossipsub = gossipsub::GossipsubBehaviour::new_with_transform(
            MessageAuthenticity::Anonymous,
            cfg.gossipsub_config.config.clone(),
            Compressor::default(),
        )
        .map_err(|err| anyhow!("Failed to create gossipsub behaviour: {err:?}"))?;

        let req_resp = req_resp::build(vec![
            STATUS_PROTOCOL_V1.to_string(),
            BLOCKS_BY_ROOT_PROTOCOL_V1.to_string(),
        ]);

        let connection_limits = connection_limits::Behaviour::new(
            ConnectionLimits::default()
                .with_max_pending_incoming(Some(5))
                .with_max_pending_outgoing(Some(16))
                .with_max_established_per_peer(Some(2)),
        );

        Ok(LeanNetworkBehaviour {
            identify,
            req_resp,
            gossipsub,
            connection_limits,
        })
    }

    fn build_identify(local_key: &Keypair) -> identify::Behaviour {
        let local_public_key = local_key.public();
        let identify_config = identify::Config::new("eth2/1.0.0".into(), local_public_key.clone())
            .with_agent_version("0.0.1".to_string())
            .with_cache_size(0);

        identify::Behaviour::new(identify_config)
    }

    fn multiaddr(cfg: &NetworkServiceConfig) -> Result<Multiaddr> {
        let mut addr: Multiaddr = cfg.socket_address.into();
        addr.push(Protocol::Udp(cfg.socket_port));
        addr.push(Protocol::QuicV1);
        Ok(addr)
    }

    fn listen(&mut self, addr: &Multiaddr) -> Result<()> {
        self.swarm
            .listen_on(addr.clone())
            .map_err(|e| anyhow!("Failed to listen on {addr:?}: {e:?}"))?;
        info!(?addr, "Listening on");
        Ok(())
    }

    fn subscribe_to_topics(&mut self) -> Result<()> {
        for topic in &self.network_config.gossipsub_config.topics {
            self.swarm
                .behaviour_mut()
                .gossipsub
                .subscribe(&IdentTopic::from(topic.clone()))
                .map_err(|e| anyhow!("Subscribe failed for {topic:?}: {e:?}"))?;
            info!(topic = %topic, "Subscribed to topic");
        }
        Ok(())
    }
}
