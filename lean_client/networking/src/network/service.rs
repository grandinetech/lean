use std::{
    collections::{HashMap, HashSet},
    fs::File,
    io,
    net::IpAddr,
    num::{NonZeroU8, NonZeroUsize},
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
};

use anyhow::{Result, anyhow};
use derive_more::Display;
use discv5::Enr;
use futures::StreamExt;
use libp2p::{
    Multiaddr, SwarmBuilder,
    connection_limits::{self, ConnectionLimits},
    gossipsub::{Event, IdentTopic, MessageAuthenticity},
    identify,
    multiaddr::Protocol,
    request_response::OutboundRequestId,
    swarm::{Config, ConnectionError, Swarm, SwarmEvent},
};
use libp2p_identity::{Keypair, PeerId};
use metrics::{DisconnectReason, METRICS};
use parking_lot::Mutex;
use rand::seq::IndexedRandom;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use ssz::{H256, SszHash, SszWrite as _};
use tokio::select;
use tokio::sync::Notify;
use tokio::time::{Duration, MissedTickBehavior, interval};
use tracing::{debug, info, trace, warn};

use crate::{
    bootnodes::{BootnodeSource, StaticBootnodes},
    compressor::Compressor,
    discovery::{DiscoveryConfig, DiscoveryService},
    enr_ext::EnrExt,
    gossipsub::{self, config::GossipsubConfig, message::GossipsubMessage, topic::GossipsubKind},
    network::behaviour::{LeanNetworkBehaviour, LeanNetworkBehaviourEvent},
    network::range_sync::{MAX_SYNC_RANGE, RangeSyncState},
    req_resp::{self, LeanRequest, ReqRespMessage},
    types::{
        CanonicalBlocksProvider, ChainMessage, ChainMessageSink, ConnectionState,
        MAX_BLOCK_CACHE_SIZE, NetworkFinalizedSlot, NetworkHeadSlot, OutboundP2pRequest,
        P2pRequestSource, SignedBlockProvider, StatusProvider,
    },
};

const MAX_BLOCKS_BY_ROOT_RETRIES: u8 = 10;
const MAX_BLOCK_FETCH_DEPTH: u32 = 65536;
const MAX_BLOCKS_PER_REQUEST: usize = 10;
/// Stalled request timeout. If a peer accepts the stream but never sends a response,
/// the request is cancelled and retried with a different peer after this duration.
/// Set comfortably above libp2p's default protocol timeout (10s) so the app-layer
/// gives the underlying stream room to complete under host CPU contention.
const BLOCKS_BY_ROOT_REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

struct PendingBlocksRequest {
    roots: Vec<H256>,
    retries: u8,
    depth: u32,
    created_at: tokio::time::Instant,
}

#[derive(Debug, Clone)]
pub struct NetworkServiceConfig {
    pub gossipsub_config: GossipsubConfig,
    pub socket_address: IpAddr,
    pub socket_port: u16,
    pub discovery_port: u16,
    pub discovery_enabled: bool,
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
        discovery_port: u16,
        discovery_enabled: bool,
        bootnodes: Vec<String>,
    ) -> Self {
        let bootnodes = StaticBootnodes::new(
            bootnodes
                .iter()
                .flat_map(|addr_str| parse_bootnode_argument(&addr_str))
                .map(|bootnode| {
                    if bootnode.addrs().is_empty() {
                        warn!("bootnode {bootnode} doesn't have valid address to dial");
                    }
                    match bootnode {
                        Bootnode::Multiaddr(addr) => crate::bootnodes::Bootnode::Multiaddr(addr),
                        Bootnode::Enr(enr) => crate::bootnodes::Bootnode::Enr(enr),
                    }
                })
                .collect::<Vec<_>>(),
        );

        NetworkServiceConfig {
            gossipsub_config,
            socket_address,
            socket_port,
            discovery_port,
            discovery_enabled,
            bootnodes,
        }
    }

    /// Get ENR bootnodes for discv5.
    pub fn enr_bootnodes(&self) -> Vec<enr::Enr<discv5::enr::CombinedKey>> {
        self.bootnodes.enrs().to_vec()
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
    discovery: Option<DiscoveryService>,
    peer_table: Arc<Mutex<HashMap<PeerId, ConnectionState>>>,
    peer_count: Arc<AtomicU64>,
    outbound_p2p_requests: R,
    chain_message_sink: S,
    /// Shared block provider for serving BlocksByRoot requests
    signed_block_provider: SignedBlockProvider,
    /// Shared status provider for Status req/resp protocol
    status_provider: StatusProvider,
    /// Canonical-blocks-by-range provider for serving BlocksByRange requests
    blocks_by_range_provider: CanonicalBlocksProvider,
    /// Pending BlocksByRoot requests for retry on empty response
    pending_blocks_by_root: HashMap<OutboundRequestId, PendingBlocksRequest>,
    /// In-flight BlocksByRange requests, deduplicated by (peer, start_slot, count).
    /// `inflight_range_keys` is the O(1) dedup check; `inflight_blocks_by_range`
    /// maps the libp2p request id to its key so we can drop both entries when
    /// a Response, OutboundFailure, or peer disconnect arrives.
    inflight_blocks_by_range: HashMap<OutboundRequestId, (PeerId, u64, u64)>,
    inflight_range_keys: HashSet<(PeerId, u64, u64)>,
    /// Depth tracking per block root for limiting backward chain walking
    pending_block_depths: HashMap<H256, u32>,
    /// Roots currently in-flight to deduplicate network-layer pipelining vs chain-side requests
    in_flight_roots: HashSet<H256>,
    network_finalized_slot: NetworkFinalizedSlot,
    network_head_slot: NetworkHeadSlot,
    peer_finalized_slots: HashMap<PeerId, u64>,
    /// Peer head slots reported via Status; used by the caller to decide
    /// when a backfill should switch from per-root BlocksByRoot to batched BlocksByRange.
    peer_head_slots: HashMap<PeerId, u64>,
    /// Active long-range sync session; `None` when up-to-date with peers.
    range_sync_state: Option<RangeSyncState>,
    status_notify: Arc<Notify>,
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
        signed_block_provider: SignedBlockProvider,
        status_provider: StatusProvider,
        blocks_by_range_provider: CanonicalBlocksProvider,
        network_finalized_slot: NetworkFinalizedSlot,
        network_head_slot: NetworkHeadSlot,
        status_notify: Arc<Notify>,
    ) -> Result<Self> {
        Self::new_with_peer_count(
            network_config,
            outbound_p2p_requests,
            chain_message_sink,
            Arc::new(AtomicU64::new(0)),
            signed_block_provider,
            status_provider,
            blocks_by_range_provider,
            network_finalized_slot,
            network_head_slot,
            status_notify,
        )
        .await
    }

    pub async fn new_with_peer_count(
        network_config: Arc<NetworkServiceConfig>,
        outbound_p2p_requests: R,
        chain_message_sink: S,
        peer_count: Arc<AtomicU64>,
        signed_block_provider: SignedBlockProvider,
        status_provider: StatusProvider,
        blocks_by_range_provider: CanonicalBlocksProvider,
        network_finalized_slot: NetworkFinalizedSlot,
        network_head_slot: NetworkHeadSlot,
        status_notify: Arc<Notify>,
    ) -> Result<Self> {
        let local_key = Keypair::generate_secp256k1();
        Self::new_with_keypair(
            network_config,
            outbound_p2p_requests,
            chain_message_sink,
            peer_count,
            local_key,
            signed_block_provider,
            status_provider,
            blocks_by_range_provider,
            network_finalized_slot,
            network_head_slot,
            status_notify,
        )
        .await
    }

    pub async fn new_with_keypair(
        network_config: Arc<NetworkServiceConfig>,
        outbound_p2p_requests: R,
        chain_message_sink: S,
        peer_count: Arc<AtomicU64>,
        local_key: Keypair,
        signed_block_provider: SignedBlockProvider,
        status_provider: StatusProvider,
        blocks_by_range_provider: CanonicalBlocksProvider,
        network_finalized_slot: NetworkFinalizedSlot,
        network_head_slot: NetworkHeadSlot,
        status_notify: Arc<Notify>,
    ) -> Result<Self> {
        let behaviour = Self::build_behaviour(&local_key, &network_config)?;

        let config = Config::with_tokio_executor()
            .with_notify_handler_buffer_size(NonZeroUsize::new(7).unwrap())
            .with_per_connection_event_buffer_size(4)
            .with_dial_concurrency_factor(NonZeroU8::new(1).unwrap())
            .with_idle_connection_timeout(Duration::from_secs(u64::MAX));

        let multiaddr = Self::multiaddr(&network_config)?;
        let swarm = SwarmBuilder::with_existing_identity(local_key.clone())
            .with_tokio()
            .with_quic()
            .with_behaviour(|_| behaviour)?
            .with_swarm_config(|_| config)
            .build();

        let discovery = if network_config.discovery_enabled {
            let discovery_config = DiscoveryConfig::new(
                network_config.socket_address,
                network_config.discovery_port,
                network_config.socket_port,
            )
            .with_bootnodes(network_config.enr_bootnodes());

            match DiscoveryService::new(discovery_config, &local_key).await {
                Ok(disc) => {
                    info!(
                        enr = %disc.local_enr(),
                        "Discovery service initialized"
                    );
                    Some(disc)
                }
                Err(e) => {
                    warn!(error = ?e, "Failed to initialize discovery service, continuing without it");
                    None
                }
            }
        } else {
            info!("Discovery service disabled");
            None
        };

        let mut service = Self {
            network_config,
            swarm,
            discovery,
            peer_table: Arc::new(Mutex::new(HashMap::new())),
            peer_count,
            outbound_p2p_requests,
            chain_message_sink,
            signed_block_provider,
            status_provider,
            blocks_by_range_provider,
            pending_blocks_by_root: HashMap::new(),
            inflight_blocks_by_range: HashMap::new(),
            inflight_range_keys: HashSet::new(),
            pending_block_depths: HashMap::new(),
            in_flight_roots: HashSet::new(),
            network_finalized_slot,
            network_head_slot,
            peer_finalized_slots: HashMap::new(),
            peer_head_slots: HashMap::new(),
            range_sync_state: None,
            status_notify,
        };

        service.listen(&multiaddr)?;
        service.subscribe_to_topics()?;

        Ok(service)
    }

    pub async fn start(&mut self) -> Result<()> {
        // Periodic reconnect attempts to bootnodes
        let mut reconnect_interval = interval(Duration::from_secs(30));
        reconnect_interval.set_missed_tick_behavior(MissedTickBehavior::Skip);

        // Periodic discovery searches
        let mut discovery_interval = interval(Duration::from_secs(30));
        discovery_interval.set_missed_tick_behavior(MissedTickBehavior::Skip);

        // Periodic sync trigger: send status to all connected peers so backfill re-fires
        // whenever lean is behind, regardless of who dialed whom.
        let mut sync_interval = interval(Duration::from_secs(30));
        sync_interval.set_missed_tick_behavior(MissedTickBehavior::Skip);

        // Sweep for stalled BlocksByRoot requests. Fires at the same cadence as the timeout
        // so stale entries are caught within one extra period at most.
        let mut timeout_interval = interval(BLOCKS_BY_ROOT_REQUEST_TIMEOUT);
        timeout_interval.set_missed_tick_behavior(MissedTickBehavior::Skip);

        // Periodic gossipsub mesh-peer count refresh. Reads the current set of
        // unique peers across all subscribed mesh topics and publishes it as a
        // gauge so churn between subscribe/unsubscribe events is captured.
        let mut mesh_metric_interval = interval(Duration::from_secs(10));
        mesh_metric_interval.set_missed_tick_behavior(MissedTickBehavior::Skip);

        loop {
            select! {
                _ = reconnect_interval.tick() => {
                    self.connect_to_peers(self.network_config.bootnodes.to_multiaddrs()).await;
                }
                _ = sync_interval.tick() => {
                    self.send_status_to_all_connected_peers();
                }
                _ = timeout_interval.tick() => {
                    self.sweep_timed_out_requests();
                }
                _ = mesh_metric_interval.tick() => {
                    let mesh_peer_count = self
                        .swarm
                        .behaviour()
                        .gossipsub
                        .all_mesh_peers()
                        .count() as i64;
                    METRICS.get().map(|metrics| {
                        metrics
                            .lean_gossip_mesh_peers
                            .with_label_values(&["unknown"])
                            .set(mesh_peer_count)
                    });
                }
                _ = discovery_interval.tick() => {
                    // Trigger active peer discovery
                    if let Some(ref discovery) = self.discovery {
                        let known_peers = discovery.connected_peers();
                        debug!(known_peers, "Triggering random peer discovery lookup");
                        discovery.find_random_peers();
                    }
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
                enr = async {
                    match &mut self.discovery {
                        Some(disc) => disc.recv().await,
                        None => std::future::pending().await,
                    }
                } => {
                    if let Some(enr) = enr {
                        if let Some(multiaddr) = DiscoveryService::enr_to_multiaddr(&enr) {
                            info!(
                                node_id = %enr.node_id(),
                                %multiaddr,
                                "Discovered peer via discv5, attempting connection"
                            );
                            self.connect_to_peers(vec![multiaddr]).await;
                        }
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
            SwarmEvent::Behaviour(event) => {
                match event {
                    LeanNetworkBehaviourEvent::Gossipsub(event) => {
                        self.handle_gossipsub_event(event).await
                    }
                    LeanNetworkBehaviourEvent::StatusReqResp(event) => {
                        self.handle_status_req_resp_event(event)
                    }
                    LeanNetworkBehaviourEvent::BlocksByRootReqResp(event) => {
                        self.handle_blocks_by_root_req_resp_event(event)
                    }
                    LeanNetworkBehaviourEvent::BlocksByRangeReqResp(event) => {
                        self.handle_blocks_by_range_req_resp_event(event)
                    }
                    LeanNetworkBehaviourEvent::Identify(event) => self.handle_identify_event(event),
                    LeanNetworkBehaviourEvent::ConnectionLimits(_) => {
                        // ConnectionLimits behaviour has no events
                        None
                    }
                }
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

                METRICS.get().map(|metrics| {
                    metrics.register_peer_connection_success(endpoint.is_listener());
                    metrics
                        .lean_connected_peers
                        .with_label_values(&["unknown"])
                        .set(connected as i64);
                });

                None
            }
            SwarmEvent::ConnectionClosed {
                peer_id,
                cause,
                endpoint,
                ..
            } => {
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

                self.peer_finalized_slots.remove(&peer_id);
                self.peer_head_slots.remove(&peer_id);
                if let Some(state) = &mut self.range_sync_state {
                    state.fail_peer(&peer_id);
                    if state.peer_set.is_empty() {
                        self.range_sync_state = None;
                    }
                }
                self.inflight_blocks_by_range
                    .retain(|_, (p, _, _)| *p != peer_id);
                self.inflight_range_keys.retain(|(p, _, _)| *p != peer_id);
                self.recompute_network_finalized_slot();
                self.recompute_network_head_slot();

                info!(peer = %peer_id, ?cause, "Disconnected from peer (total: {})", connected);

                METRICS.get().map(|metrics| {
                    let reason = match cause {
                        None => DisconnectReason::LocalClose,
                        Some(ConnectionError::IO(io_error)) => match io_error.kind() {
                            io::ErrorKind::UnexpectedEof | io::ErrorKind::ConnectionReset => {
                                DisconnectReason::RemoteClose
                            }
                            io::ErrorKind::TimedOut => DisconnectReason::Timeout,
                            _ => DisconnectReason::Error,
                        },
                        Some(ConnectionError::KeepAliveTimeout) => DisconnectReason::Timeout,
                    };

                    metrics.register_peer_disconnect(endpoint.is_listener(), reason);
                    metrics
                        .lean_connected_peers
                        .with_label_values(&["unknown"])
                        .set(connected as i64);
                });

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
            SwarmEvent::IncomingConnectionError {
                send_back_addr,
                error,
                ..
            } => {
                warn!(?error, ?send_back_addr, "Incoming connection error");

                METRICS
                    .get()
                    .map(|metrics| metrics.register_peer_connection_failure(true));

                None
            }
            SwarmEvent::OutgoingConnectionError { peer_id, error, .. } => {
                warn!(?peer_id, ?error, "Failed to connect to peer");

                METRICS
                    .get()
                    .map(|metrics| metrics.register_peer_connection_failure(false));

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

            Event::Message {
                message,
                propagation_source,
                ..
            } => {
                let data_len = message.data.len();
                match GossipsubMessage::decode(&message.topic, &message.data) {
                    Ok(GossipsubMessage::Block(signed_block)) => {
                        METRICS
                            .get()
                            .map(|m| m.lean_gossip_block_size_bytes.observe(data_len as f64));
                        let slot = signed_block.block.slot.0;
                        info!(slot, block_root = %signed_block.block.hash_tree_root(), "received block via gossip");

                        if let Err(err) = self
                            .chain_message_sink
                            .send(ChainMessage::ProcessBlock {
                                signed_block,
                                is_trusted: false,
                                should_gossip: false,
                                cached_post_state: None,
                            })
                            .await
                        {
                            warn!(
                                "failed to send block with attestation for slot {slot} to chain: {err:?}"
                            );
                        }
                    }
                    Ok(GossipsubMessage::AttestationSubnet {
                        subnet_id,
                        attestation,
                    }) => {
                        METRICS.get().map(|m| {
                            m.lean_gossip_attestation_size_bytes
                                .observe(data_len as f64)
                        });
                        info!(
                            validator = %attestation.validator_id,
                            slot = %attestation.message.slot.0,
                            subnet_id = subnet_id,
                            "received attestation via subnet gossip"
                        );
                        let slot = attestation.message.slot.0;

                        if let Err(err) = self
                            .chain_message_sink
                            .send(ChainMessage::ProcessAttestation {
                                signed_attestation: attestation,
                                is_trusted: false,
                                should_gossip: false,
                            })
                            .await
                        {
                            warn!(
                                "failed to send subnet attestation for slot {slot} to chain: {err:?}"
                            );
                        }
                    }
                    Ok(GossipsubMessage::Aggregation(signed_aggregated_attestation)) => {
                        METRICS.get().map(|m| {
                            m.lean_gossip_aggregation_size_bytes
                                .observe(data_len as f64)
                        });
                        info!(
                            slot = %signed_aggregated_attestation.data.slot.0,
                            "received aggregated attestation via gossip"
                        );
                        let slot = signed_aggregated_attestation.data.slot.0;

                        if let Err(err) = self
                            .chain_message_sink
                            .send(ChainMessage::ProcessAggregation {
                                signed_aggregated_attestation,
                                is_trusted: false,
                                should_gossip: false,
                            })
                            .await
                        {
                            warn!("failed to send aggregation for slot {slot} to chain: {err:?}");
                        }
                    }
                    Err(err) => {
                        let sha = hex::encode(Sha256::digest(&message.data));
                        warn!(
                            %err,
                            topic = %message.topic,
                            peer = %propagation_source,
                            len = message.data.len(),
                            sha256_inbound = %&sha[..16],
                            "gossip decode failed"
                        );
                    }
                }
            }
            _ => {
                info!(?event, "Unhandled gossipsub event");
            }
        }
        None
    }

    fn handle_status_req_resp_event(&mut self, event: ReqRespMessage) -> Option<NetworkEvent> {
        use crate::req_resp::LeanResponse;
        use libp2p::request_response::{Event, Message};

        match event {
            Event::Message { peer, message, .. } => match message {
                Message::Response { response, .. } => match response {
                    LeanResponse::Status(peer_status) => {
                        let (our_finalized_slot, our_head_slot) = {
                            let s = self.status_provider.read();
                            (s.finalized.slot.0, s.head.slot.0)
                        };
                        let peer_finalized_slot = peer_status.finalized.slot.0;
                        let peer_head_root = peer_status.head.root;
                        let peer_head_slot = peer_status.head.slot.0;

                        info!(
                            peer = %peer,
                            our_finalized = our_finalized_slot,
                            peer_finalized = peer_finalized_slot,
                            peer_head = peer_head_slot,
                            "Received Status response"
                        );

                        self.maybe_trigger_backfill(
                            peer,
                            peer_finalized_slot,
                            peer_head_slot,
                            peer_head_root,
                            our_finalized_slot,
                            our_head_slot,
                        );
                    }
                    _ => {
                        warn!(peer = %peer, "Unexpected response type on Status protocol");
                    }
                },
                Message::Request {
                    request, channel, ..
                } => {
                    use crate::req_resp::{LeanRequest, LeanResponse};

                    let (
                        response,
                        peer_finalized_slot,
                        peer_head_root,
                        peer_head_slot,
                        our_finalized_slot,
                        our_head_slot,
                    ) = match request {
                        LeanRequest::Status(peer_status) => {
                            let status = self.status_provider.read().clone();
                            let our_finalized = status.finalized.slot.0;
                            let our_head = status.head.slot.0;
                            info!(peer = %peer, finalized_slot = our_finalized, head_slot = our_head, "Received Status request");
                            let pf = peer_status.finalized.slot.0;
                            let ph = peer_status.head.root;
                            let phs = peer_status.head.slot.0;
                            (
                                LeanResponse::Status(status),
                                pf,
                                ph,
                                phs,
                                our_finalized,
                                our_head,
                            )
                        }
                        _ => {
                            warn!(peer = %peer, "Unexpected request type on Status protocol");
                            return None;
                        }
                    };

                    if let Err(e) = self
                        .swarm
                        .behaviour_mut()
                        .status_req_resp
                        .send_response(channel, response)
                    {
                        warn!(peer = %peer, ?e, "Failed to send Status response");
                    }

                    self.maybe_trigger_backfill(
                        peer,
                        peer_finalized_slot,
                        peer_head_slot,
                        peer_head_root,
                        our_finalized_slot,
                        our_head_slot,
                    );
                }
            },
            Event::OutboundFailure { peer, error, .. } => {
                warn!(peer = %peer, ?error, "Status outbound request failed");
            }
            Event::InboundFailure { peer, error, .. } => {
                warn!(peer = %peer, ?error, "Status inbound request failed");
            }
            Event::ResponseSent { peer, .. } => {
                trace!(peer = %peer, "Status response sent");
            }
        }
        None
    }

    fn handle_blocks_by_root_req_resp_event(
        &mut self,
        event: ReqRespMessage,
    ) -> Option<NetworkEvent> {
        use crate::req_resp::LeanResponse;
        use libp2p::request_response::{Event, Message};

        match event {
            Event::Message { peer, message, .. } => match message {
                Message::Response {
                    response,
                    request_id,
                } => {
                    let pending = self.pending_blocks_by_root.remove(&request_id);
                    let request_depth = pending.as_ref().map(|p| p.depth).unwrap_or(0);
                    METRICS.get().map(|m| {
                        m.grandine_pending_blocks_by_root_size
                            .set(self.pending_blocks_by_root.len() as i64)
                    });

                    // Release in-flight tracking so these roots can be re-requested if needed.
                    // Retry paths re-add them via send_blocks_by_root_request_internal.
                    if let Some(ref req) = pending {
                        for root in &req.roots {
                            self.in_flight_roots.remove(root);
                        }
                    }

                    match response {
                        LeanResponse::BlocksByRoot(blocks) => {
                            info!(
                                peer = %peer,
                                num_blocks = blocks.len(),
                                depth = request_depth,
                                "Received BlocksByRoot response"
                            );

                            // Step 1: Insert all received blocks into signed_block_provider
                            // immediately — before chain processing. This mirrors leanSpec's
                            // BlockCache.add(): blocks are "known" as soon as they arrive.
                            // Siblings within the same response batch are visible to each other
                            // during the parent check below.
                            {
                                let mut provider = self.signed_block_provider.write();
                                for block in &blocks {
                                    let root = block.block.hash_tree_root();
                                    provider.insert(root, block.clone());
                                }
                                // Hard cap: evict lowest-slot blocks if still over limit.
                                if provider.len() > MAX_BLOCK_CACHE_SIZE {
                                    let to_remove = provider.len() - MAX_BLOCK_CACHE_SIZE;
                                    let mut slots: Vec<(H256, u64)> = provider
                                        .iter()
                                        .map(|(root, b)| (*root, b.block.slot.0))
                                        .collect();
                                    slots.sort_by_key(|(_, slot)| *slot);
                                    for (root, _) in slots.into_iter().take(to_remove) {
                                        provider.remove(&root);
                                    }
                                }
                                METRICS.get().map(|m| {
                                    m.grandine_signed_block_provider_size
                                        .set(provider.len() as i64)
                                });
                            }

                            // Step 2: Collect unique parent roots that are not yet received.
                            // Fire the next BlocksByRoot request immediately from the network
                            // layer, overlapping the next RTT with chain processing time.
                            // This is the leanSpec BackfillSync recursive pattern:
                            //   _process_received_blocks → fill_missing(new_orphan_parents)
                            let next_depth = request_depth + 1;
                            if next_depth < MAX_BLOCK_FETCH_DEPTH {
                                let unknown_parents: Vec<H256> = {
                                    let provider = self.signed_block_provider.read();
                                    let mut seen = HashSet::new();
                                    blocks
                                        .iter()
                                        .filter_map(|block| {
                                            let parent_root = block.block.parent_root;
                                            if parent_root.is_zero() {
                                                return None;
                                            }
                                            // Already received (in this batch or previously)?
                                            if provider.contains_key(&parent_root) {
                                                return None;
                                            }
                                            // Already in-flight from a prior request?
                                            if self.in_flight_roots.contains(&parent_root) {
                                                return None;
                                            }
                                            // Deduplicate within this batch
                                            if !seen.insert(parent_root) {
                                                return None;
                                            }
                                            Some(parent_root)
                                        })
                                        .collect()
                                };

                                if !unknown_parents.is_empty() {
                                    const RANGE_CASCADE_TRIGGER: usize = 3;
                                    const RANGE_CASCADE_COUNT: u64 = 256;

                                    if unknown_parents.len() >= RANGE_CASCADE_TRIGGER {
                                        let min_received_slot = blocks
                                            .iter()
                                            .map(|b| b.block.slot.0)
                                            .min()
                                            .unwrap_or(0);
                                        let start_slot =
                                            min_received_slot.saturating_sub(RANGE_CASCADE_COUNT);
                                        let chosen = self
                                            .peer_head_slots
                                            .iter()
                                            .find(|(_, head)| **head >= min_received_slot)
                                            .map(|(p, _)| *p)
                                            .or_else(|| self.get_random_connected_peer());
                                        if let Some(peer_id) = chosen {
                                            info!(
                                                num_parents = unknown_parents.len(),
                                                start_slot,
                                                count = RANGE_CASCADE_COUNT,
                                                "Pipelining backfill via BlocksByRange"
                                            );
                                            self.send_blocks_by_range_request(
                                                peer_id,
                                                start_slot,
                                                RANGE_CASCADE_COUNT,
                                            );
                                        }
                                    } else {
                                        info!(
                                            num_parents = unknown_parents.len(),
                                            depth = next_depth,
                                            "Pipelining parent fetch before chain processing"
                                        );
                                        for &root in &unknown_parents {
                                            self.pending_block_depths.insert(root, next_depth);
                                        }
                                        for chunk in unknown_parents.chunks(MAX_BLOCKS_PER_REQUEST)
                                        {
                                            if let Some(peer_id) = self.get_random_connected_peer()
                                            {
                                                self.send_blocks_by_root_request_internal(
                                                    peer_id,
                                                    chunk.to_vec(),
                                                    0,
                                                    next_depth,
                                                );
                                            }
                                        }
                                    }
                                }
                            }

                            let chain_sink = self.chain_message_sink.clone();
                            tokio::spawn(async move {
                                for block in blocks {
                                    let slot = block.block.slot.0;
                                    match chain_sink.try_send(ChainMessage::ProcessBlock {
                                        signed_block: block,
                                        is_trusted: false,
                                        should_gossip: false,
                                        cached_post_state: None,
                                    }) {
                                        Ok(()) => debug!(
                                            slot = slot,
                                            "Queued requested block for processing"
                                        ),
                                        Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => {
                                            warn!(
                                                slot = slot,
                                                protocol = "blocks_by_root",
                                                "Dropping RPC chunk: chain channel full"
                                            );
                                            METRICS.get().map(|m| {
                                                m.lean_chain_message_drop_total
                                                    .with_label_values(&["blocks_by_root"])
                                                    .inc()
                                            });
                                        }
                                        Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => {
                                            warn!(
                                                slot = slot,
                                                "Failed to send requested block to chain: channel closed"
                                            );
                                            break;
                                        }
                                    }
                                }
                            });
                        }
                        LeanResponse::Empty => {
                            if let Some(req) = pending {
                                self.retry_blocks_by_root_request(peer, req);
                            } else {
                                warn!(peer = %peer, "Received empty BlocksByRoot response (no pending request)");
                            }
                        }
                        _ => {
                            warn!(peer = %peer, "Unexpected response type on BlocksByRoot protocol");
                        }
                    }
                }
                Message::Request {
                    request, channel, ..
                } => {
                    use crate::req_resp::{LeanRequest, LeanResponse};

                    let response = match request {
                        LeanRequest::BlocksByRoot(roots) => {
                            info!(peer = %peer, num_roots = roots.len(), "Received BlocksByRoot request");

                            // Look up blocks from our signed_blocks store
                            let blocks_guard = self.signed_block_provider.read();

                            let blocks: Vec<_> = roots
                                .iter()
                                .filter_map(|root| blocks_guard.get(root).cloned())
                                .collect();
                            info!(peer = %peer, found = blocks.len(), requested = roots.len(), "Serving BlocksByRoot response");
                            LeanResponse::BlocksByRoot(blocks)
                        }
                        _ => {
                            warn!(peer = %peer, "Unexpected request type on BlocksByRoot protocol");
                            return None;
                        }
                    };

                    if let Err(e) = self
                        .swarm
                        .behaviour_mut()
                        .blocks_by_root_req_resp
                        .send_response(channel, response)
                    {
                        warn!(peer = %peer, ?e, "Failed to send BlocksByRoot response");
                    }
                }
            },
            Event::OutboundFailure {
                peer,
                error,
                request_id,
                ..
            } => {
                warn!(peer = %peer, ?error, "BlocksByRoot outbound request failed");
                if let Some(req) = self.pending_blocks_by_root.remove(&request_id) {
                    METRICS.get().map(|m| {
                        m.grandine_pending_blocks_by_root_size
                            .set(self.pending_blocks_by_root.len() as i64)
                    });
                    // Release in-flight tracking before retry; retry re-adds via send_internal.
                    for root in &req.roots {
                        self.in_flight_roots.remove(root);
                    }
                    self.retry_blocks_by_root_request(peer, req);
                }
            }
            Event::InboundFailure { peer, error, .. } => {
                warn!(peer = %peer, ?error, "BlocksByRoot inbound request failed");
            }
            Event::ResponseSent { peer, .. } => {
                trace!(peer = %peer, "BlocksByRoot response sent");
            }
        }
        None
    }

    fn retry_blocks_by_root_request(&mut self, failed_peer: PeerId, req: PendingBlocksRequest) {
        if req.retries >= MAX_BLOCKS_BY_ROOT_RETRIES {
            warn!(
                retries = req.retries,
                num_roots = req.roots.len(),
                depth = req.depth,
                "BlocksByRoot max retries exceeded, giving up"
            );
            return;
        }

        let connected_peers: Vec<PeerId> = self
            .peer_table
            .lock()
            .iter()
            .filter(|(id, state)| **state == ConnectionState::Connected && **id != failed_peer)
            .map(|(id, _)| *id)
            .collect();

        if let Some(peer_id) = connected_peers.choose(&mut rand::rng()).cloned() {
            info!(
                peer = %peer_id,
                retries = req.retries + 1,
                depth = req.depth,
                num_roots = req.roots.len(),
                "Retrying BlocksByRoot request with different peer"
            );
            self.send_blocks_by_root_request_internal(
                peer_id,
                req.roots,
                req.retries + 1,
                req.depth,
            );
        } else {
            warn!(
                num_roots = req.roots.len(),
                "No other connected peers to retry BlocksByRoot request"
            );
        }
    }

    fn sweep_timed_out_requests(&mut self) {
        let timed_out: Vec<OutboundRequestId> = self
            .pending_blocks_by_root
            .iter()
            .filter(|(_, req)| req.created_at.elapsed() > BLOCKS_BY_ROOT_REQUEST_TIMEOUT)
            .map(|(id, _)| *id)
            .collect();

        for request_id in timed_out {
            if let Some(req) = self.pending_blocks_by_root.remove(&request_id) {
                METRICS.get().map(|m| {
                    m.grandine_pending_blocks_by_root_size
                        .set(self.pending_blocks_by_root.len() as i64)
                });
                warn!(
                    num_roots = req.roots.len(),
                    depth = req.depth,
                    "BlocksByRoot request timed out, retrying with different peer"
                );
                for root in &req.roots {
                    self.in_flight_roots.remove(root);
                }
                // Pass a non-existent peer so all connected peers are eligible for retry.
                self.retry_blocks_by_root_request(PeerId::random(), req);
            }
        }
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
                if !matches!(current_state, Some(ConnectionState::Disconnected) | None) {
                    trace!(?peer_id, "Already connected or connecting");
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
            peers.choose(&mut rand::rng()).copied()
        }
    }

    fn recompute_network_finalized_slot(&mut self) {
        let mut counts: HashMap<u64, usize> = HashMap::new();
        for &slot in self.peer_finalized_slots.values() {
            *counts.entry(slot).or_insert(0) += 1;
        }
        let mode = if counts.is_empty() {
            None
        } else {
            let max_count = *counts.values().max().unwrap();
            counts
                .iter()
                .filter(|(_, c)| **c == max_count)
                .map(|(s, _)| *s)
                .min()
        };
        let mut slot_guard = self.network_finalized_slot.lock();
        if *slot_guard != mode {
            *slot_guard = mode;
            drop(slot_guard);
            self.status_notify.notify_one();
        }
    }

    fn recompute_network_head_slot(&mut self) {
        let max_head = self.peer_head_slots.values().copied().max();
        let mut slot_guard = self.network_head_slot.lock();
        if *slot_guard != max_head {
            *slot_guard = max_head;
        }
    }

    fn maybe_trigger_backfill(
        &mut self,
        peer: PeerId,
        peer_finalized_slot: u64,
        peer_head_slot: u64,
        peer_head_root: H256,
        our_finalized_slot: u64,
        our_head_slot: u64,
    ) {
        self.peer_finalized_slots.insert(peer, peer_finalized_slot);
        self.peer_head_slots.insert(peer, peer_head_slot);
        self.recompute_network_finalized_slot();
        self.recompute_network_head_slot();

        if peer_head_slot > our_head_slot {
            let gap = peer_head_slot - our_head_slot;
            let start_slot = our_head_slot.saturating_add(1);
            let end_exclusive = start_slot.saturating_add(gap.min(MAX_SYNC_RANGE));

            match &mut self.range_sync_state {
                Some(state) => state.merge_peer(peer, peer_head_slot, end_exclusive),
                None => {
                    self.range_sync_state = Some(RangeSyncState::new(
                        start_slot..end_exclusive,
                        peer,
                        peer_head_slot,
                    ));
                }
            }

            info!(
                peer = %peer,
                start_slot,
                gap,
                "Long-range sync: triggering BlocksByRange"
            );
            self.drain_range_sync_batches();
            return;
        }

        if peer_finalized_slot > our_finalized_slot && !peer_head_root.is_zero() {
            info!(
                peer = %peer,
                peer_finalized = peer_finalized_slot,
                our_finalized = our_finalized_slot,
                "Peer ahead on finalized only — fetching head root"
            );
            self.send_blocks_by_root_request(peer, vec![peer_head_root]);
        }
    }

    /// Must only be called from the swarm event loop. `next_batch`'s
    /// `in_flight` guard is not atomic against concurrent callers.
    fn drain_range_sync_batches(&mut self) {
        let Some(state) = &self.range_sync_state else {
            return;
        };
        let Some((peer, range)) = state.next_batch() else {
            return;
        };

        let start_slot = range.start;
        let count = range.end - range.start;
        self.send_blocks_by_range_request(peer, start_slot, count);

        if let Some(state) = &mut self.range_sync_state {
            state.in_flight = true;
        }
    }

    fn send_status_to_all_connected_peers(&mut self) {
        let peers: Vec<PeerId> = self
            .peer_table
            .lock()
            .iter()
            .filter(|(_, state)| **state == ConnectionState::Connected)
            .map(|(peer_id, _)| *peer_id)
            .collect();

        if peers.is_empty() {
            return;
        }

        let our_finalized = self.status_provider.read().finalized.slot.0;
        info!(
            num_peers = peers.len(),
            our_finalized, "Periodic sync check: sending status to all connected peers"
        );
        for peer_id in peers {
            self.send_status_request(peer_id);
        }
    }

    async fn dispatch_outbound_request(&mut self, request: OutboundP2pRequest) {
        match request {
            OutboundP2pRequest::GossipBlock(signed_block) => {
                let slot = signed_block.block.slot.0;
                match signed_block.to_ssz() {
                    Ok(bytes) => {
                        if let Err(err) = self.publish_to_topic(GossipsubKind::Block, bytes) {
                            warn!(slot = slot, ?err, "Publish block failed");
                        } else {
                            info!(slot = slot, "Broadcasted block");
                        }
                    }
                    Err(err) => {
                        warn!(slot = slot, ?err, "Serialize block failed");
                    }
                }
            }
            OutboundP2pRequest::GossipAttestation(signed_attestation, subnet_id) => {
                let slot = signed_attestation.message.slot.0;
                let validator_id = signed_attestation.validator_id;

                match signed_attestation.to_ssz() {
                    Ok(bytes) => {
                        // Devnet-3: Publish to subnet-specific topic only
                        let topic_kind = GossipsubKind::AttestationSubnet(subnet_id);
                        if let Err(err) = self.publish_to_topic(topic_kind, bytes) {
                            warn!(
                                slot = slot,
                                subnet_id = subnet_id,
                                ?err,
                                "Publish attestation to subnet failed"
                            );
                        } else {
                            info!(
                                slot = slot,
                                validator = validator_id,
                                subnet_id = subnet_id,
                                "Broadcasted attestation to subnet"
                            );
                        }
                    }
                    Err(err) => {
                        warn!(slot = slot, ?err, "Serialize attestation failed");
                    }
                }
            }
            OutboundP2pRequest::GossipAggregation(signed_aggregated_attestation) => {
                let slot = signed_aggregated_attestation.data.slot.0;
                match signed_aggregated_attestation.to_ssz() {
                    Ok(bytes) => {
                        if let Err(err) = self.publish_to_topic(GossipsubKind::Aggregation, bytes) {
                            warn!(slot = slot, ?err, "Publish aggregation failed");
                        } else {
                            info!(slot = slot, "Broadcasted aggregated attestation");
                        }
                    }
                    Err(err) => {
                        warn!(slot = slot, ?err, "Serialize aggregation failed");
                    }
                }
            }
            OutboundP2pRequest::RequestBlocksByRange { start_slot, count } => {
                let mut chosen: Option<PeerId> = None;
                let target = start_slot.saturating_add(count.saturating_sub(1));
                for (peer, head) in &self.peer_head_slots {
                    if *head >= target {
                        chosen = Some(*peer);
                        break;
                    }
                }
                let peer_id = chosen.or_else(|| self.get_random_connected_peer());
                if let Some(peer_id) = peer_id {
                    self.send_blocks_by_range_request(peer_id, start_slot, count);
                } else {
                    debug!("BlocksByRange: no connected peer to dispatch to");
                }
            }
            OutboundP2pRequest::RequestBlocksByRoot(roots) => {
                // Look up and validate depth for each root
                // Depth is set when we receive a block and track its parent
                // For initial gossip-triggered requests, depth will be 0 (not found)
                let mut roots_to_request = Vec::new();
                for root in roots {
                    let depth = self.pending_block_depths.remove(&root).unwrap_or(0);
                    if depth >= MAX_BLOCK_FETCH_DEPTH {
                        warn!(
                            root = %root,
                            depth = depth,
                            max_depth = MAX_BLOCK_FETCH_DEPTH,
                            "Skipping block request: exceeded max fetch depth"
                        );
                    } else if self.in_flight_roots.contains(&root) {
                        // Network-layer pipelining already sent this request; skip the
                        // duplicate from the chain-side pending_fetch_roots drain.
                        debug!(root = %root, "Skipping chain-side request: root already in-flight");
                    } else {
                        roots_to_request.push((root, depth));
                    }
                }

                if roots_to_request.is_empty() {
                    return;
                }

                // Split into chunks of MAX_BLOCKS_PER_REQUEST (aligned with leanSpec BackfillSync).
                // Each chunk is sent to a random connected peer, spreading the load and allowing
                // parallel fetches when multiple roots are needed.
                let all_roots: Vec<(H256, u32)> = roots_to_request;
                let chunks: Vec<Vec<(H256, u32)>> = all_roots
                    .chunks(MAX_BLOCKS_PER_REQUEST)
                    .map(|c| c.to_vec())
                    .collect();

                let num_chunks = chunks.len();
                for chunk in chunks {
                    let depth = chunk.iter().map(|(_, d)| *d).max().unwrap_or(0);
                    let roots: Vec<H256> = chunk.into_iter().map(|(r, _)| r).collect();

                    if let Some(peer_id) = self.get_random_connected_peer() {
                        info!(
                            peer = %peer_id,
                            num_blocks = roots.len(),
                            total_chunks = num_chunks,
                            depth = depth,
                            "Requesting missing blocks from peer (batch)"
                        );
                        self.send_blocks_by_root_request_with_depth(peer_id, roots, depth);
                    } else {
                        warn!("Cannot request blocks: no connected peers");
                        break;
                    }
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

    pub fn local_enr(&self) -> Option<&enr::Enr<discv5::enr::CombinedKey>> {
        self.discovery.as_ref().map(|d| d.local_enr())
    }

    pub fn swarm_mut(&mut self) -> &mut Swarm<LeanNetworkBehaviour> {
        &mut self.swarm
    }

    fn send_status_request(&mut self, peer_id: PeerId) {
        let status = self.status_provider.read().clone();
        info!(peer = %peer_id, finalized_slot = status.finalized.slot.0, head_slot = status.head.slot.0, "Sending Status request for handshake");
        let request = LeanRequest::Status(status);
        let _request_id = self
            .swarm
            .behaviour_mut()
            .status_req_resp
            .send_request(&peer_id, request);
    }

    pub fn send_blocks_by_root_request(&mut self, peer_id: PeerId, roots: Vec<H256>) {
        self.send_blocks_by_root_request_with_depth(peer_id, roots, 0);
    }

    pub fn send_blocks_by_range_request(&mut self, peer_id: PeerId, start_slot: u64, count: u64) {
        if count == 0 {
            return;
        }
        if count > req_resp::MAX_REQUEST_BLOCKS as u64 {
            warn!(
                peer = %peer_id,
                count,
                max = req_resp::MAX_REQUEST_BLOCKS,
                "BlocksByRange request exceeds MAX_REQUEST_BLOCKS"
            );
            return;
        }

        let key = (peer_id, start_slot, count);
        if self.inflight_range_keys.contains(&key) {
            trace!(
                peer = %peer_id,
                start_slot,
                count,
                "Skipping duplicate BlocksByRange request"
            );
            return;
        }

        info!(
            peer = %peer_id,
            start_slot,
            count,
            "Sending BlocksByRange request"
        );
        let request = LeanRequest::BlocksByRange { start_slot, count };
        let request_id = self
            .swarm
            .behaviour_mut()
            .blocks_by_range_req_resp
            .send_request(&peer_id, request);
        self.inflight_range_keys.insert(key);
        self.inflight_blocks_by_range.insert(request_id, key);
    }

    pub fn send_blocks_by_root_request_with_depth(
        &mut self,
        peer_id: PeerId,
        roots: Vec<H256>,
        depth: u32,
    ) {
        self.send_blocks_by_root_request_internal(peer_id, roots, 0, depth);
    }

    fn send_blocks_by_root_request_internal(
        &mut self,
        peer_id: PeerId,
        roots: Vec<H256>,
        retries: u8,
        depth: u32,
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

        // Register roots as in-flight before sending so the chain-side drain
        // (pending_fetch_roots) and the network-layer pipeline both see them and skip duplicates.
        for &root in &roots {
            self.in_flight_roots.insert(root);
        }

        let request = LeanRequest::BlocksByRoot(roots.clone());
        info!(peer = %peer_id, num_roots = roots.len(), retries, depth, "Sending BlocksByRoot request");
        let request_id = self
            .swarm
            .behaviour_mut()
            .blocks_by_root_req_resp
            .send_request(&peer_id, request);

        self.pending_blocks_by_root.insert(
            request_id,
            PendingBlocksRequest {
                roots,
                retries,
                depth,
                created_at: tokio::time::Instant::now(),
            },
        );
        METRICS.get().map(|m| {
            m.grandine_pending_blocks_by_root_size
                .set(self.pending_blocks_by_root.len() as i64)
        });
    }

    fn handle_blocks_by_range_req_resp_event(
        &mut self,
        event: ReqRespMessage,
    ) -> Option<NetworkEvent> {
        use crate::req_resp::{LeanRequest, LeanResponse};
        use libp2p::request_response::{Event, Message};

        match event {
            Event::Message { peer, message, .. } => match message {
                Message::Request {
                    request, channel, ..
                } => {
                    let (start_slot, count) = match request {
                        LeanRequest::BlocksByRange { start_slot, count } => (start_slot, count),
                        _ => {
                            warn!(peer = %peer, "Unexpected request type on BlocksByRange protocol");
                            return None;
                        }
                    };

                    if count == 0 || count > req_resp::MAX_REQUEST_BLOCKS as u64 {
                        info!(peer = %peer, start_slot, count, "Rejecting BlocksByRange: invalid count");
                        // Send an empty response — peer will treat as no data.
                        let response = LeanResponse::BlocksByRange(Vec::new());
                        if let Err(e) = self
                            .swarm
                            .behaviour_mut()
                            .blocks_by_range_req_resp
                            .send_response(channel, response)
                        {
                            warn!(peer = %peer, ?e, "Failed to send BlocksByRange error response");
                        }
                        return None;
                    }

                    info!(peer = %peer, start_slot, count, "Received BlocksByRange request");

                    let blocks = (self.blocks_by_range_provider)(start_slot, count);

                    info!(
                        peer = %peer,
                        start_slot,
                        count,
                        found = blocks.len(),
                        "Serving BlocksByRange response"
                    );

                    let response = LeanResponse::BlocksByRange(blocks);
                    if let Err(e) = self
                        .swarm
                        .behaviour_mut()
                        .blocks_by_range_req_resp
                        .send_response(channel, response)
                    {
                        warn!(peer = %peer, ?e, "Failed to send BlocksByRange response");
                    }
                }
                Message::Response {
                    request_id,
                    response,
                    ..
                } => {
                    let requested = self.inflight_blocks_by_range.remove(&request_id);
                    if let Some(ref key) = requested {
                        self.inflight_range_keys.remove(key);
                    }
                    match response {
                        LeanResponse::BlocksByRange(blocks) => {
                            info!(
                                peer = %peer,
                                num_blocks = blocks.len(),
                                "Received BlocksByRange response"
                            );

                            if blocks.is_empty() {
                                if let Some(state) = &mut self.range_sync_state {
                                    state.fail_peer(&peer);
                                    if state.peer_set.is_empty() {
                                        self.range_sync_state = None;
                                        warn!(
                                            "Long-range sync abandoned: no peers remaining after empty response"
                                        );
                                    }
                                }
                                self.drain_range_sync_batches();
                            } else {
                                {
                                    let mut provider = self.signed_block_provider.write();
                                    for block in &blocks {
                                        let root = block.block.hash_tree_root();
                                        provider.insert(root, block.clone());
                                    }
                                    if provider.len() > MAX_BLOCK_CACHE_SIZE {
                                        let to_remove = provider.len() - MAX_BLOCK_CACHE_SIZE;
                                        let mut slots: Vec<(H256, u64)> = provider
                                            .iter()
                                            .map(|(root, b)| (*root, b.block.slot.0))
                                            .collect();
                                        slots.sort_by_key(|(_, slot)| *slot);
                                        for (root, _) in slots.into_iter().take(to_remove) {
                                            provider.remove(&root);
                                        }
                                    }
                                    METRICS.get().map(|m| {
                                        m.grandine_signed_block_provider_size
                                            .set(provider.len() as i64)
                                    });
                                }

                                let chain_sink = self.chain_message_sink.clone();
                                tokio::spawn(async move {
                                    for block in blocks {
                                        let slot = block.block.slot.0;
                                        match chain_sink.try_send(ChainMessage::ProcessBlock {
                                            signed_block: block,
                                            is_trusted: false,
                                            should_gossip: false,
                                            cached_post_state: None,
                                        }) {
                                            Ok(()) => {}
                                            Err(tokio::sync::mpsc::error::TrySendError::Full(
                                                _,
                                            )) => {
                                                warn!(
                                                    slot,
                                                    protocol = "blocks_by_range",
                                                    "Dropping RPC chunk: chain channel full"
                                                );
                                                METRICS.get().map(|m| {
                                                    m.lean_chain_message_drop_total
                                                        .with_label_values(&["blocks_by_range"])
                                                        .inc()
                                                });
                                            }
                                            Err(
                                                tokio::sync::mpsc::error::TrySendError::Closed(_),
                                            ) => {
                                                warn!(
                                                    slot,
                                                    "Failed to forward range block to chain: channel closed"
                                                );
                                                break;
                                            }
                                        }
                                    }
                                });

                                if let Some((_, start_slot, count)) = requested {
                                    let requested_end_slot =
                                        start_slot.saturating_add(count).saturating_sub(1);
                                    if let Some(state) = &mut self.range_sync_state {
                                        state.complete_batch(requested_end_slot);
                                        if state.current_range.is_empty()
                                            || state.peer_set.is_empty()
                                        {
                                            self.range_sync_state = None;
                                            info!("Long-range sync complete");
                                        }
                                    }
                                }
                                self.drain_range_sync_batches();
                            }
                        }
                        _ => {
                            warn!(peer = %peer, "Unexpected response type on BlocksByRange protocol");
                            if let Some(state) = &mut self.range_sync_state {
                                state.fail_peer(&peer);
                                if state.peer_set.is_empty() {
                                    self.range_sync_state = None;
                                    warn!(
                                        "Long-range sync abandoned: no peers remaining after codec mismatch"
                                    );
                                }
                            }
                            self.drain_range_sync_batches();
                        }
                    }
                }
            },
            Event::OutboundFailure {
                peer,
                request_id,
                error,
                ..
            } => {
                if let Some(key) = self.inflight_blocks_by_range.remove(&request_id) {
                    self.inflight_range_keys.remove(&key);
                }
                if let Some(state) = &mut self.range_sync_state {
                    state.fail_peer(&peer);
                    if state.peer_set.is_empty() {
                        self.range_sync_state = None;
                        warn!("Long-range sync abandoned: no peers remaining");
                    }
                }
                warn!(peer = %peer, ?error, "BlocksByRange outbound request failed");
                self.drain_range_sync_batches();
            }
            Event::InboundFailure { peer, error, .. } => {
                warn!(peer = %peer, ?error, "BlocksByRange inbound request failed");
            }
            Event::ResponseSent { peer, .. } => {
                trace!(peer = %peer, "BlocksByRange response sent");
            }
        }
        None
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

        let status_req_resp = req_resp::build_status();
        let blocks_by_root_req_resp = req_resp::build_blocks_by_root();
        let blocks_by_range_req_resp = req_resp::build_blocks_by_range();

        let connection_limits = connection_limits::Behaviour::new(
            ConnectionLimits::default()
                .with_max_pending_incoming(Some(5))
                .with_max_pending_outgoing(Some(16))
                .with_max_established_per_peer(Some(2)),
        );

        Ok(LeanNetworkBehaviour {
            identify,
            status_req_resp,
            blocks_by_root_req_resp,
            blocks_by_range_req_resp,
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
