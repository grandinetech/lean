use std::{
    collections::HashMap,
    net::IpAddr,
    num::{NonZeroU8, NonZeroUsize},
    path::PathBuf,
    sync::Arc,
};

use anyhow::{Result, anyhow};
use containers::ssz::SszWrite;
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
use tokio::select;
use tracing::{info, warn};

use crate::{
    bootnodes::{BootnodeSource, StaticBootnodes},
    compressor::Compressor,
    gossipsub::{self, config::GossipsubConfig, message::GossipsubMessage, topic::GossipsubKind},
    network::behaviour::{LeanNetworkBehaviour, LeanNetworkBehaviourEvent},
    req_resp::{self, ReqRespMessage},
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
                .filter_map(|addr_str| addr_str.parse().ok())
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

pub struct NetworkService<R>
where
    R: P2pRequestSource<OutboundP2pRequest> + Send + 'static,
{
    network_config: Arc<NetworkServiceConfig>,
    swarm: Swarm<LeanNetworkBehaviour>,
    peer_table: Arc<Mutex<HashMap<PeerId, ConnectionState>>>,
    outbound_p2p_requests: R,
}

impl<R> NetworkService<R>
where
    R: P2pRequestSource<OutboundP2pRequest> + Send + 'static,
{
    pub async fn new(
        network_config: Arc<NetworkServiceConfig>,
        outbound_p2p_requests: R,
    ) -> Result<Self> {
        let local_key = Keypair::generate_secp256k1();
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
            outbound_p2p_requests,
        };

        service.listen(&multiaddr)?;
        service.subscribe_to_topics()?;

        Ok(service)
    }

    pub async fn start(&mut self) -> Result<()>
    {
        self.connect_to_peers(self.network_config.bootnodes.to_multiaddrs()).await;
        loop {
            select! {
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
            SwarmEvent::ConnectionEstablished { peer_id, .. } => {
                self.peer_table
                    .lock()
                    .insert(peer_id, ConnectionState::Connected);

                info!(peer = %peer_id, "Connected to peer");
                None
            }
            SwarmEvent::ConnectionClosed { peer_id, .. } => {
                self.peer_table
                    .lock()
                    .insert(peer_id, ConnectionState::Disconnected);

                info!(peer = %peer_id, "Disconnected from peer");
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
            SwarmEvent::NewListenAddr { listener_id, address } => {
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
            },
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
                    Ok(GossipsubMessage::Block(signed_block)) => {
                        info!("block");
                    }
                    Ok(GossipsubMessage::Vote(signed_vote)) => {
                        info!("vote");
                    }
                    Err(err) => warn!(%err, "gossip decode failed"),
                }
            }
            _ => {
                info!(?event, "Unhandled gossipsub event");
            }
        }        
        None
    }

    fn handle_request_response_event(
        &mut self,
        _event: ReqRespMessage,
    ) -> Option<NetworkEvent> {
        None
    }

    fn handle_identify_event(
        &mut self,
        event: identify::Event,
    ) -> Option<NetworkEvent> {
        match event {
            identify::Event::Received { peer_id, info, connection_id: _ } => {
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
            identify::Event::Sent { peer_id, connection_id: _ } => {
                info!(peer = %peer_id, "Sent identify info");
                None
            }
            identify::Event::Pushed { peer_id, .. } => {
                info!(peer = %peer_id, "Pushed identify update");
                None
            }
            identify::Event::Error { peer_id, error, connection_id: _ } => {
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

    async fn dispatch_outbound_request(&mut self, request: OutboundP2pRequest) {
        match request {
            OutboundP2pRequest::GossipBlock(signed_block) => {
                let slot = signed_block.message.slot.0;
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
            OutboundP2pRequest::GossipVote(signed_vote) => {
                let slot = signed_vote.message.slot.0;
                match signed_vote.to_ssz() {
                    Ok(bytes) => {
                        if let Err(err) = self.publish_to_topic(GossipsubKind::Vote, bytes) {
                            warn!(slot = slot, ?err, "Publish vote failed");
                        } else {
                            info!(slot = slot, "Broadcasted vote");
                        }
                    }
                    Err(err) => {
                        warn!(slot = slot, ?err, "Serialize vote failed");
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

    pub fn swarm_mut(&mut self) -> &mut Swarm<LeanNetworkBehaviour> {
        &mut self.swarm
    }

    fn build_behaviour(local_key: &Keypair, cfg: &NetworkServiceConfig) -> Result<LeanNetworkBehaviour> {
        let identify = Self::build_identify(local_key);
        let gossipsub = gossipsub::GossipsubBehaviour::new_with_transform(
            MessageAuthenticity::Anonymous,
            cfg.gossipsub_config.config.clone(),
            Compressor::default(),
        )
            .map_err(|err| anyhow!("Failed to create gossipsub behaviour: {err:?}"))?;

        let req_resp = req_resp::build(vec!["/lean/req/1".to_string()]);

        let connection_limits = connection_limits::Behaviour::new(
            ConnectionLimits::default()
                .with_max_pending_incoming(Some(5))
                .with_max_pending_outgoing(Some(16))
                .with_max_established_per_peer(Some(2)),
        );

        Ok(LeanNetworkBehaviour { identify, req_resp, gossipsub, connection_limits })
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
        self.swarm.listen_on(addr.clone())
            .map_err(|e| anyhow!("Failed to listen on {addr:?}: {e:?}"))?;
        info!(?addr, "Listening on");
        Ok(())
    }

    fn subscribe_to_topics(&mut self) -> Result<()> {
        for topic in &self.network_config.gossipsub_config.topics {
            self.swarm.behaviour_mut().gossipsub
                .subscribe(&IdentTopic::from(topic.clone()))
                .map_err(|e| anyhow!("Subscribe failed for {topic:?}: {e:?}"))?;
            info!(topic = %topic, "Subscribed to topic");
        }
        Ok(())
    }
}
