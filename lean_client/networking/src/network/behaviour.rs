use libp2p::{connection_limits, identify, swarm::NetworkBehaviour};

use crate::gossipsub::GossipsubBehaviour;
use crate::req_resp::ReqResp;

#[derive(NetworkBehaviour)]
pub struct LeanNetworkBehaviour {
    pub identify: identify::Behaviour,
    pub req_resp: ReqResp,
    pub gossipsub: GossipsubBehaviour,
    pub connection_limits: connection_limits::Behaviour,
}
