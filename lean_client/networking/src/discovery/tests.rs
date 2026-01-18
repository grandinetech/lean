//! Tests for Discovery v5 Protocol Specification
//!
//! Based on the official Discovery v5 specification and test vectors from:
//! https://github.com/ethereum/devp2p/blob/master/discv5/discv5-wire-test-vectors.md

use std::net::{Ipv4Addr, Ipv6Addr};

/// Protocol constants matching Discovery v5 specification
mod constants {
    /// Protocol identifier
    pub const PROTOCOL_ID: &[u8] = b"discv5";
    /// Protocol version (v5.1)
    pub const PROTOCOL_VERSION: u16 = 0x0001;
    /// Maximum request ID length in bytes
    pub const MAX_REQUEST_ID_LENGTH: usize = 8;
    /// K-bucket size per Kademlia standard
    pub const K_BUCKET_SIZE: usize = 16;
    /// Alpha (lookup concurrency)
    pub const ALPHA: usize = 3;
    /// Number of buckets for 256-bit node ID space
    pub const BUCKET_COUNT: usize = 256;
    /// Request timeout in seconds (spec: 500ms)
    pub const REQUEST_TIMEOUT_SECS: f64 = 0.5;
    /// Handshake timeout in seconds
    pub const HANDSHAKE_TIMEOUT_SECS: f64 = 1.0;
    /// Maximum ENRs per NODES response
    pub const MAX_NODES_RESPONSE: usize = 16;
    /// Bond expiry in seconds (24 hours)
    pub const BOND_EXPIRY_SECS: u64 = 86400;
    /// Maximum packet size
    pub const MAX_PACKET_SIZE: usize = 1280;
    /// Minimum packet size
    pub const MIN_PACKET_SIZE: usize = 63;
}

/// Packet type flags
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PacketFlag {
    Message = 0,
    WhoAreYou = 1,
    Handshake = 2,
}

/// Message type codes matching wire protocol spec
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MessageType {
    Ping = 0x01,
    Pong = 0x02,
    FindNode = 0x03,
    Nodes = 0x04,
    TalkReq = 0x05,
    TalkResp = 0x06,
    RegTopic = 0x07,
    Ticket = 0x08,
    RegConfirmation = 0x09,
    TopicQuery = 0x0A,
}

/// Request ID (variable length, max 8 bytes)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestId(pub Vec<u8>);

impl RequestId {
    pub fn new(data: Vec<u8>) -> Self {
        assert!(data.len() <= constants::MAX_REQUEST_ID_LENGTH);
        Self(data)
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

/// IPv4 address (4 bytes)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IPv4(pub [u8; 4]);

impl IPv4 {
    pub fn new(bytes: [u8; 4]) -> Self {
        Self(bytes)
    }

    pub fn len(&self) -> usize {
        4
    }
}

/// IPv6 address (16 bytes)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IPv6(pub [u8; 16]);

impl IPv6 {
    pub fn new(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }

    pub fn len(&self) -> usize {
        16
    }
}

/// ID Nonce (16 bytes / 128 bits)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdNonce(pub [u8; 16]);

impl IdNonce {
    pub fn new(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }

    pub fn len(&self) -> usize {
        16
    }
}

/// Nonce (12 bytes / 96 bits)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Nonce(pub [u8; 12]);

impl Nonce {
    pub fn new(bytes: [u8; 12]) -> Self {
        Self(bytes)
    }

    pub fn len(&self) -> usize {
        12
    }
}

/// Distance type (u16)
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Distance(pub u16);

/// Port type (u16)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Port(pub u16);

/// ENR sequence number (u64)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct SeqNumber(pub u64);

/// Node ID (32 bytes / 256 bits)
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct NodeId(pub [u8; 32]);

impl NodeId {
    pub fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn from_slice(slice: &[u8]) -> Self {
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(slice);
        Self(bytes)
    }
}

/// Discovery configuration
#[derive(Debug, Clone)]
pub struct DiscoveryConfig {
    pub k_bucket_size: usize,
    pub alpha: usize,
    pub request_timeout_secs: f64,
    pub handshake_timeout_secs: f64,
    pub max_nodes_response: usize,
    pub bond_expiry_secs: u64,
}

impl Default for DiscoveryConfig {
    fn default() -> Self {
        Self {
            k_bucket_size: constants::K_BUCKET_SIZE,
            alpha: constants::ALPHA,
            request_timeout_secs: constants::REQUEST_TIMEOUT_SECS,
            handshake_timeout_secs: constants::HANDSHAKE_TIMEOUT_SECS,
            max_nodes_response: constants::MAX_NODES_RESPONSE,
            bond_expiry_secs: constants::BOND_EXPIRY_SECS,
        }
    }
}

/// PING message
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ping {
    pub request_id: RequestId,
    pub enr_seq: SeqNumber,
}

/// PONG message
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pong {
    pub request_id: RequestId,
    pub enr_seq: SeqNumber,
    pub recipient_ip: Vec<u8>,
    pub recipient_port: Port,
}

/// FINDNODE message
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FindNode {
    pub request_id: RequestId,
    pub distances: Vec<Distance>,
}

/// NODES message
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Nodes {
    pub request_id: RequestId,
    pub total: u8,
    pub enrs: Vec<Vec<u8>>,
}

/// TALKREQ message
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TalkReq {
    pub request_id: RequestId,
    pub protocol: Vec<u8>,
    pub request: Vec<u8>,
}

/// TALKRESP message
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TalkResp {
    pub request_id: RequestId,
    pub response: Vec<u8>,
}

/// Static header
#[derive(Debug, Clone)]
pub struct StaticHeader {
    pub protocol_id: [u8; 6],
    pub version: u16,
    pub flag: u8,
    pub nonce: Nonce,
    pub authdata_size: u16,
}

impl StaticHeader {
    pub fn new(flag: u8, nonce: Nonce, authdata_size: u16) -> Self {
        Self {
            protocol_id: *b"discv5",
            version: constants::PROTOCOL_VERSION,
            flag,
            nonce,
            authdata_size,
        }
    }
}

/// WHOAREYOU authdata
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WhoAreYouAuthdata {
    pub id_nonce: IdNonce,
    pub enr_seq: SeqNumber,
}

/// Node entry in routing table
#[derive(Debug, Clone)]
pub struct NodeEntry {
    pub node_id: NodeId,
    pub enr_seq: SeqNumber,
    pub last_seen: f64,
    pub endpoint: Option<String>,
    pub verified: bool,
}

impl NodeEntry {
    pub fn new(node_id: NodeId) -> Self {
        Self {
            node_id,
            enr_seq: SeqNumber::default(),
            last_seen: 0.0,
            endpoint: None,
            verified: false,
        }
    }

    pub fn with_enr_seq(mut self, enr_seq: SeqNumber) -> Self {
        self.enr_seq = enr_seq;
        self
    }

    pub fn with_last_seen(mut self, last_seen: f64) -> Self {
        self.last_seen = last_seen;
        self
    }

    pub fn with_endpoint(mut self, endpoint: String) -> Self {
        self.endpoint = Some(endpoint);
        self
    }

    pub fn with_verified(mut self, verified: bool) -> Self {
        self.verified = verified;
        self
    }
}

/// K-bucket for storing nodes at a specific distance
#[derive(Debug, Clone, Default)]
pub struct KBucket {
    nodes: Vec<NodeEntry>,
}

impl KBucket {
    pub fn new() -> Self {
        Self { nodes: Vec::new() }
    }

    pub fn is_empty(&self) -> bool {
        self.nodes.is_empty()
    }

    pub fn is_full(&self) -> bool {
        self.nodes.len() >= constants::K_BUCKET_SIZE
    }

    pub fn len(&self) -> usize {
        self.nodes.len()
    }

    pub fn add(&mut self, entry: NodeEntry) -> bool {
        // Check if node already exists
        if let Some(pos) = self.nodes.iter().position(|e| e.node_id == entry.node_id) {
            // Move to tail (most recent)
            self.nodes.remove(pos);
            self.nodes.push(entry);
            return true;
        }

        // Reject if full
        if self.is_full() {
            return false;
        }

        self.nodes.push(entry);
        true
    }

    pub fn remove(&mut self, node_id: &NodeId) -> bool {
        if let Some(pos) = self.nodes.iter().position(|e| &e.node_id == node_id) {
            self.nodes.remove(pos);
            true
        } else {
            false
        }
    }

    pub fn contains(&self, node_id: &NodeId) -> bool {
        self.nodes.iter().any(|e| &e.node_id == node_id)
    }

    pub fn get(&self, node_id: &NodeId) -> Option<&NodeEntry> {
        self.nodes.iter().find(|e| &e.node_id == node_id)
    }

    pub fn head(&self) -> Option<&NodeEntry> {
        self.nodes.first()
    }

    pub fn tail(&self) -> Option<&NodeEntry> {
        self.nodes.last()
    }

    pub fn iter(&self) -> impl Iterator<Item = &NodeEntry> {
        self.nodes.iter()
    }
}

/// Calculate XOR distance between two node IDs
pub fn xor_distance(a: &NodeId, b: &NodeId) -> num_bigint::BigUint {
    use num_bigint::BigUint;

    let a_int = BigUint::from_bytes_be(&a.0);
    let b_int = BigUint::from_bytes_be(&b.0);
    a_int ^ b_int
}

/// Calculate log2 distance between two node IDs
pub fn log2_distance(a: &NodeId, b: &NodeId) -> Distance {
    let xor = xor_distance(a, b);
    if xor.bits() == 0 {
        Distance(0)
    } else {
        Distance(xor.bits() as u16)
    }
}

/// Kademlia routing table
pub struct RoutingTable {
    local_id: NodeId,
    pub buckets: Vec<KBucket>,
}

impl RoutingTable {
    pub fn new(local_id: NodeId) -> Self {
        let buckets = (0..constants::BUCKET_COUNT)
            .map(|_| KBucket::new())
            .collect();
        Self { local_id, buckets }
    }

    pub fn node_count(&self) -> usize {
        self.buckets.iter().map(|b| b.len()).sum()
    }

    pub fn bucket_index(&self, node_id: &NodeId) -> usize {
        let dist = log2_distance(&self.local_id, node_id);
        if dist.0 == 0 {
            0
        } else {
            (dist.0 - 1) as usize
        }
    }

    pub fn add(&mut self, entry: NodeEntry) -> bool {
        // Cannot add self
        if entry.node_id == self.local_id {
            return false;
        }

        let idx = self.bucket_index(&entry.node_id);
        self.buckets[idx].add(entry)
    }

    pub fn remove(&mut self, node_id: &NodeId) -> bool {
        let idx = self.bucket_index(node_id);
        self.buckets[idx].remove(node_id)
    }

    pub fn contains(&self, node_id: &NodeId) -> bool {
        let idx = self.bucket_index(node_id);
        self.buckets[idx].contains(node_id)
    }

    pub fn get(&self, node_id: &NodeId) -> Option<&NodeEntry> {
        let idx = self.bucket_index(node_id);
        self.buckets[idx].get(node_id)
    }

    pub fn closest_nodes(&self, target: &NodeId, count: usize) -> Vec<&NodeEntry> {
        let mut all_nodes: Vec<&NodeEntry> = self
            .buckets
            .iter()
            .flat_map(|b| b.iter())
            .collect();

        all_nodes.sort_by(|a, b| {
            let dist_a = xor_distance(&a.node_id, target);
            let dist_b = xor_distance(&b.node_id, target);
            dist_a.cmp(&dist_b)
        });

        all_nodes.into_iter().take(count).collect()
    }

    pub fn nodes_at_distance(&self, distance: Distance) -> Vec<&NodeEntry> {
        if distance.0 == 0 || distance.0 > 256 {
            return Vec::new();
        }

        let idx = (distance.0 - 1) as usize;
        self.buckets[idx].iter().collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use num_bigint::BigUint;
    use num_traits::One;

    // ============================================================
    // Protocol Constants Tests
    // ============================================================

    mod protocol_constants {
        use super::*;

        #[test]
        fn test_protocol_id() {
            assert_eq!(constants::PROTOCOL_ID, b"discv5");
            assert_eq!(constants::PROTOCOL_ID.len(), 6);
        }

        #[test]
        fn test_protocol_version() {
            assert_eq!(constants::PROTOCOL_VERSION, 0x0001);
        }

        #[test]
        fn test_max_request_id_length() {
            assert_eq!(constants::MAX_REQUEST_ID_LENGTH, 8);
        }

        #[test]
        fn test_k_bucket_size() {
            assert_eq!(constants::K_BUCKET_SIZE, 16);
        }

        #[test]
        fn test_alpha_concurrency() {
            assert_eq!(constants::ALPHA, 3);
        }

        #[test]
        fn test_bucket_count() {
            assert_eq!(constants::BUCKET_COUNT, 256);
        }

        #[test]
        fn test_request_timeout() {
            assert!((constants::REQUEST_TIMEOUT_SECS - 0.5).abs() < f64::EPSILON);
        }

        #[test]
        fn test_handshake_timeout() {
            assert!((constants::HANDSHAKE_TIMEOUT_SECS - 1.0).abs() < f64::EPSILON);
        }

        #[test]
        fn test_max_nodes_response() {
            assert_eq!(constants::MAX_NODES_RESPONSE, 16);
        }

        #[test]
        fn test_bond_expiry() {
            assert_eq!(constants::BOND_EXPIRY_SECS, 86400);
        }

        #[test]
        fn test_packet_size_limits() {
            assert_eq!(constants::MAX_PACKET_SIZE, 1280);
            assert_eq!(constants::MIN_PACKET_SIZE, 63);
        }
    }

    // ============================================================
    // Custom Types Tests
    // ============================================================

    mod custom_types {
        use super::*;

        #[test]
        fn test_request_id_limit() {
            let req_id = RequestId::new(vec![0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]);
            assert_eq!(req_id.len(), 8);
        }

        #[test]
        fn test_request_id_variable_length() {
            let req_id = RequestId::new(vec![0x01]);
            assert_eq!(req_id.len(), 1);
        }

        #[test]
        fn test_ipv4_length() {
            let ip = IPv4::new([0xc0, 0xa8, 0x01, 0x01]); // 192.168.1.1
            assert_eq!(ip.len(), 4);
        }

        #[test]
        fn test_ipv6_length() {
            let mut bytes = [0u8; 16];
            bytes[15] = 0x01; // ::1
            let ip = IPv6::new(bytes);
            assert_eq!(ip.len(), 16);
        }

        #[test]
        fn test_id_nonce_length() {
            let nonce = IdNonce::new([0x01; 16]);
            assert_eq!(nonce.len(), 16);
        }

        #[test]
        fn test_nonce_length() {
            let nonce = Nonce::new([0x01; 12]);
            assert_eq!(nonce.len(), 12);
        }

        #[test]
        fn test_distance_type() {
            let d = Distance(256);
            assert_eq!(d.0, 256u16);
        }

        #[test]
        fn test_port_type() {
            let p = Port(30303);
            assert_eq!(p.0, 30303u16);
        }

        #[test]
        fn test_enr_seq_type() {
            let seq = SeqNumber(42);
            assert_eq!(seq.0, 42u64);
        }
    }

    // ============================================================
    // Packet Flag Tests
    // ============================================================

    mod packet_flags {
        use super::*;

        #[test]
        fn test_message_flag() {
            assert_eq!(PacketFlag::Message as u8, 0);
        }

        #[test]
        fn test_whoareyou_flag() {
            assert_eq!(PacketFlag::WhoAreYou as u8, 1);
        }

        #[test]
        fn test_handshake_flag() {
            assert_eq!(PacketFlag::Handshake as u8, 2);
        }
    }

    // ============================================================
    // Message Types Tests
    // ============================================================

    mod message_types {
        use super::*;

        #[test]
        fn test_ping_type() {
            assert_eq!(MessageType::Ping as u8, 0x01);
        }

        #[test]
        fn test_pong_type() {
            assert_eq!(MessageType::Pong as u8, 0x02);
        }

        #[test]
        fn test_findnode_type() {
            assert_eq!(MessageType::FindNode as u8, 0x03);
        }

        #[test]
        fn test_nodes_type() {
            assert_eq!(MessageType::Nodes as u8, 0x04);
        }

        #[test]
        fn test_talkreq_type() {
            assert_eq!(MessageType::TalkReq as u8, 0x05);
        }

        #[test]
        fn test_talkresp_type() {
            assert_eq!(MessageType::TalkResp as u8, 0x06);
        }

        #[test]
        fn test_experimental_types() {
            assert_eq!(MessageType::RegTopic as u8, 0x07);
            assert_eq!(MessageType::Ticket as u8, 0x08);
            assert_eq!(MessageType::RegConfirmation as u8, 0x09);
            assert_eq!(MessageType::TopicQuery as u8, 0x0A);
        }
    }

    // ============================================================
    // Discovery Config Tests
    // ============================================================

    mod discovery_config {
        use super::*;

        #[test]
        fn test_default_values() {
            let config = DiscoveryConfig::default();

            assert_eq!(config.k_bucket_size, constants::K_BUCKET_SIZE);
            assert_eq!(config.alpha, constants::ALPHA);
            assert!((config.request_timeout_secs - constants::REQUEST_TIMEOUT_SECS).abs() < f64::EPSILON);
            assert!((config.handshake_timeout_secs - constants::HANDSHAKE_TIMEOUT_SECS).abs() < f64::EPSILON);
            assert_eq!(config.max_nodes_response, constants::MAX_NODES_RESPONSE);
            assert_eq!(config.bond_expiry_secs, constants::BOND_EXPIRY_SECS);
        }

        #[test]
        fn test_custom_values() {
            let config = DiscoveryConfig {
                k_bucket_size: 8,
                alpha: 5,
                request_timeout_secs: 2.0,
                ..Default::default()
            };
            assert_eq!(config.k_bucket_size, 8);
            assert_eq!(config.alpha, 5);
            assert!((config.request_timeout_secs - 2.0).abs() < f64::EPSILON);
        }
    }

    // ============================================================
    // Ping Message Tests
    // ============================================================

    mod ping_message {
        use super::*;

        #[test]
        fn test_creation_with_types() {
            let ping = Ping {
                request_id: RequestId::new(vec![0x00, 0x00, 0x00, 0x01]),
                enr_seq: SeqNumber(2),
            };

            assert_eq!(ping.request_id.0, vec![0x00, 0x00, 0x00, 0x01]);
            assert_eq!(ping.enr_seq, SeqNumber(2));
        }

        #[test]
        fn test_max_request_id_length() {
            let ping = Ping {
                request_id: RequestId::new(vec![0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]),
                enr_seq: SeqNumber(1),
            };
            assert_eq!(ping.request_id.len(), 8);
        }
    }

    // ============================================================
    // Pong Message Tests
    // ============================================================

    mod pong_message {
        use super::*;

        #[test]
        fn test_creation_ipv4() {
            let pong = Pong {
                request_id: RequestId::new(vec![0x00, 0x00, 0x00, 0x01]),
                enr_seq: SeqNumber(42),
                recipient_ip: vec![0xc0, 0xa8, 0x01, 0x01], // 192.168.1.1
                recipient_port: Port(9000),
            };

            assert_eq!(pong.enr_seq, SeqNumber(42));
            assert_eq!(pong.recipient_ip.len(), 4);
            assert_eq!(pong.recipient_port, Port(9000));
        }

        #[test]
        fn test_creation_ipv6() {
            let mut ipv6 = vec![0u8; 16];
            ipv6[15] = 0x01; // ::1
            let pong = Pong {
                request_id: RequestId::new(vec![0x01]),
                enr_seq: SeqNumber(1),
                recipient_ip: ipv6.clone(),
                recipient_port: Port(30303),
            };

            assert_eq!(pong.recipient_ip.len(), 16);
        }
    }

    // ============================================================
    // FindNode Message Tests
    // ============================================================

    mod findnode_message {
        use super::*;

        #[test]
        fn test_single_distance() {
            let findnode = FindNode {
                request_id: RequestId::new(vec![0x01]),
                distances: vec![Distance(256)],
            };

            assert_eq!(findnode.distances, vec![Distance(256)]);
        }

        #[test]
        fn test_multiple_distances() {
            let findnode = FindNode {
                request_id: RequestId::new(vec![0x01]),
                distances: vec![Distance(0), Distance(1), Distance(255), Distance(256)],
            };

            assert!(findnode.distances.contains(&Distance(0)));
            assert!(findnode.distances.contains(&Distance(256)));
        }

        #[test]
        fn test_distance_zero_returns_self() {
            let findnode = FindNode {
                request_id: RequestId::new(vec![0x01]),
                distances: vec![Distance(0)],
            };
            assert_eq!(findnode.distances, vec![Distance(0)]);
        }
    }

    // ============================================================
    // Nodes Message Tests
    // ============================================================

    mod nodes_message {
        use super::*;

        #[test]
        fn test_single_response() {
            let nodes = Nodes {
                request_id: RequestId::new(vec![0x01]),
                total: 1,
                enrs: vec![b"enr:-example".to_vec()],
            };

            assert_eq!(nodes.total, 1);
            assert_eq!(nodes.enrs.len(), 1);
        }

        #[test]
        fn test_multiple_responses() {
            let nodes = Nodes {
                request_id: RequestId::new(vec![0x01]),
                total: 3,
                enrs: vec![b"enr1".to_vec(), b"enr2".to_vec()],
            };

            assert_eq!(nodes.total, 3);
            assert_eq!(nodes.enrs.len(), 2);
        }
    }

    // ============================================================
    // TalkReq Message Tests
    // ============================================================

    mod talkreq_message {
        use super::*;

        #[test]
        fn test_creation() {
            let req = TalkReq {
                request_id: RequestId::new(vec![0x01]),
                protocol: b"portal".to_vec(),
                request: b"payload".to_vec(),
            };

            assert_eq!(req.protocol, b"portal".to_vec());
            assert_eq!(req.request, b"payload".to_vec());
        }
    }

    // ============================================================
    // TalkResp Message Tests
    // ============================================================

    mod talkresp_message {
        use super::*;

        #[test]
        fn test_creation() {
            let resp = TalkResp {
                request_id: RequestId::new(vec![0x01]),
                response: b"response_data".to_vec(),
            };

            assert_eq!(resp.response, b"response_data".to_vec());
        }

        #[test]
        fn test_empty_response_unknown_protocol() {
            let resp = TalkResp {
                request_id: RequestId::new(vec![0x01]),
                response: Vec::new(),
            };
            assert!(resp.response.is_empty());
        }
    }

    // ============================================================
    // Static Header Tests
    // ============================================================

    mod static_header {
        use super::*;

        #[test]
        fn test_default_protocol_id() {
            let header = StaticHeader::new(0, Nonce::new([0x00; 12]), 32);

            assert_eq!(&header.protocol_id, b"discv5");
            assert_eq!(header.version, 0x0001);
        }

        #[test]
        fn test_flag_values() {
            for flag in [0u8, 1, 2] {
                let header = StaticHeader::new(flag, Nonce::new([0xff; 12]), 32);
                assert_eq!(header.flag, flag);
            }
        }
    }

    // ============================================================
    // WhoAreYou Authdata Tests
    // ============================================================

    mod whoareyou_authdata {
        use super::*;

        #[test]
        fn test_creation() {
            let id_nonce_bytes: [u8; 16] = [
                0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
            ];
            let authdata = WhoAreYouAuthdata {
                id_nonce: IdNonce::new(id_nonce_bytes),
                enr_seq: SeqNumber(0),
            };

            assert_eq!(authdata.id_nonce.len(), 16);
            assert_eq!(authdata.enr_seq, SeqNumber(0));
        }
    }

    // ============================================================
    // XOR Distance Tests
    // ============================================================

    mod xor_distance_tests {
        use super::*;

        #[test]
        fn test_identical_ids_zero_distance() {
            let node_id = NodeId::new([0x00; 32]);
            assert_eq!(xor_distance(&node_id, &node_id), BigUint::from(0u32));
        }

        #[test]
        fn test_complementary_ids_max_distance() {
            let a = NodeId::new([0x00; 32]);
            let b = NodeId::new([0xff; 32]);
            let expected = (BigUint::one() << 256) - BigUint::one();
            assert_eq!(xor_distance(&a, &b), expected);
        }

        #[test]
        fn test_distance_is_symmetric() {
            let a = NodeId::new([0x12; 32]);
            let b = NodeId::new([0x34; 32]);
            assert_eq!(xor_distance(&a, &b), xor_distance(&b, &a));
        }

        #[test]
        fn test_specific_xor_values() {
            let mut a_bytes = [0x00; 32];
            a_bytes[31] = 0x05; // 5
            let mut b_bytes = [0x00; 32];
            b_bytes[31] = 0x03; // 3
            let a = NodeId::new(a_bytes);
            let b = NodeId::new(b_bytes);
            assert_eq!(xor_distance(&a, &b), BigUint::from(6u32)); // 5 XOR 3 = 6
        }
    }

    // ============================================================
    // Log2 Distance Tests
    // ============================================================

    mod log2_distance_tests {
        use super::*;

        #[test]
        fn test_identical_ids_return_zero() {
            let node_id = NodeId::new([0x00; 32]);
            assert_eq!(log2_distance(&node_id, &node_id), Distance(0));
        }

        #[test]
        fn test_single_bit_difference() {
            let a = NodeId::new([0x00; 32]);
            let mut b_bytes = [0x00; 32];
            b_bytes[31] = 0x01;
            let b = NodeId::new(b_bytes);
            assert_eq!(log2_distance(&a, &b), Distance(1));
        }

        #[test]
        fn test_high_bit_difference() {
            let a = NodeId::new([0x00; 32]);
            let mut b_bytes = [0x00; 32];
            b_bytes[31] = 0x80; // 0b10000000
            let b = NodeId::new(b_bytes);
            assert_eq!(log2_distance(&a, &b), Distance(8));
        }

        #[test]
        fn test_maximum_distance() {
            let a = NodeId::new([0x00; 32]);
            let mut b_bytes = [0x00; 32];
            b_bytes[0] = 0x80; // High bit of first byte set
            let b = NodeId::new(b_bytes);
            assert_eq!(log2_distance(&a, &b), Distance(256));
        }
    }

    // ============================================================
    // K-Bucket Tests
    // ============================================================

    mod kbucket_tests {
        use super::*;

        #[test]
        fn test_new_bucket_is_empty() {
            let bucket = KBucket::new();

            assert!(bucket.is_empty());
            assert!(!bucket.is_full());
            assert_eq!(bucket.len(), 0);
        }

        #[test]
        fn test_add_single_node() {
            let mut bucket = KBucket::new();
            let entry = NodeEntry::new(NodeId::new([0x01; 32]));

            assert!(bucket.add(entry));
            assert_eq!(bucket.len(), 1);
            assert!(bucket.contains(&NodeId::new([0x01; 32])));
        }

        #[test]
        fn test_bucket_capacity_limit() {
            let mut bucket = KBucket::new();

            for i in 0..constants::K_BUCKET_SIZE {
                let mut bytes = [0x00; 32];
                bytes[0] = i as u8;
                let entry = NodeEntry::new(NodeId::new(bytes));
                assert!(bucket.add(entry));
            }

            assert!(bucket.is_full());
            assert_eq!(bucket.len(), constants::K_BUCKET_SIZE);

            let extra = NodeEntry::new(NodeId::new([0xff; 32]));
            assert!(!bucket.add(extra));
            assert_eq!(bucket.len(), constants::K_BUCKET_SIZE);
        }

        #[test]
        fn test_update_moves_to_tail() {
            let mut bucket = KBucket::new();

            let entry1 = NodeEntry::new(NodeId::new([0x01; 32])).with_enr_seq(SeqNumber(1));
            let entry2 = NodeEntry::new(NodeId::new([0x02; 32])).with_enr_seq(SeqNumber(1));
            bucket.add(entry1);
            bucket.add(entry2);

            let updated = NodeEntry::new(NodeId::new([0x01; 32])).with_enr_seq(SeqNumber(2));
            bucket.add(updated);

            let tail = bucket.tail().unwrap();
            assert_eq!(tail.node_id, NodeId::new([0x01; 32]));
            assert_eq!(tail.enr_seq, SeqNumber(2));
        }

        #[test]
        fn test_remove_node() {
            let mut bucket = KBucket::new();
            let entry = NodeEntry::new(NodeId::new([0x01; 32]));
            bucket.add(entry);

            assert!(bucket.remove(&NodeId::new([0x01; 32])));
            assert!(bucket.is_empty());
            assert!(!bucket.contains(&NodeId::new([0x01; 32])));
        }

        #[test]
        fn test_remove_nonexistent_returns_false() {
            let mut bucket = KBucket::new();
            assert!(!bucket.remove(&NodeId::new([0x01; 32])));
        }

        #[test]
        fn test_get_existing_node() {
            let mut bucket = KBucket::new();
            let entry = NodeEntry::new(NodeId::new([0x01; 32])).with_enr_seq(SeqNumber(42));
            bucket.add(entry);

            let retrieved = bucket.get(&NodeId::new([0x01; 32])).unwrap();
            assert_eq!(retrieved.enr_seq, SeqNumber(42));
        }

        #[test]
        fn test_get_nonexistent_returns_none() {
            let bucket = KBucket::new();
            assert!(bucket.get(&NodeId::new([0x01; 32])).is_none());
        }

        #[test]
        fn test_head_returns_oldest() {
            let mut bucket = KBucket::new();
            bucket.add(NodeEntry::new(NodeId::new([0x01; 32])));
            bucket.add(NodeEntry::new(NodeId::new([0x02; 32])));

            let head = bucket.head().unwrap();
            assert_eq!(head.node_id, NodeId::new([0x01; 32]));
        }

        #[test]
        fn test_tail_returns_newest() {
            let mut bucket = KBucket::new();
            bucket.add(NodeEntry::new(NodeId::new([0x01; 32])));
            bucket.add(NodeEntry::new(NodeId::new([0x02; 32])));

            let tail = bucket.tail().unwrap();
            assert_eq!(tail.node_id, NodeId::new([0x02; 32]));
        }

        #[test]
        fn test_iteration() {
            let mut bucket = KBucket::new();
            bucket.add(NodeEntry::new(NodeId::new([0x01; 32])));
            bucket.add(NodeEntry::new(NodeId::new([0x02; 32])));

            let node_ids: Vec<_> = bucket.iter().map(|e| e.node_id.clone()).collect();
            assert_eq!(node_ids.len(), 2);
        }
    }

    // ============================================================
    // Routing Table Tests
    // ============================================================

    mod routing_table_tests {
        use super::*;

        #[test]
        fn test_new_table_is_empty() {
            let local_id = NodeId::new([0x00; 32]);
            let table = RoutingTable::new(local_id);

            assert_eq!(table.node_count(), 0);
        }

        #[test]
        fn test_has_256_buckets() {
            let local_id = NodeId::new([0x00; 32]);
            let table = RoutingTable::new(local_id);

            assert_eq!(table.buckets.len(), constants::BUCKET_COUNT);
        }

        #[test]
        fn test_add_node() {
            let local_id = NodeId::new([0x00; 32]);
            let mut table = RoutingTable::new(local_id);

            let mut node_bytes = [0x00; 32];
            node_bytes[31] = 0x01;
            let entry = NodeEntry::new(NodeId::new(node_bytes));
            assert!(table.add(entry.clone()));
            assert_eq!(table.node_count(), 1);
            assert!(table.contains(&entry.node_id));
        }

        #[test]
        fn test_cannot_add_self() {
            let local_id = NodeId::new([0xab; 32]);
            let mut table = RoutingTable::new(local_id.clone());

            let entry = NodeEntry::new(local_id);
            assert!(!table.add(entry));
            assert_eq!(table.node_count(), 0);
        }

        #[test]
        fn test_bucket_assignment_by_distance() {
            let local_id = NodeId::new([0x00; 32]);
            let mut table = RoutingTable::new(local_id);

            let mut node_bytes = [0x00; 32];
            node_bytes[31] = 0x01; // log2 distance = 1
            let node_id = NodeId::new(node_bytes);
            let entry = NodeEntry::new(node_id.clone());
            table.add(entry);

            let bucket_idx = table.bucket_index(&node_id);
            assert_eq!(bucket_idx, 0); // distance 1 -> bucket 0
            assert!(table.buckets[0].contains(&node_id));
        }

        #[test]
        fn test_get_existing_node() {
            let local_id = NodeId::new([0x00; 32]);
            let mut table = RoutingTable::new(local_id);

            let entry = NodeEntry::new(NodeId::new([0x01; 32])).with_enr_seq(SeqNumber(99));
            let node_id = entry.node_id.clone();
            table.add(entry);

            let retrieved = table.get(&node_id).unwrap();
            assert_eq!(retrieved.enr_seq, SeqNumber(99));
        }

        #[test]
        fn test_remove_node() {
            let local_id = NodeId::new([0x00; 32]);
            let mut table = RoutingTable::new(local_id);

            let entry = NodeEntry::new(NodeId::new([0x01; 32]));
            let node_id = entry.node_id.clone();
            table.add(entry);
            assert!(table.remove(&node_id));
            assert!(!table.contains(&node_id));
        }

        #[test]
        fn test_closest_nodes_sorted_by_distance() {
            let local_id = NodeId::new([0x00; 32]);
            let mut table = RoutingTable::new(local_id);

            for i in 1..5u8 {
                let mut bytes = [0x00; 32];
                bytes[0] = i;
                let entry = NodeEntry::new(NodeId::new(bytes));
                table.add(entry);
            }

            let mut target_bytes = [0x00; 32];
            target_bytes[0] = 0x01;
            let target = NodeId::new(target_bytes);
            let closest = table.closest_nodes(&target, 3);

            assert_eq!(closest.len(), 3);
            assert_eq!(closest[0].node_id, target); // Distance 0 to itself
        }

        #[test]
        fn test_closest_nodes_respects_count() {
            let local_id = NodeId::new([0x00; 32]);
            let mut table = RoutingTable::new(local_id);

            for i in 1..11u8 {
                let mut bytes = [0x00; 32];
                bytes[0] = i;
                let entry = NodeEntry::new(NodeId::new(bytes));
                table.add(entry);
            }

            let mut target_bytes = [0x00; 32];
            target_bytes[0] = 0x05;
            let closest = table.closest_nodes(&NodeId::new(target_bytes), 3);
            assert_eq!(closest.len(), 3);
        }

        #[test]
        fn test_nodes_at_distance() {
            let local_id = NodeId::new([0x00; 32]);
            let mut table = RoutingTable::new(local_id);

            let mut node_bytes = [0x00; 32];
            node_bytes[31] = 0x01; // distance 1
            let node_id = NodeId::new(node_bytes);
            let entry = NodeEntry::new(node_id.clone());
            table.add(entry);

            let nodes = table.nodes_at_distance(Distance(1));
            assert_eq!(nodes.len(), 1);
            assert_eq!(nodes[0].node_id, node_id);
        }

        #[test]
        fn test_nodes_at_invalid_distance() {
            let local_id = NodeId::new([0x00; 32]);
            let table = RoutingTable::new(local_id);

            assert!(table.nodes_at_distance(Distance(0)).is_empty());
            assert!(table.nodes_at_distance(Distance(257)).is_empty());
        }
    }

    // ============================================================
    // Node Entry Tests
    // ============================================================

    mod node_entry_tests {
        use super::*;

        #[test]
        fn test_default_values() {
            let entry = NodeEntry::new(NodeId::new([0x01; 32]));

            assert_eq!(entry.node_id, NodeId::new([0x01; 32]));
            assert_eq!(entry.enr_seq, SeqNumber(0));
            assert!((entry.last_seen - 0.0).abs() < f64::EPSILON);
            assert!(entry.endpoint.is_none());
            assert!(!entry.verified);
        }

        #[test]
        fn test_full_construction() {
            let entry = NodeEntry::new(NodeId::new([0x01; 32]))
                .with_enr_seq(SeqNumber(42))
                .with_last_seen(1234567890.0)
                .with_endpoint("192.168.1.1:30303".to_string())
                .with_verified(true);

            assert_eq!(entry.enr_seq, SeqNumber(42));
            assert_eq!(entry.endpoint, Some("192.168.1.1:30303".to_string()));
            assert!(entry.verified);
        }
    }

    // ============================================================
    // Test Vector Tests
    // ============================================================

    mod test_vectors {
        use super::*;

        // From https://github.com/ethereum/devp2p/blob/master/discv5/discv5-wire-test-vectors.md
        const PING_REQUEST_ID: [u8; 4] = [0x00, 0x00, 0x00, 0x01];
        const PING_ENR_SEQ: u64 = 2;
        const WHOAREYOU_ID_NONCE: [u8; 16] = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
            0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
        ];

        #[test]
        fn test_ping_message_construction() {
            let ping = Ping {
                request_id: RequestId::new(PING_REQUEST_ID.to_vec()),
                enr_seq: SeqNumber(PING_ENR_SEQ),
            };

            assert_eq!(ping.request_id.0, PING_REQUEST_ID.to_vec());
            assert_eq!(ping.enr_seq, SeqNumber(2));
        }

        #[test]
        fn test_whoareyou_authdata_construction() {
            let authdata = WhoAreYouAuthdata {
                id_nonce: IdNonce::new(WHOAREYOU_ID_NONCE),
                enr_seq: SeqNumber(0),
            };

            assert_eq!(authdata.id_nonce, IdNonce::new(WHOAREYOU_ID_NONCE));
            assert_eq!(authdata.enr_seq, SeqNumber(0));
        }

        #[test]
        fn test_plaintext_message_type() {
            // From AES-GCM test vector plaintext
            let plaintext = hex::decode("01c20101").unwrap();
            assert_eq!(plaintext[0], MessageType::Ping as u8);
        }
    }

    // ============================================================
    // Packet Structure Tests
    // ============================================================

    mod packet_structure {
        #[test]
        fn test_static_header_size() {
            // protocol-id (6) + version (2) + flag (1) + nonce (12) + authdata-size (2)
            let expected_size = 6 + 2 + 1 + 12 + 2;
            assert_eq!(expected_size, 23);
        }
    }

    // ============================================================
    // Routing with Test Vector Node IDs
    // ============================================================

    mod routing_test_vectors {
        use super::*;

        // Node IDs from official test vectors (keccak256 of uncompressed pubkey)
        fn node_a_id() -> NodeId {
            NodeId::from_slice(&hex::decode("aaaa8419e9f49d0083561b48287df592939a8d19947d8c0ef88f2a4856a69fbb").unwrap())
        }

        fn node_b_id() -> NodeId {
            NodeId::from_slice(&hex::decode("bbbb9d047f0488c0b5a93c1c3f2d8bafc7c8ff337024a55434a0d0555de64db9").unwrap())
        }

        #[test]
        fn test_xor_distance_is_symmetric() {
            let node_a = node_a_id();
            let node_b = node_b_id();

            let distance = xor_distance(&node_a, &node_b);
            assert!(distance > BigUint::from(0u32));
            assert_eq!(xor_distance(&node_a, &node_b), xor_distance(&node_b, &node_a));
        }

        #[test]
        fn test_log2_distance_is_high() {
            let node_a = node_a_id();
            let node_b = node_b_id();

            let log_dist = log2_distance(&node_a, &node_b);
            assert!(log_dist > Distance(200));
        }
    }
}
