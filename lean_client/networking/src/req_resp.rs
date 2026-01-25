use std::io;
use std::io::{Read, Write};

use async_trait::async_trait;
use containers::ssz::{SszReadDefault, SszWrite};
use containers::{Bytes32, SignedBlockWithAttestation, Status};
use futures::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use libp2p::request_response::{
    Behaviour as RequestResponse, Codec, Config, Event, ProtocolSupport,
};
use snap::read::FrameDecoder;
use snap::write::FrameEncoder;

pub const MAX_REQUEST_BLOCKS: usize = 1024;

pub const STATUS_PROTOCOL_V1: &str = "/leanconsensus/req/status/1/ssz_snappy";
pub const BLOCKS_BY_ROOT_PROTOCOL_V1: &str = "/leanconsensus/req/blocks_by_root/1/ssz_snappy";

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct LeanProtocol(pub String);

impl AsRef<str> for LeanProtocol {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LeanRequest {
    Status(Status),
    BlocksByRoot(Vec<Bytes32>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LeanResponse {
    Status(Status),
    BlocksByRoot(Vec<SignedBlockWithAttestation>),
    Empty,
}

#[derive(Clone, Default)]
pub struct LeanCodec;

impl LeanCodec {
    /// Compress data using Snappy framing format (required for req/resp protocol)
    fn compress(data: &[u8]) -> io::Result<Vec<u8>> {
        let mut encoder = FrameEncoder::new(Vec::new());
        encoder.write_all(data)?;
        encoder.into_inner().map_err(|e| {
            io::Error::new(io::ErrorKind::Other, format!("Snappy framing failed: {e}"))
        })
    }

    /// Decompress data using Snappy framing format (required for req/resp protocol)
    fn decompress(data: &[u8]) -> io::Result<Vec<u8>> {
        let mut decoder = FrameDecoder::new(data);
        let mut decompressed = Vec::new();
        decoder.read_to_end(&mut decompressed)?;
        Ok(decompressed)
    }

    fn encode_request(request: &LeanRequest) -> io::Result<Vec<u8>> {
        let ssz_bytes = match request {
            LeanRequest::Status(status) => status.to_ssz().map_err(|e| {
                io::Error::new(io::ErrorKind::Other, format!("SSZ encode failed: {e}"))
            })?,
            LeanRequest::BlocksByRoot(roots) => {
                let mut bytes = Vec::new();
                for root in roots {
                    bytes.extend_from_slice(root.0.as_bytes());
                }
                bytes
            }
        };
        Self::compress(&ssz_bytes)
    }

    fn decode_request(protocol: &str, data: &[u8]) -> io::Result<LeanRequest> {
        if data.is_empty() {
            return Ok(LeanRequest::Status(Status::default()));
        }

        let ssz_bytes = Self::decompress(data)?;

        if protocol.contains("status") {
            let status = Status::from_ssz_default(&ssz_bytes).map_err(|e| {
                io::Error::new(
                    io::ErrorKind::Other,
                    format!("SSZ decode Status failed: {e:?}"),
                )
            })?;
            Ok(LeanRequest::Status(status))
        } else if protocol.contains("blocks_by_root") {
            let mut roots = Vec::new();
            for chunk in ssz_bytes.chunks(32) {
                if chunk.len() == 32 {
                    let mut root = [0u8; 32];
                    root.copy_from_slice(chunk);
                    roots.push(Bytes32(containers::ssz::H256::from(root)));
                }
            }
            if roots.len() > MAX_REQUEST_BLOCKS {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "Too many block roots requested: {} > {}",
                        roots.len(),
                        MAX_REQUEST_BLOCKS
                    ),
                ));
            }
            Ok(LeanRequest::BlocksByRoot(roots))
        } else {
            Err(io::Error::new(
                io::ErrorKind::Other,
                format!("Unknown protocol: {protocol}"),
            ))
        }
    }

    fn encode_response(response: &LeanResponse) -> io::Result<Vec<u8>> {
        let ssz_bytes = match response {
            LeanResponse::Status(status) => status.to_ssz().map_err(|e| {
                io::Error::new(io::ErrorKind::Other, format!("SSZ encode failed: {e}"))
            })?,
            LeanResponse::BlocksByRoot(blocks) => {
                let mut bytes = Vec::new();
                for block in blocks {
                    let block_bytes = block.to_ssz().map_err(|e| {
                        io::Error::new(io::ErrorKind::Other, format!("SSZ encode failed: {e}"))
                    })?;
                    bytes.extend_from_slice(&block_bytes);
                }
                bytes
            }
            LeanResponse::Empty => Vec::new(),
        };

        if ssz_bytes.is_empty() {
            return Ok(Vec::new());
        }

        Self::compress(&ssz_bytes)
    }

    fn decode_response(protocol: &str, data: &[u8]) -> io::Result<LeanResponse> {
        if data.is_empty() {
            return Ok(LeanResponse::Empty);
        }

        let ssz_bytes = Self::decompress(data)?;

        if protocol.contains("status") {
            let status = Status::from_ssz_default(&ssz_bytes).map_err(|e| {
                io::Error::new(
                    io::ErrorKind::Other,
                    format!("SSZ decode Status failed: {e:?}"),
                )
            })?;
            Ok(LeanResponse::Status(status))
        } else if protocol.contains("blocks_by_root") {
            if ssz_bytes.is_empty() {
                return Ok(LeanResponse::BlocksByRoot(Vec::new()));
            }
            let block = SignedBlockWithAttestation::from_ssz_default(&ssz_bytes).map_err(|e| {
                io::Error::new(
                    io::ErrorKind::Other,
                    format!("SSZ decode Block failed: {e:?}"),
                )
            })?;
            Ok(LeanResponse::BlocksByRoot(vec![block]))
        } else {
            Err(io::Error::new(
                io::ErrorKind::Other,
                format!("Unknown protocol: {protocol}"),
            ))
        }
    }
}

#[async_trait]
impl Codec for LeanCodec {
    type Protocol = LeanProtocol;
    type Request = LeanRequest;
    type Response = LeanResponse;

    async fn read_request<T>(
        &mut self,
        protocol: &Self::Protocol,
        io: &mut T,
    ) -> io::Result<Self::Request>
    where
        T: AsyncRead + Unpin + Send,
    {
        let mut data = Vec::new();
        io.read_to_end(&mut data).await?;
        Self::decode_request(&protocol.0, &data)
    }

    async fn read_response<T>(
        &mut self,
        protocol: &Self::Protocol,
        io: &mut T,
    ) -> io::Result<Self::Response>
    where
        T: AsyncRead + Unpin + Send,
    {
        let mut data = Vec::new();
        io.read_to_end(&mut data).await?;
        Self::decode_response(&protocol.0, &data)
    }

    async fn write_request<T>(
        &mut self,
        _protocol: &Self::Protocol,
        io: &mut T,
        request: Self::Request,
    ) -> io::Result<()>
    where
        T: AsyncWrite + Unpin + Send,
    {
        let data = Self::encode_request(&request)?;
        io.write_all(&data).await?;
        io.close().await
    }

    async fn write_response<T>(
        &mut self,
        _protocol: &Self::Protocol,
        io: &mut T,
        response: Self::Response,
    ) -> io::Result<()>
    where
        T: AsyncWrite + Unpin + Send,
    {
        let data = Self::encode_response(&response)?;
        io.write_all(&data).await?;
        io.close().await
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct GenericProtocol(pub String);

impl AsRef<str> for GenericProtocol {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

#[derive(Clone, Default)]
pub struct GenericCodec;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GenericRequest(pub Vec<u8>);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GenericResponse(pub Vec<u8>);

#[async_trait]
impl Codec for GenericCodec {
    type Protocol = GenericProtocol;
    type Request = GenericRequest;
    type Response = GenericResponse;

    async fn read_request<T>(
        &mut self,
        _protocol: &Self::Protocol,
        io: &mut T,
    ) -> io::Result<Self::Request>
    where
        T: AsyncRead + Unpin + Send,
    {
        let mut data = Vec::new();
        io.read_to_end(&mut data).await?;
        Ok(GenericRequest(data))
    }

    async fn read_response<T>(
        &mut self,
        _protocol: &Self::Protocol,
        io: &mut T,
    ) -> io::Result<Self::Response>
    where
        T: AsyncRead + Unpin + Send,
    {
        let mut data = Vec::new();
        io.read_to_end(&mut data).await?;
        Ok(GenericResponse(data))
    }

    async fn write_request<T>(
        &mut self,
        _protocol: &Self::Protocol,
        io: &mut T,
        GenericRequest(data): Self::Request,
    ) -> io::Result<()>
    where
        T: AsyncWrite + Unpin + Send,
    {
        io.write_all(&data).await?;
        io.close().await
    }

    async fn write_response<T>(
        &mut self,
        _protocol: &Self::Protocol,
        io: &mut T,
        GenericResponse(data): Self::Response,
    ) -> io::Result<()>
    where
        T: AsyncWrite + Unpin + Send,
    {
        io.write_all(&data).await?;
        io.close().await
    }
}

pub type ReqResp = RequestResponse<LeanCodec>;

pub type ReqRespMessage = Event<LeanRequest, LeanResponse>;

pub fn build(protocols: impl IntoIterator<Item = String>) -> ReqResp {
    let protocols = protocols
        .into_iter()
        .map(|name| (LeanProtocol(name), ProtocolSupport::Full))
        .collect::<Vec<_>>();

    RequestResponse::with_codec(LeanCodec::default(), protocols, Config::default())
}

pub fn build_default() -> ReqResp {
    build(vec![
        STATUS_PROTOCOL_V1.to_string(),
        BLOCKS_BY_ROOT_PROTOCOL_V1.to_string(),
    ])
}
