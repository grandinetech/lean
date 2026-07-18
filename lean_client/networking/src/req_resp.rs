use std::io;
use std::io::{Read, Write};
use std::time::Duration;

use async_trait::async_trait;
use containers::{SignedBlock, Status};
use futures::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use libp2p::request_response::{
    Behaviour as RequestResponse, Codec, Config, Event, ProtocolSupport,
};
use snap::read::FrameDecoder;
use snap::write::FrameEncoder;
use ssz::{H256, PersistentList, Ssz, SszReadDefault as _, SszWrite as _};
use tracing::warn;
use typenum::U1024;

pub const MAX_REQUEST_BLOCKS: usize = 1024;
pub const MIN_SLOTS_FOR_BLOCK_REQUESTS: u64 = 3600;
pub const MAX_PAYLOAD_SIZE: usize = 10 * 1024 * 1024; // 10 MiB

pub const STATUS_PROTOCOL_V1: &str = "/leanconsensus/req/status/1/ssz_snappy";
pub const BLOCKS_BY_ROOT_PROTOCOL_V1: &str = "/leanconsensus/req/blocks_by_root/1/ssz_snappy";
pub const BLOCKS_BY_RANGE_PROTOCOL_V1: &str = "/leanconsensus/req/blocks_by_range/1/ssz_snappy";

/// Response codes for req/resp protocol messages.
pub const RESPONSE_SUCCESS: u8 = 0;
pub const RESPONSE_INVALID_REQUEST: u8 = 1;
pub const RESPONSE_SERVER_ERROR: u8 = 2;
pub const RESPONSE_RESOURCE_UNAVAILABLE: u8 = 3;

pub type RequestedBlockRoots = PersistentList<H256, U1024>;

#[derive(Clone, Debug, PartialEq, Eq, Ssz)]
pub struct BlocksByRootRequest {
    pub roots: RequestedBlockRoots,
}

#[derive(Clone, Debug, PartialEq, Eq, Ssz)]
pub struct BlocksByRangeRequest {
    pub start_slot: u64,
    pub count: u64,
}

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
    BlocksByRoot(Vec<H256>),
    BlocksByRange { start_slot: u64, count: u64 },
}

#[derive(Debug, Clone)]
pub enum LeanResponse {
    Status(Status),
    BlocksByRoot(Vec<SignedBlock>),
    BlocksByRange(Vec<SignedBlock>),
    Error { code: u8, message: String },
    Empty,
}

#[derive(Clone, Default)]
pub struct LeanCodec;

impl LeanCodec {
    /// Encode a u32 as an unsigned LEB128 varint.
    fn encode_varint(value: u32) -> Vec<u8> {
        let mut result = Vec::new();
        let mut v = value;
        loop {
            let mut byte = (v & 0x7F) as u8;
            v >>= 7;
            if v != 0 {
                byte |= 0x80;
            }
            result.push(byte);
            if v == 0 {
                break;
            }
        }
        result
    }

    /// Decode an unsigned LEB128 varint from data.
    /// Returns (value, bytes_consumed) on success.
    fn decode_varint(data: &[u8]) -> io::Result<(u32, usize)> {
        let mut result = 0u32;
        for (i, &byte) in data.iter().enumerate().take(5) {
            let value = (byte & 0x7F) as u32;
            result |= value << (7 * i);
            if byte & 0x80 == 0 {
                return Ok((result, i + 1));
            }
        }
        Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Invalid or truncated varint",
        ))
    }

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

    /// Encode request with varint length prefix per spec:
    /// [varint: uncompressed_length][snappy_framed_payload]
    fn encode_request(request: &LeanRequest) -> io::Result<Vec<u8>> {
        let ssz_bytes = match request {
            LeanRequest::Status(status) => status.to_ssz().map_err(|e| {
                io::Error::new(io::ErrorKind::Other, format!("SSZ encode failed: {e}"))
            })?,
            LeanRequest::BlocksByRoot(roots) => {
                let mut request_roots = RequestedBlockRoots::default();
                for root in roots {
                    request_roots.push(*root).map_err(|e| {
                        io::Error::new(io::ErrorKind::Other, format!("Failed to add root: {e:?}"))
                    })?;
                }
                let request = BlocksByRootRequest {
                    roots: request_roots,
                };
                request.to_ssz().map_err(|e| {
                    io::Error::new(io::ErrorKind::Other, format!("SSZ encode failed: {e}"))
                })?
            }
            LeanRequest::BlocksByRange { start_slot, count } => {
                let request = BlocksByRangeRequest {
                    start_slot: *start_slot,
                    count: *count,
                };
                request.to_ssz().map_err(|e| {
                    io::Error::new(io::ErrorKind::Other, format!("SSZ encode failed: {e}"))
                })?
            }
        };

        if ssz_bytes.len() > MAX_PAYLOAD_SIZE {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "Payload too large: {} > {}",
                    ssz_bytes.len(),
                    MAX_PAYLOAD_SIZE
                ),
            ));
        }

        let compressed = Self::compress(&ssz_bytes)?;
        let mut result = Self::encode_varint(ssz_bytes.len() as u32);
        result.extend(compressed);

        Ok(result)
    }

    /// Decode request with varint length prefix per spec:
    /// [varint: uncompressed_length][snappy_framed_payload]
    fn decode_request(protocol: &str, data: &[u8]) -> io::Result<LeanRequest> {
        if data.is_empty() {
            return Ok(LeanRequest::Status(Status::default()));
        }

        // Parse varint length prefix
        let (declared_len, varint_size) = Self::decode_varint(data)?;

        if declared_len as usize > MAX_PAYLOAD_SIZE {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "Declared length too large: {} > {}",
                    declared_len, MAX_PAYLOAD_SIZE
                ),
            ));
        }

        // Decompress payload after varint
        let compressed = &data[varint_size..];
        let ssz_bytes = Self::decompress(compressed)?;

        // Validate length matches
        if ssz_bytes.len() != declared_len as usize {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "Length mismatch: declared {}, got {}",
                    declared_len,
                    ssz_bytes.len()
                ),
            ));
        }

        if protocol.contains("status") {
            let status = Status::from_ssz_default(&ssz_bytes).map_err(|e| {
                io::Error::new(
                    io::ErrorKind::Other,
                    format!("SSZ decode Status failed: {e:?}"),
                )
            })?;
            Ok(LeanRequest::Status(status))
        } else if protocol.contains("blocks_by_root") {
            let request = BlocksByRootRequest::from_ssz_default(&ssz_bytes).map_err(|e| {
                io::Error::new(
                    io::ErrorKind::Other,
                    format!("SSZ decode BlocksByRootRequest failed: {e:?}"),
                )
            })?;
            let roots: Vec<H256> = request.roots.into_iter().copied().collect();
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
        } else if protocol.contains("blocks_by_range") {
            let request = BlocksByRangeRequest::from_ssz_default(&ssz_bytes).map_err(|e| {
                io::Error::new(
                    io::ErrorKind::Other,
                    format!("SSZ decode BlocksByRangeRequest failed: {e:?}"),
                )
            })?;
            Ok(LeanRequest::BlocksByRange {
                start_slot: request.start_slot,
                count: request.count,
            })
        } else {
            Err(io::Error::new(
                io::ErrorKind::Other,
                format!("Unknown protocol: {protocol}"),
            ))
        }
    }

    /// Encode a single response chunk with response code and varint length prefix per spec:
    /// [response_code: 1 byte][varint: uncompressed_length][snappy_framed_payload]
    fn encode_response_chunk(code: u8, ssz_bytes: &[u8]) -> io::Result<Vec<u8>> {
        let compressed = Self::compress(ssz_bytes)?;
        let mut result = vec![code];
        result.extend(Self::encode_varint(ssz_bytes.len() as u32));
        result.extend(compressed);
        Ok(result)
    }

    /// Encode response per spec. For BlocksByRoot, each block is a separate chunk:
    /// [code][varint][snappy(block1)][code][varint][snappy(block2)]...
    fn encode_response(response: &LeanResponse) -> io::Result<Vec<u8>> {
        match response {
            LeanResponse::Status(status) => {
                let ssz_bytes = status.to_ssz().map_err(|e| {
                    io::Error::new(io::ErrorKind::Other, format!("SSZ encode failed: {e}"))
                })?;
                Self::encode_response_chunk(RESPONSE_SUCCESS, &ssz_bytes)
            }
            LeanResponse::BlocksByRoot(blocks) => {
                // Each block is a separate chunk with its own response code
                let mut result = Vec::new();
                for block in blocks {
                    let ssz_bytes = block.to_ssz().map_err(|e| {
                        io::Error::new(io::ErrorKind::Other, format!("SSZ encode failed: {e}"))
                    })?;
                    let chunk = Self::encode_response_chunk(RESPONSE_SUCCESS, &ssz_bytes)?;
                    result.extend(chunk);
                }
                // Empty response: no chunks written (stream just ends)
                Ok(result)
            }
            LeanResponse::BlocksByRange(blocks) => {
                let mut result = Vec::new();
                for block in blocks {
                    let ssz_bytes = block.to_ssz().map_err(|e| {
                        io::Error::new(io::ErrorKind::Other, format!("SSZ encode failed: {e}"))
                    })?;
                    let chunk = Self::encode_response_chunk(RESPONSE_SUCCESS, &ssz_bytes)?;
                    result.extend(chunk);
                }
                Ok(result)
            }
            LeanResponse::Error { code, message } => {
                Self::encode_response_chunk(*code, message.as_bytes())
            }
            LeanResponse::Empty => Ok(Vec::new()),
        }
    }

    /// Returns the byte length consumed by one ssz-snappy framed payload starting at data[0].
    ///
    /// Driven by `expected_uncompressed_size` from the response's varint prefix: we walk
    /// chunk-by-chunk, accumulating each chunk's uncompressed contribution, and stop when
    /// we've collected the declared message size.
    ///
    /// Snappy framing format (https://github.com/google/snappy/blob/main/framing_format.txt):
    ///   0xFF (stream identifier):           fixed 10 bytes: [0xFF][0x06 0x00 0x00][s][N][a][P][p][Y]
    ///   0x00 (compressed data):             [type][len:3LE][crc:4][snappy_block]
    ///   0x01 (uncompressed data):           [type][len:3LE][crc:4][raw_bytes]
    ///   0x80..=0xFF (reserved skippable):   skip whole chunk, contributes 0 to uncompressed
    ///   0x02..=0x7F (reserved unskippable): MUST reject per spec
    fn snappy_frame_size(data: &[u8], expected_uncompressed_size: usize) -> io::Result<usize> {
        const STREAM_ID: &[u8] = b"\xff\x06\x00\x00sNaPpY";
        if data.len() < STREAM_ID.len() || &data[..STREAM_ID.len()] != STREAM_ID {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Missing snappy stream identifier",
            ));
        }

        let mut pos = STREAM_ID.len();
        let mut uncompressed_len = 0_usize;

        while uncompressed_len < expected_uncompressed_size {
            if pos + 4 > data.len() {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "Truncated snappy chunk header",
                ));
            }
            let chunk_type = data[pos];
            let chunk_len =
                u32::from_le_bytes([data[pos + 1], data[pos + 2], data[pos + 3], 0]) as usize;

            if pos + 4 + chunk_len > data.len() {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    format!(
                        "Truncated snappy chunk: type=0x{:02x} chunk_len={} at pos={} buffer={}",
                        chunk_type,
                        chunk_len,
                        pos,
                        data.len()
                    ),
                ));
            }
            let chunk_payload = &data[pos + 4..pos + 4 + chunk_len];

            let chunk_uncompressed_len = match chunk_type {
                // Compressed: [4-byte CRC][snappy block]. snap::raw::decompress_len reads the
                // uncompressed length from the block's own varint header without decompressing.
                0x00 => {
                    let block = chunk_payload.get(4..).ok_or_else(|| {
                        io::Error::new(io::ErrorKind::InvalidData, "Compressed chunk missing CRC")
                    })?;
                    snap::raw::decompress_len(block).map_err(|err| {
                        io::Error::new(io::ErrorKind::InvalidData, format!("snappy len: {err}"))
                    })?
                }
                // Uncompressed: [4-byte CRC][raw bytes] → contributes chunk_len - 4 bytes.
                0x01 => chunk_len.checked_sub(4).ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidData, "Uncompressed chunk missing CRC")
                })?,
                // Reserved skippable (includes mid-stream 0xFF stream identifier).
                0x80..=0xFF => 0,
                // Reserved unskippable: MUST reject per snappy framing spec.
                _ => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!(
                            "Reserved unskippable snappy chunk type 0x{:02x}",
                            chunk_type
                        ),
                    ));
                }
            };

            uncompressed_len = uncompressed_len
                .checked_add(chunk_uncompressed_len)
                .ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidData, "Uncompressed size overflow")
                })?;

            if uncompressed_len > expected_uncompressed_size {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "Snappy uncompressed_len {} exceeds varint-declared {}",
                        uncompressed_len, expected_uncompressed_size
                    ),
                ));
            }

            pos += 4 + chunk_len;
        }

        Ok(pos)
    }

    /// Decode a single response chunk per spec:
    /// [response_code: 1 byte][varint: uncompressed_length][snappy_framed_payload]
    /// Returns (code, ssz_bytes, total_bytes_consumed) so the caller can advance the offset.
    fn decode_response_chunk(data: &[u8]) -> io::Result<(u8, Vec<u8>, usize)> {
        if data.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "Empty response chunk",
            ));
        }

        // First byte is response code
        let code = data[0];

        // Parse uncompressed length varint at offset 1
        let (declared_len, varint_size) = Self::decode_varint(&data[1..])?;

        if declared_len as usize > MAX_PAYLOAD_SIZE {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "Declared length too large: {} > {}",
                    declared_len, MAX_PAYLOAD_SIZE
                ),
            ));
        }

        let payload_start = 1 + varint_size;

        // Determine the byte length of this snappy framing stream so we know
        // exactly where the next chunk begins (required for multi-block responses).
        let frame_size = Self::snappy_frame_size(&data[payload_start..], declared_len as usize)?;
        let payload_end = payload_start + frame_size;

        let ssz_bytes = Self::decompress(&data[payload_start..payload_end])?;

        if ssz_bytes.len() != declared_len as usize {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "Length mismatch: declared {}, got {}",
                    declared_len,
                    ssz_bytes.len()
                ),
            ));
        }

        Ok((code, ssz_bytes, payload_end))
    }

    /// Decode response per spec. For BlocksByRoot, handle chunked format:
    /// [code][varint][snappy(block1)][code][varint][snappy(block2)]...
    fn decode_response(protocol: &str, data: &[u8]) -> io::Result<LeanResponse> {
        if data.is_empty() {
            if protocol.contains("blocks_by_range") {
                return Ok(LeanResponse::BlocksByRange(Vec::new()));
            }
            if protocol.contains("blocks_by_root") {
                return Ok(LeanResponse::BlocksByRoot(Vec::new()));
            }
            return Ok(LeanResponse::Empty);
        }

        if protocol.contains("status") {
            let (code, ssz_bytes, _) = Self::decode_response_chunk(data)?;

            if code != RESPONSE_SUCCESS {
                return Err(io::Error::new(
                    io::ErrorKind::Other,
                    format!("Status request failed with code: {}", code),
                ));
            }

            let status = Status::from_ssz_default(&ssz_bytes).map_err(|e| {
                io::Error::new(
                    io::ErrorKind::Other,
                    format!("SSZ decode Status failed: {e:?}"),
                )
            })?;
            Ok(LeanResponse::Status(status))
        } else if protocol.contains("blocks_by_root") {
            // Multi-chunk response: each block is a separate chunk.
            // Loop until all bytes are consumed.
            let mut blocks = Vec::new();
            let mut offset = 0;
            while offset < data.len() {
                let (code, ssz_bytes, consumed) = Self::decode_response_chunk(&data[offset..])?;
                offset += consumed;

                if code != RESPONSE_SUCCESS {
                    warn!(
                        response_code = code,
                        "BlocksByRoot non-success response chunk"
                    );
                    continue;
                }
                if ssz_bytes.is_empty() {
                    continue;
                }

                let block = SignedBlock::from_ssz_default(&ssz_bytes).map_err(|e| {
                    io::Error::new(
                        io::ErrorKind::Other,
                        format!("SSZ decode Block failed: {e:?}"),
                    )
                })?;
                blocks.push(block);
            }
            Ok(LeanResponse::BlocksByRoot(blocks))
        } else if protocol.contains("blocks_by_range") {
            let mut blocks = Vec::new();
            let mut offset = 0;
            while offset < data.len() {
                let (code, ssz_bytes, consumed) = Self::decode_response_chunk(&data[offset..])?;
                offset += consumed;

                if code != RESPONSE_SUCCESS {
                    warn!(
                        response_code = code,
                        "BlocksByRange non-success response chunk"
                    );
                    continue;
                }
                if ssz_bytes.is_empty() {
                    continue;
                }

                let block = SignedBlock::from_ssz_default(&ssz_bytes).map_err(|e| {
                    io::Error::new(
                        io::ErrorKind::Other,
                        format!("SSZ decode Block failed: {e:?}"),
                    )
                })?;
                blocks.push(block);
            }
            Ok(LeanResponse::BlocksByRange(blocks))
        } else {
            Err(io::Error::new(
                io::ErrorKind::Other,
                format!("Unknown protocol: {protocol}"),
            ))
        }
    }
}

impl Codec for LeanCodec {
    type Protocol = LeanProtocol;
    type Request = LeanRequest;
    type Response = LeanResponse;

    fn read_request<T>(
        &mut self,
        protocol: &Self::Protocol,
        io: &mut T,
    ) -> impl core::future::Future<Output = io::Result<Self::Request>> + Send
    where
        T: AsyncRead + Unpin + Send,
    {
        async move {
            let mut data = Vec::new();
            io.read_to_end(&mut data).await?;
            Self::decode_request(&protocol.0, &data)
        }
    }

    fn read_response<T>(
        &mut self,
        protocol: &Self::Protocol,
        io: &mut T,
    ) -> impl core::future::Future<Output = io::Result<Self::Response>> + Send
    where
        T: AsyncRead + Unpin + Send,
    {
        async move {
            let mut data = Vec::new();
            io.read_to_end(&mut data).await?;
            Self::decode_response(&protocol.0, &data)
        }
    }

    fn write_request<T>(
        &mut self,
        _protocol: &Self::Protocol,
        io: &mut T,
        request: Self::Request,
    ) -> impl core::future::Future<Output = io::Result<()>> + Send
    where
        T: AsyncWrite + Unpin + Send,
    {
        async move {
            let data = Self::encode_request(&request)?;
            io.write_all(&data).await?;
            io.close().await
        }
    }

    fn write_response<T>(
        &mut self,
        _protocol: &Self::Protocol,
        io: &mut T,
        response: Self::Response,
    ) -> impl core::future::Future<Output = io::Result<()>> + Send
    where
        T: AsyncWrite + Unpin + Send,
    {
        async move {
            let data = Self::encode_response(&response)?;
            io.write_all(&data).await?;
            io.close().await
        }
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

impl Codec for GenericCodec {
    type Protocol = GenericProtocol;
    type Request = GenericRequest;
    type Response = GenericResponse;

    fn read_request<T>(
        &mut self,
        _protocol: &Self::Protocol,
        io: &mut T,
    ) -> impl core::future::Future<Output = io::Result<Self::Request>> + Send
    where
        T: AsyncRead + Unpin + Send,
    {
        async move {
            let mut data = Vec::new();
            io.read_to_end(&mut data).await?;
            Ok(GenericRequest(data))
        }
    }

    fn read_response<T>(
        &mut self,
        _protocol: &Self::Protocol,
        io: &mut T,
    ) -> impl core::future::Future<Output = io::Result<Self::Response>> + Send
    where
        T: AsyncRead + Unpin + Send,
    {
        async move {
            let mut data = Vec::new();
            io.read_to_end(&mut data).await?;
            Ok(GenericResponse(data))
        }
    }

    fn write_request<T>(
        &mut self,
        _protocol: &Self::Protocol,
        io: &mut T,
        GenericRequest(data): Self::Request,
    ) -> impl core::future::Future<Output = io::Result<()>> + Send
    where
        T: AsyncWrite + Unpin + Send,
    {
        async move {
            io.write_all(&data).await?;
            io.close().await
        }
    }

    fn write_response<T>(
        &mut self,
        _protocol: &Self::Protocol,
        io: &mut T,
        GenericResponse(data): Self::Response,
    ) -> impl core::future::Future<Output = io::Result<()>> + Send
    where
        T: AsyncWrite + Unpin + Send,
    {
        async move {
            io.write_all(&data).await?;
            io.close().await
        }
    }
}

pub type ReqResp = RequestResponse<LeanCodec>;

pub type ReqRespMessage = Event<LeanRequest, LeanResponse>;

pub fn build(protocols: impl IntoIterator<Item = String>) -> ReqResp {
    let protocols = protocols
        .into_iter()
        .map(|name| (LeanProtocol(name), ProtocolSupport::Full))
        .collect::<Vec<_>>();

    // libp2p Config::default() sets request_timeout to 10s. Under host CPU
    // contention, lean's tokio worker can be late polling the stream and the
    // protocol layer kills the request before our app-level retry logic gets
    // a chance to react. Raise it well above the app-layer 30s timeout.
    let config = Config::default().with_request_timeout(Duration::from_secs(60));
    RequestResponse::with_codec(LeanCodec::default(), protocols, config)
}

/// Build a RequestResponse behavior for Status protocol only
pub fn build_status() -> ReqResp {
    build(vec![STATUS_PROTOCOL_V1.to_string()])
}

/// Build a RequestResponse behavior for BlocksByRoot protocol only
pub fn build_blocks_by_root() -> ReqResp {
    build(vec![BLOCKS_BY_ROOT_PROTOCOL_V1.to_string()])
}

/// Build a RequestResponse behavior for BlocksByRange protocol only
pub fn build_blocks_by_range() -> ReqResp {
    build(vec![BLOCKS_BY_RANGE_PROTOCOL_V1.to_string()])
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Encoding an error response must produce a single, well-formed ssz-snappy
    /// chunk whose response-code byte is the requested error code. This mirrors
    /// what the hive `reqresp/blocks_by_range/zero_count` scenario asserts on the
    /// wire: `!chunks.is_empty() && chunks[0].0 == RESPONSE_CODE_INVALID_REQUEST`.
    #[test]
    fn encode_error_response_sets_invalid_request_code() {
        let message = "count must be greater than zero";
        let response = LeanResponse::Error {
            code: RESPONSE_INVALID_REQUEST,
            message: message.to_string(),
        };

        let encoded = LeanCodec::encode_response(&response).expect("error response should encode");

        // The mock rejects an empty response, so there must be at least the code byte.
        assert!(!encoded.is_empty(), "encoded error response must not be empty");
        // First byte is the response code the peer reads.
        assert_eq!(
            encoded[0], RESPONSE_INVALID_REQUEST,
            "first byte must be the INVALID_REQUEST code"
        );

        // The chunk must be parseable back with the same framing the peer uses,
        // recovering the code and the original message payload, consuming all bytes.
        let (code, payload, consumed) =
            LeanCodec::decode_response_chunk(&encoded).expect("error chunk should decode");
        assert_eq!(code, RESPONSE_INVALID_REQUEST);
        assert_eq!(payload, message.as_bytes());
        assert_eq!(consumed, encoded.len(), "error response must be a single chunk");
    }

    /// The error code carried in the variant is what ends up on the wire, so a
    /// different code round-trips independently of the payload.
    #[test]
    fn encode_error_response_preserves_code_and_message() {
        let response = LeanResponse::Error {
            code: RESPONSE_SERVER_ERROR,
            message: "boom".to_string(),
        };

        let encoded = LeanCodec::encode_response(&response).expect("error response should encode");
        let (code, payload, _) =
            LeanCodec::decode_response_chunk(&encoded).expect("error chunk should decode");

        assert_eq!(code, RESPONSE_SERVER_ERROR);
        assert_eq!(payload, b"boom");
    }
}
