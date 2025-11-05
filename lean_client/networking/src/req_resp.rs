use std::io;

use async_trait::async_trait;
use futures::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use libp2p::request_response::{
    Behaviour as RequestResponse, Codec, Config, Event, ProtocolSupport,
};

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

pub type ReqResp = RequestResponse<GenericCodec>;

pub type ReqRespMessage = Event<GenericRequest, GenericResponse>;

pub fn build(protocols: impl IntoIterator<Item = String>) -> ReqResp {
    let protocols = protocols
        .into_iter()
        .map(|name| (GenericProtocol(name), ProtocolSupport::Full))
        .collect::<Vec<_>>();

    RequestResponse::with_codec(GenericCodec::default(), protocols, Config::default())
}
