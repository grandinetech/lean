use core::net::{IpAddr, Ipv4Addr, SocketAddr};

use anyhow::Result;
use clap::Args;
use metrics::MetricsServerConfig;
use tokio::net::TcpListener;

const DEFAULT_HTTP_PORT: u16 = 8080;

#[derive(Debug, Clone, Args)]
pub struct HttpServerConfig {
    #[clap(long = "http-address", default_value_t = IpAddr::V4(Ipv4Addr::LOCALHOST))]
    http_address: IpAddr,

    #[clap(long = "http-port", default_value_t = DEFAULT_HTTP_PORT)]
    http_port: u16,

    #[clap(flatten)]
    pub(crate) metrics: MetricsServerConfig,
}

impl HttpServerConfig {
    pub(crate) async fn listener(&self) -> Result<TcpListener> {
        TcpListener::bind(self.address()).await.map_err(Into::into)
    }

    pub fn address(&self) -> SocketAddr {
        (self.http_address, self.http_port).into()
    }

    pub fn metrics_enabled(&self) -> bool {
        self.metrics.enabled()
    }
}
