use std::net::IpAddr;
use std::sync::Arc;
use clap::Parser;
use networking::bootnodes::{BootnodeSource, StaticBootnodes};
use tokio::{sync::mpsc, task};
use networking::network::{NetworkService, NetworkServiceConfig};
use networking::gossipsub::config::GossipsubConfig;
use networking::gossipsub::topic::get_topics;
use networking::types::OutboundP2pRequest;

#[derive(Parser, Debug)]
struct Args {
    #[arg(short, long, default_value = "127.0.0.1")]
    address: IpAddr,

    #[arg(short, long, default_value_t = 8083)]
    port: u16,

    #[arg(short, long)]
    bootnodes: Vec<String>,
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let args = Args::parse();

    let (outbound_p2p_sender, outbound_p2p_receiver) = mpsc::unbounded_channel::<OutboundP2pRequest>();

    let fork = "devnet0".to_string();
    let gossipsub_topics = get_topics(fork);
    let mut gossipsub_config = GossipsubConfig::new();
    gossipsub_config.set_topics(gossipsub_topics);

    let network_service_config = Arc::new(NetworkServiceConfig::new(
        gossipsub_config,
        args.address,
        args.port,
        args.bootnodes,
    ));
    let mut network_service = NetworkService::new(
        network_service_config.clone(),
        outbound_p2p_receiver,
    )
        .await
        .expect("Failed to create network service");

    let network_handle = task::spawn(async move {
        if let Err(err) = network_service.start().await {
            panic!("Network service exited with error: {err}");
        }
    });

    tokio::select! {
        _ = network_handle => {
            println!("Network service finished.");
        }
    }

    println!("Main async task exiting...");
}
