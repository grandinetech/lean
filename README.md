# leanEthereum Consensus Client

leanEthereum Consensus Client written in Rust using Grandine's libraries.

## Testing against other implementations

1. Clone the quickstart repository as a sibling folder:
   ```bash
   cd ..  # Go to parent directory (same level as this repo)
   git clone https://github.com/blockblaz/lean-quickstart
   cd lean-quickstart
   ```
2. Launch Zeam, Ream, Latern nodes (DEVNET 1):
   ```bash
   NETWORK_DIR=local-devnet ./spin-node.sh --tag=devnet1 --node zeam_0,ream_0,lantern_0 --generateGenesis --metrics 
   ```
3. Launch the client:
   ```bash
   cd lean_client/
   cargo build --release
   ```
   
   Run in debug mode via terminal (with XMSS signing):
   ```
   RUST_LOG=info ./target/release/lean_client \
                 --genesis ../../lean-quickstart/local-devnet/genesis/config.yaml \
                 --validator-registry-path ../../lean-quickstart/local-devnet/genesis/validators.yaml \
                 --hash-sig-key-dir ../../lean-quickstart/local-devnet/genesis/hash-sig-keys \
                 --node-id qlean_0 \
                 --node-key ../../lean-quickstart/local-devnet/genesis/qlean_0.key \
                 --port 9003 \
                 --disable-discovery \
                 --bootnodes "/ip4/127.0.0.1/udp/9001/quic-v1/p2p/16Uiu2HAkvi2sxT75Bpq1c7yV2FjnSQJJ432d6jeshbmfdJss1i6f" \
                 --bootnodes "/ip4/127.0.0.1/udp/9002/quic-v1/p2p/16Uiu2HAmPQhkD6Zg5Co2ee8ShshkiY4tDePKFARPpCS2oKSLj1E1" \
                 --bootnodes "/ip4/127.0.0.1/udp/9004/quic-v1/p2p/16Uiu2HAm7TYVs6qvDKnrovd9m4vvRikc4HPXm1WyLumKSe5fHxBv"
   ```
4. Leave client running for a few minutes and observe warnings, errors, check if blocks are being justified and finalized (don't need debug mode for this last one)

## Testing discovery

1. Build the client:
   ```bash
   cd lean_client/
   cargo build --release
   ```
   
2. Start the bootnode

   Run in the terminal:
   ```
   RUST_LOG=info ./target/release/lean_client \
                 --port 9000 \
                 --discovery-port 9100
   ```
   
3. Start the other nodes

   Run in the terminal:
   ```
   RUST_LOG=info ./target/release/lean_client \
                 --port 9001 \
                 --discovery-port 9101 \
                 --bootnodes "<bootnode-enr>"
   ```
   
   ```
   RUST_LOG=info ./target/release/lean_client \
                 --port 9002 \
                 --discovery-port 9102 \
                 --bootnodes "<bootnode-enr>"
   ```
   
After a minute all the nodes should be synced up and see each other

## Running Hive tests

Runs the [Hive](https://github.com/ethereum/hive) lean simulator against our
`grandine_lean` client. From the repo root:

```bash
make test-hive
```

Requires a **Go toolchain**, **Docker** (running, usable without `sudo`), and
**Rust + [`cross`](https://github.com/cross-rs/cross)**.

Pin a hive version (defaults to latest `master`):

```bash
make test-hive HIVE_VERSION=<full-commit-hash>
```

Remove the hive clone and other build artifacts:

```bash
make clean
```
