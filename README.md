# LeanEtheriumReengeneer
Block Chain technology university course

Initial 2

tests run by executing in lean_client folder following command:  cargo test --workspace



## Testing against other implementations

1. Clone the quickstart repository:
   ```bash
   git clone https://github.com/blockblaz/lean-quickstart
   cd lean-quickstart
   ```
2. Generate genesis configuration:
   ```bash
   ./generate-genesis.sh local-devnet/genesis
   ```
3. Update configuration:
   Replace `lean_client/config.yaml` in this repository with the `config.yaml` generated in the previous step.
4. Launch Zeam and Ream nodes or if gossipsub deserialization fails only ream as zeam might have been not updated to latest spec:
   ```bash
   NETWORK_DIR=local-devnet ./spin-node.sh --node zeam_0,ream_0
   ```
5. Launch the client:
   Once the nodes are running, launch the client using the `.vscode/launch.json` script.
