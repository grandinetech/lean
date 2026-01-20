# Lean Client Metrics

This crate provides Prometheus-compatible metrics for the Lean Ethereum client, implementing metrics from the [Lean Metrics Specifications](https://github.com/leanEthereum/leanMetrics).

## Implemented Metrics

### Node Info and Basic Metrics
- **`network_peers_connected`** : Number of currently connected peers.
- **`beacon_head_slot`** : Current head slot of the Beacon Chain.
- **`validators_total`** : Total number of validators in the registry.
- **`validators_active`** : Number of active validators (currently stubbed; needs proper implementation).

### Network Metrics
- **`lean_peer_connection_events_total`** : Total peer connection events, labeled by `direction` (inbound/outbound) and `result` (success/error).
- **`lean_peer_disconnection_events_total`** : Total peer disconnection events, labeled by `direction` and `reason` (timeout/remote_close/error).


### Fork-Choice Metrics
- **`lean_current_slot`** : Current slot of the Lean chain.
- **`lean_safe_target_slot`** : Safe target slot.
- **`lean_fork_choice_block_processing_time_seconds`** : Time taken to process blocks (buckets: 0.005, 0.01, 0.025, 0.05, 0.1, 1.0).
- **`lean_attestations_valid_total`** : Number of valid attestations, labeled by `source` (block/gossip).
- **`lean_attestations_invalid_total`** : Number of invalid attestations, labeled by `source`.
- **`lean_attestation_validation_time_seconds`** : Time taken to validate attestations (buckets: 0.005, 0.01, 0.025, 0.05, 0.1, 1.0).
- **`lean_fork_choice_reorgs_total`** : Total number of fork-choice reorgs.
- **`lean_fork_choice_reorg_depth`** : Depth of fork-choice reorgs in blocks (buckets: 1, 2, 3, 5, 7, 10, 20, 30, 50, 100).

## Enabling Metrics

To enable the metrics server, run the Lean client with the `--metrics` flag:

```bash
./lean_client --metrics --metrics-port 9100
```

- `--metrics`: Enables the Prometheus metrics server.
- `--metrics-port`: Specifies the port for the metrics server (default: 9100).

The server will start an HTTP endpoint exposing metrics in Prometheus format.

## Viewing Metrics

Once the client is running with metrics enabled, you can view the metrics in several ways:

### Via HTTP Endpoint
Access the metrics directly via HTTP:

```bash
curl http://localhost:9100/metrics
```

This returns the full Prometheus metrics output, including all gauges, counters, and histograms.

### Using Prometheus
Configure Prometheus to scrape the endpoint:

```yaml
# prometheus.yml
scrape_configs:
  - job_name: 'lean_client'
    static_configs:
      - targets: ['localhost:9100']
```

Then, use the Prometheus web UI or Grafana to visualize the metrics.

### Example Output
A sample metrics output might look like:

```
# HELP network_peers_connected Number of connected peers
# TYPE network_peers_connected gauge
network_peers_connected 5

# HELP lean_current_slot Current slot of the lean chain
# TYPE lean_current_slot gauge
lean_current_slot 12345

# HELP lean_attestations_valid_total Total number of valid attestations
# TYPE lean_attestations_valid_total counter
lean_attestations_valid_total{source="gossip"} 42
```

## Setting Up Monitoring Stack

For a complete monitoring setup with dashboards, use the provided Docker Compose configuration to run Prometheus and Grafana locally.

### Prerequisites
- Docker and Docker Compose installed
- Lean client built and running with metrics enabled

### Launching the Monitoring Stack

1. **Start the Lean client with metrics:**
   ```bash
   cd lean/lean_client
   cargo build --release
   cd ../..
   ./lean/lean_client --metrics --metrics-port 9100
   ```

2. **Launch Prometheus and Grafana:**
   ```bash
   docker-compose up -d
   ```

   This will start:
   - Prometheus on http://localhost:9090
   - Grafana on http://localhost:3000 (default credentials: admin/admin)

### Configuring Grafana

1. **Access Grafana:**
   Open http://localhost:3000 in your browser and log in with `admin`/`admin`.

2. **Add Prometheus Data Source:**
   - Click the gear icon in the left sidebar → "Data sources"
   - Click "Add data source"
   - Select "Prometheus"
   - Configure:
     - **Name:** `Prometheus`
     - **URL:** `http://prometheus:9090` (if using Docker) or `http://localhost:9090` (if Prometheus is running locally)
   - Click "Save & test" to verify the connection

### Creating the Dashboard

You can either import a pre-configured dashboard or create one manually:

#### Option 1: Import Dashboard (Recommended)
1. Click the "+" icon in the left sidebar → "Import dashboard"
2. Upload the `lean_client_dashboard.json` file from the repository root
3. Select the Prometheus data source you just created
4. Click "Import"

#### Option 2: Create Dashboard Manually
1. Click the "+" icon in the left sidebar → "New dashboard"
2. Click "Add a new panel"
3. Select your Prometheus data source
4. Add the following panels with these queries:

   **Current Slot (Stat Panel):**
   - Query: `lean_current_slot`

   **Beacon Head Slot (Stat Panel):**
   - Query: `beacon_head_slot`

   **Connected Peers (Stat Panel):**
   - Query: `network_peers_connected`

   **Validators Total (Stat Panel):**
   - Query: `validators_total`

   **Slot Progression (Graph Panel):**
   - Query: `lean_current_slot`
   - Legend: `Current Slot`

   **Peer Connections (Graph Panel):**
   - Query: `rate(lean_peer_connection_events_total[5m])`
   - Legend: `{{direction}} {{result}}`

   **Block Processing Time (Heatmap Panel):**
   - Query: `rate(lean_fork_choice_block_processing_time_seconds_bucket[5m])`

   **Attestation Validation (Graph Panel):**
   - Query A: `rate(lean_attestations_valid_total[5m])` - Legend: `Valid {{source}}`
   - Query B: `rate(lean_attestations_invalid_total[5m])` - Legend: `Invalid {{source}}`

5. Adjust panel layouts and save the dashboard

### Troubleshooting

- **Dashboard import fails:** Ensure the Prometheus data source is properly configured and named "Prometheus"
- **No data in panels:** Verify the Lean client is running with `--metrics` flag and Prometheus can scrape the endpoint
- **Grafana can't connect to Prometheus:** Check that Docker containers are running (`docker ps`) and network configuration
- **Metrics not updating:** Ensure the Lean client is actively processing blocks/attestations to generate metric updates

### Stopping the Monitoring Stack

To stop the monitoring containers:
```bash
docker-compose down
```

To also remove the containers and volumes:
```bash
docker-compose down -v
```