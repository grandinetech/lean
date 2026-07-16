/// Integration tests for api_endpoint test vectors.
///
/// Discovers all JSON files under `test_vectors/api_endpoint/` and for each:
///   1. Deserialises the test-vector fields.
///   2. Builds the axum router with the aggregator controller seeded from
///      `initialIsAggregator`.
///   3. Drives the router directly via `tower::ServiceExt::oneshot` (no TCP).
///   4. Asserts status code, Content-Type, and response body match.
use std::{collections::HashMap, fs, path::Path, sync::Arc};

use axum::{
    body::Body,
    http::{Request, header::CONTENT_TYPE},
};
use containers::{Block, BlockBody, Checkpoint, MultiMessageAggregate, SignedBlock, Slot};
use fork_choice::store::Store;
use http_api::{
    AggregatorController, HttpServerConfig, SharedSignedBlocks, SharedStore, normal_routes,
};
use http_body_util::BodyExt;
use parking_lot::RwLock;
use serde::Deserialize;
use serde_json::Value;
use ssz::{H256, SszHash, SszReadDefault as _};
use test_generator::test_resources;
use tower::ServiceExt;

#[derive(Debug, Deserialize)]
struct ApiEndpointTestVectorFile {
    #[serde(flatten)]
    tests: HashMap<String, ApiEndpointTestCase>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ApiEndpointTestCase {
    endpoint: String,
    #[serde(default = "default_get")]
    method: String,
    #[serde(default)]
    initial_is_aggregator: Option<bool>,
    #[serde(default)]
    request_body: Option<Value>,
    expected_status_code: u16,
    expected_content_type: String,
    #[serde(default)]
    expected_body: Option<Value>,
}

fn default_get() -> String {
    "GET".to_string()
}

#[test_resources("test_vectors/api_endpoint/**/*.json")]
fn api_endpoint(spec_file: &str) {
    let test_path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join(spec_file);

    let json_content = fs::read_to_string(&test_path).expect("read test vector");
    let file: ApiEndpointTestVectorFile =
        serde_json::from_str(&json_content).expect("parse test vector");

    let (test_name, case) = file
        .tests
        .into_iter()
        .next()
        .expect("at least one test case per file");

    let rt = tokio::runtime::Runtime::new().expect("tokio runtime");
    rt.block_on(async move {
        // Build a minimal store — aggregator handlers only read/write
        // `store.is_aggregator`; no chain state is needed.
        let initial_is_aggregator = case.initial_is_aggregator.unwrap_or(false);
        let store: SharedStore = Arc::new(RwLock::new(Store {
            is_aggregator: initial_is_aggregator,
            ..Default::default()
        }));

        let signed_blocks: SharedSignedBlocks = Arc::new(RwLock::new(HashMap::new()));

        let controller = Some(Arc::new(AggregatorController::new(store.clone(), None)));

        let config = HttpServerConfig::default();
        let router = normal_routes(&config, store, signed_blocks, controller);

        let request = match (case.method.as_str(), case.request_body.as_ref()) {
            ("POST", Some(body)) => {
                let bytes = serde_json::to_vec(body).expect("serialize request body");
                Request::builder()
                    .method("POST")
                    .uri(&case.endpoint)
                    .header(CONTENT_TYPE, "application/json")
                    .body(Body::from(bytes))
                    .expect("build request")
            }
            ("POST", None) => Request::builder()
                .method("POST")
                .uri(&case.endpoint)
                .body(Body::empty())
                .expect("build request"),
            _ => Request::builder()
                .method("GET")
                .uri(&case.endpoint)
                .body(Body::empty())
                .expect("build request"),
        };

        let response = router.oneshot(request).await.expect("router oneshot");

        let actual_status = response.status().as_u16();
        let actual_content_type = response
            .headers()
            .get(CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_owned();

        let body_bytes = response
            .into_body()
            .collect()
            .await
            .expect("collect response body")
            .to_bytes();

        assert_eq!(
            actual_status, case.expected_status_code,
            "status code mismatch in {}",
            test_name,
        );

        assert!(
            actual_content_type.contains(&case.expected_content_type),
            "content-type mismatch in {}: got '{}', expected '{}'",
            test_name,
            actual_content_type,
            case.expected_content_type,
        );

        if let Some(expected_body) = case.expected_body {
            let actual_body: Value =
                serde_json::from_slice(&body_bytes).expect("parse response body as JSON");
            assert_eq!(actual_body, expected_body, "body mismatch in {}", test_name);
        }
    });
}

fn sample_signed_block() -> SignedBlock {
    SignedBlock {
        block: Block {
            slot: Slot(13),
            proposer_index: 0,
            parent_root: H256::default(),
            state_root: H256::default(),
            body: BlockBody {
                attestations: Default::default(),
            },
        },
        proof: MultiMessageAggregate::default(),
    }
}

fn blocks_finalized_request() -> Request<Body> {
    Request::builder()
        .method("GET")
        .uri("/lean/v0/blocks/finalized")
        .body(Body::empty())
        .expect("build request")
}

#[test]
fn blocks_finalized_returns_signed_block_ssz() {
    let rt = tokio::runtime::Runtime::new().expect("tokio runtime");
    rt.block_on(async move {
        let signed_block = sample_signed_block();
        let root = signed_block.block.hash_tree_root();

        let store: SharedStore = Arc::new(RwLock::new(Store {
            latest_finalized: Checkpoint {
                root,
                slot: signed_block.block.slot,
            },
            ..Default::default()
        }));
        let signed_blocks: SharedSignedBlocks =
            Arc::new(RwLock::new(HashMap::from([(root, signed_block.clone())])));
        let controller = Some(Arc::new(AggregatorController::new(store.clone(), None)));

        let config = HttpServerConfig::default();
        let router = normal_routes(&config, store, signed_blocks, controller);

        let response = router
            .oneshot(blocks_finalized_request())
            .await
            .expect("router oneshot");

        assert_eq!(response.status().as_u16(), 200);
        assert_eq!(
            response
                .headers()
                .get(CONTENT_TYPE)
                .and_then(|value| value.to_str().ok()),
            Some("application/octet-stream"),
        );

        let body_bytes = response
            .into_body()
            .collect()
            .await
            .expect("collect response body")
            .to_bytes();

        let decoded = SignedBlock::from_ssz_default(&body_bytes).expect("decode SignedBlock SSZ");
        assert_eq!(decoded.block.hash_tree_root(), root);
        assert_eq!(decoded.block.slot, signed_block.block.slot);
    });
}

#[test]
fn blocks_finalized_returns_404_when_signed_block_missing() {
    let rt = tokio::runtime::Runtime::new().expect("tokio runtime");
    rt.block_on(async move {
        let signed_block = sample_signed_block();

        let store: SharedStore = Arc::new(RwLock::new(Store {
            latest_finalized: Checkpoint {
                root: signed_block.block.hash_tree_root(),
                slot: signed_block.block.slot,
            },
            ..Default::default()
        }));
        let signed_blocks: SharedSignedBlocks = Arc::new(RwLock::new(HashMap::new()));
        let controller = Some(Arc::new(AggregatorController::new(store.clone(), None)));

        let config = HttpServerConfig::default();
        let router = normal_routes(&config, store, signed_blocks, controller);

        let response = router
            .oneshot(blocks_finalized_request())
            .await
            .expect("router oneshot");

        assert_eq!(response.status().as_u16(), 404);
    });
}
