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
use fork_choice::store::Store;
use http_api::{AggregatorController, HttpServerConfig, SharedStore, normal_routes};
use http_body_util::BodyExt;
use parking_lot::RwLock;
use serde::Deserialize;
use serde_json::Value;
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
            time: Default::default(),
            config: Default::default(),
            is_aggregator: initial_is_aggregator,
            head: Default::default(),
            safe_target: Default::default(),
            latest_justified: Default::default(),
            latest_finalized: Default::default(),
            justified_ever_updated: false,
            finalized_ever_updated: false,
            blocks: Default::default(),
            states: Default::default(),
            latest_known_attestations: Default::default(),
            latest_new_attestations: Default::default(),
            gossip_signatures: Default::default(),
            latest_known_aggregated_payloads: Default::default(),
            latest_new_aggregated_payloads: Default::default(),
            attestation_data_by_root: Default::default(),
            pending_attestations: Default::default(),
            pending_aggregated_attestations: Default::default(),
            pending_fetch_roots: Default::default(),
            log_inv_rate: Default::default(),
        }));

        let controller = Some(Arc::new(AggregatorController::new(store.clone(), None)));

        let config = HttpServerConfig::default();
        let router = normal_routes(&config, store, controller);

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
