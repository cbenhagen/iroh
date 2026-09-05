//! Regression test: `remote_state::State::pending_open_paths` must stay bounded.
//!
//! When path opening fails with `MaxPathIdReached` / `RemoteCidsExhausted`, the addr is
//! queued and retried via `open_path_on_all_conns`, which re-attempts it on every
//! connection to the peer. Without dedup, a peer with two or more connections at their
//! path-id cap re-queues each drained addr once per connection, so the queue grows
//! unboundedly (it reached ~32768 entries in under 5 s here before the fix, and >20 GB
//! in the field).
//!
//! Path-id exhaustion can't be reached through the public API, so it is injected with the
//! `test_utils::path_cap_hooks` hook. With the dedup + cap fix the queue stays bounded for
//! any connection count.
//!
//! Run: cargo test --features test-utils --test pending_open_paths_leak -- --nocapture

use std::time::Duration;

use iroh::{
    Endpoint, RelayMode, SecretKey,
    endpoint::presets,
    test_utils::{path_cap_hooks, run_relay_server},
    tls::CaTlsConfig,
};
use n0_error::{Result, StdResultExt};
use tracing::info;

const ALPN_A: &[u8] = b"leak-test/a";
const ALPN_B: &[u8] = b"leak-test/b";

/// Connects `num_conns` connections from a fresh client to a fresh server (both using a
/// local relay + direct localhost paths), lets the remote-state actor run for `dwell`,
/// and returns the high-water mark of `pending_open_paths`.
async fn run_phase(relay_map: iroh::RelayMap, num_conns: usize, dwell: Duration) -> Result<usize> {
    let server_secret = SecretKey::generate();
    let server = Endpoint::builder(presets::Minimal)
        .relay_mode(RelayMode::Custom(relay_map.clone()))
        .secret_key(server_secret)
        .alpns(vec![ALPN_A.to_vec(), ALPN_B.to_vec()])
        .ca_tls_config(CaTlsConfig::insecure_skip_verify())
        .bind()
        .await
        .anyerr()?;
    server.online().await;
    let server_addr = server.addr();
    info!(?server_addr, "server online");

    // Server side: accept and hold the connections open.
    let server_task = tokio::spawn({
        let server = server.clone();
        async move {
            let mut conns = Vec::new();
            while let Some(incoming) = server.accept().await {
                if let Ok(conn) = incoming.await {
                    conns.push(conn);
                }
            }
            drop(conns);
        }
    });

    let client = Endpoint::builder(presets::Minimal)
        .relay_mode(RelayMode::Custom(relay_map))
        .secret_key(SecretKey::generate())
        .ca_tls_config(CaTlsConfig::insecure_skip_verify())
        .bind()
        .await
        .anyerr()?;

    path_cap_hooks::reset_high_water();

    // Open the connections. Both go to the same endpoint id, so they share one
    // RemoteStateActor on the client.
    let mut conns = Vec::new();
    for (i, alpn) in [ALPN_A, ALPN_B].iter().enumerate() {
        if i >= num_conns {
            break;
        }
        let conn = client.connect(server_addr.clone(), alpn).await.anyerr()?;
        info!(alpn = ?std::str::from_utf8(alpn), "client connection established");
        conns.push(conn);
    }

    // Let the actor run: seeding happens via handle_msg_add_connection (relay addr
    // re-add) / apply_selected_path; the 333 ms retry loop then drains + re-queues.
    tokio::time::sleep(dwell).await;

    let high_water = path_cap_hooks::pending_open_paths_high_water();

    drop(conns);
    client.close().await;
    server.close().await;
    server_task.abort();

    Ok(high_water)
}

#[tokio::test]
async fn pending_open_paths_stays_bounded() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "warn,pending_open_paths_leak=info".into()),
        )
        .try_init()
        .ok();

    let (relay_map, _relay_url, _relay_guard) = run_relay_server().await.anyerr()?;

    // Simulate connections whose multipath path-id budget is exhausted
    // (PathError::MaxPathIdReached), which is the state observed in production.
    path_cap_hooks::force_max_path_id_reached(true);

    let dwell = Duration::from_secs(5);

    // Control: a single connection must not amplify. Each 333 ms drain re-queues each
    // entry at most once (1 conn), so the queue stays at its seed size.
    let hw_single = run_phase(relay_map.clone(), 1, dwell).await?;
    info!(hw_single, "phase 1 (1 connection) done");

    // Two connections to the same peer: the unfixed code re-queues each drained addr on
    // both connections every retry (doubling); the dedup + cap must keep it bounded.
    let hw_double = run_phase(relay_map, 2, dwell).await?;
    info!(hw_double, "phase 2 (2 connections) done");

    println!("pending_open_paths high-water: 1 conn = {hw_single}, 2 conns = {hw_double}");

    // With the fix (dedup + cap in `enqueue_pending_open_path`) the queue holds only the
    // distinct pending addresses, independent of connection count. Without the fix,
    // `hw_double` reaches ~32768 here in < 5 s and keeps doubling. Assert well under the
    // MAX_PENDING_OPEN_PATHS cap (64) so any reintroduction of the unbounded requeue fails.
    assert!(
        hw_single <= 64,
        "single-connection queue should stay bounded, got {hw_single}"
    );
    assert!(
        hw_double <= 64,
        "queue must stay bounded with 2 connections; \
         a large value means the unbounded per-connection requeue regressed (got {hw_double})"
    );

    Ok(())
}
