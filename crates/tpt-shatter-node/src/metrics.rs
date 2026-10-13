// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 TPT Solutions

//! Operational counters, and the Prometheus text endpoint that exposes them.
//!
//! Labels hold only fixed vocabulary: HTTP status, the gateway's public code, and vault
//! label. No value, token, or shard key ever becomes a label or a sample. The endpoint is
//! meant for the management network (see `DECISIONS.md`, Observability).

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::Bytes;
use http_body_util::Full;
use hyper::body::Incoming;
use hyper::header::{CACHE_CONTROL, CONTENT_TYPE};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Method, Request, Response as HttpResponse, StatusCode};
use hyper_util::rt::TokioIo;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;
use tpt_shatter_vault_client::{BreakerState, VaultStatus};

/// Upper bounds, in seconds, of the assembly latency buckets. A `+Inf` bucket is implied.
const LATENCY_BOUNDS: [f64; 6] = [0.005, 0.025, 0.1, 0.5, 1.0, 3.0];

/// The path the metrics endpoint serves.
pub const METRICS_PATH: &str = "/metrics";

/// Counters and histograms for one node.
#[derive(Default)]
pub struct Metrics {
    /// Access outcomes, keyed by HTTP status and the gateway's public code.
    access: Mutex<BTreeMap<(u16, String), u64>>,
    alarms: AtomicU64,
    analytics_emitted: AtomicU64,
    fragments_purged: AtomicU64,
    /// Cumulative: bucket `i` counts observations at or below `LATENCY_BOUNDS[i]`.
    latency_buckets: [AtomicU64; 6],
    latency_count: AtomicU64,
    latency_sum_micros: AtomicU64,
}

impl Metrics {
    /// Counts one access-log line. Lines look like `status=200 code=ok token_hash=... fields=2`.
    /// A line without both a status and a code is not counted.
    pub fn record_access_line(&self, line: &str) {
        let mut status = None;
        let mut code = None;
        for part in line.split_whitespace() {
            if let Some(value) = part.strip_prefix("status=") {
                status = value.parse::<u16>().ok();
            } else if let Some(value) = part.strip_prefix("code=") {
                code = Some(value.to_owned());
            }
        }
        if let (Some(status), Some(code)) = (status, code) {
            if let Ok(mut access) = self.access.lock() {
                *access.entry((status, code)).or_default() += 1;
            }
        }
    }

    /// Counts one canary alarm response.
    pub fn record_alarm(&self) {
        self.alarms.fetch_add(1, Ordering::Relaxed);
    }

    /// Counts `events` analytics events emitted.
    pub fn record_analytics_emitted(&self, events: usize) {
        self.analytics_emitted
            .fetch_add(events as u64, Ordering::Relaxed);
    }

    /// Counts `fragments` fragments erased by retention.
    pub fn record_purged(&self, fragments: usize) {
        self.fragments_purged
            .fetch_add(fragments as u64, Ordering::Relaxed);
    }

    /// Records one read's assembly time.
    pub fn observe_assembly(&self, elapsed: Duration) {
        let seconds = elapsed.as_secs_f64();
        for (bucket, bound) in self.latency_buckets.iter().zip(LATENCY_BOUNDS) {
            if seconds <= bound {
                bucket.fetch_add(1, Ordering::Relaxed);
            }
        }
        self.latency_count.fetch_add(1, Ordering::Relaxed);
        let micros = u64::try_from(elapsed.as_micros()).unwrap_or(u64::MAX);
        self.latency_sum_micros.fetch_add(micros, Ordering::Relaxed);
    }

    /// The metrics as Prometheus text. `vaults` supplies the per-vault gauges, read at
    /// scrape time, so they are current.
    #[must_use]
    pub fn render(&self, vaults: &[VaultStatus]) -> String {
        let mut out = String::new();
        let access = self.access.lock().map(|a| a.clone()).unwrap_or_default();

        header(
            &mut out,
            "tpt_shatter_access_total",
            "counter",
            "Requests by HTTP status and code.",
        );
        for ((status, code), count) in &access {
            let _ = writeln!(
                out,
                "tpt_shatter_access_total{{status=\"{status}\",code=\"{code}\"}} {count}"
            );
        }

        counter(
            &mut out,
            "tpt_shatter_canary_alarms_total",
            "Canary alarm responses.",
            self.alarms.load(Ordering::Relaxed),
        );
        counter(
            &mut out,
            "tpt_shatter_analytics_emitted_total",
            "Analytics events emitted.",
            self.analytics_emitted.load(Ordering::Relaxed),
        );
        counter(
            &mut out,
            "tpt_shatter_fragments_purged_total",
            "Fragments erased by retention.",
            self.fragments_purged.load(Ordering::Relaxed),
        );

        header(
            &mut out,
            "tpt_shatter_vault_breaker_open",
            "gauge",
            "1 when a vault's breaker is open.",
        );
        for status in vaults {
            let open = u8::from(status.state == BreakerState::Open);
            let _ = writeln!(
                out,
                "tpt_shatter_vault_breaker_open{{vault=\"{}\"}} {open}",
                status.vault.label()
            );
        }
        header(
            &mut out,
            "tpt_shatter_vault_consecutive_failures",
            "gauge",
            "Failed operations since a vault's last success.",
        );
        for status in vaults {
            let _ = writeln!(
                out,
                "tpt_shatter_vault_consecutive_failures{{vault=\"{}\"}} {}",
                status.vault.label(),
                status.consecutive_failures
            );
        }
        // Stalled calls never fail, so they never reach the failure count. This gauge is
        // the only place they show.
        header(
            &mut out,
            "tpt_shatter_vault_in_flight",
            "gauge",
            "Calls running against a vault, including stalled ones.",
        );
        for status in vaults {
            let _ = writeln!(
                out,
                "tpt_shatter_vault_in_flight{{vault=\"{}\"}} {}",
                status.vault.label(),
                status.in_flight
            );
        }

        header(
            &mut out,
            "tpt_shatter_assembly_seconds",
            "histogram",
            "Time to reconstruct a record.",
        );
        for (bucket, bound) in self.latency_buckets.iter().zip(LATENCY_BOUNDS) {
            let _ = writeln!(
                out,
                "tpt_shatter_assembly_seconds_bucket{{le=\"{bound}\"}} {}",
                bucket.load(Ordering::Relaxed)
            );
        }
        let count = self.latency_count.load(Ordering::Relaxed);
        let _ = writeln!(
            out,
            "tpt_shatter_assembly_seconds_bucket{{le=\"+Inf\"}} {count}"
        );
        let sum = self.latency_sum_micros.load(Ordering::Relaxed) as f64 / 1_000_000.0;
        let _ = writeln!(out, "tpt_shatter_assembly_seconds_sum {sum}");
        let _ = writeln!(out, "tpt_shatter_assembly_seconds_count {count}");
        out
    }
}

fn header(out: &mut String, name: &str, kind: &str, help: &str) {
    let _ = writeln!(out, "# HELP {name} {help}");
    let _ = writeln!(out, "# TYPE {name} {kind}");
}

fn counter(out: &mut String, name: &str, help: &str, value: u64) {
    header(out, name, "counter", help);
    let _ = writeln!(out, "{name} {value}");
}

/// Serves `GET /metrics` on `listener` until the listener fails. `render` produces the body
/// for each scrape. With `acceptor`, the endpoint is TLS. Every other request gets `404`.
pub async fn serve_metrics(
    listener: TcpListener,
    acceptor: Option<TlsAcceptor>,
    render: Arc<dyn Fn() -> String + Send + Sync>,
) -> std::io::Result<()> {
    loop {
        let (stream, _) = listener.accept().await?;
        let render = Arc::clone(&render);
        let acceptor = acceptor.clone();
        tokio::spawn(async move {
            match acceptor {
                None => serve_metrics_connection(stream, render).await,
                Some(acceptor) => {
                    if let Ok(Ok(tls)) =
                        tokio::time::timeout(Duration::from_secs(5), acceptor.accept(stream)).await
                    {
                        serve_metrics_connection(tls, render).await;
                    }
                }
            }
        });
    }
}

async fn serve_metrics_connection<IO>(io: IO, render: Arc<dyn Fn() -> String + Send + Sync>)
where
    IO: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let service = service_fn(move |req| {
        let render = Arc::clone(&render);
        async move { Ok::<_, std::convert::Infallible>(route_metrics(req, render)) }
    });
    let _ = http1::Builder::new()
        .max_buf_size(8 * 1024)
        .serve_connection(TokioIo::new(io), service)
        .await;
}

fn route_metrics(
    req: Request<Incoming>,
    render: Arc<dyn Fn() -> String + Send + Sync>,
) -> HttpResponse<Full<Bytes>> {
    if req.method() != Method::GET || req.uri().path() != METRICS_PATH {
        return plain(StatusCode::NOT_FOUND, "not found\n");
    }
    HttpResponse::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "text/plain; version=0.0.4")
        .header(CACHE_CONTROL, "no-store")
        .body(Full::new(Bytes::from(render())))
        .unwrap_or_else(|_| plain(StatusCode::INTERNAL_SERVER_ERROR, "internal\n"))
}

fn plain(status: StatusCode, body: &'static str) -> HttpResponse<Full<Bytes>> {
    HttpResponse::builder()
        .status(status)
        .header(CONTENT_TYPE, "text/plain")
        .body(Full::new(Bytes::from_static(body.as_bytes())))
        .unwrap_or_else(|_| HttpResponse::new(Full::new(Bytes::new())))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tpt_shatter_common::VaultId;

    fn status(vault: VaultId, state: BreakerState, failures: u32) -> VaultStatus {
        VaultStatus {
            vault,
            state,
            consecutive_failures: failures,
            in_flight: 0,
        }
    }

    #[test]
    fn access_lines_are_counted_by_status_and_code() {
        let metrics = Metrics::default();
        metrics.record_access_line("status=200 code=ok token_hash=abc fields=2");
        metrics.record_access_line("status=200 code=ok token_hash=def fields=1");
        metrics.record_access_line("status=401 code=unauthorized token_hash=abc fields=0");
        metrics.record_access_line("not an access line");
        let text = metrics.render(&[]);
        assert!(text.contains("tpt_shatter_access_total{status=\"200\",code=\"ok\"} 2"));
        assert!(text.contains("tpt_shatter_access_total{status=\"401\",code=\"unauthorized\"} 1"));
        assert_eq!(text.matches("tpt_shatter_access_total{").count(), 2);
    }

    #[test]
    fn vault_gauges_reflect_the_statuses_passed_in() {
        let metrics = Metrics::default();
        let text = metrics.render(&[
            status(VaultId::A, BreakerState::Open, 4),
            status(VaultId::B, BreakerState::Closed, 0),
        ]);
        assert!(text.contains("tpt_shatter_vault_breaker_open{vault=\"A\"} 1"));
        assert!(text.contains("tpt_shatter_vault_breaker_open{vault=\"B\"} 0"));
        assert!(text.contains("tpt_shatter_vault_consecutive_failures{vault=\"A\"} 4"));
        assert!(text.contains("tpt_shatter_vault_in_flight{vault=\"A\"} 0"));
    }

    #[test]
    fn latency_buckets_are_cumulative() {
        let metrics = Metrics::default();
        metrics.observe_assembly(Duration::from_millis(1));
        metrics.observe_assembly(Duration::from_millis(50));
        let text = metrics.render(&[]);
        assert!(text.contains("tpt_shatter_assembly_seconds_bucket{le=\"0.005\"} 1"));
        assert!(text.contains("tpt_shatter_assembly_seconds_bucket{le=\"0.1\"} 2"));
        assert!(text.contains("tpt_shatter_assembly_seconds_bucket{le=\"+Inf\"} 2"));
        assert!(text.contains("tpt_shatter_assembly_seconds_count 2"));
    }

    async fn fetch(address: std::net::SocketAddr, path: &str) -> String {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let mut stream = tokio::net::TcpStream::connect(address)
            .await
            .expect("connect");
        let request = format!(
            "GET {path} HTTP/1.1
Host: test
Connection: close

"
        );
        stream.write_all(request.as_bytes()).await.expect("write");
        let mut reply = String::new();
        stream.read_to_string(&mut reply).await.expect("read");
        reply
    }

    #[tokio::test]
    async fn the_endpoint_serves_metrics_and_refuses_other_paths() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let address = listener.local_addr().expect("addr");
        let render: Arc<dyn Fn() -> String + Send + Sync> = Arc::new(|| {
            "tpt_shatter_test 1
"
            .to_owned()
        });
        tokio::spawn(serve_metrics(listener, None, render));

        let ok = fetch(address, METRICS_PATH).await;
        assert!(ok.starts_with("HTTP/1.1 200"), "{ok}");
        assert!(ok.contains("text/plain; version=0.0.4"), "{ok}");
        assert!(ok.contains("tpt_shatter_test 1"), "{ok}");

        let missing = fetch(address, "/other").await;
        assert!(missing.starts_with("HTTP/1.1 404"), "{missing}");
    }

    #[test]
    fn counters_count() {
        let metrics = Metrics::default();
        metrics.record_alarm();
        metrics.record_analytics_emitted(3);
        metrics.record_purged(2);
        let text = metrics.render(&[]);
        assert!(text.contains("tpt_shatter_canary_alarms_total 1"));
        assert!(text.contains("tpt_shatter_analytics_emitted_total 3"));
        assert!(text.contains("tpt_shatter_fragments_purged_total 2"));
    }
}
