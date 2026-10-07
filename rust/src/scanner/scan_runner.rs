// SPDX-FileCopyrightText: 2024 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

use std::future::Future;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use crate::models::HostInfo;
use crate::nasl::ScanCtx;
use crate::nasl::utils::ctx::TargetId;
use futures::{Stream, StreamExt, stream};
use tokio::runtime::Handle;
use tokio::sync::mpsc::Receiver;

use crate::scheduling::{ConcurrentVT, ConcurrentVTResult, VTError};

use super::error::{ExecuteError, ScriptResult};
use super::vt_runner::VTRunner;

/// Name of the scan preference limiting how many hosts are scanned at
/// the same time. Same name as used by the classic OpenVAS scanner.
const MAX_HOSTS_PREFERENCE: &str = "max_hosts";

/// Number of hosts scanned in parallel if the scan does not configure
/// `max_hosts` (or configures an invalid value).
pub const DEFAULT_MAX_HOSTS: usize = 15;

#[derive(Debug, Clone)]
struct Position {
    target: TargetId,
    stage: usize,
    vt: usize,
}

/// Given the currently known `vts` schedule, returns all `(stage, vt)`
/// positions that need to be run for `host`, in the order they have to be
/// executed.
fn host_positions(host: TargetId, vts: &[ConcurrentVT]) -> Vec<Position> {
    vts.iter()
        .enumerate()
        .flat_map(|(stage, (_, stage_vts))| {
            (0..stage_vts.len()).map(move |vt| Position {
                target: host,
                stage,
                vt,
            })
        })
        .collect()
}

/// Turns the value of the `max_hosts` preference into the number of hosts
/// that may be scanned in parallel. Missing, non-positive or unparsable
/// values fall back to [`DEFAULT_MAX_HOSTS`].
fn parallel_hosts(preference: Option<i64>) -> usize {
    match preference {
        Some(n) if n > 0 => usize::try_from(n).unwrap_or(DEFAULT_MAX_HOSTS),
        _ => DEFAULT_MAX_HOSTS,
    }
}

/// Runs a single scan by executing all the VTs within a given schedule.
/// This does not provide any control over the scan but merely executes the
/// necessary instructions. In order to have control over the scan (such as
/// starting and stopping it), use `RunningScan` instead.
pub struct ScanRunner<'a> {
    concurrent_vts: Arc<Vec<ConcurrentVT>>,
    host_feed: Receiver<TargetId>,
    scan_ctx: &'a ScanCtx<'a>,
    max_hosts: usize,
}

impl<'a> ScanRunner<'a> {
    pub fn new<Sched>(
        schedule: Sched,
        host_feed: Receiver<TargetId>,
        scan_ctx: &'a ScanCtx<'a>,
    ) -> Result<Self, VTError>
    where
        Sched: Iterator<Item = ConcurrentVTResult> + 'a,
    {
        let concurrent_vts = Arc::new(schedule.collect::<Result<Vec<_>, _>>()?);
        let max_hosts = parallel_hosts(
            scan_ctx
                .scan_preferences
                .get_preference_int(MAX_HOSTS_PREFERENCE),
        );
        Ok(Self {
            concurrent_vts,
            host_feed,
            scan_ctx,
            max_hosts,
        })
    }

    /// Overrides the number of hosts that are scanned in parallel.
    /// A value of 0 is treated as 1.
    pub fn with_max_hosts(mut self, max_hosts: usize) -> Self {
        self.max_hosts = max_hosts.max(1);
        self
    }

    pub fn host_info(&self) -> HostInfo {
        HostInfo::from_hosts_and_num_vts(
            self.scan_ctx
                .targets()
                .iter()
                .map(|target| target.original_target_str()),
            self.concurrent_vts.len(),
        )
    }

    /// Runs all VTs against all hosts received on the host feed, scanning
    /// each host on its own OS thread, with at most `max_hosts` threads
    /// alive at the same time. A thread is started as soon as a host is
    /// reported alive and a slot is free.
    ///
    /// NASL network functions use blocking sockets, so hosts sharing one
    /// task would never overlap. Scoped threads are used (instead of
    /// `tokio::spawn`) because the `ScanCtx` is borrowed, not `'static`.
    ///
    /// For each host the VTs run strictly in schedule order. `on_result`
    /// is called, on the host's thread, with the result of every VT; no
    /// ordering is guaranteed between results of different hosts. When
    /// `keep_running` becomes false no further VT or host is started, but
    /// VTs already running are not interrupted.
    ///
    /// This blocks the calling thread until all hosts are done. Call it
    /// through `tokio::task::block_in_place` when on a multi-threaded
    /// runtime. `handle` is used to drive the async code on the new threads.
    pub fn run_threaded<F, Fut>(self, handle: Handle, keep_running: &AtomicBool, on_result: F)
    where
        F: Fn(Result<ScriptResult, ExecuteError>) -> Fut + Sync,
        Fut: Future<Output = ()>,
    {
        let ScanRunner {
            concurrent_vts,
            mut host_feed,
            scan_ctx,
            max_hosts,
        } = self;
        let (done_tx, done_rx) = std::sync::mpsc::channel::<()>();
        let mut running = 0usize;
        let (handle, on_result, concurrent_vts) = (&handle, &on_result, &concurrent_vts);

        std::thread::scope(|scope| {
            'hosts: while keep_running.load(Ordering::SeqCst) {
                // Free the slots of the hosts which are already done, and
                // wait for one if all slots are taken.
                while done_rx.try_recv().is_ok() {
                    running -= 1;
                }
                while running >= max_hosts {
                    if done_rx.recv().is_err() {
                        break 'hosts;
                    }
                    running -= 1;
                }
                // Wait for the next alive host, but wake up regularly to
                // notice that the scan was stopped.
                let host = loop {
                    match handle.block_on(tokio::time::timeout(
                        Duration::from_millis(200),
                        host_feed.recv(),
                    )) {
                        Ok(host) => break host,
                        Err(_) if !keep_running.load(Ordering::SeqCst) => break None,
                        Err(_) => {}
                    }
                };
                let Some(host) = host else { break };

                running += 1;
                let done_tx = done_tx.clone();
                scope.spawn(move || {
                    handle.block_on(async {
                        for pos in host_positions(host, concurrent_vts) {
                            if !keep_running.load(Ordering::SeqCst) {
                                break;
                            }
                            let (stage, vts) = &concurrent_vts[pos.stage];
                            let (vt, param) = &vts[pos.vt];
                            let result =
                                VTRunner::run(pos.target, vt, *stage, param.as_ref(), scan_ctx)
                                    .await;
                            on_result(result).await;
                        }
                    });
                    let _ = done_tx.send(());
                });
            }
        });
    }

    /// Streams the results of all VTs run against all hosts received on the
    /// host feed.
    ///
    /// Up to `max_hosts` hosts are scanned in parallel: as soon as a host
    /// finishes, the next host from the feed takes its place. For each
    /// individual host, the VTs are still run strictly one after the other
    /// and in the order given by the schedule, so the scheduling
    /// requirements (stage ordering and dependencies between VTs) hold for
    /// every host. No ordering is guaranteed between results of different
    /// hosts.
    ///
    /// The hosts are driven concurrently within the task polling the
    /// returned stream, so no VT needs to be `'static`; since VTs are
    /// asynchronous this lets them overlap whenever they wait on I/O.
    pub fn stream(self) -> impl Stream<Item = Result<ScriptResult, ExecuteError>> + 'a {
        let ScanRunner {
            concurrent_vts,
            host_feed,
            scan_ctx,
            max_hosts,
        } = self;

        // Hosts show up on the feed as the alive test reports them.
        let hosts = stream::unfold(host_feed, |mut feed| async move {
            feed.recv().await.map(|host| (host, feed))
        });

        hosts
            .map(move |host| {
                let positions = host_positions(host, &concurrent_vts);
                let concurrent_vts = concurrent_vts.clone();
                // `then` awaits each VT before starting the next one, which
                // keeps the per-host scheduling order intact.
                stream::iter(positions)
                    .then(move |pos| {
                        let concurrent_vts = concurrent_vts.clone();
                        async move {
                            let (stage, vts) = &concurrent_vts[pos.stage];
                            let (vt, param) = &vts[pos.vt];
                            VTRunner::run(pos.target, vt, *stage, param.as_ref(), scan_ctx).await
                        }
                    })
                    // `boxed` (not `boxed_local`) so the stream stays `Send`;
                    // `RunningScan::run` is spawned with `tokio::spawn`.
                    .boxed()
            })
            // Run at most `max_hosts` per-host streams at the same time.
            .flatten_unordered(max_hosts)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parallel_hosts_uses_preference_when_valid() {
        assert_eq!(parallel_hosts(Some(4)), 4);
        assert_eq!(parallel_hosts(Some(1)), 1);
    }

    #[test]
    fn parallel_hosts_falls_back_to_default() {
        assert_eq!(parallel_hosts(None), DEFAULT_MAX_HOSTS);
        assert_eq!(parallel_hosts(Some(0)), DEFAULT_MAX_HOSTS);
        assert_eq!(parallel_hosts(Some(-3)), DEFAULT_MAX_HOSTS);
    }

    #[test]
    fn host_positions_keep_schedule_order() {
        use crate::nasl::utils::indexed_arena::ArenaIndex;
        use crate::scheduling::Stage;

        let vt = |name: &str| crate::models::VTData {
            oid: name.to_string(),
            filename: name.to_string(),
            ..Default::default()
        };
        let schedule: Vec<ConcurrentVT> = vec![
            (Stage::Discovery, vec![(vt("a"), None), (vt("b"), None)]),
            (Stage::NonEvasive, vec![(vt("c"), None)]),
        ];
        let positions = host_positions(TargetId::from_index(7), &schedule);
        let got: Vec<_> = positions
            .iter()
            .map(|p| (p.target.to_index(), p.stage, p.vt))
            .collect();
        assert_eq!(got, vec![(7, 0, 0), (7, 0, 1), (7, 1, 0)]);
    }
}
