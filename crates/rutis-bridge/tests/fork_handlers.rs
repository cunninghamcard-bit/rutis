//! Processes started while another thread initializes libnotify (#287).
//!
//! On macOS, `fork` runs libSystem's handlers in the child, and libnotify's
//! takes its once-only global state. A child forked while another thread
//! of the host was initializing that state inherits a half-taken once-gate
//! and is killed (SIGKILL) before it runs anything. The Security framework
//! initializes libnotify the first time something reads the trust settings,
//! as loading the system's root certificates for TLS does; the bridge's
//! tests lost Node runtimes that way on macOS 27.
//!
//! Each round is a fresh process (libnotify initializes once per process):
//! one thread reads the trust settings while `THREADS` threads start a
//! process each through the local transport, all at the same moment; every
//! process must then end by itself.
// macOS only (Q7.8): the fork handlers and the once-gate are libSystem's;
// elsewhere a fork runs no such handler.
#![cfg(target_vendor = "apple")]

use std::sync::{Arc, Barrier};
use std::time::Duration;

use rutis_bridge::channel::{ChannelError, PeerId};
use rutis_bridge::transport::local::{LocalTransport, Spawn};
use rutis_bridge::{Dial, Transport};

const THREADS: usize = 16;
const ROUNDS: usize = 20;
/// A hang guard only.
const HANG_GUARD: Duration = Duration::from_secs(30);
/// Set in the environment of a round's process.
const ROUND: &str = "RUTIS_FORK_HANDLERS_ROUND";

#[link(name = "Security", kind = "framework")]
extern "C" {
    fn SecTrustSettingsCopyCertificates(domain: u32, certificates: *mut *const ()) -> i32;
}
#[link(name = "CoreFoundation", kind = "framework")]
extern "C" {
    fn CFRelease(object: *const ());
}

/// What loading the system's root certificates does first (as
/// rustls-native-certs does): read the trust settings.
fn read_trust_settings() {
    let mut certificates = std::ptr::null();
    // SAFETY: domain 0 is the user domain; `certificates` is released if set.
    unsafe {
        if SecTrustSettingsCopyCertificates(0, &mut certificates) == 0 && !certificates.is_null() {
            CFRelease(certificates);
        }
    }
}

/// guarantee: bridge/spawned-processes-survive-fork (issue #287): a process
/// the local transport starts is not killed by libSystem's fork handlers
/// when another thread of the host initializes libnotify at that moment.
#[test]
fn processes_started_while_libnotify_initializes_survive_the_fork() {
    let exe = std::env::current_exe().unwrap();
    for number in 0..ROUNDS {
        let output = std::process::Command::new(&exe)
            .args(["--exact", "round", "--ignored", "--nocapture", "--test-threads=1"])
            .env(ROUND, "1")
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "round {number}: {}\n{}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        );
    }
}

/// One round, in a process of its own (see the test above).
#[test]
#[ignore = "a round of processes_started_while_libnotify_initializes_survive_the_fork, run in a process of its own"]
fn round() {
    assert!(
        std::env::var_os(ROUND).is_some(),
        "run by processes_started_while_libnotify_initializes_survive_the_fork"
    );
    let mut spawn = Spawn::new("sh", PeerId::new("child").unwrap());
    spawn.args = vec!["-c".into(), "exit 0".into()];
    let lineup = Arc::new(Barrier::new(THREADS + 1));
    let trust = {
        let lineup = lineup.clone();
        std::thread::spawn(move || {
            lineup.wait();
            read_trust_settings();
        })
    };
    let threads: Vec<_> = (0..THREADS)
        .map(|thread| {
            let (lineup, spawn) = (lineup.clone(), spawn.clone());
            std::thread::spawn(move || {
                let runtime = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .unwrap();
                let transport = LocalTransport::default();
                transport.spawner("probe", spawn);
                lineup.wait();
                let mut channel = runtime
                    .block_on(transport.dial(&Dial::address("spawn:probe")))
                    .map_err(|error| format!("thread {thread}: start: {error}"))?;
                let end = runtime.block_on(async move {
                    let end = tokio::task::spawn_blocking(move || channel.receiver.recv());
                    tokio::time::timeout(HANG_GUARD, end).await
                });
                match end {
                    Ok(Ok(Err(ChannelError::Closed { reason })))
                        if reason == "the process exited normally" =>
                    {
                        Ok(())
                    }
                    other => Err(format!("thread {thread}: {other:?}")),
                }
            })
        })
        .collect();
    let failures: Vec<String> = threads
        .into_iter()
        .filter_map(|thread| thread.join().unwrap().err())
        .collect();
    trust.join().unwrap();
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}
