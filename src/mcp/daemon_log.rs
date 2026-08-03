//! Daemon log — where the daemon's own `tracing` output can actually be read.
//!
//! The daemon is a detached background process, so its stderr goes wherever the
//! spawner pointed it: `~/.mati/daemon_start.log` when `ensure_daemon` started
//! it, and `/dev/null` otherwise. That file is shared by every store on the
//! machine, unbounded, and — because the process-wide filter defaults to `warn`
//! — carries no INFO. The lines that answer "did this actually run?"
//! (`staleness analysis complete scanned=… updated=…`, `gotcha candidates
//! auto-promoted`) were therefore unreadable in normal operation.
//!
//! [`install`] redirects the subscriber to `<root>/daemon.log`: per store,
//! next to `lifecycle.log`, and size-bounded. Until it is called, and in every
//! non-daemon process, writes go to stderr exactly as before.
//!
//! Local file only. No network, and no store records — the durability split in
//! `store::durability` does not apply.

use std::fs::{File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};

use tracing_subscriber::fmt::MakeWriter;

/// Log filename under a store root.
pub const DAEMON_LOG_FILENAME: &str = "daemon.log";

/// Rotation threshold. One previous generation is kept, so a store's daemon
/// logs cost at most twice this on disk however long the daemon runs.
const MAX_BYTES: u64 = 1 << 20;

/// Tracing directives used when the process is the daemon.
///
/// Scoped to mati's own targets: a bare `info` would also admit surrealkv,
/// tantivy, and tokio internals, which is volume without answers.
pub const DAEMON_DIRECTIVES: &str = "warn,mati=info,mati_core=info";

struct Sink {
    path: PathBuf,
    file: File,
    written: u64,
}

impl Sink {
    fn write_line(&mut self, buf: &[u8]) -> io::Result<usize> {
        if self.written + buf.len() as u64 > MAX_BYTES {
            self.rotate()?;
        }
        let n = self.file.write(buf)?;
        self.written += n as u64;
        Ok(n)
    }

    fn rotate(&mut self) -> io::Result<()> {
        let previous = self.path.with_extension("log.1");
        std::fs::rename(&self.path, &previous)?;
        self.file = open_append(&self.path)?;
        self.written = 0;
        Ok(())
    }
}

static SINK: OnceLock<Mutex<Sink>> = OnceLock::new();

fn open_append(path: &Path) -> io::Result<File> {
    OpenOptions::new().create(true).append(true).open(path)
}

/// Path of the daemon log for a store root.
pub fn log_path(root: &Path) -> PathBuf {
    root.join(DAEMON_LOG_FILENAME)
}

/// Point subsequent tracing output at `<root>/daemon.log`.
///
/// Returns `false` if the file cannot be opened (read-only home, missing
/// runtime dir) or if a sink is already installed — in both cases output keeps
/// going to stderr rather than being lost. Call once, from the daemon process.
pub fn install(root: &Path) -> bool {
    let path = log_path(root);
    let Ok(file) = open_append(&path) else {
        return false;
    };
    let written = file.metadata().map(|m| m.len()).unwrap_or(0);
    SINK.set(Mutex::new(Sink {
        path,
        file,
        written,
    }))
    .is_ok()
}

/// Writer factory for `tracing_subscriber::fmt().with_writer(..)`.
///
/// Resolves per event, so the daemon's pre-[`install`] startup lines still
/// reach stderr and everything after lands in the file.
#[derive(Clone, Copy, Default)]
pub struct DaemonLogWriter;

/// Where one event's bytes go.
pub enum Target {
    Rotating,
    Stderr(io::Stderr),
}

impl Write for Target {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match self {
            // A poisoned lock must not take the daemon down with it: drop the
            // line and report it written. Logging is diagnostics, not data.
            Self::Rotating => match SINK.get().and_then(|s| s.lock().ok()) {
                Some(mut sink) => sink.write_line(buf),
                None => Ok(buf.len()),
            },
            Self::Stderr(w) => w.write(buf),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match self {
            // `append` writes are unbuffered in userspace; nothing to push.
            Self::Rotating => Ok(()),
            Self::Stderr(w) => w.flush(),
        }
    }
}

impl<'a> MakeWriter<'a> for DaemonLogWriter {
    type Writer = Target;

    fn make_writer(&'a self) -> Self::Writer {
        if SINK.get().is_some() {
            Target::Rotating
        } else {
            Target::Stderr(io::stderr())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The sink is a process-wide `OnceLock`, so rotation is exercised on a
    /// `Sink` built directly rather than through `install`.
    fn sink_at(path: &Path) -> Sink {
        Sink {
            path: path.to_path_buf(),
            file: open_append(path).unwrap(),
            written: 0,
        }
    }

    #[test]
    fn growth_is_bounded_by_two_generations() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join(DAEMON_LOG_FILENAME);
        let mut sink = sink_at(&path);

        let line = vec![b'x'; 64 * 1024];
        for _ in 0..64 {
            sink.write_line(&line).unwrap();
        }

        let total: u64 = std::fs::read_dir(dir.path())
            .unwrap()
            .flatten()
            .map(|e| e.metadata().unwrap().len())
            .sum();
        assert!(
            total <= 2 * MAX_BYTES,
            "daemon log grew past two generations: {total} bytes"
        );
        assert!(
            path.with_extension("log.1").exists(),
            "rotation must keep one previous generation"
        );
    }

    #[test]
    fn rotation_preserves_the_most_recent_lines() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join(DAEMON_LOG_FILENAME);
        let mut sink = sink_at(&path);

        sink.write_line(&vec![b'o'; MAX_BYTES as usize]).unwrap();
        sink.write_line(b"newest\n").unwrap();

        assert_eq!(std::fs::read_to_string(&path).unwrap(), "newest\n");
    }

    /// Without an installed sink the writer must behave exactly as before —
    /// stderr, so a daemon that fails before `install` is still diagnosable
    /// through `daemon_start.log`.
    #[test]
    fn writer_falls_back_to_stderr_until_installed() {
        if SINK.get().is_some() {
            return;
        }
        assert!(matches!(DaemonLogWriter.make_writer(), Target::Stderr(_)));
    }
}
