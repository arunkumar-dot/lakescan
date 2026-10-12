//! [`Sink`]: the one place broken-pipe handling and buffering live, shared
//! by every writer in this module.

use std::io::{self, BufWriter, Write};

/// A 64 KB buffered [`Write`] wrapper that treats
/// [`io::ErrorKind::BrokenPipe`] as "the reader went away", not a failure:
/// once seen, every later write silently succeeds without touching the
/// underlying sink, and [`Sink::is_broken`] reports that it happened.
///
/// Implements [`Write`] itself (rather than exposing its inner
/// [`BufWriter`] directly) so `write!`/`writeln!` work on it unchanged,
/// with broken-pipe suppression applied uniformly to every write and every
/// flush through the one pair of methods below.
pub(super) struct Sink<W: Write> {
    out: BufWriter<W>,
    broken: bool,
}

impl<W: Write> Sink<W> {
    /// Wraps `out` in a 64 KB buffer.
    pub(super) fn new(out: W) -> Self {
        Self {
            out: BufWriter::with_capacity(64 * 1024, out),
            broken: false,
        }
    }

    /// `true` once a write or flush has reported
    /// [`io::ErrorKind::BrokenPipe`]; from that point on, every write and
    /// flush on this `Sink` is a no-op that reports success.
    pub(super) fn is_broken(&self) -> bool {
        self.broken
    }
}

impl<W: Write> Write for Sink<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if self.broken {
            return Ok(buf.len());
        }
        match self.out.write(buf) {
            Ok(written) => Ok(written),
            Err(err) if err.kind() == io::ErrorKind::BrokenPipe => {
                self.broken = true;
                Ok(buf.len())
            }
            Err(err) => Err(err),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        if self.broken {
            return Ok(());
        }
        match self.out.flush() {
            Ok(()) => Ok(()),
            Err(err) if err.kind() == io::ErrorKind::BrokenPipe => {
                self.broken = true;
                Ok(())
            }
            Err(err) => Err(err),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::io::{self, Write};

    use super::Sink;

    /// A writer scripted to fail in a specific way after `fail_after`
    /// successful writes.
    struct FailingWriter {
        fail_after: usize,
        writes_seen: usize,
        kind: io::ErrorKind,
        fail_on_flush: bool,
        received: Vec<u8>,
    }

    impl Write for FailingWriter {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            if self.writes_seen >= self.fail_after {
                return Err(io::Error::from(self.kind));
            }
            self.writes_seen += 1;
            self.received.extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            if self.fail_on_flush {
                Err(io::Error::from(self.kind))
            } else {
                Ok(())
            }
        }
    }

    #[test]
    fn broken_pipe_is_swallowed_and_marks_the_sink_broken() {
        let inner = FailingWriter {
            fail_after: 0,
            writes_seen: 0,
            kind: io::ErrorKind::BrokenPipe,
            fail_on_flush: false,
            received: Vec::new(),
        };
        let mut sink = Sink::new(inner);

        assert!(!sink.is_broken());
        // `write_all` only copies into the 64 KB buffer; the inner writer
        // is not touched (and so cannot fail) until that buffer actually
        // flushes, here forced explicitly.
        assert!(sink.write_all(b"hello").is_ok());
        assert!(sink.flush().is_ok());
        assert!(sink.is_broken());

        // Later writes are no-ops that still report success.
        assert!(sink.write_all(b"more").is_ok());
        assert!(sink.flush().is_ok());
    }

    #[test]
    fn a_non_broken_pipe_write_error_propagates() {
        let inner = FailingWriter {
            fail_after: 0,
            writes_seen: 0,
            kind: io::ErrorKind::PermissionDenied,
            fail_on_flush: false,
            received: Vec::new(),
        };
        let mut sink = Sink::new(inner);

        assert!(sink.write_all(b"hello").is_ok());
        let result = sink.flush();
        assert!(result.is_err());
        assert!(!sink.is_broken());
    }

    #[test]
    fn a_flush_only_failure_propagates_as_an_error() {
        let inner = FailingWriter {
            fail_after: 100,
            writes_seen: 0,
            kind: io::ErrorKind::Other,
            fail_on_flush: true,
            received: Vec::new(),
        };
        let mut sink = Sink::new(inner);

        assert!(sink.write_all(b"hello").is_ok());
        assert!(sink.flush().is_err());
    }

    #[test]
    fn a_flush_only_broken_pipe_is_swallowed() {
        let inner = FailingWriter {
            fail_after: 100,
            writes_seen: 0,
            kind: io::ErrorKind::BrokenPipe,
            fail_on_flush: true,
            received: Vec::new(),
        };
        let mut sink = Sink::new(inner);

        assert!(sink.write_all(b"hello").is_ok());
        assert!(sink.flush().is_ok());
        assert!(sink.is_broken());
    }

    #[test]
    fn a_write_larger_than_the_buffer_can_fail_without_an_explicit_flush() {
        // A write bigger than the 64 KB buffer forces `BufWriter` to touch
        // the inner writer immediately, rather than deferring to a flush.
        let inner = FailingWriter {
            fail_after: 0,
            writes_seen: 0,
            kind: io::ErrorKind::BrokenPipe,
            fail_on_flush: false,
            received: Vec::new(),
        };
        let mut sink = Sink::new(inner);

        let big = vec![0_u8; 128 * 1024];
        assert!(sink.write_all(&big).is_ok());
        assert!(sink.is_broken());
    }
}
