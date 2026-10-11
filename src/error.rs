//! Crate-wide error type and the frozen process exit-code contract.
//!
//! Every failure in `LakeScan` is expressible as a [`LakeScanError`], and every
//! [`LakeScanError`] maps to exactly one [`ExitCode`]. The integer values of
//! [`ExitCode`] are a public interface: CI pipelines branch on them, so they
//! are frozen and must never be reordered or renumbered.

/// The single error type returned by every fallible operation in `LakeScan`.
#[derive(thiserror::Error, Debug)]
pub enum LakeScanError {
    /// The invocation was malformed: bad flags, an unparseable target, or
    /// mutually exclusive options.
    #[error("usage: {0}")]
    Usage(String),

    /// Credentials are absent, expired, or rejected by the remote.
    #[error("auth: {0}")]
    Auth(String),

    /// The network or the remote service failed: DNS, TLS, timeout, or 5xx.
    #[error("transport: {0}")]
    Transport(String),

    /// The report could not be written to its destination.
    #[error("report: {0}")]
    Report(#[source] std::io::Error),
}

/// Process exit codes.
///
/// **Frozen contract.** These discriminants are consumed by external CI
/// tooling. Add new variants with new values; never change an existing one.
///
/// | Variant                   | Code |
/// |---------------------------|------|
/// | `Ok`                      | 0    |
/// | `FindingsExceedThreshold` | 1    |
/// | `Usage`                   | 2    |
/// | `Auth`                    | 3    |
/// | `Transport`               | 4    |
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i32)]
pub enum ExitCode {
    /// The scan completed and no finding reached the configured threshold.
    Ok = 0,

    /// The scan completed, but findings reached or exceeded the configured
    /// severity threshold. This is a successful run with a failing verdict.
    FindingsExceedThreshold = 1,

    /// The invocation was malformed. Maps from [`LakeScanError::Usage`].
    Usage = 2,

    /// Credentials were missing or rejected. Maps from [`LakeScanError::Auth`].
    Auth = 3,

    /// An I/O boundary failed. Maps from both [`LakeScanError::Transport`] and
    /// [`LakeScanError::Report`], since both are failures to move bytes.
    Transport = 4,
}

impl ExitCode {
    /// Returns the integer this code hands back to the operating system.
    #[must_use]
    pub fn as_i32(self) -> i32 {
        self as i32
    }
}

impl From<&LakeScanError> for ExitCode {
    fn from(error: &LakeScanError) -> Self {
        match error {
            LakeScanError::Usage(_) => Self::Usage,
            LakeScanError::Auth(_) => Self::Auth,
            LakeScanError::Transport(_) | LakeScanError::Report(_) => Self::Transport,
        }
    }
}

impl From<ExitCode> for std::process::ExitCode {
    fn from(code: ExitCode) -> Self {
        match code {
            ExitCode::Ok => Self::from(0_u8),
            ExitCode::FindingsExceedThreshold => Self::from(1_u8),
            ExitCode::Usage => Self::from(2_u8),
            ExitCode::Auth => Self::from(3_u8),
            ExitCode::Transport => Self::from(4_u8),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{ExitCode, LakeScanError};

    /// The frozen contract. If this test is edited, the contract is broken.
    #[test]
    fn exit_code_discriminants_match_the_frozen_contract() {
        assert_eq!(ExitCode::Ok.as_i32(), 0);
        assert_eq!(ExitCode::FindingsExceedThreshold.as_i32(), 1);
        assert_eq!(ExitCode::Usage.as_i32(), 2);
        assert_eq!(ExitCode::Auth.as_i32(), 3);
        assert_eq!(ExitCode::Transport.as_i32(), 4);
    }

    #[test]
    fn every_error_maps_to_its_contracted_exit_code() {
        let cases: [(LakeScanError, ExitCode); 4] = [
            (LakeScanError::Usage(String::new()), ExitCode::Usage),
            (LakeScanError::Auth(String::new()), ExitCode::Auth),
            (LakeScanError::Transport(String::new()), ExitCode::Transport),
            (
                LakeScanError::Report(std::io::Error::from(std::io::ErrorKind::BrokenPipe)),
                ExitCode::Transport,
            ),
        ];

        for (error, expected) in &cases {
            assert_eq!(ExitCode::from(error), *expected);
        }
    }
}
