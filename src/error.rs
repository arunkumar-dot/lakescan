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
    /// Often worth retrying, since the remote end or the path to it may
    /// recover on its own.
    #[error("transport: {0}")]
    Transport(String),

    /// The report could not be written to its destination: a full disk, a
    /// missing directory, a permissions error, or a closed pipe. Distinct
    /// from [`Self::Transport`] because retrying without fixing the
    /// destination will not help; the remote S3 side of the scan already
    /// succeeded, and nothing about retrying the network changes the local
    /// write failing again.
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
/// | `Report`                  | 5    |
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

    /// The network or the remote service failed. Maps from
    /// [`LakeScanError::Transport`]. Often worth retrying.
    Transport = 4,

    /// The report could not be written to its destination. Maps from
    /// [`LakeScanError::Report`]. Retrying without fixing the destination
    /// will not help.
    Report = 5,
}

impl ExitCode {
    /// Every exit code, in ascending numeric order.
    pub const ALL: [Self; 6] = [
        Self::Ok,
        Self::FindingsExceedThreshold,
        Self::Usage,
        Self::Auth,
        Self::Transport,
        Self::Report,
    ];

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
            LakeScanError::Transport(_) => Self::Transport,
            LakeScanError::Report(_) => Self::Report,
        }
    }
}

impl From<ExitCode> for std::process::ExitCode {
    fn from(code: ExitCode) -> Self {
        Self::from(u8::try_from(code.as_i32()).unwrap_or(u8::MAX))
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
        assert_eq!(ExitCode::Report.as_i32(), 5);
    }

    #[test]
    fn every_error_maps_to_its_contracted_exit_code() {
        let cases: [(LakeScanError, ExitCode); 4] = [
            (LakeScanError::Usage(String::new()), ExitCode::Usage),
            (LakeScanError::Auth(String::new()), ExitCode::Auth),
            (LakeScanError::Transport(String::new()), ExitCode::Transport),
            (
                LakeScanError::Report(std::io::Error::from(std::io::ErrorKind::BrokenPipe)),
                ExitCode::Report,
            ),
        ];

        for (error, expected) in &cases {
            assert_eq!(ExitCode::from(error), *expected);
        }
    }

    #[test]
    fn every_discriminant_fits_in_a_process_status_byte() {
        for code in ExitCode::ALL {
            assert!(u8::try_from(code.as_i32()).is_ok());
        }
    }

    /// `ALL` lists every variant once, in ascending order. The exhaustive
    /// `match` makes adding a variant a compile error here until it is
    /// given a position, and the assertion then requires it in `ALL`.
    #[test]
    fn all_lists_every_variant_once_in_order() {
        fn position(code: ExitCode) -> usize {
            match code {
                ExitCode::Ok => 0,
                ExitCode::FindingsExceedThreshold => 1,
                ExitCode::Usage => 2,
                ExitCode::Auth => 3,
                ExitCode::Transport => 4,
                ExitCode::Report => 5,
            }
        }
        for (index, code) in ExitCode::ALL.into_iter().enumerate() {
            assert_eq!(position(code), index, "{code:?}");
        }
    }
}
