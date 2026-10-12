//! A small, hand-written RFC 3339 formatter (UTC, seconds precision,
//! trailing `Z`), using Howard Hinnant's days-from-civil algorithm rather
//! than a date/time dependency. Only the one direction this crate needs —
//! [`SystemTime`] to a civil date — is implemented; there is no parser.
//!
//! Correct for any [`SystemTime`] representable at all, including times
//! before the Unix epoch: [`SystemTime::duration_since`] returns `Err`
//! rather than panicking for those, and this module's own arithmetic uses
//! [`i64::div_euclid`]/[`i64::rem_euclid`] throughout specifically so that
//! negative inputs floor correctly instead of truncating toward zero.

use std::time::SystemTime;

/// Seconds since the Unix epoch, floored toward negative infinity (so a
/// non-zero sub-second part is truncated down, not toward zero): for a
/// time before the epoch with e.g. a half-second remainder, this reports
/// one second further back, matching the civil second the time actually
/// falls within.
fn unix_seconds(time: SystemTime) -> i64 {
    match time.duration_since(SystemTime::UNIX_EPOCH) {
        Ok(since_epoch) => i64::try_from(since_epoch.as_secs()).unwrap_or(i64::MAX),
        Err(before_epoch) => {
            let gap = before_epoch.duration();
            let gap_secs = i64::try_from(gap.as_secs()).unwrap_or(i64::MAX);
            if gap.subsec_nanos() > 0 {
                gap_secs.saturating_neg().saturating_sub(1)
            } else {
                gap_secs.saturating_neg()
            }
        }
    }
}

/// Howard Hinnant's `civil_from_days`: the proleptic Gregorian
/// `(year, month, day)` for `days` days since 1970-01-01, negative `days`
/// included. See <http://howardhinnant.github.io/date_algorithms.html>.
fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days.saturating_add(719_468);
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097); // [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365; // [0, 399]
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let d = doy - (153 * mp + 2) / 5 + 1; // [1, 31]
    let m = if mp < 10 { mp + 3 } else { mp - 9 }; // [1, 12]
    let year = if m <= 2 { y + 1 } else { y };
    (
        year,
        u32::try_from(m).unwrap_or(1),
        u32::try_from(d).unwrap_or(1),
    )
}

/// Formats `time` as RFC 3339, UTC, seconds precision, e.g.
/// `"2024-02-29T00:00:00Z"`. Never panics, including for `time` before the
/// Unix epoch.
#[must_use]
pub(super) fn format_rfc3339(time: SystemTime) -> String {
    let total_seconds = unix_seconds(time);
    let days = total_seconds.div_euclid(86_400);
    let secs_of_day = total_seconds.rem_euclid(86_400);
    let (year, month, day) = civil_from_days(days);
    let hour = secs_of_day / 3600;
    let minute = (secs_of_day % 3600) / 60;
    let second = secs_of_day % 60;
    format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}Z")
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, SystemTime};

    use super::format_rfc3339;

    /// Howard Hinnant's `days_from_civil`, the counterpart to this module's
    /// `civil_from_days` — test-only, so test inputs can be built from a
    /// civil date directly instead of a hand-computed epoch-seconds magic
    /// number. If this and the production `civil_from_days` disagreed,
    /// these tests would fail; they don't, which is itself evidence both
    /// directions are correct, not just mutually consistent by accident
    /// (this is the well-known published algorithm, not a guess).
    fn days_from_civil(year: i64, month: u32, day: u32) -> i64 {
        let y = if month <= 2 { year - 1 } else { year };
        let era = y.div_euclid(400);
        let yoe = y - era * 400; // [0, 399]
        let m = i64::from(month);
        let d = i64::from(day);
        let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + d - 1; // [0, 365]
        let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy; // [0, 146096]
        era * 146_097 + doe - 719_468
    }

    fn at(year: i64, month: u32, day: u32, hour: u32, minute: u32, second: u32) -> SystemTime {
        let days = days_from_civil(year, month, day);
        let seconds_of_day = i64::from(hour) * 3600 + i64::from(minute) * 60 + i64::from(second);
        let total_seconds = days * 86_400 + seconds_of_day;
        if total_seconds >= 0 {
            SystemTime::UNIX_EPOCH + Duration::from_secs(u64::try_from(total_seconds).unwrap_or(0))
        } else {
            let before = u64::try_from(-total_seconds).unwrap_or(0);
            SystemTime::UNIX_EPOCH - Duration::from_secs(before)
        }
    }

    fn expected(year: i64, month: u32, day: u32, hour: u32, minute: u32, second: u32) -> String {
        format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}Z")
    }

    #[test]
    fn the_epoch() {
        assert_eq!(
            format_rfc3339(SystemTime::UNIX_EPOCH),
            "1970-01-01T00:00:00Z"
        );
    }

    #[test]
    fn year_2000_march_1st_a_leap_year() {
        let time = at(2000, 3, 1, 0, 0, 0);
        assert_eq!(format_rfc3339(time), expected(2000, 3, 1, 0, 0, 0));
    }

    #[test]
    fn leap_day_2024() {
        let time = at(2024, 2, 29, 12, 34, 56);
        assert_eq!(format_rfc3339(time), expected(2024, 2, 29, 12, 34, 56));
    }

    #[test]
    fn year_2100_march_1st_a_century_non_leap_year() {
        // 2100 is divisible by 100 but not 400, so not a leap year: the
        // century rule, which the naive "divisible by 4" check gets wrong.
        let time = at(2100, 3, 1, 0, 0, 0);
        assert_eq!(format_rfc3339(time), expected(2100, 3, 1, 0, 0, 0));
    }

    #[test]
    fn a_date_before_1970_does_not_panic_and_formats_correctly() {
        let time = at(1969, 7, 20, 20, 17, 0);
        assert_eq!(format_rfc3339(time), expected(1969, 7, 20, 20, 17, 0));
    }

    #[test]
    fn a_nonzero_subsecond_part_is_truncated_toward_the_floor() {
        let positive = SystemTime::UNIX_EPOCH + Duration::new(1_000, 500_000_000);
        assert_eq!(
            format_rfc3339(positive),
            format_rfc3339(SystemTime::UNIX_EPOCH + Duration::from_secs(1_000))
        );

        // Half a second before the epoch: the civil second it falls within
        // is the one just before, 1969-12-31T23:59:59Z, not the epoch
        // itself.
        let negative = SystemTime::UNIX_EPOCH - Duration::new(0, 500_000_000);
        assert_eq!(format_rfc3339(negative), "1969-12-31T23:59:59Z");
    }
}
