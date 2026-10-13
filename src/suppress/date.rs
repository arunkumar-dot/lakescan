//! [`Date`]: a validated proleptic-Gregorian calendar date, for a
//! suppression's `expires` field, and the UTC date a scan ran on.
//!
//! Hand-written like `report::rfc3339`, rather than a date/time
//! dependency: the only operations needed are "parse `YYYY-MM-DD`",
//! "which UTC day is this `SystemTime`", and "is one date before another".

use std::fmt;
use std::time::SystemTime;

/// A calendar date, always valid: the month is 1–12 and the day exists in
/// that month of that year. Ordered chronologically (field order is year,
/// month, day, so the derived [`Ord`] is the calendar order).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Date {
    year: u16,
    month: u8,
    day: u8,
}

impl Date {
    /// Builds a date, or `None` if the month or day does not exist.
    #[must_use]
    pub fn new(year: u16, month: u8, day: u8) -> Option<Self> {
        let valid = (1..=12).contains(&month) && day >= 1 && day <= days_in_month(year, month);
        valid.then_some(Self { year, month, day })
    }

    /// Parses exactly `YYYY-MM-DD`: four, two, and two ASCII digits.
    #[must_use]
    pub fn parse(text: &str) -> Option<Self> {
        let mut parts = text.split('-');
        let (Some(year), Some(month), Some(day), None) =
            (parts.next(), parts.next(), parts.next(), parts.next())
        else {
            return None;
        };
        let all_digits = |part: &str, len: usize| {
            part.len() == len && part.bytes().all(|byte| byte.is_ascii_digit())
        };
        if !(all_digits(year, 4) && all_digits(month, 2) && all_digits(day, 2)) {
            return None;
        }
        Self::new(year.parse().ok()?, month.parse().ok()?, day.parse().ok()?)
    }

    /// The UTC calendar date `time` falls on. Times before the Unix epoch
    /// (which a scan's start never is) map to 1970-01-01.
    #[must_use]
    pub fn utc_of(time: SystemTime) -> Self {
        let days = time
            .duration_since(SystemTime::UNIX_EPOCH)
            .map_or(0, |since| since.as_secs() / 86_400);
        civil_from_days(days)
    }
}

impl fmt::Display for Date {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:04}-{:02}-{:02}", self.year, self.month, self.day)
    }
}

fn is_leap_year(year: u16) -> bool {
    year.is_multiple_of(4) && (!year.is_multiple_of(100) || year.is_multiple_of(400))
}

fn days_in_month(year: u16, month: u8) -> u8 {
    match month {
        2 if is_leap_year(year) => 29,
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    }
}

/// Howard Hinnant's `civil_from_days`, restricted to non-negative day
/// counts (dates on or after 1970-01-01). Years past 65535 saturate.
fn civil_from_days(days: u64) -> Date {
    let z = days.saturating_add(719_468);
    let era = z / 146_097;
    let doe = z % 146_097; // [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365; // [0, 399]
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let day = doy - (153 * mp + 2) / 5 + 1; // [1, 31]
    let month = if mp < 10 { mp + 3 } else { mp - 9 }; // [1, 12]
    let year = yoe + era * 400 + u64::from(month <= 2);
    Date {
        year: u16::try_from(year).unwrap_or(u16::MAX),
        month: u8::try_from(month).unwrap_or(1),
        day: u8::try_from(day).unwrap_or(1),
    }
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, SystemTime};

    use super::Date;

    #[test]
    fn parse_accepts_valid_dates_including_leap_days() {
        assert_eq!(Date::parse("2027-01-31"), Date::new(2027, 1, 31));
        assert_eq!(Date::parse("2024-02-29"), Date::new(2024, 2, 29));
        assert_eq!(Date::parse("2000-02-29"), Date::new(2000, 2, 29));
        assert!(Date::parse("2027-12-31").is_some());
    }

    #[test]
    fn parse_rejects_malformed_or_nonexistent_dates() {
        for bad in [
            "",
            "2027-1-31",
            "27-01-31",
            "2027-01-31T00:00:00Z",
            "2027/01/31",
            "2027-13-01",
            "2027-00-10",
            "2027-04-31",
            "2027-02-29",
            "1900-02-29",
            "2027-01-00",
            "+027-01-01",
            "2027-01-31-",
        ] {
            assert_eq!(Date::parse(bad), None, "{bad:?}");
        }
    }

    #[test]
    fn utc_of_finds_the_calendar_day() {
        let epoch = SystemTime::UNIX_EPOCH;
        assert_eq!(Some(Date::utc_of(epoch)), Date::new(1970, 1, 1));
        // 2023-11-14T22:13:20Z.
        let t = epoch + Duration::from_secs(1_700_000_000);
        assert_eq!(Some(Date::utc_of(t)), Date::new(2023, 11, 14));
        // 2024-02-29T23:59:59Z, then one second later.
        let leap = epoch + Duration::from_secs(1_709_251_199);
        assert_eq!(Some(Date::utc_of(leap)), Date::new(2024, 2, 29));
        assert_eq!(
            Some(Date::utc_of(leap + Duration::from_secs(1))),
            Date::new(2024, 3, 1)
        );
    }

    #[test]
    fn dates_order_chronologically_and_display_as_iso() {
        assert!(Date::parse("2026-12-31") < Date::parse("2027-01-01"));
        assert!(Date::parse("2027-01-09") < Date::parse("2027-01-10"));
        assert_eq!(
            Date::parse("2027-01-05").map(|d| d.to_string()),
            Some("2027-01-05".to_owned())
        );
    }
}
