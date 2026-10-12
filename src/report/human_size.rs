//! Human-readable byte sizes (`B`, `KiB`, `MiB`, `GiB`, `TiB`, `PiB`,
//! `EiB`), one decimal place, integer arithmetic only — no floats, no `as`
//! casts, so there is nothing here for `clippy`'s cast or float lints to
//! ever complain about, and no rounding surprises from floating-point
//! division.

/// Binary units, largest first, so the first one `bytes` is at least as
/// large as wins.
const UNITS: [(&str, u64); 6] = [
    ("EiB", 1_u64 << 60),
    ("PiB", 1_u64 << 50),
    ("TiB", 1_u64 << 40),
    ("GiB", 1_u64 << 30),
    ("MiB", 1_u64 << 20),
    ("KiB", 1_u64 << 10),
];

/// Renders `bytes` as a human-readable size with one decimal place (e.g.
/// `"1.5 KiB"`), or a plain byte count below 1 KiB (e.g. `"1023 B"`).
///
/// The one decimal digit is computed as `(remainder * 10) / unit_size`,
/// which never overflows `u64`: `remainder` is always smaller than
/// `unit_size`, so `remainder * 10` is always smaller than `10 *
/// unit_size`, and the largest unit here (`EiB` = `2^60`) leaves four
/// unused bits before `u64`'s own limit (`2^64`).
#[must_use]
pub(super) fn human_bytes(bytes: u64) -> String {
    for &(unit, unit_size) in &UNITS {
        if bytes >= unit_size {
            let whole = bytes / unit_size;
            let remainder = bytes % unit_size;
            let tenths = (remainder * 10) / unit_size;
            return format!("{whole}.{tenths} {unit}");
        }
    }
    format!("{bytes} B")
}

#[cfg(test)]
mod tests {
    use super::human_bytes;

    #[test]
    fn zero_bytes() {
        assert_eq!(human_bytes(0), "0 B");
    }

    #[test]
    fn just_under_one_kibibyte() {
        assert_eq!(human_bytes(1023), "1023 B");
    }

    #[test]
    fn exactly_one_kibibyte() {
        assert_eq!(human_bytes(1024), "1.0 KiB");
    }

    #[test]
    fn one_and_a_half_kibibytes() {
        assert_eq!(human_bytes(1536), "1.5 KiB");
    }

    #[test]
    fn u64_max_is_just_under_sixteen_exbibytes() {
        assert_eq!(human_bytes(u64::MAX), "15.9 EiB");
    }
}
