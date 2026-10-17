//! Value detectors: one validator per [`PiiType`] that can be recognized
//! from a value, ported from the `spikes/parquet-pii` experiment.
//!
//! [`VALUE_TYPES`] lists them strictest first — checksums, then a parser,
//! then structured patterns, then the loosest — which is the order that
//! breaks ties when several types qualify for one column.

use std::net::IpAddr;
use std::sync::LazyLock;

use regex::Regex;

use crate::model::PiiType;

/// The types a value can confirm, strictest validator first.
pub(super) const VALUE_TYPES: [PiiType; 6] = [
    PiiType::InAadhaar,
    PiiType::CardNumber,
    PiiType::IpAddress,
    PiiType::InPan,
    PiiType::Email,
    PiiType::Phone,
];

/// The longest valid email address (RFC 5321's path limit).
const MAX_EMAIL_BYTES: usize = 254;

/// A compiled pattern, or `None` if it failed to compile, in which case it
/// matches nothing. Every pattern here is a constant, and
/// `every_pattern_compiles` checks them all.
fn pattern(source: &str) -> Option<Regex> {
    Regex::new(source).ok()
}

static EMAIL: LazyLock<Option<Regex>> = LazyLock::new(|| {
    pattern(r"^[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}$")
});
static PAN: LazyLock<Option<Regex>> =
    LazyLock::new(|| pattern(r"^[A-Z]{3}[ABCFGHLJPT][A-Z][0-9]{4}[A-Z]$"));
static E164: LazyLock<Option<Regex>> = LazyLock::new(|| pattern(r"^\+[1-9][0-9]{7,14}$"));
static INDIAN_MOBILE: LazyLock<Option<Regex>> =
    LazyLock::new(|| pattern(r"^(?:\+?91|0)?[6-9][0-9]{9}$"));
/// The North American Numbering Plan: an optional country code 1, an area
/// code and an exchange that do not start with 0 or 1, four digits.
static NANP: LazyLock<Option<Regex>> = LazyLock::new(|| pattern(r"^1?[2-9][0-9]{2}[2-9][0-9]{6}$"));
/// A national number with a trunk prefix 0, as the UK and most of Europe
/// write them: 9 to 11 digits in all (`020 7946 0123`, `01 23 45 67 89`,
/// `030 1234567`).
static NATIONAL_TRUNK: LazyLock<Option<Regex>> = LazyLock::new(|| pattern(r"^0[1-9][0-9]{7,9}$"));
/// An international number dialled with `00` instead of `+`.
static INTERNATIONAL_00: LazyLock<Option<Regex>> =
    LazyLock::new(|| pattern(r"^00[1-9][0-9]{7,13}$"));

fn matches(regex: &LazyLock<Option<Regex>>, value: &str) -> bool {
    regex.as_ref().is_some_and(|regex| regex.is_match(value))
}

/// Whether the cleaned `value` validates as `pii`. Always `false` for the
/// name-only types.
pub(super) fn validates(pii: PiiType, value: &str) -> bool {
    match pii {
        PiiType::Email => value.len() <= MAX_EMAIL_BYTES && matches(&EMAIL, value),
        // PAN letters are uppercase by definition; lowercase is the same
        // number typed carelessly.
        PiiType::InPan => matches(&PAN, &value.to_ascii_uppercase()),
        PiiType::Phone => phone(value),
        PiiType::InAadhaar => {
            let digits = digits_without(value, &[' ']);
            digits.len() == 12 && digits.first().is_some_and(|&d| d >= 2) && verhoeff_valid(&digits)
        }
        PiiType::CardNumber => {
            let digits = digits_without(value, &[' ', '-']);
            (13..=19).contains(&digits.len()) && luhn_valid(&digits)
        }
        PiiType::IpAddress => value.parse::<IpAddr>().is_ok(),
        PiiType::PersonName | PiiType::DateOfBirth => false,
    }
}

/// Whether `value` is a phone number: E.164 (`+` and 8 to 15 digits), an
/// Indian mobile number, or, written with separators as people write
/// them, a North American number (`(201) 555-0123`, `+1 201 555 0123`),
/// a national number with a trunk 0 (UK, EU: `020 7946 0123`), or an
/// international number dialled with `00`. Separators are spaces, `-`,
/// `.`, `/` and parentheses. A bare run of digits is a phone only as an
/// Indian mobile: as a NANP or national number it is as likely an
/// identifier (`2015550123` is also an account number). Even then
/// `classify` counts it only under a phone or contact name (see
/// [`bare_digits`]).
fn phone(value: &str) -> bool {
    let compact: String = value
        .chars()
        .filter(|c| !matches!(c, ' ' | '-' | '(' | ')' | '.' | '/'))
        .collect();
    if matches(&E164, &compact) || matches(&INDIAN_MOBILE, &compact) {
        return true;
    }
    let separated = compact.len() < value.len();
    separated
        && (matches(&NANP, &compact)
            || matches(&NATIONAL_TRUNK, &compact)
            || matches(&INTERNATIONAL_00, &compact))
}

/// Whether `value` is a bare digit run: ASCII digits only, no `+` and no
/// separators. As a phone it is as likely an identifier (see `classify`).
pub(super) fn bare_digits(value: &str) -> bool {
    !value.is_empty() && value.bytes().all(|b| b.is_ascii_digit())
}

/// The digit values of `value` with every `separators` character removed,
/// or an empty vector if anything else is not an ASCII digit.
fn digits_without(value: &str, separators: &[char]) -> Vec<u8> {
    let mut digits = Vec::with_capacity(value.len());
    for c in value.chars() {
        if separators.contains(&c) {
            continue;
        }
        match c.to_digit(10).and_then(|d| u8::try_from(d).ok()) {
            Some(d) if c.is_ascii_digit() => digits.push(d),
            _ => return Vec::new(),
        }
    }
    digits
}

/// The Verhoeff checksum over `digits` (most significant first), as used
/// by Aadhaar.
fn verhoeff_valid(digits: &[u8]) -> bool {
    const D: [[u8; 10]; 10] = [
        [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
        [1, 2, 3, 4, 0, 6, 7, 8, 9, 5],
        [2, 3, 4, 0, 1, 7, 8, 9, 5, 6],
        [3, 4, 0, 1, 2, 8, 9, 5, 6, 7],
        [4, 0, 1, 2, 3, 9, 5, 6, 7, 8],
        [5, 9, 8, 7, 6, 0, 4, 3, 2, 1],
        [6, 5, 9, 8, 7, 1, 0, 4, 3, 2],
        [7, 6, 5, 9, 8, 2, 1, 0, 4, 3],
        [8, 7, 6, 5, 9, 3, 2, 1, 0, 4],
        [9, 8, 7, 6, 5, 4, 3, 2, 1, 0],
    ];
    const P: [[u8; 10]; 8] = [
        [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
        [1, 5, 7, 6, 2, 8, 3, 0, 9, 4],
        [5, 8, 0, 3, 7, 9, 6, 1, 4, 2],
        [8, 9, 1, 6, 0, 4, 3, 5, 2, 7],
        [9, 4, 5, 3, 1, 2, 6, 8, 7, 0],
        [4, 2, 8, 6, 5, 7, 3, 9, 0, 1],
        [2, 7, 9, 3, 8, 0, 6, 4, 1, 5],
        [7, 0, 4, 6, 9, 1, 3, 2, 5, 8],
    ];
    let mut check = 0u8;
    for (position, &digit) in digits.iter().rev().enumerate() {
        let permuted = P
            .get(position % 8)
            .and_then(|row| row.get(usize::from(digit)))
            .copied();
        let next = permuted.and_then(|p| {
            D.get(usize::from(check))
                .and_then(|row| row.get(usize::from(p)))
        });
        match next {
            Some(&value) => check = value,
            None => return false,
        }
    }
    check == 0
}

/// The Luhn checksum over `digits` (most significant first), as used by
/// payment cards.
fn luhn_valid(digits: &[u8]) -> bool {
    let sum: u32 = digits
        .iter()
        .rev()
        .enumerate()
        .map(|(position, &digit)| {
            let digit = u32::from(digit);
            if position % 2 == 1 {
                let doubled = digit * 2;
                if doubled > 9 { doubled - 9 } else { doubled }
            } else {
                digit
            }
        })
        .sum();
    sum.is_multiple_of(10)
}

#[cfg(test)]
mod tests {
    use super::{
        E164, EMAIL, INDIAN_MOBILE, INTERNATIONAL_00, NANP, NATIONAL_TRUNK, PAN, VALUE_TYPES,
        validates,
    };
    use crate::model::PiiType;

    #[test]
    fn every_pattern_compiles() {
        for regex in [
            &EMAIL,
            &PAN,
            &E164,
            &INDIAN_MOBILE,
            &NANP,
            &NATIONAL_TRUNK,
            &INTERNATIONAL_00,
        ] {
            assert!(regex.is_some());
        }
    }

    #[test]
    fn email() {
        for good in [
            "a@b.co",
            "first.last+tag@mail.example.org",
            "X_Y%z-1@sub-d.io",
        ] {
            assert!(validates(PiiType::Email, good), "{good}");
        }
        for bad in [
            "plainaddress",
            "a@b",
            "@b.co",
            "a@b.c",
            "a b@c.io",
            "a@-.io.",
            &format!("{}@example.com", "a".repeat(250)),
        ] {
            assert!(!validates(PiiType::Email, bad), "{bad}");
        }
    }

    #[test]
    fn phone() {
        for good in [
            "+91 98765 43210",
            "+919876543210",
            "919876543210",
            "09876543210",
            "9876543210",
            "+14155550123",
            "+1 (415) 555-0123",
            "+44 20 7946 0958",
        ] {
            assert!(validates(PiiType::Phone, good), "{good}");
        }
        for bad in [
            "98765",
            "5876543210",
            "+0123456789",
            "phone",
            "12345678901234567",
        ] {
            assert!(!validates(PiiType::Phone, bad), "{bad}");
        }
    }

    /// National formats, with reserved numbers only: the NANP's fictional
    /// 555-0100 to 555-0199, Ofcom's drama ranges (020 7946 0xxx, 07700
    /// 900xxx), and the like-shaped French and German examples.
    #[test]
    fn phone_national_formats() {
        for good in [
            // US and Canada (NANP).
            "(201) 555-0123",
            "201-555-0142",
            "201.555.0187",
            "201 555 0199",
            "1-201-555-0100",
            "+1 201 555 0150",
            "+1 (201) 555-0161",
            // The experiment's FHIR patients: `555-xxx-xxxx`, area 555.
            "555-234-0100",
            // UK.
            "020 7946 0123",
            "07700 900123",
            "+44 7700 900123",
            "0044 20 7946 0123",
            // EU groupings.
            "01 23 45 67 89",
            "+33 1 23 45 67 89",
            "030 1234567",
            "030/1234567",
            "+49 30 1234567",
            "020-123 4567",
            "06 1234 5678",
        ] {
            assert!(validates(PiiType::Phone, good), "{good}");
        }
        for bad in [
            // Bare digits: as likely identifiers.
            "2015550123",
            "02079460123",
            "0012345678",
            // NANP area codes and exchanges never start with 0 or 1.
            "(101) 555-0123",
            "201-155-0123",
            // Dates, postcodes, SSNs, card numbers, versions, addresses.
            "2026-01-15",
            "15/01/2026",
            "01.02.2026",
            "94105-1234",
            "123-45-6789",
            "4111 1111 1111 1111",
            "10.0.0.123",
            "1.2.3",
            "(201) 555-012",
            "201-555-01234",
        ] {
            assert!(!validates(PiiType::Phone, bad), "{bad}");
        }
    }

    #[test]
    fn indian_pan() {
        for good in ["ABCPE1234F", "abcpe1234f", "AbCpE1234f"] {
            assert!(validates(PiiType::InPan, good), "{good}");
        }
        for bad in ["ABCXE1234F", "abcxe1234f", "ABCPE1234", "ABCPE12345"] {
            assert!(!validates(PiiType::InPan, bad), "{bad}");
        }
    }

    #[test]
    fn aadhaar_needs_twelve_digits_a_valid_first_digit_and_verhoeff() {
        // 2345 6789 0124 is Verhoeff-valid; changing the last digit breaks it.
        assert!(validates(PiiType::InAadhaar, "234567890124"));
        assert!(validates(PiiType::InAadhaar, "2345 6789 0124"));
        assert!(!validates(PiiType::InAadhaar, "234567890123"));
        assert!(!validates(PiiType::InAadhaar, "134567890124"));
        assert!(!validates(PiiType::InAadhaar, "23456789012"));
        assert!(!validates(PiiType::InAadhaar, "2345678901a4"));
    }

    #[test]
    fn card_needs_thirteen_to_nineteen_digits_and_luhn() {
        for good in [
            "4111111111111111",
            "4111 1111 1111 1111",
            "378282246310005",
            "5555-5555-5555-4444",
        ] {
            assert!(validates(PiiType::CardNumber, good), "{good}");
        }
        for bad in ["4111111111111112", "411111111111", "4111x11111111111"] {
            assert!(!validates(PiiType::CardNumber, bad), "{bad}");
        }
    }

    #[test]
    fn ip_address() {
        for good in ["10.0.0.1", "2001:db8::1", "::1"] {
            assert!(validates(PiiType::IpAddress, good), "{good}");
        }
        for bad in ["10.0.0", "256.1.1.1", "2001:db8::zz"] {
            assert!(!validates(PiiType::IpAddress, bad), "{bad}");
        }
    }

    #[test]
    fn name_only_types_never_validate() {
        assert!(!validates(PiiType::PersonName, "Asha Rao"));
        assert!(!validates(PiiType::DateOfBirth, "1990-01-01"));
    }

    #[test]
    fn checksums_come_before_patterns() {
        let position = |t| VALUE_TYPES.iter().position(|&v| v == t);
        assert!(position(PiiType::InAadhaar) < position(PiiType::Phone));
        assert!(position(PiiType::CardNumber) < position(PiiType::Phone));
        assert!(position(PiiType::InPan) < position(PiiType::Email));
    }
}
