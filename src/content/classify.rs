//! Confidence: turning a column's cleaned sample and name hint into at
//! most one PII verdict.
//!
//! Per type, with `n` cleaned values of which `m` validate:
//!
//! - **`CONFIRMED`**: `n >= 30` and `m >= 80%` of `n`.
//! - **`LIKELY`**: `n >= 30` and `50% <= m < 80%`; or the value rule
//!   (`m >= 80%`) passes on fewer than 30 values; or a name hint plus at
//!   least one matching value; or, for `PERSON_NAME` and `DATE_OF_BIRTH`, a
//!   strong name hint on a column of fitting type.
//! - **`POSSIBLE`**: a name hint only.
//!
//! A column that was read and kept no value after cleaning (all null,
//! empty or placeholder) is never reported, whatever its name: there is
//! nothing in it to protect. Dates and timestamps are never read, so this
//! does not apply to them (`read` checks their statistics instead).
//!
//! **Phones** are the one type organisations share with people: a
//! business's switchboard validates like a customer's mobile. A phone
//! column is `CONFIRMED` only when its name is about a person or a
//! personal device (`customer_phone`, `contact`, `mobile`; see
//! `names::about_person`), or when at least [`HIGH_PHONE_PERCENT`] of its
//! values validate. Otherwise it stays at `LIKELY`.
//!
//! A **bare digit run** (`9876543210`: no `+`, no separators, as an
//! integer column always is) is as likely an identifier as a phone (the
//! experiment's NPI numbers are bare 10-digit runs starting with 9). It
//! counts as a phone only when the column's name has a phone or contact
//! word in it (`mobile_no`, `contact`, `PHONE`; see `names::phone_named`).
//! Otherwise it counts toward nothing, so such a column is never confirmed,
//! and an unnamed column of bare numbers is not reported as phones at all.
//! Formatted numbers (`+91 98765 43210`, `(201) 555-0123`) always count.
//!
//! Value evidence comes first and overrides names: when values qualify
//! for one or more types, the most confident wins, then the strictest
//! validator. A column with at least 30 cleaned values and no match for
//! its hinted type is not reported for that type, whatever its name. An
//! `IN_PAN` hint needs at least one matching value, so a card column named
//! `pan` is never reported as an Indian tax ID on its name alone.

use super::detect::{VALUE_TYPES, bare_digits, validates};
use super::names::{Hint, Strength};
use crate::model::{Confidence, Evidence as Basis, PiiType};

/// The fewest cleaned values for `CONFIRMED`.
pub(super) const MIN_CONFIRMED: usize = 30;

/// The share of values (percent) that confirms a phone column whose name
/// is not about a person.
pub(super) const HIGH_PHONE_PERCENT: u64 = 95;

/// What kind of values a column holds, as far as detection cares.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Kind {
    /// Strings or binary.
    Text,
    /// `INT32` or `INT64` integers, rendered as decimal digits.
    Integer,
    /// `DATE` or `TIMESTAMP`: checked by name only, never read.
    Temporal,
}

/// How many of a sample's cleaned values validate as each value type, in
/// [`VALUE_TYPES`] order.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(super) struct Evidence {
    pub(super) sampled: u64,
    pub(super) matched: [u64; VALUE_TYPES.len()],
    /// Of the phone matches, the bare digit runs (see this module's doc).
    pub(super) bare_phones: u64,
}

impl Evidence {
    /// Counts `values` against every value type.
    pub(super) fn of(values: &[String]) -> Self {
        let mut evidence = Self {
            sampled: u64::try_from(values.len()).unwrap_or(u64::MAX),
            ..Self::default()
        };
        for value in values {
            for (count, &pii) in evidence.matched.iter_mut().zip(&VALUE_TYPES) {
                if validates(pii, value) {
                    *count = count.saturating_add(1);
                    if pii == PiiType::Phone && bare_digits(value) {
                        evidence.bare_phones = evidence.bare_phones.saturating_add(1);
                    }
                }
            }
        }
        evidence
    }

    /// This evidence as a column named `phone_named` or not sees it:
    /// without a phone or contact word in the name, bare digit runs are
    /// not phone matches.
    fn for_name(&self, phone_named: bool) -> Self {
        let mut seen = *self;
        if !phone_named
            && let Some(at) = VALUE_TYPES.iter().position(|&t| t == PiiType::Phone)
            && let Some(count) = seen.matched.get_mut(at)
        {
            *count = count.saturating_sub(self.bare_phones);
        }
        seen
    }

    fn matched_for(&self, pii: PiiType) -> u64 {
        VALUE_TYPES
            .iter()
            .position(|&t| t == pii)
            .and_then(|i| self.matched.get(i))
            .copied()
            .unwrap_or(0)
    }

    /// Whether another row group should be sampled: too few cleaned
    /// values to be sure, or a best match share between 20% and 80%.
    /// A column that is clearly PII, or clearly not, stops here.
    pub(super) fn needs_more(&self) -> bool {
        if self.sampled < MIN_CONFIRMED as u64 {
            return true;
        }
        let best = self.matched.iter().copied().max().unwrap_or(0);
        let share = percent(best, self.sampled);
        share > 20 && share < 80
    }
}

/// `part` as a whole percentage of `whole`, rounded down; 0 when `whole`
/// is 0.
fn percent(part: u64, whole: u64) -> u64 {
    part.saturating_mul(100).checked_div(whole).unwrap_or(0)
}

/// Whether `part` is at least `pct` percent of `whole`, exactly.
fn at_least(part: u64, whole: u64, pct: u64) -> bool {
    u128::from(part) * 100 >= u128::from(whole) * u128::from(pct)
}

/// The confidence values alone give type `pii`, if any, in a column whose
/// name is about a person (`person`) or not.
fn value_confidence(evidence: &Evidence, pii: PiiType, person: bool) -> Option<Confidence> {
    let n = evidence.sampled;
    let m = evidence.matched_for(pii);
    if n == 0 || m == 0 {
        return None;
    }
    if n >= MIN_CONFIRMED as u64 {
        if at_least(m, n, 80) {
            let organisation_phone =
                pii == PiiType::Phone && !person && !at_least(m, n, HIGH_PHONE_PERCENT);
            Some(if organisation_phone {
                Confidence::Likely
            } else {
                Confidence::Confirmed
            })
        } else if at_least(m, n, 50) {
            Some(Confidence::Likely)
        } else {
            None
        }
    } else if at_least(m, n, 80) {
        Some(Confidence::Likely)
    } else {
        None
    }
}

/// A column's verdict: the type, how sure, and what it rests on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct Verdict {
    pub(super) pii: PiiType,
    pub(super) confidence: Confidence,
    pub(super) evidence: Basis,
}

/// What a column's name says, beyond its hint.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(super) struct Named {
    /// About a person or a personal device (`names::about_person`).
    pub(super) person: bool,
    /// Has a phone or contact word in it (`names::phone_named`).
    pub(super) phone: bool,
}

/// At most one verdict for a column with this `evidence`, name `hint`,
/// value `kind`, and what else its name says (`named`); see this module's
/// doc for the rules.
pub(super) fn classify(
    evidence: &Evidence,
    hint: Option<Hint>,
    kind: Kind,
    named: Named,
) -> Option<Verdict> {
    // Read, and nothing left after cleaning: nothing to report.
    if kind != Kind::Temporal && evidence.sampled == 0 {
        return None;
    }
    let person = named.person;
    let evidence = &evidence.for_name(named.phone);
    // Values first: the most confident type, then the strictest.
    let mut best: Option<(PiiType, Confidence)> = None;
    for pii in VALUE_TYPES {
        if let Some(confidence) = value_confidence(evidence, pii, person)
            && best.is_none_or(|(_, held)| confidence > held)
        {
            best = Some((pii, confidence));
        }
    }
    let values = |pii| Basis::Values {
        matched: evidence.matched_for(pii),
        sampled: evidence.sampled,
    };
    if let Some((pii, confidence)) = best {
        return Some(Verdict {
            pii,
            confidence,
            evidence: values(pii),
        });
    }

    let hint = hint?;
    let pii = hint.pii;
    let verdict = |confidence, evidence| {
        Some(Verdict {
            pii,
            confidence,
            evidence,
        })
    };
    if pii.has_validator() {
        if evidence.matched_for(pii) > 0 {
            return verdict(Confidence::Likely, values(pii));
        }
        if evidence.sampled >= MIN_CONFIRMED as u64 || pii == PiiType::InPan {
            return None;
        }
        return verdict(Confidence::Possible, Basis::ColumnName);
    }
    let fits = match pii {
        PiiType::PersonName => kind == Kind::Text,
        _ => matches!(kind, Kind::Temporal | Kind::Text),
    };
    if hint.strength == Strength::Strong && fits {
        verdict(Confidence::Likely, Basis::ColumnName)
    } else {
        verdict(Confidence::Possible, Basis::ColumnName)
    }
}

#[cfg(test)]
mod tests {
    use super::{Evidence, Kind, Named, Verdict, classify};

    /// A name with a phone word but not about a person (`PHONE`): the
    /// behaviour before the bare-digit rule, for the tests below it.
    const PHONE_NAMED: Named = Named {
        person: false,
        phone: true,
    };

    /// A person's phone (`customer_phone`).
    const PERSON: Named = Named {
        person: true,
        phone: true,
    };

    fn named(person: bool) -> Named {
        Named {
            person,
            phone: true,
        }
    }
    use crate::content::names::{Hint, Strength};
    use crate::model::{Confidence, Evidence as Basis, PiiType};

    /// `matching` values that validate as `good`, then `other` that match
    /// nothing.
    fn sample(good: &str, matching: usize, other: usize) -> Vec<String> {
        let mut values = vec![good.to_owned(); matching];
        values.extend((0..other).map(|i| format!("plain text {i}")));
        values
    }

    fn email_evidence(matching: usize, other: usize) -> Evidence {
        Evidence::of(&sample("a@b.co", matching, other))
    }

    fn hint(pii: PiiType, strength: Strength) -> Hint {
        Hint { pii, strength }
    }

    fn confidence(verdict: Option<Verdict>) -> Option<(PiiType, Confidence)> {
        verdict.map(|v| (v.pii, v.confidence))
    }

    #[test]
    fn eighty_percent_of_thirty_or_more_is_confirmed() {
        let verdict = classify(&email_evidence(24, 6), None, Kind::Text, PHONE_NAMED);
        assert_eq!(
            verdict,
            Some(Verdict {
                pii: PiiType::Email,
                confidence: Confidence::Confirmed,
                evidence: Basis::Values {
                    matched: 24,
                    sampled: 30
                },
            })
        );
    }

    #[test]
    fn fifty_to_eighty_percent_is_likely_and_below_is_nothing() {
        assert_eq!(
            confidence(classify(
                &email_evidence(15, 15),
                None,
                Kind::Text,
                PHONE_NAMED
            )),
            Some((PiiType::Email, Confidence::Likely))
        );
        assert_eq!(
            classify(&email_evidence(14, 16), None, Kind::Text, PHONE_NAMED),
            None
        );
    }

    #[test]
    fn the_value_rule_on_fewer_than_thirty_values_is_likely() {
        assert_eq!(
            confidence(classify(
                &email_evidence(8, 2),
                None,
                Kind::Text,
                PHONE_NAMED
            )),
            Some((PiiType::Email, Confidence::Likely))
        );
        assert_eq!(
            classify(&email_evidence(7, 3), None, Kind::Text, PHONE_NAMED),
            None
        );
    }

    #[test]
    fn a_name_hint_plus_one_match_is_likely_and_a_hint_alone_possible() {
        let email = Some(hint(PiiType::Email, Strength::Strong));
        assert_eq!(
            confidence(classify(
                &email_evidence(1, 10),
                email,
                Kind::Text,
                PHONE_NAMED
            )),
            Some((PiiType::Email, Confidence::Likely))
        );
        assert_eq!(
            confidence(classify(
                &email_evidence(0, 10),
                email,
                Kind::Text,
                PHONE_NAMED
            )),
            Some((PiiType::Email, Confidence::Possible))
        );
    }

    /// The real-data experiment's `payers.PHONE`: named a phone, every value
    /// null. Read, nothing kept: no finding of any confidence.
    #[test]
    fn a_column_with_no_value_after_cleaning_is_never_reported() {
        let empty = Evidence::default();
        for (pii, strength) in [
            (PiiType::Phone, Strength::Strong),
            (PiiType::Email, Strength::Strong),
            (PiiType::PersonName, Strength::Strong),
            (PiiType::DateOfBirth, Strength::Strong),
            (PiiType::CardNumber, Strength::Weak),
        ] {
            for kind in [Kind::Text, Kind::Integer] {
                for person in [false, true] {
                    assert_eq!(
                        classify(&empty, Some(hint(pii, strength)), kind, named(person)),
                        None,
                        "{pii:?} {kind:?}"
                    );
                }
            }
        }
        // Dates are never read, so their name still counts.
        assert_eq!(
            confidence(classify(
                &empty,
                Some(hint(PiiType::DateOfBirth, Strength::Strong)),
                Kind::Temporal,
                PHONE_NAMED
            )),
            Some((PiiType::DateOfBirth, Confidence::Likely))
        );
    }

    /// The experiment's FHIR practitioner `identifier.list.element.value`:
    /// US NPI numbers, bare 10-digit runs starting with 9, which the
    /// Indian-mobile rule accepts. Unnamed, a bare run is not a phone, so
    /// the column is not reported; named for a phone or contact
    /// (`mobile_no`, `contact`), the same values still confirm. Formatted
    /// numbers count whatever the name.
    #[test]
    fn a_bare_digit_run_is_a_phone_only_under_a_phone_or_contact_name() {
        let npis: Vec<String> = (0..278).map(|i| format!("99999{i:05}")).collect();
        let npis = Evidence::of(&npis);
        assert_eq!(npis.bare_phones, 278);
        let unnamed = Named::default();
        assert_eq!(classify(&npis, None, Kind::Text, unnamed), None);
        assert_eq!(classify(&npis, None, Kind::Integer, unnamed), None);
        // A mobile column, as the Indian fixtures name theirs.
        for named in [PHONE_NAMED, PERSON] {
            assert_eq!(
                confidence(classify(&npis, None, Kind::Integer, named)),
                Some((PiiType::Phone, Confidence::Confirmed))
            );
        }
        // Formatted numbers are unaffected by the name.
        let formatted: Vec<String> = (0..40).map(|i| format!("+91 98765 432{i:02}")).collect();
        assert_eq!(
            confidence(classify(
                &Evidence::of(&formatted),
                None,
                Kind::Text,
                unnamed
            )),
            Some((PiiType::Phone, Confidence::Confirmed))
        );
        // Mixed, unnamed: only the formatted share counts toward 80%.
        let mut mixed: Vec<String> = (0..40).map(|i| format!("98765432{i:02}")).collect();
        mixed.extend((0..60).map(|i| format!("+1 201 555 01{i:02}")));
        assert_eq!(
            confidence(classify(&Evidence::of(&mixed), None, Kind::Text, unnamed)),
            Some((PiiType::Phone, Confidence::Likely)),
            "60% formatted: likely, never confirmed"
        );
        assert_eq!(
            confidence(classify(&Evidence::of(&mixed), None, Kind::Text, PERSON)),
            Some((PiiType::Phone, Confidence::Confirmed))
        );
    }

    /// `n` values, `matching` of them a reserved US number, the rest junk.
    fn phones(matching: usize, n: usize) -> Evidence {
        let mut values = vec!["(201) 555-0123".to_owned(); matching];
        values.extend((matching..n).map(|i| format!("ext {i}")));
        Evidence::of(&values)
    }

    /// The experiment's Synthea `organizations.PHONE` (named `PHONE`, an
    /// organisation's switchboard, 57% valid) and FHIR patient
    /// `telecom.value` (unnamed, 91% valid): neither name is about a
    /// person, so only a very high match rate confirms.
    #[test]
    fn a_phone_column_is_confirmed_only_with_a_person_name_or_a_high_match_rate() {
        let phone = Some(hint(PiiType::Phone, Strength::Strong));
        let at = |matching, person, hint| {
            confidence(classify(
                &phones(matching, 100),
                hint,
                Kind::Text,
                named(person),
            ))
        };
        // organizations.PHONE: 57%, likely either way.
        assert_eq!(
            at(57, false, phone),
            Some((PiiType::Phone, Confidence::Likely))
        );
        // telecom.value: 91%, no person in the name: capped at likely.
        assert_eq!(
            at(91, false, None),
            Some((PiiType::Phone, Confidence::Likely))
        );
        assert_eq!(
            at(94, false, phone),
            Some((PiiType::Phone, Confidence::Likely))
        );
        // A very high match rate confirms on values alone.
        assert_eq!(
            at(95, false, None),
            Some((PiiType::Phone, Confidence::Confirmed))
        );
        assert_eq!(
            at(100, false, phone),
            Some((PiiType::Phone, Confidence::Confirmed))
        );
        // A person's phone (customer_phone, contact, mobile_no) confirms at 80%.
        assert_eq!(
            at(80, true, phone),
            Some((PiiType::Phone, Confidence::Confirmed))
        );
        assert_eq!(
            at(91, true, None),
            Some((PiiType::Phone, Confidence::Confirmed))
        );
        // Other types are not capped.
        let emails = Evidence::of(&sample("a@b.co", 80, 20));
        assert_eq!(
            confidence(classify(&emails, None, Kind::Text, PHONE_NAMED)),
            Some((PiiType::Email, Confidence::Confirmed))
        );
    }

    #[test]
    fn values_override_names_once_there_are_thirty() {
        // email_sha256: named like an email, holds hex digests.
        let digests = Evidence::of(&sample("x", 0, 40));
        assert_eq!(
            classify(
                &digests,
                Some(hint(PiiType::Email, Strength::Strong)),
                Kind::Text,
                PHONE_NAMED
            ),
            None
        );
    }

    #[test]
    fn a_pan_hint_needs_the_validator_to_agree() {
        let pan = Some(hint(PiiType::InPan, Strength::Strong));
        let words = Evidence::of(&sample("x", 0, 5));
        assert_eq!(classify(&words, pan, Kind::Text, PHONE_NAMED), None);
        let cards = Evidence::of(&sample("4111111111111111", 10, 0));
        assert_eq!(
            confidence(classify(&cards, pan, Kind::Text, PHONE_NAMED)),
            Some((PiiType::CardNumber, Confidence::Likely))
        );
        let pans = Evidence::of(&sample("ABCPE1234F", 1, 5));
        assert_eq!(
            confidence(classify(&pans, pan, Kind::Text, PHONE_NAMED)),
            Some((PiiType::InPan, Confidence::Likely))
        );
    }

    #[test]
    fn checksums_beat_patterns_at_equal_confidence() {
        // A Verhoeff-valid 12-digit number that is also a 91-prefixed
        // Indian mobile number: both validators pass, the checksum wins.
        let values = vec!["919876543216".to_owned(); 40];
        assert_eq!(
            confidence(classify(
                &Evidence::of(&values),
                None,
                Kind::Integer,
                PHONE_NAMED
            )),
            Some((PiiType::InAadhaar, Confidence::Confirmed))
        );
    }

    #[test]
    fn a_more_confident_type_beats_a_stricter_one() {
        // 40 emails and 20 Aadhaar numbers: `EMAIL` is confirmed (>=80%? no:
        // 40/60 = 66%, likely), Aadhaar 33% is nothing.
        let mut values = sample("a@b.co", 40, 0);
        values.extend(std::iter::repeat_n("234567890124".to_owned(), 20));
        assert_eq!(
            confidence(classify(
                &Evidence::of(&values),
                None,
                Kind::Text,
                PHONE_NAMED
            )),
            Some((PiiType::Email, Confidence::Likely))
        );
    }

    #[test]
    fn name_only_types_need_a_strong_hint_on_a_fitting_column() {
        let full_name = Some(hint(PiiType::PersonName, Strength::Strong));
        let name = Some(hint(PiiType::PersonName, Strength::Weak));
        let dob = Some(hint(PiiType::DateOfBirth, Strength::Strong));
        // Values read, none validates as anything (names have no
        // validator); dates are never read.
        let none = Evidence::of(&sample("x", 0, 40));
        let unread = Evidence::default();
        assert_eq!(
            confidence(classify(&none, full_name, Kind::Text, PHONE_NAMED)),
            Some((PiiType::PersonName, Confidence::Likely))
        );
        assert_eq!(
            confidence(classify(&none, full_name, Kind::Integer, PHONE_NAMED)),
            Some((PiiType::PersonName, Confidence::Possible))
        );
        assert_eq!(
            confidence(classify(&none, name, Kind::Text, PHONE_NAMED)),
            Some((PiiType::PersonName, Confidence::Possible))
        );
        assert_eq!(
            confidence(classify(&unread, dob, Kind::Temporal, PHONE_NAMED)),
            Some((PiiType::DateOfBirth, Confidence::Likely))
        );
        assert_eq!(
            confidence(classify(&none, dob, Kind::Integer, PHONE_NAMED)),
            Some((PiiType::DateOfBirth, Confidence::Possible))
        );
    }

    #[test]
    fn escalation_is_needed_for_small_or_ambiguous_samples_only() {
        assert!(email_evidence(5, 5).needs_more(), "fewer than 30");
        assert!(email_evidence(0, 0).needs_more(), "nothing cleaned");
        assert!(email_evidence(15, 15).needs_more(), "50% is ambiguous");
        assert!(!email_evidence(30, 0).needs_more(), "clearly PII");
        assert!(!email_evidence(24, 6).needs_more(), "exactly 80%");
        assert!(!email_evidence(6, 24).needs_more(), "exactly 20%");
        assert!(!email_evidence(0, 40).needs_more(), "clearly not");
    }
}
