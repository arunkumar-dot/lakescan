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
//! Value evidence comes first and overrides names: when values qualify
//! for one or more types, the most confident wins, then the strictest
//! validator. A column with at least 30 cleaned values and no match for
//! its hinted type is not reported for that type, whatever its name. An
//! `IN_PAN` hint needs at least one matching value, so a card column named
//! `pan` is never reported as an Indian tax ID on its name alone.

use super::detect::{VALUE_TYPES, validates};
use super::names::{Hint, Strength};
use crate::model::{Confidence, Evidence as Basis, PiiType};

/// The fewest cleaned values for `CONFIRMED`.
pub(super) const MIN_CONFIRMED: usize = 30;

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
                }
            }
        }
        evidence
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

/// The confidence values alone give type `pii`, if any.
fn value_confidence(evidence: &Evidence, pii: PiiType) -> Option<Confidence> {
    let n = evidence.sampled;
    let m = evidence.matched_for(pii);
    if n == 0 || m == 0 {
        return None;
    }
    if n >= MIN_CONFIRMED as u64 {
        if at_least(m, n, 80) {
            Some(Confidence::Confirmed)
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

/// At most one verdict for a column with this `evidence`, name `hint` and
/// value `kind`; see this module's doc for the rules.
pub(super) fn classify(evidence: &Evidence, hint: Option<Hint>, kind: Kind) -> Option<Verdict> {
    // Values first: the most confident type, then the strictest.
    let mut best: Option<(PiiType, Confidence)> = None;
    for pii in VALUE_TYPES {
        if let Some(confidence) = value_confidence(evidence, pii)
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
    use super::{Evidence, Kind, Verdict, classify};
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
        let verdict = classify(&email_evidence(24, 6), None, Kind::Text);
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
            confidence(classify(&email_evidence(15, 15), None, Kind::Text)),
            Some((PiiType::Email, Confidence::Likely))
        );
        assert_eq!(classify(&email_evidence(14, 16), None, Kind::Text), None);
    }

    #[test]
    fn the_value_rule_on_fewer_than_thirty_values_is_likely() {
        assert_eq!(
            confidence(classify(&email_evidence(8, 2), None, Kind::Text)),
            Some((PiiType::Email, Confidence::Likely))
        );
        assert_eq!(classify(&email_evidence(7, 3), None, Kind::Text), None);
    }

    #[test]
    fn a_name_hint_plus_one_match_is_likely_and_a_hint_alone_possible() {
        let email = Some(hint(PiiType::Email, Strength::Strong));
        assert_eq!(
            confidence(classify(&email_evidence(1, 10), email, Kind::Text)),
            Some((PiiType::Email, Confidence::Likely))
        );
        assert_eq!(
            confidence(classify(&email_evidence(0, 10), email, Kind::Text)),
            Some((PiiType::Email, Confidence::Possible))
        );
        assert_eq!(
            confidence(classify(&Evidence::default(), email, Kind::Text)),
            Some((PiiType::Email, Confidence::Possible))
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
                Kind::Text
            ),
            None
        );
    }

    #[test]
    fn a_pan_hint_needs_the_validator_to_agree() {
        let pan = Some(hint(PiiType::InPan, Strength::Strong));
        assert_eq!(classify(&Evidence::default(), pan, Kind::Text), None);
        let cards = Evidence::of(&sample("4111111111111111", 10, 0));
        assert_eq!(
            confidence(classify(&cards, pan, Kind::Text)),
            Some((PiiType::CardNumber, Confidence::Likely))
        );
        let pans = Evidence::of(&sample("ABCPE1234F", 1, 5));
        assert_eq!(
            confidence(classify(&pans, pan, Kind::Text)),
            Some((PiiType::InPan, Confidence::Likely))
        );
    }

    #[test]
    fn checksums_beat_patterns_at_equal_confidence() {
        // A Verhoeff-valid 12-digit number that is also a 91-prefixed
        // Indian mobile number: both validators pass, the checksum wins.
        let values = vec!["919876543216".to_owned(); 40];
        assert_eq!(
            confidence(classify(&Evidence::of(&values), None, Kind::Integer)),
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
            confidence(classify(&Evidence::of(&values), None, Kind::Text)),
            Some((PiiType::Email, Confidence::Likely))
        );
    }

    #[test]
    fn name_only_types_need_a_strong_hint_on_a_fitting_column() {
        let full_name = Some(hint(PiiType::PersonName, Strength::Strong));
        let name = Some(hint(PiiType::PersonName, Strength::Weak));
        let dob = Some(hint(PiiType::DateOfBirth, Strength::Strong));
        let none = Evidence::default();
        assert_eq!(
            confidence(classify(&none, full_name, Kind::Text)),
            Some((PiiType::PersonName, Confidence::Likely))
        );
        assert_eq!(
            confidence(classify(&none, full_name, Kind::Integer)),
            Some((PiiType::PersonName, Confidence::Possible))
        );
        assert_eq!(
            confidence(classify(&none, name, Kind::Text)),
            Some((PiiType::PersonName, Confidence::Possible))
        );
        assert_eq!(
            confidence(classify(&none, dob, Kind::Temporal)),
            Some((PiiType::DateOfBirth, Confidence::Likely))
        );
        assert_eq!(
            confidence(classify(&none, dob, Kind::Integer)),
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
