//! Name hints: what a column's name suggests it holds.
//!
//! Only the last path segment counts (`email` in `customer.contact.email`).
//! It is split into lowercase tokens on `_`, `-`, `.`, spaces and camelCase
//! boundaries (`clientIPAddress` becomes `client`, `ip`, `address`), and
//! the tokens are matched against [`HINTS`], the one place every hint is
//! defined. A hint is a word, or a phrase of adjacent words; a phrase
//! match is *strong*. For [`PiiType::PersonName`] and
//! [`PiiType::DateOfBirth`], which have no validator, only a strong hint
//! on a column of fitting type reaches `LIKELY`.
//!
//! A hint is only ever a hint: value evidence overrides it (see
//! `classify`), so `email_sha256` hinting `EMAIL` is never reported once its
//! values have been read.

use crate::model::PiiType;

/// How much a hint says.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Strength {
    /// A single, possibly ambiguous word: `name`, `card`.
    Weak,
    /// An unambiguous word or phrase: `email`, `first name`, `dob`.
    Strong,
}

/// A column name's hint: the type it suggests, and how strongly.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct Hint {
    pub(super) pii: PiiType,
    pub(super) strength: Strength,
}

/// Every hint, as (type, strength, token phrase). Checked in order; the
/// first match wins. Phrases are space-separated tokens that must appear
/// adjacent and in order.
const HINTS: &[(PiiType, Strength, &str)] = &[
    (PiiType::Email, Strength::Strong, "email"),
    (PiiType::Email, Strength::Strong, "emails"),
    (PiiType::Email, Strength::Strong, "emailaddress"),
    (PiiType::Email, Strength::Strong, "emailid"),
    (PiiType::Email, Strength::Strong, "e mail"),
    (PiiType::Email, Strength::Weak, "mail"),
    (PiiType::Phone, Strength::Strong, "phone"),
    (PiiType::Phone, Strength::Strong, "phonenumber"),
    (PiiType::Phone, Strength::Strong, "phoneno"),
    (PiiType::Phone, Strength::Strong, "mobile"),
    (PiiType::Phone, Strength::Strong, "mobileno"),
    (PiiType::Phone, Strength::Strong, "msisdn"),
    (PiiType::Phone, Strength::Strong, "telephone"),
    (PiiType::Phone, Strength::Strong, "cellphone"),
    (PiiType::Phone, Strength::Weak, "tel"),
    (PiiType::Phone, Strength::Weak, "cell"),
    (PiiType::InAadhaar, Strength::Strong, "aadhaar"),
    (PiiType::InAadhaar, Strength::Strong, "aadhar"),
    (PiiType::InAadhaar, Strength::Strong, "adhaar"),
    (PiiType::InAadhaar, Strength::Strong, "uidai"),
    (PiiType::CardNumber, Strength::Strong, "card number"),
    (PiiType::CardNumber, Strength::Strong, "cardnumber"),
    (PiiType::CardNumber, Strength::Strong, "card no"),
    (PiiType::CardNumber, Strength::Strong, "creditcard"),
    (PiiType::CardNumber, Strength::Strong, "credit card"),
    (PiiType::CardNumber, Strength::Strong, "debitcard"),
    (PiiType::CardNumber, Strength::Strong, "debit card"),
    (PiiType::CardNumber, Strength::Strong, "ccnum"),
    (PiiType::CardNumber, Strength::Weak, "card"),
    (PiiType::CardNumber, Strength::Weak, "cc"),
    // PAN: checked after the card phrases, so "card pan" (a primary
    // account number) is a card hint. An `IN_PAN` hint is only ever used
    // when the PAN validator agrees.
    (PiiType::InPan, Strength::Strong, "pan"),
    (PiiType::InPan, Strength::Strong, "pannumber"),
    (PiiType::InPan, Strength::Strong, "panno"),
    (PiiType::IpAddress, Strength::Strong, "ip"),
    (PiiType::IpAddress, Strength::Strong, "ipaddress"),
    (PiiType::IpAddress, Strength::Strong, "ipaddr"),
    (PiiType::IpAddress, Strength::Strong, "ipv4"),
    (PiiType::IpAddress, Strength::Strong, "ipv6"),
    (PiiType::DateOfBirth, Strength::Strong, "dob"),
    (PiiType::DateOfBirth, Strength::Strong, "date of birth"),
    (PiiType::DateOfBirth, Strength::Strong, "birth date"),
    (PiiType::DateOfBirth, Strength::Strong, "birthdate"),
    (PiiType::DateOfBirth, Strength::Strong, "birthday"),
    (PiiType::DateOfBirth, Strength::Weak, "birth"),
    (PiiType::PersonName, Strength::Strong, "full name"),
    (PiiType::PersonName, Strength::Strong, "fullname"),
    (PiiType::PersonName, Strength::Strong, "first name"),
    (PiiType::PersonName, Strength::Strong, "firstname"),
    (PiiType::PersonName, Strength::Strong, "middle name"),
    (PiiType::PersonName, Strength::Strong, "last name"),
    (PiiType::PersonName, Strength::Strong, "lastname"),
    (PiiType::PersonName, Strength::Strong, "given name"),
    (PiiType::PersonName, Strength::Strong, "family name"),
    (PiiType::PersonName, Strength::Strong, "surname"),
    (PiiType::PersonName, Strength::Strong, "customer name"),
    (PiiType::PersonName, Strength::Strong, "person name"),
    (PiiType::PersonName, Strength::Strong, "holder name"),
    (PiiType::PersonName, Strength::Strong, "cardholder name"),
    (PiiType::PersonName, Strength::Weak, "name"),
];

/// Splits `segment` into lowercase tokens on `_`, `-`, `.`, whitespace and
/// camelCase boundaries. An uppercase run followed by a lowercase letter
/// ends one letter early (`IPAddress` is `ip`, `address`).
pub(super) fn tokens(segment: &str) -> Vec<String> {
    let chars: Vec<char> = segment.chars().collect();
    let mut out = Vec::new();
    let mut current = String::new();
    for (index, &c) in chars.iter().enumerate() {
        if matches!(c, '_' | '-' | '.') || c.is_whitespace() {
            if !current.is_empty() {
                out.push(std::mem::take(&mut current));
            }
            continue;
        }
        let previous = index.checked_sub(1).and_then(|i| chars.get(i)).copied();
        let next = chars.get(index + 1).copied();
        let boundary = c.is_uppercase()
            && previous.is_some_and(|p| {
                p.is_lowercase()
                    || p.is_ascii_digit()
                    || (p.is_uppercase() && next.is_some_and(char::is_lowercase))
            });
        if boundary && !current.is_empty() {
            out.push(std::mem::take(&mut current));
        }
        current.extend(c.to_lowercase());
    }
    if !current.is_empty() {
        out.push(current);
    }
    out
}

/// The hint the last path segment of a column suggests, if any.
pub(super) fn hint(leaf: &str) -> Option<Hint> {
    let tokens = tokens(leaf);
    HINTS.iter().find_map(|&(pii, strength, phrase)| {
        let words: Vec<&str> = phrase.split(' ').collect();
        let found = tokens
            .windows(words.len())
            .any(|window| window.iter().zip(&words).all(|(t, w)| t == w));
        found.then_some(Hint { pii, strength })
    })
}

#[cfg(test)]
mod tests {
    use super::{Hint, Strength, hint, tokens};
    use crate::model::PiiType;

    fn strong(pii: PiiType) -> Hint {
        Hint {
            pii,
            strength: Strength::Strong,
        }
    }

    fn weak(pii: PiiType) -> Hint {
        Hint {
            pii,
            strength: Strength::Weak,
        }
    }

    #[test]
    fn tokenizing_splits_separators_and_camel_case() {
        assert_eq!(tokens("customer_email"), ["customer", "email"]);
        assert_eq!(tokens("customer-email.v2"), ["customer", "email", "v2"]);
        assert_eq!(tokens("customerEmail"), ["customer", "email"]);
        assert_eq!(tokens("clientIPAddress"), ["client", "ip", "address"]);
        assert_eq!(tokens("IP"), ["ip"]);
        assert_eq!(tokens("dateOfBirth"), ["date", "of", "birth"]);
        assert_eq!(tokens("addr2Line"), ["addr2", "line"]);
        assert_eq!(tokens("__x__"), ["x"]);
        assert_eq!(tokens(""), Vec::<String>::new());
    }

    #[test]
    fn column_names_hint_their_type() {
        assert_eq!(hint("email"), Some(strong(PiiType::Email)));
        assert_eq!(hint("contactEmail"), Some(strong(PiiType::Email)));
        assert_eq!(hint("email_sha256"), Some(strong(PiiType::Email)));
        assert_eq!(hint("mobile_no"), Some(strong(PiiType::Phone)));
        assert_eq!(hint("aadhaar_no"), Some(strong(PiiType::InAadhaar)));
        assert_eq!(hint("card_number"), Some(strong(PiiType::CardNumber)));
        assert_eq!(hint("card"), Some(weak(PiiType::CardNumber)));
        assert_eq!(hint("pan"), Some(strong(PiiType::InPan)));
        assert_eq!(hint("src_ip"), Some(strong(PiiType::IpAddress)));
        assert_eq!(hint("dob"), Some(strong(PiiType::DateOfBirth)));
        assert_eq!(hint("DateOfBirth"), Some(strong(PiiType::DateOfBirth)));
        assert_eq!(hint("full_name"), Some(strong(PiiType::PersonName)));
        assert_eq!(hint("lastName"), Some(strong(PiiType::PersonName)));
        assert_eq!(hint("name"), Some(weak(PiiType::PersonName)));
    }

    #[test]
    fn a_card_column_called_pan_hints_card_when_the_name_says_so() {
        assert_eq!(hint("card_pan"), Some(weak(PiiType::CardNumber)));
        assert_eq!(hint("credit_card_pan"), Some(strong(PiiType::CardNumber)));
    }

    #[test]
    fn unrelated_names_hint_nothing() {
        for name in [
            "customer_id",
            "amount",
            "city",
            "plan",
            "notes",
            "company",
            "tip",
            "panel",
        ] {
            assert_eq!(hint(name), None, "{name}");
        }
    }
}
