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
//!
//! **Names and dates of birth** have no validator, so their hints must not
//! fire on the many columns that are not about people. A `name` counts
//! only by what qualifies it, the word just before it, as its own token
//! (`product_name`) or joined (`hostname`): a part of a person's name
//! (`first`, `last`, `full`, `given`, `family`, `middle`) or a person noun
//! (`customer`, `user`, `patient`, `employee`, `member`, `person`,
//! `contact`, account `holder`) is a strong hint, and so is `surname`; a
//! non-person noun ([`NOT_PEOPLE`]: `product`, `file`, `host`, `table`,
//! `city`, ...) is no hint at all; anything else (`name` alone,
//! `display_name`) is a weak one. `birth` is treated the same way:
//! `date of birth`, `birth date`, `birthday` and `dob` are strong, and
//! `birth` qualified as a place, a measure or a document ([`NOT_DATES`]:
//! `birth_place`, `country_of_birth`, `birth_weight`) is no hint.

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
    (PiiType::DateOfBirth, Strength::Strong, "dateofbirth"),
    (PiiType::DateOfBirth, Strength::Strong, "birth date"),
    (PiiType::DateOfBirth, Strength::Strong, "birthdate"),
    (PiiType::DateOfBirth, Strength::Strong, "birthday"),
];

/// Words that make `name` a part of a person's name, or a person's.
const PERSON_QUALIFIERS: &[&str] = &[
    "first",
    "last",
    "full",
    "given",
    "family",
    "middle",
    "customer",
    "user",
    "patient",
    "employee",
    "member",
    "person",
    "contact",
    "holder",
    "cardholder",
];

/// Nouns that make `name` something other than a person's.
pub(super) const NOT_PEOPLE: &[&str] = &[
    "product",
    "file",
    "service",
    "company",
    "business",
    "brand",
    "host",
    "bucket",
    "table",
    "column",
    "schema",
    "database",
    "db",
    "app",
    "device",
    "model",
    "event",
    "job",
    "task",
    "topic",
    "stream",
    "field",
    "feature",
    "plan",
    "category",
    "tag",
    "label",
    "domain",
    "role",
    "group",
    "team",
    "org",
    "organization",
    "vendor",
    "merchant",
    "city",
    "state",
    "country",
    "project",
    "dataset",
    "cluster",
    "region",
    "store",
    "item",
    "campaign",
    "department",
    "branch",
    "package",
    "module",
    "class",
    "function",
    "method",
    "metric",
    "partition",
    "index",
    "key",
    "queue",
    "server",
    "machine",
    "bank",
    "street",
    "place",
    "location",
];

/// Words that make `birth` something other than a date: a place, a
/// measure, a document.
pub(super) const NOT_DATES: &[&str] = &[
    "place",
    "country",
    "city",
    "state",
    "town",
    "location",
    "weight",
    "height",
    "length",
    "order",
    "rate",
    "rank",
    "certificate",
    "cert",
    "registration",
    "name",
];

/// How `name` qualified by `qualifier` (the word before it; `None` if it
/// starts the column name) hints a person's name.
fn name_qualified_by(qualifier: Option<&str>) -> Option<Strength> {
    match qualifier {
        Some(word) if PERSON_QUALIFIERS.contains(&word) => Some(Strength::Strong),
        Some(word) if NOT_PEOPLE.contains(&word) => None,
        _ => Some(Strength::Weak),
    }
}

/// The person-name hint in `tokens`: the strongest of every `name`
/// (or `names`), standalone or joined (`username`, `hostname`), and
/// `surname`.
fn person_name(tokens: &[String]) -> Option<Strength> {
    let mut best = None;
    for (index, token) in tokens.iter().enumerate() {
        let found = if token == "surname" || token == "surnames" {
            Some(Strength::Strong)
        } else if token == "name" || token == "names" {
            let before = index.checked_sub(1).and_then(|at| tokens.get(at));
            name_qualified_by(before.map(String::as_str))
        } else if let Some(prefix) = token
            .strip_suffix("names")
            .or_else(|| token.strip_suffix("name"))
            .filter(|prefix| !prefix.is_empty())
        {
            // Joined: only a known qualifier counts, so `rename` and
            // `codename` hint nothing.
            if PERSON_QUALIFIERS.contains(&prefix) {
                Some(Strength::Strong)
            } else {
                None
            }
        } else {
            None
        };
        best = match (best, found) {
            (Some(Strength::Strong), _) | (_, Some(Strength::Strong)) => Some(Strength::Strong),
            (Some(Strength::Weak), _) | (_, Some(Strength::Weak)) => Some(Strength::Weak),
            _ => None,
        };
    }
    best
}

/// A weak date-of-birth hint: `birth` not qualified by [`NOT_DATES`],
/// neither just after it (`birth_place`) nor as `<word> of birth`
/// (`country_of_birth`). The strong forms are in [`HINTS`].
fn birth(tokens: &[String]) -> Option<Strength> {
    let at = |index: Option<usize>| {
        index
            .and_then(|index| tokens.get(index))
            .map(String::as_str)
    };
    tokens
        .iter()
        .enumerate()
        .any(|(index, token)| {
            token == "birth"
                && !at(Some(index + 1)).is_some_and(|next| NOT_DATES.contains(&next))
                && !(at(index.checked_sub(1)) == Some("of")
                    && at(index.checked_sub(2)).is_some_and(|word| NOT_DATES.contains(&word)))
        })
        .then_some(Strength::Weak)
}

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

/// The hint the last path segment of a column suggests, if any: the
/// first match in [`HINTS`], else a date of birth, else a person's name.
pub(super) fn hint(leaf: &str) -> Option<Hint> {
    let tokens = tokens(leaf);
    HINTS
        .iter()
        .find_map(|&(pii, strength, phrase)| {
            let words: Vec<&str> = phrase.split(' ').collect();
            let found = tokens
                .windows(words.len())
                .any(|window| window.iter().zip(&words).all(|(t, w)| t == w));
            found.then_some(Hint { pii, strength })
        })
        .or_else(|| {
            birth(&tokens).map(|strength| Hint {
                pii: PiiType::DateOfBirth,
                strength,
            })
        })
        .or_else(|| {
            person_name(&tokens).map(|strength| Hint {
                pii: PiiType::PersonName,
                strength,
            })
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

    /// Realistic column names, both sides of the person-name and
    /// date-of-birth lines.
    #[test]
    fn people_s_names_and_birth_dates_are_told_from_everything_else() {
        let name = |strength| {
            Some(Hint {
                pii: PiiType::PersonName,
                strength,
            })
        };
        let birth = |strength| {
            Some(Hint {
                pii: PiiType::DateOfBirth,
                strength,
            })
        };
        let cases: &[(&str, Option<Hint>)] = &[
            // People's names.
            ("first_name", name(Strength::Strong)),
            ("FirstName", name(Strength::Strong)),
            ("lastName", name(Strength::Strong)),
            ("full_name", name(Strength::Strong)),
            ("given_name", name(Strength::Strong)),
            ("family_name", name(Strength::Strong)),
            ("middle_name", name(Strength::Strong)),
            ("surname", name(Strength::Strong)),
            ("customer_name", name(Strength::Strong)),
            ("customerName", name(Strength::Strong)),
            ("user_name", name(Strength::Strong)),
            ("username", name(Strength::Strong)),
            ("patient_name", name(Strength::Strong)),
            ("employee_name", name(Strength::Strong)),
            ("member_name", name(Strength::Strong)),
            ("person_name", name(Strength::Strong)),
            ("contact_name", name(Strength::Strong)),
            ("account_holder_name", name(Strength::Strong)),
            ("cardholder_name", name(Strength::Strong)),
            ("company_contact_name", name(Strength::Strong)),
            // A name, unqualified or oddly qualified: possible.
            ("name", name(Strength::Weak)),
            ("Name", name(Strength::Weak)),
            ("display_name", name(Strength::Weak)),
            ("legal_name", name(Strength::Weak)),
            ("name_en", name(Strength::Weak)),
            // Names of things.
            ("product_name", None),
            ("productName", None),
            ("file_name", None),
            ("filename", None),
            ("service_name", None),
            ("company_name", None),
            ("business_name", None),
            ("brand_name", None),
            ("host_name", None),
            ("hostname", None),
            ("bucket_name", None),
            ("table_name", None),
            ("column_name", None),
            ("schema_name", None),
            ("database_name", None),
            ("app_name", None),
            ("device_name", None),
            ("model_name", None),
            ("event_name", None),
            ("job_name", None),
            ("task_name", None),
            ("topic_name", None),
            ("stream_name", None),
            ("field_name", None),
            ("feature_name", None),
            ("plan_name", None),
            ("category_name", None),
            ("tag_name", None),
            ("label_name", None),
            ("domain_name", None),
            ("role_name", None),
            ("group_name", None),
            ("team_name", None),
            ("org_name", None),
            ("vendor_name", None),
            ("merchant_name", None),
            ("city_name", None),
            ("state_name", None),
            ("country_name", None),
            ("rename_count", None),
            // Dates of birth, and things born.
            ("dob", birth(Strength::Strong)),
            ("date_of_birth", birth(Strength::Strong)),
            ("dateOfBirth", birth(Strength::Strong)),
            ("birth_date", birth(Strength::Strong)),
            ("birthdate", birth(Strength::Strong)),
            ("birthday", birth(Strength::Strong)),
            ("birth_year", birth(Strength::Weak)),
            ("year_of_birth", birth(Strength::Weak)),
            ("birth_place", None),
            ("place_of_birth", None),
            ("country_of_birth", None),
            ("birth_country", None),
            ("birth_weight", None),
            ("birth_order", None),
            ("birth_certificate_no", None),
        ];
        assert!(cases.len() >= 40);
        for (column, expected) in cases {
            assert_eq!(hint(column), *expected, "{column}");
        }
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
