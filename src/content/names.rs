//! Name hints: what a column's name suggests it holds.
//!
//! Only the column's own name counts: the last path segment that is not a
//! list or map wrapper (`email` in `customer.contact.email`, `given` in
//! `name.list.element.given.list.element`; `read` finds it). It is split
//! into lowercase tokens on `_`, `-`, `.`, spaces and camelCase boundaries
//! (`clientIPAddress` becomes `client`, `ip`, `address`), and the tokens are
//! matched against [`HINTS`], the one place every value-type hint is
//! defined. A hint is a word, or a phrase of adjacent words; a phrase match
//! is *strong*. For [`PiiType::PersonName`] and [`PiiType::DateOfBirth`],
//! which have no validator, only a strong hint on a column of fitting type
//! reaches `LIKELY`.
//!
//! A hint is only ever a hint: value evidence overrides it (see
//! `classify`), so `email_sha256` hinting `EMAIL` is never reported once its
//! values have been read.
//!
//! **Names and dates of birth** have no validator, so their hints must not
//! fire on the many columns that are not about people. These rules were
//! tuned on real public datasets (`docs/experiments/real-data.md`), where
//! `NAME` named organisations as often as people, and `Short Name`,
//! `Indicator Name` or `drug_name` named no one:
//!
//! - A part of a person's name standing alone as the whole column name is a
//!   strong hint: `FIRST`, `LAST`, `MIDDLE`, `MAIDEN`, `family`, `given`
//!   ([`NAME_PARTS`]). So is an unambiguous name word anywhere in it:
//!   `surname`, `forename`, `fname`, `lname` ([`NAME_WORDS`]).
//! - `name` (or `names`, or `nm`) is a strong hint only when a person
//!   qualifies it: a name part (`first_name`, `nameFirst`) or a person noun
//!   ([`PERSON_NOUNS`]: `customer`, `patient`, `member`, `user`, ...)
//!   before it, as its own token (`customer_display_name`) or joined
//!   (`username`). Looking back from `name`, a non-person noun
//!   ([`NOT_PEOPLE`]: `product`, `organization`, `drug`, `station`, ...)
//!   ends the search: `customer_company_name` is a company's. A bare or
//!   otherwise qualified `name` (`NAME`, `display_name`, `Short Name`) is
//!   no hint at all.
//! - `date of birth`, `birth date`, `birthdate`, `birthday`, `dob`, `bdate`
//!   and `bday` are strong. `birth` alone is weak, and no hint when
//!   qualified as a place, a measure, a count or a flag ([`NOT_DATES`]:
//!   `birth_place`, `country_of_birth`, `birth_weight`, `birth_rate`) or
//!   when it is about several births (`multipleBirthInteger`, `births`).
//!
//! Separately, [`about_person`] says whether a name is about a person or a
//! personal device (`customer_phone`, `contact`, `mobile`): `classify`
//! confirms a phone column without such a name only on a very high match
//! rate, since organisations have phone numbers too.

use crate::model::PiiType;

/// How much a hint says.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Strength {
    /// A single, possibly ambiguous word: `mail`, `card`, `birth`.
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

/// Every value-type and strong date-of-birth hint, as (type, strength,
/// token phrase). Checked in order; the first match wins. Phrases are
/// space-separated tokens that must appear adjacent and in order.
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
    (PiiType::DateOfBirth, Strength::Strong, "birth dt"),
    (PiiType::DateOfBirth, Strength::Strong, "date birth"),
    (PiiType::DateOfBirth, Strength::Strong, "birthdate"),
    (PiiType::DateOfBirth, Strength::Strong, "birthday"),
    (PiiType::DateOfBirth, Strength::Strong, "bdate"),
    (PiiType::DateOfBirth, Strength::Strong, "bday"),
];

/// Parts of a person's name: a strong hint as the whole column name
/// (`FIRST`, `family`), or before `name` (`first_name`, `familyName`).
const NAME_PARTS: &[&str] = &[
    "first", "last", "middle", "maiden", "given", "family", "full", "fore", "sur", "nick",
];

/// The parts that are a name on their own. `full`, `fore`, `sur` and
/// `nick` alone are not.
const STANDALONE_PARTS: &[&str] = &["first", "last", "middle", "maiden", "given", "family"];

/// Words that are a person's name wherever they appear in a column name.
const NAME_WORDS: &[&str] = &[
    "surname",
    "surnames",
    "forename",
    "forenames",
    "fname",
    "lname",
    "mname",
];

/// The spellings of `name` itself.
const NAME: &[&str] = &["name", "names", "nm"];

/// Nouns for people: before `name`, they make it a person's name; in any
/// name, they make a phone column a person's.
const PERSON_NOUNS: &[&str] = &[
    "customer",
    "customers",
    "cust",
    "client",
    "patient",
    "member",
    "user",
    "employee",
    "emp",
    "staff",
    "person",
    "contact",
    "holder",
    "cardholder",
    "provider",
    "practitioner",
    "physician",
    "doctor",
    "nurse",
    "applicant",
    "candidate",
    "owner",
    "driver",
    "passenger",
    "beneficiary",
    "insured",
    "subscriber",
    "guardian",
    "parent",
    "father",
    "mother",
    "spouse",
    "nominee",
    "student",
    "teacher",
    "author",
    "artist",
    "player",
    "sender",
    "recipient",
    "tenant",
    "borrower",
    "buyer",
    "consumer",
    "signatory",
];

/// Words that make a phone a person's own: their mobile, their home.
const PERSONAL_DEVICES: &[&str] = &[
    "mobile",
    "mobileno",
    "cell",
    "cellphone",
    "msisdn",
    "home",
    "personal",
    "whatsapp",
];

/// Nouns that make `name` something other than a person's. Looking back
/// from `name`, one of these ends the search for a person noun.
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
    "organisation",
    "organization",
    "payer",
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
    "short",
    "long",
    "indicator",
    "drug",
    "species",
    "scientific",
    "common",
    "station",
    "airport",
    "sheet",
    "series",
];

/// Words that make `birth` something other than a date: a place, a
/// measure, a document, a count, a flag.
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
    "ratio",
    "rank",
    "count",
    "counts",
    "number",
    "num",
    "total",
    "integer",
    "boolean",
    "bool",
    "flag",
    "indicator",
    "certificate",
    "cert",
    "registration",
    "name",
];

/// Words before `birth` that make it about several births.
const SEVERAL_BIRTHS: &[&str] = &["multiple", "live", "total"];

/// How strongly `tokens` hint a person's name; see this module's doc.
/// Never weak: a name nothing qualifies as a person's is no hint.
fn person_name(tokens: &[String]) -> Option<Strength> {
    if let [only] = tokens
        && STANDALONE_PARTS.contains(&only.as_str())
    {
        return Some(Strength::Strong);
    }
    let found = tokens.iter().enumerate().any(|(index, token)| {
        let token = token.as_str();
        if NAME_WORDS.contains(&token) {
            return true;
        }
        if NAME.contains(&token) {
            let next = tokens.get(index + 1).map(String::as_str);
            return next.is_some_and(|next| NAME_PARTS.contains(&next))
                || qualified_by_person(tokens.get(..index).unwrap_or_default());
        }
        // Joined: `username`, `firstname`, `nickname`; never `rename` or
        // `hostname`.
        token
            .strip_suffix("names")
            .or_else(|| token.strip_suffix("name"))
            .filter(|prefix| !prefix.is_empty())
            .is_some_and(|prefix| NAME_PARTS.contains(&prefix) || PERSON_NOUNS.contains(&prefix))
    });
    found.then_some(Strength::Strong)
}

/// Whether the words before a `name` qualify it as a person's: looking
/// back, a name part or person noun before any non-person noun.
fn qualified_by_person(before: &[String]) -> bool {
    for word in before.iter().rev().map(String::as_str) {
        if NAME_PARTS.contains(&word) || PERSON_NOUNS.contains(&word) {
            return true;
        }
        if NOT_PEOPLE.contains(&word) {
            return false;
        }
    }
    false
}

/// A weak date-of-birth hint: `birth` neither qualified by [`NOT_DATES`]
/// (just after it, `birth_place`, or as `<word> of birth`,
/// `country_of_birth`) nor about several births ([`SEVERAL_BIRTHS`] just
/// before it, `multipleBirth`). The strong forms are in [`HINTS`].
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
            let before = at(index.checked_sub(1));
            let qualified = at(Some(index + 1)).is_some_and(|next| NOT_DATES.contains(&next))
                || before.is_some_and(|word| SEVERAL_BIRTHS.contains(&word))
                || (before == Some("of")
                    && at(index.checked_sub(2)).is_some_and(|word| NOT_DATES.contains(&word)));
            token == "birth" && !qualified
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

/// Words that name a phone or a contact: a bare digit run in a column
/// named with one counts as a phone (see `classify`).
const PHONE_WORDS: &[&str] = &[
    "phone",
    "phones",
    "phonenumber",
    "phoneno",
    "telephone",
    "mobile",
    "mobileno",
    "cell",
    "cellphone",
    "tel",
    "contact",
    "contacts",
    "msisdn",
];

/// Whether the column name `leaf` has a phone or contact word in it
/// ([`PHONE_WORDS`]): `mobile_no`, `contact`, `PHONE`, `tel_no`.
pub(super) fn phone_named(leaf: &str) -> bool {
    tokens(leaf)
        .iter()
        .any(|token| PHONE_WORDS.contains(&token.as_str()))
}

/// Whether the column name `leaf` is about a person or a personal device:
/// it has a word from [`PERSON_NOUNS`] or [`PERSONAL_DEVICES`] in it.
pub(super) fn about_person(leaf: &str) -> bool {
    tokens(leaf).iter().any(|token| {
        PERSON_NOUNS.contains(&token.as_str()) || PERSONAL_DEVICES.contains(&token.as_str())
    })
}

/// The hint the column name `leaf` suggests, if any: the first match in
/// [`HINTS`], else a date of birth, else a person's name.
pub(super) fn hint(leaf: &str) -> Option<Hint> {
    let tokens = tokens(leaf);
    let hinted = |pii, strength| Hint { pii, strength };
    HINTS
        .iter()
        .find_map(|&(pii, strength, phrase)| {
            let words: Vec<&str> = phrase.split(' ').collect();
            let found = tokens
                .windows(words.len())
                .any(|window| window.iter().zip(&words).all(|(t, w)| t == w));
            found.then(|| hinted(pii, strength))
        })
        .or_else(|| birth(&tokens).map(|strength| hinted(PiiType::DateOfBirth, strength)))
        .or_else(|| person_name(&tokens).map(|strength| hinted(PiiType::PersonName, strength)))
}

#[cfg(test)]
mod tests {
    use super::{Strength, about_person, hint, phone_named, tokens};
    use crate::model::PiiType;

    /// The type and strength `column` hints.
    fn hinted(column: &str) -> Option<(PiiType, Strength)> {
        hint(column).map(|hint| (hint.pii, hint.strength))
    }

    fn strong(pii: PiiType) -> (PiiType, Strength) {
        (pii, Strength::Strong)
    }

    fn weak(pii: PiiType) -> (PiiType, Strength) {
        (pii, Strength::Weak)
    }

    /// What a column name hints: `(type, strength)`, or nothing.
    type Hinted = Option<(PiiType, Strength)>;

    const NAME: Hinted = Some((PiiType::PersonName, Strength::Strong));
    const DOB: Hinted = Some((PiiType::DateOfBirth, Strength::Strong));
    const BIRTH: Hinted = Some((PiiType::DateOfBirth, Strength::Weak));
    const EMAIL: Hinted = Some((PiiType::Email, Strength::Strong));
    const MAIL: Hinted = Some((PiiType::Email, Strength::Weak));
    const PHONE: Hinted = Some((PiiType::Phone, Strength::Strong));
    const TEL: Hinted = Some((PiiType::Phone, Strength::Weak));

    /// Realistic column names, both sides of the person-name and
    /// date-of-birth lines.
    const PEOPLE_AND_THINGS: &[(&str, Hinted)] = &[
        // People's names.
        ("first_name", NAME),
        ("FirstName", NAME),
        ("lastName", NAME),
        ("full_name", NAME),
        ("given_name", NAME),
        ("family_name", NAME),
        ("middle_name", NAME),
        ("surname", NAME),
        ("customer_name", NAME),
        ("customerName", NAME),
        ("user_name", NAME),
        ("username", NAME),
        ("patient_name", NAME),
        ("employee_name", NAME),
        ("member_name", NAME),
        ("person_name", NAME),
        ("contact_name", NAME),
        ("account_holder_name", NAME),
        ("cardholder_name", NAME),
        ("company_contact_name", NAME),
        ("provider_name", NAME),
        ("practitioner_name", NAME),
        ("customer_display_name", NAME),
        // A name nothing qualifies as a person's: no hint.
        ("name", None),
        ("Name", None),
        ("display_name", None),
        ("legal_name", None),
        ("name_en", None),
        ("customer_company_name", None),
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
        ("organisation_name", None),
        ("organization_name", None),
        ("payer_name", None),
        ("vendor_name", None),
        ("merchant_name", None),
        ("city_name", None),
        ("state_name", None),
        ("country_name", None),
        ("rename_count", None),
        ("codename", None),
        // Parts of names alone, as whole column names; and not.
        ("first_seen", None),
        ("last_login", None),
        ("last_updated", None),
        ("full", None),
        // Dates of birth, and things born.
        ("dob", DOB),
        ("date_of_birth", DOB),
        ("dateOfBirth", DOB),
        ("birth_date", DOB),
        ("birthdate", DOB),
        ("birthday", DOB),
        ("birth_year", BIRTH),
        ("year_of_birth", BIRTH),
        ("birth_place", None),
        ("place_of_birth", None),
        ("country_of_birth", None),
        ("birth_country", None),
        ("birth_weight", None),
        ("birth_order", None),
        ("birth_certificate_no", None),
        ("birth_count", None),
        ("birth_number", None),
        ("live_birth", None),
        ("total_births", None),
    ];

    /// The column names the real-data experiment's datasets used
    /// (`docs/experiments/real-data.md`): true positives, and the false
    /// positives before M12.
    const EXPERIMENT_DATASETS: &[(&str, Hinted)] = &[
        // Synthea (patients, providers, organizations, payers).
        ("FIRST", NAME),
        ("LAST", NAME),
        ("MIDDLE", NAME),
        ("MAIDEN", NAME),
        ("BIRTHDATE", DOB),
        ("BIRTHPLACE", None),
        ("DEATHDATE", None),
        ("PREFIX", None),
        ("SUFFIX", None),
        ("NAME", None),
        ("PHONE", PHONE),
        // Synthea FHIR, leaf names under list wrappers.
        ("family", NAME),
        ("given", NAME),
        ("birthDate", DOB),
        ("multipleBirthInteger", None),
        ("multipleBirthBoolean", None),
        ("name", None),
        ("valueString", None),
        ("value", None),
        // World Bank WDI, BTS on-time, NYC taxi.
        ("Short Name", None),
        ("Long Name", None),
        ("Table Name", None),
        ("Country Name", None),
        ("Indicator Name", None),
        ("OriginCityName", None),
        ("DestCityName", None),
        ("OriginStateName", None),
        ("DestStateName", None),
        ("Tail_Number", None),
        ("Div1TailNum", None),
        ("Reporting_Airline", None),
        ("store_and_fwd_flag", None),
        // Payments.
        ("card_number", Some((PiiType::CardNumber, Strength::Strong))),
    ];

    /// The experiment's probe of 83 common real-world variants (not taken
    /// from any dataset).
    const EXPERIMENT_PROBE: &[(&str, Hinted)] = &[
        // Person-name variants.
        ("fname", NAME),
        ("lname", NAME),
        ("first_nm", NAME),
        ("last_nm", NAME),
        ("cust_nm", NAME),
        ("nameFirst", NAME),
        ("nameLast", NAME),
        ("givenName", NAME),
        ("familyName", NAME),
        ("FIRST", NAME),
        ("LAST", NAME),
        ("MAIDEN", NAME),
        ("maiden_name", NAME),
        ("forename", NAME),
        ("display_name", None),
        ("nickname", NAME),
        ("full_nm", NAME),
        ("applicant_name", NAME),
        ("owner_name", NAME),
        ("driver_name", NAME),
        ("beneficiary_name", NAME),
        ("insured_name", NAME),
        ("guardian_name", NAME),
        ("father_name", NAME),
        ("mother_name", NAME),
        ("spouse_name", NAME),
        ("nominee_name", NAME),
        ("emp_name", NAME),
        ("student_name", NAME),
        ("author_name", NAME),
        ("artist_name", NAME),
        ("player_name", NAME),
        ("team_name", None),
        ("species_name", None),
        ("drug_name", None),
        ("street_name", None),
        ("file_name", None),
        ("indicator_name", None),
        ("short_name", None),
        ("long_name", None),
        ("common_name", None),
        ("scientific_name", None),
        ("station_name", None),
        ("airport_name", None),
        ("series_name", None),
        ("sheet_name", None),
        ("account_name", None),
        ("screen_name", None),
        ("user_name", NAME),
        ("login_name", None),
        ("sender_name", NAME),
        ("recipient_name", NAME),
        // Date-of-birth variants.
        ("DOB", DOB),
        ("dob_date", DOB),
        ("birth_dt", DOB),
        ("bdate", DOB),
        ("bday", DOB),
        ("date_birth", DOB),
        ("birth_year", BIRTH),
        ("yob", None),
        ("age", None),
        ("multiple_birth", None),
        ("birth_rate", None),
        ("births", None),
        ("birth_month", BIRTH),
        ("birth_day", BIRTH),
        ("BirthDate", DOB),
        ("birthDate", DOB),
        ("date_of_birth_str", DOB),
        ("deathdate", None),
        ("date_of_death", None),
        // Contact variants.
        ("e_mail", EMAIL),
        ("emailAddr", EMAIL),
        ("mail_id", MAIL),
        ("email_address", EMAIL),
        ("mobile_number", PHONE),
        ("contact_no", None),
        ("ph_no", None),
        ("phone_1", PHONE),
        ("Phone 1", PHONE),
        ("tel_no", TEL),
        ("telecom_value", None),
        ("contact", None),
    ];

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
        assert_eq!(hinted("email"), Some(strong(PiiType::Email)));
        assert_eq!(hinted("contactEmail"), Some(strong(PiiType::Email)));
        assert_eq!(hinted("email_sha256"), Some(strong(PiiType::Email)));
        assert_eq!(hinted("mobile_no"), Some(strong(PiiType::Phone)));
        assert_eq!(hinted("aadhaar_no"), Some(strong(PiiType::InAadhaar)));
        assert_eq!(hinted("card_number"), Some(strong(PiiType::CardNumber)));
        assert_eq!(hinted("card"), Some(weak(PiiType::CardNumber)));
        assert_eq!(hinted("pan"), Some(strong(PiiType::InPan)));
        assert_eq!(hinted("src_ip"), Some(strong(PiiType::IpAddress)));
        assert_eq!(hinted("dob"), Some(strong(PiiType::DateOfBirth)));
        assert_eq!(hinted("DateOfBirth"), Some(strong(PiiType::DateOfBirth)));
        assert_eq!(hinted("full_name"), Some(strong(PiiType::PersonName)));
        assert_eq!(hinted("lastName"), Some(strong(PiiType::PersonName)));
        assert_eq!(hinted("name"), None);
    }

    #[test]
    fn a_card_column_called_pan_hints_card_when_the_name_says_so() {
        assert_eq!(hinted("card_pan"), Some(weak(PiiType::CardNumber)));
        assert_eq!(hinted("credit_card_pan"), Some(strong(PiiType::CardNumber)));
    }

    #[test]
    fn a_name_about_a_person_or_their_device_says_so() {
        for column in [
            "customer_phone",
            "contact",
            "contact_no",
            "mobile_no",
            "cell",
            "home_phone",
            "patientPhone",
            "member_email",
            "telecom_value_of_patient",
        ] {
            assert!(about_person(column), "{column}");
        }
        for column in [
            "PHONE",
            "phone",
            "office_phone",
            "fax_phone",
            "value",
            "NAME",
        ] {
            assert!(!about_person(column), "{column}");
        }
    }

    #[test]
    fn a_name_with_a_phone_or_contact_word_says_so() {
        for column in [
            "PHONE",
            "mobile_no",
            "contact",
            "contact_no",
            "tel_no",
            "cellPhone",
            "msisdn",
            "home_telephone",
            "Phone 1",
        ] {
            assert!(phone_named(column), "{column}");
        }
        // The experiment's NPI column and other identifiers.
        for column in [
            "value",
            "identifier",
            "npi",
            "customer_id",
            "account_no",
            "telecom",
        ] {
            assert!(!phone_named(column), "{column}");
        }
    }

    /// Realistic column names, both sides of the person-name and
    /// date-of-birth lines.
    #[test]
    fn people_s_names_and_birth_dates_are_told_from_everything_else() {
        let cases = PEOPLE_AND_THINGS;
        for (column, expected) in cases {
            assert_eq!(hinted(column), *expected, "{column}");
        }
    }

    /// Every person-name and date-of-birth question the real-data
    /// experiment (`docs/experiments/real-data.md`) raised, with what a
    /// reviewer would want: the column names its datasets used (true
    /// positives, and false positives before M12), then its probe of 83
    /// common real-world variants. Each row is `(column, expected)`.
    #[test]
    fn the_real_data_experiment_s_column_names_hint_what_they_hold() {
        let datasets = EXPERIMENT_DATASETS;
        let probe = EXPERIMENT_PROBE;
        assert_eq!(probe.len(), 83);
        for (column, expected) in datasets.iter().chain(probe) {
            assert_eq!(hinted(column), *expected, "{column}");
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
            assert_eq!(hinted(name), None, "{name}");
        }
    }
}
