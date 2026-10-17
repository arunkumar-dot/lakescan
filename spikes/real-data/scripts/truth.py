"""Ground truth: what a human reviewer would call personal data, from
column names and published descriptions only.

Tier A columns are scored: direct identifiers and contact details of a
person. `in_scope` is True when LakeScan claims the type (email, phone,
Aadhaar, PAN, card number, IP, person name, date of birth). Tier B
(quasi-identifiers, pseudonymous keys, health details) is listed for the
record but not scored: LakeScan does not claim to find them.

Columns are spelled as LakeScan reports them (the Parquet column path).
"""

# (table, column, kind, in_scope)
TIER_A = [
    ("synthea575k/patients", "BIRTHDATE", "date-of-birth", True),
    ("synthea575k/patients", "FIRST", "person-name", True),
    ("synthea575k/patients", "MIDDLE", "person-name", True),
    ("synthea575k/patients", "LAST", "person-name", True),
    ("synthea575k/patients", "MAIDEN", "person-name", True),
    ("synthea575k/patients", "SSN", "us-ssn", False),
    ("synthea575k/patients", "DRIVERS", "driver-licence", False),
    ("synthea575k/patients", "PASSPORT", "passport", False),
    ("synthea575k/patients", "ADDRESS", "street-address", False),
    ("synthea575k/patients", "LAT", "home-geolocation", False),
    ("synthea575k/patients", "LON", "home-geolocation", False),
    ("synthea575k/providers", "NAME", "person-name", True),
    ("payments/transactions", "card_number", "card-number", True),
    ("nemotron/documents", "text", "free-text (names, emails, phones, SSNs, ...)", True),
    ("nemotron/documents", "text_tagged", "free-text (names, emails, phones, SSNs, ...)", True),
    ("fhir/patient", "birthDate", "date-of-birth", True),
    ("fhir/patient", "name.list.element.family", "person-name", True),
    ("fhir/patient", "name.list.element.given.list.element", "person-name", True),
    ("fhir/patient", "telecom.list.element.value", "phone", True),
    ("fhir/patient", "extension.list.element.valueString", "person-name (mother's maiden name)", True),
    ("fhir/patient", "identifier.list.element.value", "us-ssn / driver-licence / passport / MRN", False),
    ("fhir/patient", "address.list.element.line.list.element", "street-address", False),
    ("fhir/patient_first", "birthDate", "date-of-birth", True),
    ("fhir/patient_first", "name.family", "person-name", True),
    ("fhir/patient_first", "name.given.list.element", "person-name", True),
    ("fhir/patient_first", "telecom.value", "phone", True),
    ("fhir/patient_first", "identifier_mr.value", "medical-record-number", False),
    ("fhir/patient_first", "identifier_ss.value", "us-ssn", False),
    ("fhir/patient_first", "identifier_dl.value", "driver-licence", False),
    ("fhir/patient_first", "identifier_pp.value", "passport", False),
    ("fhir/patient_first", "address.line.list.element", "street-address", False),
    ("fhir/practitioner", "name.list.element.family", "person-name", True),
    ("fhir/practitioner", "name.list.element.given.list.element", "person-name", True),
    ("fhir/practitioner", "telecom.list.element.value", "email", True),
]

TIER_B = {
    "synthea575k/patients": ["Id", "DEATHDATE", "PREFIX", "SUFFIX", "MARITAL", "RACE",
                             "ETHNICITY", "GENDER", "BIRTHPLACE", "CITY", "COUNTY", "FIPS",
                             "ZIP", "INCOME", "HEALTHCARE_EXPENSES", "HEALTHCARE_COVERAGE"],
    "synthea575k/providers": ["Id", "GENDER"],
    "synthea575k/allergies": ["PATIENT", "ENCOUNTER", "DESCRIPTION (health)"],
    "synthea575k/careplans": ["PATIENT", "ENCOUNTER", "REASONDESCRIPTION (health)"],
    "fhir/patient": ["id", "gender", "deceasedDateTime", "maritalStatus.text",
                     "address city/state/postalCode", "birthplace extension"],
    "fhir/patient_first": ["id", "gender", "deceasedDateTime", "address.city/state/postalCode"],
    "fhir/practitioner": ["identifier value (NPI)", "gender"],
}
