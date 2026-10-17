# Experiment: detection quality on real-world public datasets

Date: 2026-10-17. Binary: `lakescan 0.1.0` release build at `89cc30a`.
Question: how well does `--pii` find personal data in Parquet that we did
not generate, with column names, writers and values we did not choose?

No product code was changed. No dataset, sample, or personal-data value
appears here: columns are named, values are described only by shape
(`9` digit, `A` upper, `a` lower) or by validator pass rates.

## Method

- Downloads in `spikes/real-data/data/` (git-ignored); scripts in
  `spikes/real-data/scripts/`.
- Two published-Parquet datasets were used as published. CSV and NDJSON
  sources were converted with DuckDB 1.5.6 at default writer settings.
- Every file was uploaded to a local moto 5.2.3 bucket (`seed.py`, which
  checks keys and sizes back), one directory per table, and scanned with
  `--pii` per dataset prefix and for the whole bucket, at default settings
  and with `--pii-whole-file-max 0` (`scan.sh`).
- Ground truth (`truth.py`) was set from column names and published
  descriptions only. **Tier A** (scored): direct identifiers and contact
  details of a person. **In scope**: Tier A types LakeScan claims (email,
  phone, Aadhaar, PAN, card number, IP, person name, date of birth).
  **Tier B** (quasi-identifiers, pseudonymous keys, health details) is
  listed but not scored.
- To explain misses, `profile.py` read every value of every leaf column
  and recorded only counts: validator pass rates (LakeScan's validators,
  ported), shapes, and placeholder classes.
- Two name probes run the real binary over column names alone: every
  distinct leaf name in these datasets (368), and 83 common real-world
  variants not taken from any dataset.

## Datasets

| Dataset | Source | Licence | Size used | Writer | Rows | PII |
|---|---|---|---|---|---|---|
| Synthea 575k patients: `patients`, `providers`, `organizations`, `payers`, `allergies`, `careplans` | https://huggingface.co/datasets/richardyoung/synthea-575k-patients | MIT | 394 MB | Polars | 575,415 patients; 5.1M care plans | Synthetic patients |
| Synthetic payment transactions | https://huggingface.co/datasets/stephenhib/synthetic-payment-transactions | MIT | 2.9 MB (3 files) | pyarrow 20.0.0 | 23,975 | Synthetic card numbers |
| Nemotron-PII, test split | https://huggingface.co/datasets/nvidia/Nemotron-PII | CC BY 4.0 | 151 MB | pyarrow 19.0.1 | 100,000 | PII inside free text |
| Synthea FHIR sample: Patient, Practitioner, Organization (+ a flattened Patient) | https://synthetichealth.github.io/synthea-sample-data/ | No licence file; generator Apache-2.0 | 30 MB zip → 0.1 MB Parquet | DuckDB (nested, repeated) | 109 patients, 278 practitioners | Synthetic, nested |
| BTS Airline On-Time Performance, Jan 2024 (110 columns) | https://www.transtats.bts.gov/ (PREZIP) | US government, public domain | 28 MB zip | DuckDB | 547,271 | None |
| World Bank WDI: indicators (70 columns), country, series | https://databank.worldbank.org/data/download/WDI_CSV.zip | CC BY 4.0 | 283 MB zip | DuckDB | 398,469 | None |
| NYC TLC Yellow Taxi, Jan 2024 | https://d37ci6vzurychx.cloudfront.net/trip-data/yellow_tripdata_2024-01.parquet | NYC Open Data terms | 50 MB | pyarrow 14.0.2 | 2,964,624 | None |

Total on disk ~2.4 GB including archives; 687 MB of Parquet in the bucket.

**Skipped:** Kaggle (no credentials). Datasets of real people: the Lahman
baseball `People` table (real names, birth dates) and NYC Department of
Buildings job filings (real applicants' and owners' names and phones).
ACS PUMS and BRFSS microdata, which hold no identities but describe real
people, were also skipped.

## Runs

16 scans (8 prefixes × 2 settings): no error, skip, hang or crash; every
exit code was 0. The full bucket took ~0.35 s and read 30 MB (4.5%) in 93
GETs (122 with `--pii-whole-file-max 0`). **Findings were identical at both
settings.** 300 columns were examined, 98 skipped as repeated, 128 as
unsupported type (doubles, booleans).

## Results per dataset

**Synthea 575k (Polars)**
- TP: `patients.BIRTHDATE` date-of-birth LIKELY (column name; stored as
  string); `providers.NAME` person-name POSSIBLE (column name).
- FN: `FIRST`, `MIDDLE`, `LAST`, `MAIDEN`: column name (bare part-name
  words, no `name` token). `SSN` (all `9{3}-9{2}-9{4}`), `DRIVERS`,
  `PASSPORT`, `ADDRESS`: unsupported type. `LAT`, `LON`: unsupported
  type (double, never examined).
- FP: `organizations.NAME`, `payers.NAME` person-name POSSIBLE (bare
  `name`); `organizations.PHONE` phone LIKELY, values 1128/2000 (an
  organisation's phone, see below); `payers.PHONE` phone POSSIBLE on name
  alone, though the column is **100% null**.

**Payment transactions (pyarrow)**
- TP: `card_number` card-number LIKELY in all 3 files, values 106-117/1000.
  Full-column profile: 10.6% pass Luhn (chance level), shapes `9{16}` 66%,
  `9{15}` 34%. The generator does not produce Luhn-valid numbers, so value
  evidence alone would not report it; the name hint plus one match does.
- FN, FP: none.

**Nemotron-PII (pyarrow, 151 MB, read partially)**
- FN: `text`, `text_tagged`: free text, which the product does not scan.
  0 whole values validate as any type. `spans` is a JSON string, not a
  nested column.
- FP: none.

**Synthea FHIR (DuckDB, nested)**
- TP: `patient.birthDate`, `patient_first.birthDate` date-of-birth LIKELY
  (DATE type, by name).
- FN, skipped structure (repeated, never read): patient
  `name.list.element.family`, `name.list.element.given.list.element`,
  `telecom.list.element.value`, `extension.list.element.valueString`
  (mother's maiden name), `identifier.list.element.value` (SSN, licence,
  passport, MRN), `address.list.element.line.list.element`; practitioner
  `name...family`, `name...given...`, `telecom.list.element.value`
  (**emails: 271/278 validate**, but they are never read).
- FN, flattened `patient_first` (plain structs): `name.family`: column
  name (`family` alone is not a hint); `telecom.value`: phone format
  (`9{3}-9{3}-9{4}`, 0% validate) and generic name `value`;
  `identifier_*.value`: unsupported type; `name.given`, `address.line`:
  still repeated.
- FP: `organization.name` person-name POSSIBLE; `patient.multipleBirthInteger`
  date-of-birth POSSIBLE.

**BTS on-time (110 columns), NYC TLC**: no findings, as expected.
`OriginCityName`, `DestStateName`, `Tail_Number` and `Div1TailNum` hint
nothing.

**WDI**: FP `country."Short Name"`, `country."Long Name"`,
`series."Indicator Name"` person-name POSSIBLE. `Table Name` and
`Country Name` correctly hint nothing; the 66 year columns (`1960`..`2025`)
are doubles and hint nothing.

## Precision and recall

Per (table, column); 34 Tier A columns, 21 in scope.

| | Result |
|---|---|
| Precision, all confidences | 5/14 = **36%** |
| Precision, LIKELY or better | 4/5 = **80%** (the 1 FP is an organisation phone) |
| Recall, all Tier A | 5/34 = **15%** |
| Recall, in-scope types | 5/21 = **24%** |
| CONFIRMED findings | **0** |

Why the 16 in-scope misses were missed: skipped as repeated 8, column name
not recognised 5 (`FIRST`, `MIDDLE`, `LAST`, `MAIDEN`, `family`), free
text 2, phone format 1. Of the 13 out-of-scope misses: SSN 2, licence 2,
passport 2, MRN or mixed identifier 2, address 3, geolocation 2 (3 of them
also repeated).

Every finding is LIKELY or POSSIBLE, so severity is at most medium and
`--fail-on high` (the default) passes a lake of patient records.

## Name and date-of-birth hint false positives

From the datasets (all POSSIBLE, column-name evidence):

| Column | Table | Rule | Why |
|---|---|---|---|
| `Short Name` | wdi/country | person-name | `short` is not in `NOT_PEOPLE`, so a weak `name` |
| `Long Name` | wdi/country | person-name | same |
| `Indicator Name` | wdi/series | person-name | same |
| `NAME` | synthea575k/organizations | person-name | bare `name` is a weak hint |
| `NAME` | synthea575k/payers | person-name | same |
| `name` | fhir/organization | person-name | same |
| `multipleBirthInteger` | fhir/patient | date-of-birth | weak `birth`; `NOT_DATES` has no count or flag word |
| `multipleBirthBoolean` | fhir/patient | date-of-birth | probe only: boolean, so never examined in the real file |

From the variant probe (not from any dataset), `name` qualified by these
also fires person-name POSSIBLE on things that are not people:
`drug_name`, `species_name`, `scientific_name`, `common_name`,
`station_name`, `airport_name`, `series_name`, `sheet_name`,
`indicator_name`, `short_name`, `long_name`. `multiple_birth`,
`birth_month` and `birth_day` fire date-of-birth POSSIBLE. (`birth_month`
and `birth_day` are arguably personal; `birth_rate` and `births` correctly
hint nothing.)

The bare-`name` FPs are the hard case: in `providers` the same `NAME`
column holds people. Name alone cannot separate them; values could
(proportion of two-token title-case values) or the table name could.

## Column-name styles the hints do not recognise

- Bare part-name words, upper case: `FIRST`, `LAST`, `MIDDLE`, `MAIDEN`
  (Synthea; also `fname`, `lname`, `forename`, `first_nm`, `last_nm`,
  `full_nm`, `cust_nm` in the probe).
- FHIR HumanName parts: `family`, `given` (`familyName` and `givenName`
  work, because they contain `name`).
- Generic entity-attribute-value leaves: `telecom.value`,
  `identifier.value`, `extension.valueString`, where a sibling (`system`,
  `type.text`, `url`) says what the value is. The leaf-only rule cannot
  see it.
- Name-first ordering: `nameFirst`, `nameLast` hint only weakly.
- Contact shorthands: `contact_no`, `ph_no`, `contact` hint nothing.
- Date of birth: `bdate`, `bday`, `yob` hint nothing; `birth_dt` only
  weakly.

## Placeholders the cleaning list does not know

Patterns only, from the full-value profile:

- `555` exchange phone numbers (`9{3}-555-9{4}` style): 218 values, in FHIR
  `telecom.value`.
- Reserved example-domain emails (`…@example.com`): all 278 practitioner
  emails. They validate as emails; a real lake's test accounts look like
  this.
- Masked runs (`****`, `XXXX` within a value): 11,288 values, all in
  Nemotron free text.
- Epoch and 1900-01-01 style sentinel dates: 211 values, in Synthea
  `BIRTHDATE`, `START`, `STOP`.
- An entirely null column (`payers.PHONE`) is still reported, on its name.

No `nan`, `#N/A`, `(null)` or `not available` spellings appeared. DuckDB
turned empty CSV fields into nulls, which removes most CSV junk before
LakeScan sees it.

## Confusing output

- **Coverage says 100% when PII columns were never read.** `fhir/practitioner`
  reports `no_pii_in_scanned_files` ("No structured PII detected in sampled
  data from 1 file") while every name and email leaf was skipped as
  repeated. The skip appears only as a bucket-wide `repeated: 98`; nothing
  per table or per file says so.
- The text summary's `medium: 1 (-)` lines: the `(-)` is unexplained.
- `organizations.PHONE` LIKELY: correct type, but only because 10-digit US
  numbers starting 6-9 pass the Indian-mobile pattern (56% of values). The
  evidence reads as a phone verdict, but it is an accident.

## What to fix, in priority order

1. **Report or read repeated columns.** Evidence: 98 columns skipped, 8 of
   the 16 in-scope misses, including 271/278 valid practitioner emails, while
   coverage reads 100%. First, at minimum: count skipped columns per table
   in the inventory, and do not say "no PII detected" for a table whose
   string leaves were all skipped. Then: sample repeated leaves (list of
   string, list of struct), which is how FHIR, event and JSON-derived data
   store contact details.
2. **Phone formats beyond E.164 and Indian mobiles.** Evidence: FHIR
   `ddd-ddd-dddd` 0% match; Synthea organisation phones matched only by
   accident. Accept national formats (NANP, UK, EU) with a plausibility
   check, and keep `555` exchanges as a placeholder class.
3. **Person-name hints.** Evidence: `FIRST`, `LAST`, `MIDDLE`, `MAIDEN`,
   `family` missed (5 in-scope FNs); 6 dataset FPs plus 11 probe FPs from
   `name` qualified by a non-person word. Add bare part-name words and
   their short forms as strong; extend `NOT_PEOPLE` (`short`, `long`,
   `indicator`, `drug`, `species`, `scientific`, `common`, `station`,
   `airport`, `series`, `sheet`); consider whether the table name
   (`organizations`, `payers`) can downgrade a bare `name`.
4. **Date-of-birth hint.** Evidence: `multipleBirthInteger` and
   `multipleBirthBoolean`. Add count and flag words after or before
   `birth` (`multiple`, `count`, `boolean`, `flag`, `integer`, `births`).
5. **Severity of confirmed-by-name types.** Evidence: no finding above
   medium on a 575k-patient table with names, birth dates and SSNs. Decide
   whether a strong date-of-birth or person-name hint on a fitting column
   should be high, or whether the docs should steer CI users to
   `--fail-on medium`.
6. **Do not report all-null columns on name alone.** Evidence:
   `payers.PHONE` POSSIBLE with 0 non-null values.
7. **Placeholder classes:** example-domain emails, `555` phones, epoch
   dates and masked runs (evidence above). The domain and `555` cases
   matter most: they would make test fixtures look like real PII.
8. **Out-of-scope types worth adding next:** US SSN (2 FNs plus the mixed FHIR
   identifier, uniform `9{3}-9{2}-9{4}`), passport and driver's licence (by name), street
   address. These are roadmap items, not bugs.

## Not tested

Spark- and Hive-written files, real-S3 latency, very large row counts per
page, LZO, and free-text email detection (in the spike only, not the
product).

## Post-M12 re-measurement

Same harness, same 19 objects in the same moto bucket, same ground truth
(`truth.py`), re-run twice with M12 release binaries: first as M12 was
proposed (`results/run2/`), then with the bare-digit phone rule
(`results/run3/`, the final M12). Findings were identical at default
settings and with `--pii-whole-file-max 0` every time; no error, skip or
hang.

| | Before (v0.1.0) | M12 as proposed | M12 final |
|---|---|---|---|
| Columns reported | 14 | 19 | 17 |
| True positives | 5 | 16 | 16 |
| False positives | 9 | 3 | 1 |
| Precision, all confidences | 5/14 = 36% | 16/19 = 84% | 16/17 = **94%** |
| Precision, LIKELY or better | 4/5 = 80% | 16/19 = 84% | 16/17 = **94%** |
| Recall, all Tier A | 5/34 = 15% | 16/34 = 47% | 16/34 = **47%** |
| Recall, in-scope types | 5/21 = 24% | 16/21 = 76% | 16/21 = **76%** |
| CONFIRMED findings | 0 | 1 (a false positive) | **0** |
| Exit code, whole bucket | 0 | 1 | 0 |
| Columns examined / skipped as repeated | 300 / 98 | 394 / 0 | 394 / 0 |
| Columns not examined (new state) | not reported | 0 | 0 |

**Against an 85% gate:** precision at LIKELY or better passes (94%);
recall on the claimed types does not (76%). No CONFIRMED finding is a false
positive, because none remains: every true positive is `likely` (names and
dates of birth rest on names; the FHIR patient phones match 91%, under the
95% a phone column needs without a person in its name).

### What changed

- **New true positives (12).** Synthea `FIRST`, `MIDDLE`, `LAST`, `MAIDEN`
  (name parts as whole names). FHIR, read now that repeated columns are:
  patient and practitioner `name.list.element.family` and
  `name.list.element.given.list.element`, patient
  `telecom.list.element.value` (phone, 99/109 by NANP format), and the
  flattened patient's `name.family`, `name.given.list.element` and
  `telecom.value`. All are `likely`.
- **False positives removed (10).** `Short Name`, `Long Name`, `Indicator
  Name`, organisation `NAME` (Synthea and FHIR), payer `NAME`,
  `multipleBirthInteger`, the all-null payer `PHONE`; and, with the
  bare-digit rule, the FHIR practitioner `identifier.list.element.value`
  (US NPI numbers, bare 10-digit runs starting with 9, which the
  Indian-mobile rule accepts: `confirmed` 278/278 as M12 was proposed, now
  not reported) and the FHIR organisation `telecom.list.element.value`
  (bare digit runs under a generic `value`).
- **True positive lost (1).** Synthea `providers.NAME`: a bare `name` no
  longer hints (by design: the same bare `NAME` named organisations and
  payers in two other tables of the same dataset).
- **Practitioner emails** (`telecom.list.element.value`) are read now, but
  every one is at `example.com`, which M12 drops as a test account: no
  value is left, so no finding. Correct for a real lake; a miss on this
  synthetic one.

**The bare-digit rule.** A bare digit run (no `+`, no separators) counts
as a phone only in a column whose name has a phone or contact word
(`phone`, `mobile`, `cell`, `tel`, `contact`, `msisdn`, and their
compounds); otherwise it counts toward nothing. Formatted numbers always
count. The cost: an unnamed column of bare mobile numbers is no longer
reported. The committed Indian fixtures (`contact`, `mobile_no`) are named,
and stay `confirmed`.

### Remaining false positive

| Column | Table | Rule | Confidence | Why |
|---|---|---|---|---|
| `PHONE` | synthea575k/organizations | phone | likely, 1146/2000 | An organisation's switchboard: right type, not personal. Named `PHONE`, so its bare numbers count; 57% match (those starting 6-9, as Indian mobiles, plus the formatted ones), and the cap would hold it at `likely` anyway. |

### Remaining misses

- In scope (5): Synthea `providers.NAME` (bare name, above); Nemotron
  `text` and `text_tagged` (free text, not scanned); FHIR patient
  `extension.list.element.valueString` (mother's maiden name under a
  generic EAV name; its sibling `url` says what it is); practitioner emails
  (test domain, above). Reaching 85% recall on the claimed types needs 18
  of 21: free text (2) is a feature not built yet, and the other three are
  each a deliberate trade (bare `name`, test domains) or an EAV schema.
- Out of scope (13): US SSNs, driver's licences, passports, MRNs, street
  addresses and home coordinates, as before.

Of the 5 missed claimed-type columns, 2 are free text (Nemotron `text` and
`text_tagged`), which the product does not scan; 1 is the practitioner
emails, all at `example.com` and so treated as test accounts; and 1 is
Synthea's bare `providers.NAME`, excluded on purpose because a bare `name`
names things as often as people (`product_name`-style false positives:
organisation and payer `NAME` here). The one remaining real miss is a
maiden name in the generically named `valueString` field. Leaving out free
text and test accounts, recall on the claimed types is 16/18 (89%); the
headline figure over all 21, 16/21 (76%), stands. Free-text scanning and
value-based name detection are the known paths to higher recall, and both
are on the roadmap.

### Placeholder counts M12's cleaning changes

From `scripts/new_cleaning.py` over every value (counts only):

| Rule | Where | Values dropped | Effect on findings |
|---|---|---|---|
| Test-domain email | FHIR practitioner `telecom[].value` | 278 of 278 | the column is no longer reportable |
| Test-domain email | Nemotron `text` | 1 of 100,000 | none (free text) |
| Masked run | Nemotron `text`, `text_tagged` | 17,919 of 100,000 each, mostly dash runs | none (free text) |
| Masked run | Nemotron `document_description`, `spans` | 4 and 12 | none |
| Sentinel date | Synthea `BIRTHDATE`, `careplans.START`/`STOP`, `allergies.START` | 17, 97, 91, 6 | none (dates of birth rest on the name) |

### Next fixes, by evidence

1. **Recall past 85% on claimed types.** Free text (Nemotron, 2 columns)
   is the largest gap; then EAV columns, where FHIR keeps a value's meaning
   in a sibling (`system`, `url`): reading it would find the mother's
   maiden name.
2. **Severity of a lake of patients.** Nothing above `medium`: the
   default `--fail-on high` passes a 575k-patient table with names, dates
   of birth and phones. Decide whether strong name hints for names and
   dates of birth should be `high`, or steer CI users to
   `--fail-on medium`.
3. **Organisation phones.** The one remaining false positive is the right
   type on the wrong owner; the table name (`organizations`) is the only
   signal LakeScan has for it.
