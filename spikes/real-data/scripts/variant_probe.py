"""Probe Parquet of common real-world column-name variants (not taken from
any dataset), each a string column of 10 neutral values.

usage: python -I variant_probe.py OUT.parquet
"""
import sys

import pyarrow as pa
import pyarrow.parquet as pq

NAMES = [
    # person-name variants
    "fname", "lname", "first_nm", "last_nm", "cust_nm", "nameFirst", "nameLast",
    "givenName", "familyName", "FIRST", "LAST", "MAIDEN", "maiden_name", "forename",
    "display_name", "nickname", "full_nm", "applicant_name", "owner_name", "driver_name",
    "beneficiary_name", "insured_name", "guardian_name", "father_name", "mother_name",
    "spouse_name", "nominee_name", "emp_name", "student_name", "author_name", "artist_name",
    "player_name", "team_name", "species_name", "drug_name", "street_name", "file_name",
    "indicator_name", "short_name", "long_name", "common_name", "scientific_name",
    "station_name", "airport_name", "series_name", "sheet_name", "account_name",
    "screen_name", "user_name", "login_name", "sender_name", "recipient_name",
    # date-of-birth variants
    "DOB", "dob_date", "birth_dt", "bdate", "bday", "date_birth", "birth_year",
    "yob", "age", "multiple_birth", "birth_rate", "births", "birth_month", "birth_day",
    "BirthDate", "birthDate", "date_of_birth_str", "deathdate", "date_of_death",
    # contact variants
    "e_mail", "emailAddr", "mail_id", "email_address", "mobile_number", "contact_no",
    "ph_no", "phone_1", "Phone 1", "tel_no", "telecom_value", "contact",
]

values = pa.array([f"v{i}" for i in range(10)])
pq.write_table(pa.table({n: values for n in NAMES}), sys.argv[1])
print(len(NAMES))
