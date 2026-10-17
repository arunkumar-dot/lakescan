"""Convert the CSV and NDJSON downloads to Parquet with DuckDB (default
writer settings), into the staging lake. Prints only row counts.

usage: python -I convert.py UNZ_DIR LAKE_DIR
"""

import pathlib
import sys

import duckdb

CSV = {
    "bts/ontime/2024-01.parquet": "bts/On_Time_Reporting_Carrier_On_Time_Performance_(1987_present)_2024_1.csv",
    "wdi/indicators/WDICSV.parquet": "wdi/WDICSV.csv",
    "wdi/country/WDICountry.parquet": "wdi/WDICountry.csv",
    "wdi/series/WDISeries.parquet": "wdi/WDISeries.csv",
}

NDJSON = {
    "fhir/patient/patient.parquet": "fhir_ndjson/patient.ndjson",
    "fhir/practitioner/practitioner.parquet": "fhir_ndjson/practitioner.ndjson",
    "fhir/organization/organization.parquet": "fhir_ndjson/organization.ndjson",
}

# The first element of each repeated field as a plain struct, as some
# pipelines flatten FHIR: same data, no repetition at the top level.
FHIR_FIRST = """
SELECT id, gender, birthDate, deceasedDateTime,
       name[1] AS name, telecom[1] AS telecom, address[1] AS address,
       identifier[2] AS identifier_mr, identifier[3] AS identifier_ss,
       identifier[4] AS identifier_dl, identifier[5] AS identifier_pp,
       maritalStatus
FROM read_json('{src}', sample_size=-1)
"""


def copy(con, query, dest):
    dest.parent.mkdir(parents=True, exist_ok=True)
    con.execute(f"COPY ({query}) TO '{dest}' (FORMAT parquet)")
    rows = con.execute(f"SELECT count(*) FROM read_parquet('{dest}')").fetchone()[0]
    print(f"{dest}: {rows} rows")


def main(unz, lake):
    unz, lake = pathlib.Path(unz), pathlib.Path(lake)
    con = duckdb.connect()
    for dest, src in CSV.items():
        copy(con, f"SELECT * FROM read_csv('{unz / src}')", lake / dest)
    for dest, src in NDJSON.items():
        copy(con, f"SELECT * FROM read_json('{unz / src}', sample_size=-1)", lake / dest)
    copy(con, FHIR_FIRST.format(src=unz / NDJSON["fhir/patient/patient.parquet"]),
         lake / "fhir/patient_first/patient_first.parquet")


if __name__ == "__main__":
    main(*sys.argv[1:])
