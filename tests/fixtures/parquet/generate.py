"""Generates the committed Parquet fixtures for LakeScan's content-scanning
tests. Based on the round 2 generator in spikes/parquet-pii/gen, cut down to
small files. Seeded, so a rerun with the same pinned versions reproduces the
same values (file bytes may differ across writer versions).

    python generate.py <this directory>

Writes, at each writer's defaults except for row-group size:

- {pyarrow,polars,duckdb}/customers.parquet: 12,000 messy rows in row
  groups of about 4,000; _spark_src/customers.parquet for spark_write.py,
  which writes spark/customers.parquet (one row group);
- escalation.parquet (pyarrow): 4 row groups of 2,000 rows whose
  contact_email is only nulls and junk in row group 0, and emails after;
- bad/truncated.parquet: the first 60% of pyarrow/customers.parquet;
- bad/not_parquet.parquet: a CSV file with a .parquet name.

Ground truth per column is in README.md next to this script.
"""

import hashlib
import sys
from pathlib import Path

import duckdb
import numpy as np
import polars as pl
import pyarrow as pa
import pyarrow.parquet as pq

ROWS = 12_000
ROW_GROUP = 4_000
FIRST = "Aarav Aditi Arjun Bhavna Chetan Deepa Farhan Gaurav Ishaan Jaya Karan Kavya Meera Neha Priya Rahul Sneha Varun Alice Daniel Emma Grace Henry Liam Mia Noah Olivia Sofia Yuki Wei".split()
LAST = "Sharma Verma Gupta Singh Patel Shah Mehta Iyer Nair Reddy Rao Menon Kulkarni Patil Smith Brown Garcia Miller Davis Lee Kim Chen Tanaka Wang".split()
DOMAINS = "gmail.com yahoo.com outlook.com rediffmail.com example.org acme.io fintech.in".split()
CITIES = "Mumbai Delhi Bengaluru Pune Chennai London Singapore Toronto".split()
# Junk the generator writes. Deliberately not the same list as LakeScan's
# cleaning: "NOT PROVIDED" and "999" are not on it.
PLACEHOLDERS = ["N/A", "unknown", "-", "0000000000", "NOT PROVIDED", "999"]
BLANKS = ["", " ", "\t"]


def verhoeff_check(base):
    d = [[0,1,2,3,4,5,6,7,8,9],[1,2,3,4,0,6,7,8,9,5],[2,3,4,0,1,7,8,9,5,6],[3,4,0,1,2,8,9,5,6,7],
         [4,0,1,2,3,9,5,6,7,8],[5,9,8,7,6,0,4,3,2,1],[6,5,9,8,7,1,0,4,3,2],[7,6,5,9,8,2,1,0,4,3],
         [8,7,6,5,9,3,2,1,0,4],[9,8,7,6,5,4,3,2,1,0]]
    p = [[0,1,2,3,4,5,6,7,8,9],[1,5,7,6,2,8,3,0,9,4],[5,8,0,3,7,9,6,1,4,2],[8,9,1,6,0,4,3,5,2,7],
         [9,4,5,3,1,2,6,8,7,0],[4,2,8,6,5,7,3,9,0,1],[2,7,9,3,8,0,6,4,1,5],[7,0,4,6,9,1,3,2,5,8]]
    inv = [0,4,3,2,1,5,6,7,8,9]
    c = 0
    for i, digit in enumerate(reversed(str(base))):
        c = d[c][p[(i + 1) % 8][int(digit)]]
    return inv[c]


def luhn_check(digits):
    total = 0
    for j, dgt in enumerate(reversed(digits)):
        if j % 2 == 0:
            dgt *= 2
            dgt = dgt - 9 if dgt > 9 else dgt
        total += dgt
    return (10 - total % 10) % 10


def mess(values, rng, null_rate, malform=None, recase=None):
    """Nulls, blanks, placeholders, 2% malformed, 5% padded, 10% recased."""
    out = []
    for v in values:
        u = rng.random()
        if u < null_rate:
            out.append(None)
        elif u < null_rate + 0.02:
            out.append(BLANKS[rng.integers(len(BLANKS))])
        elif u < null_rate + 0.04:
            out.append(PLACEHOLDERS[rng.integers(len(PLACEHOLDERS))])
        elif malform and u < null_rate + 0.06:
            out.append(malform(v))
        else:
            if recase and rng.random() < 0.10:
                v = recase(v)
            if rng.random() < 0.05:
                v = "  " + v + " "
            out.append(v)
    return out


def customers(n, rng):
    first = rng.choice(FIRST, n)
    last = rng.choice(LAST, n)
    names = [f"{f} {l}" for f, l in zip(first, last)]
    emails = [f"{f.lower()}.{l.lower()}{i}@{rng.choice(DOMAINS)}" for i, (f, l) in enumerate(zip(first, last))]
    billing = [f"billing.{l.lower()}{i}@{rng.choice(DOMAINS)}" for i, l in enumerate(last)]

    def phone(i):
        m = str(int(rng.integers(6, 10)) * 10**9 + int(rng.integers(0, 10**9)))
        k = i % 4
        return ["+91 " + m[:5] + " " + m[5:], "+91" + m, m, "+1415555" + m[-4:]][k]

    mobiles = [int(rng.integers(6, 10)) * 10**9 + int(rng.integers(0, 10**9)) for _ in range(n)]
    aadhaar = []
    for _ in range(n):
        base = int(rng.integers(2 * 10**10, 10**11))
        aadhaar.append(base * 10 + verhoeff_check(base))
    letters = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    pans = ["".join(rng.choice(list(letters), 3)) + "P" + rng.choice(list(letters)) + f"{int(rng.integers(0, 10000)):04d}" + rng.choice(list(letters)) for _ in range(n)]
    cards = []
    for i in range(n):
        body = [4] + [int(x) for x in rng.integers(0, 10, 14)]
        digits = body + [luhn_check(body)]
        s = "".join(map(str, digits))
        cards.append(" ".join(s[j:j + 4] for j in range(0, 16, 4)) if i % 4 == 0 else s)
    ips = [f"{int(rng.integers(1, 224))}.{int(rng.integers(0, 256))}.{int(rng.integers(0, 256))}.{int(rng.integers(1, 255))}"
           if i % 5 else f"2001:db8::{int(rng.integers(1, 65535)):x}" for i in range(n)]

    def null_ints(values, rate):
        return [None if rng.random() < rate else v for v in values]

    dob = np.datetime64("1960-01-01") + rng.integers(0, 16000, n).astype("timedelta64[D]")
    return pl.DataFrame({
        "customer_id": np.arange(1, n + 1, dtype=np.int64),
        "full_name": mess(names, rng, 0.12, recase=str.upper),
        "email": mess(emails, rng, 0.10, malform=lambda v: v.replace("@", ""), recase=str.upper),
        "contact": mess([phone(i) for i in range(n)], rng, 0.20, malform=lambda v: v[:6]),
        "mobile_no": pl.Series(null_ints(mobiles, 0.15), dtype=pl.Int64),
        "aadhaar_no": pl.Series(null_ints(aadhaar, 0.25), dtype=pl.Int64),
        "pan": mess(pans, rng, 0.30, malform=lambda v: v[:-1], recase=str.lower),
        "card_number": mess(cards, rng, 0.30, malform=lambda v: v.replace(" ", "")[:-5]),
        "last_login_ip": mess(ips, rng, 0.20, malform=lambda v: v.rsplit(".", 1)[0]),
        "dob": pl.Series([None if rng.random() < 0.15 else d for d in dob.tolist()], dtype=pl.Date),
        "email_sha256": [hashlib.sha256(e.encode()).hexdigest() for e in emails],
        "billing": pl.DataFrame({
            "email": mess(billing, rng, 0.10),
            "city": rng.choice(CITIES, n).tolist(),
        }).to_struct(),
        "tags": [["vip", "beta"][: int(rng.integers(0, 3))] for _ in range(n)],
        "amount": np.round(rng.gamma(2.0, 40.0, n), 2),
        "signup_ts": (np.datetime64("2020-01-01T00:00:00") + rng.integers(0, 10**8, n).astype("timedelta64[s]")).astype("datetime64[us]"),
        "notes": [f"Ticket {i}: customer asked about plan {int(rng.integers(1, 5))}" for i in range(n)],
    })


def escalation(rng):
    junk = [None, "N/A", "", "  ", "-", "0000000000"]
    contact = [junk[i % len(junk)] for i in range(2000)]
    contact += [f"user{i}@example.org" for i in range(6000)]
    return pl.DataFrame({
        "event_id": np.arange(8000, dtype=np.int64),
        "contact_email": contact,
        "amount": rng.random(8000),
    })


def main():
    out = Path(sys.argv[1]).resolve()
    rng = np.random.default_rng(20261014)
    df = customers(ROWS, rng)
    table = df.to_arrow()
    for writer in ("pyarrow", "polars", "duckdb"):
        path = out / writer / "customers.parquet"
        path.parent.mkdir(parents=True, exist_ok=True)
        if writer == "pyarrow":
            pq.write_table(table, path, row_group_size=ROW_GROUP)
        elif writer == "polars":
            df.write_parquet(path, row_group_size=ROW_GROUP)
        else:
            con = duckdb.connect()
            con.register("t", table)
            con.execute(f"COPY t TO '{path}' (FORMAT PARQUET, ROW_GROUP_SIZE {ROW_GROUP})")
            con.close()
        print(f"{writer:8s} {path.stat().st_size / 1e3:8.1f} KB  {pq.ParquetFile(path).metadata.num_row_groups} row groups")
    (out / "_spark_src").mkdir(exist_ok=True)
    pq.write_table(table, out / "_spark_src" / "customers.parquet")

    pq.write_table(escalation(rng).to_arrow(), out / "escalation.parquet", row_group_size=2000)

    bad = out / "bad"
    bad.mkdir(exist_ok=True)
    whole = (out / "pyarrow" / "customers.parquet").read_bytes()
    (bad / "truncated.parquet").write_bytes(whole[: int(len(whole) * 0.6)])
    (bad / "not_parquet.parquet").write_bytes(b"customer_id,email\n1,someone@example.org\n")
    print("versions:", {"pyarrow": pa.__version__, "polars": pl.__version__, "duckdb": duckdb.__version__,
                        "numpy": np.__version__, "python": sys.version.split()[0]})


if __name__ == "__main__":
    main()
