"""Synthetic PII datasets for the parquet-pii spike.

Writes customers (1M and 10k rows) and events (2M rows), each with three
writers at their default settings (pyarrow, polars, duckdb), plus a
ground-truth manifest. Values are built from word lists with vectorized
numpy, never one fake-data call per row.

    python generate.py <out_dir>
"""

import hashlib
import json
import sys
import time
from pathlib import Path

import duckdb
import numpy as np
import polars as pl
import pyarrow as pa
import pyarrow.parquet as pq

FIRST = (
    "Aarav Aditi Akash Ananya Arjun Bhavna Chetan Deepa Divya Farhan Gaurav Ishaan "
    "Jaya Karan Kavya Lakshmi Manish Meera Mohit Naveen Neha Nikhil Pooja Priya "
    "Rahul Rajesh Ravi Rohan Sakshi Sanjay Shreya Sneha Suresh Tanvi Varun Vikram "
    "Yash Zara Aisha Amit Anil Asha Deepak Kiran Lata Mahesh Nisha Omkar Pallavi "
    "Ramesh Sunita Usha Vinod Alice Benjamin Chloe Daniel Emma Ethan Grace Henry "
    "Isabella Jack James Liam Lucas Mia Noah Olivia Sophia William Ava Charlotte "
    "Amelia Harper Evelyn Abigail Emily Elizabeth Sofia Avery Ella Scarlett Victoria "
    "Madison Luna Hannah Lily Zoe Nora Riley Leah Aria Mateo Sebastian Jacob Michael "
    "Elijah Logan Alexander Owen Wyatt Carter Jayden Luke Gabriel Anthony Dylan "
    "Isaac Julian Levi Aaron Thomas Charles Caleb Josiah Christopher Andrew Ryan "
    "Nathan Adrian Joshua Hunter Eli Connor Jeremiah Cameron Santiago Ali Fatima "
    "Omar Yusuf Layla Hana Kenji Yuki Mei Wei Chen Hiroshi Sakura Min Jin Soo"
).split()
LAST = (
    "Sharma Verma Gupta Singh Kumar Patel Shah Mehta Joshi Iyer Nair Reddy Rao "
    "Menon Pillai Das Bose Banerjee Chatterjee Mukherjee Ghosh Sen Kapoor Malhotra "
    "Khanna Chopra Bhatia Saxena Agarwal Bansal Jain Mishra Pandey Tiwari Dubey "
    "Yadav Chauhan Thakur Kulkarni Deshpande Patil Pawar Jadhav Shinde Gowda Hegde "
    "Shetty Kamath Naidu Varma Krishnan Subramanian Raman Srinivasan Venkatesh "
    "Smith Johnson Williams Brown Jones Garcia Miller Davis Rodriguez Martinez "
    "Hernandez Lopez Gonzalez Wilson Anderson Thomas Taylor Moore Jackson Martin Lee "
    "Perez Thompson White Harris Sanchez Clark Ramirez Lewis Robinson Walker Young "
    "Allen King Wright Scott Torres Nguyen Hill Flores Green Adams Nelson Baker Hall "
    "Rivera Campbell Mitchell Carter Roberts Gomez Phillips Evans Turner Diaz Parker "
    "Cruz Edwards Collins Reyes Stewart Morris Morales Murphy Cook Rogers Gutierrez "
    "Ortiz Morgan Cooper Peterson Bailey Reed Kelly Howard Ramos Kim Cox Ward Wang "
    "Tanaka Suzuki Sato Watanabe Li Zhang Liu Chen Yang Huang Zhao Wu Zhou Xu Sun"
).split()
DOMAINS = (
    "gmail.com yahoo.com outlook.com hotmail.com icloud.com proton.me rediffmail.com "
    "example.org acme.io fintech.in healthco.in saasly.com mail.com zoho.com yandex.com"
).split()
CITIES = (
    "Mumbai Delhi Bengaluru Hyderabad Chennai Kolkata Pune Ahmedabad Jaipur Surat "
    "Lucknow Kanpur Nagpur Indore Bhopal Patna Vadodara Ludhiana Agra Nashik Kochi "
    "Coimbatore Mysuru Chandigarh Guwahati London Singapore Dubai Toronto Sydney "
    "Berlin Paris Amsterdam Tokyo Seoul NewYork SanFrancisco Austin Seattle Boston"
).split()
PLANS = ["free", "starter", "pro", "team", "enterprise"]
STATUSES = ["paid", "pending", "refunded", "failed"]
COUNTRIES = (
    "IN US GB SG AE CA AU DE FR NL JP KR BR MX ZA NG KE ID MY TH VN PH ES IT SE"
).split()
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.15",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148",
    "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0 Mobile Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64; rv:127.0) Gecko/20100101 Firefox/127.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:127.0) Gecko/20100101 Firefox/127.0",
    "Mozilla/5.0 (Linux; Android 13; SM-S918B) AppleWebKit/537.36 (KHTML, like Gecko) SamsungBrowser/25.0 Chrome/121.0 Mobile Safari/537.36",
    "okhttp/4.12.0",
    "python-requests/2.32.3",
    "curl/8.7.1",
    "PostmanRuntime/7.39.0",
    "Dalvik/2.1.0 (Linux; U; Android 12; Redmi Note 11 Build/SKQ1.211103.001)",
]
NOTE_OPEN = [
    "Customer called about", "Follow-up on", "Escalated issue with", "Requested help with",
    "Feedback regarding", "Question about", "Complaint about", "Asked to review",
    "Discussed", "Reported a problem with", "Wants a demo of", "Confused by",
]
NOTE_TOPIC = [
    "billing cycle", "annual renewal", "invoice format", "GST details", "refund status",
    "plan upgrade", "seat count", "SSO setup", "API rate limits", "data export",
    "mobile app login", "password reset", "webhook retries", "dashboard latency",
    "team permissions", "usage report", "trial extension", "payment failure",
]
NOTE_CLOSE = [
    "resolved on call.", "will follow up next week.", "sent docs link.", "needs engineering input.",
    "awaiting customer reply.", "closed as duplicate.", "offered a discount.", "logged ticket",
    "scheduled callback.", "no action needed.", "shared workaround.", "escalated to tier 2.",
]


def verhoeff_tables():
    d = np.array([
        [0, 1, 2, 3, 4, 5, 6, 7, 8, 9], [1, 2, 3, 4, 0, 6, 7, 8, 9, 5],
        [2, 3, 4, 0, 1, 7, 8, 9, 5, 6], [3, 4, 0, 1, 2, 8, 9, 5, 6, 7],
        [4, 0, 1, 2, 3, 9, 5, 6, 7, 8], [5, 9, 8, 7, 6, 0, 4, 3, 2, 1],
        [6, 5, 9, 8, 7, 1, 0, 4, 3, 2], [7, 6, 5, 9, 8, 2, 1, 0, 4, 3],
        [8, 7, 6, 5, 9, 3, 2, 1, 0, 4], [9, 8, 7, 6, 5, 4, 3, 2, 1, 0],
    ])
    p = np.array([
        [0, 1, 2, 3, 4, 5, 6, 7, 8, 9], [1, 5, 7, 6, 2, 8, 3, 0, 9, 4],
        [5, 8, 0, 3, 7, 9, 6, 1, 4, 2], [8, 9, 1, 6, 0, 4, 3, 5, 2, 7],
        [9, 4, 5, 3, 1, 2, 6, 8, 7, 0], [4, 2, 8, 6, 5, 7, 3, 9, 0, 1],
        [2, 7, 9, 3, 8, 0, 6, 4, 1, 5], [7, 0, 4, 6, 9, 1, 3, 2, 5, 8],
    ])
    inv = np.array([0, 4, 3, 2, 1, 5, 6, 7, 8, 9])
    return d, p, inv


def digits_of(values, width):
    """(n, width) array of base-10 digits, most significant first."""
    out = np.empty((len(values), width), dtype=np.int64)
    v = values.copy()
    for i in range(width - 1, -1, -1):
        out[:, i] = v % 10
        v //= 10
    return out


def verhoeff_check_digit(base):
    """Verhoeff check digit for each integer in `base` (vectorized)."""
    d, p, inv = verhoeff_tables()
    digits = digits_of(base, 11)
    c = np.zeros(len(base), dtype=np.int64)
    # The check digit will sit at position 0; data digits start at position 1.
    for i, col in enumerate(range(10, -1, -1)):
        c = d[c, p[(i + 1) % 8, digits[:, col]]]
    return inv[c]


def luhn_check_digit(digits):
    """Luhn check digit for each row of a (n, k) digit array (vectorized)."""
    k = digits.shape[1]
    total = np.zeros(digits.shape[0], dtype=np.int64)
    for j in range(k):
        dgt = digits[:, k - 1 - j]
        if j % 2 == 0:  # doubled positions, counting from the check digit
            dgt = dgt * 2
            dgt = np.where(dgt > 9, dgt - 9, dgt)
        total += dgt
    return (10 - total % 10) % 10


def digits_to_str(digits):
    ascii_digits = np.ascontiguousarray((digits + ord("0")).astype(np.uint8))
    return ascii_digits.view(f"S{digits.shape[1]}").ravel().astype(str)


def customers(n, rng):
    ids = np.arange(1, n + 1, dtype=np.int64)
    first = rng.choice(FIRST, n)
    last = rng.choice(LAST, n)
    domain = rng.choice(DOMAINS, n)
    df = pl.DataFrame({"customer_id": ids, "first": first, "last": last, "domain": domain})
    df = df.with_columns(
        full_name=pl.concat_str(["first", pl.lit(" "), "last"]),
        # Unique per row: the id is part of the local part.
        email=pl.concat_str([
            pl.col("first").str.to_lowercase(), pl.lit("."), pl.col("last").str.to_lowercase(),
            pl.col("customer_id").cast(pl.Utf8), pl.lit("@"), "domain",
        ]),
    )

    # Phones: Indian mobiles (6-9 then 9 digits) in several formats, plus some US E.164.
    mobile = rng.integers(6, 10, n) * 1_000_000_000 + rng.integers(0, 1_000_000_000, n)
    mob = mobile.astype(str)
    fmt = rng.random(n)
    us = (rng.integers(201, 990, n).astype(str), rng.integers(2_000_000, 9_999_999, n).astype(str))
    spaced = np.char.add(np.char.add(np.array([m[:5] for m in mob]), " "), np.array([m[5:] for m in mob]))
    contact = np.char.add("+91 ", spaced)  # 40%: "+91 98765 43210"
    contact = np.where((fmt >= 0.40) & (fmt < 0.65), np.char.add("+91", mob), contact)
    contact = np.where((fmt >= 0.65) & (fmt < 0.90), mob, contact)
    contact = np.where(fmt >= 0.90, np.char.add(np.char.add("+1", us[0]), us[1]), contact)

    dob_days = rng.integers(np.datetime64("1950-01-01").astype(int), np.datetime64("2006-12-31").astype(int), n)
    dob = dob_days.astype("datetime64[D]")

    letters = np.array(list("ABCDEFGHIJKLMNOPQRSTUVWXYZ"))
    # PAN: AAA + P (individual) + surname initial + 4 digits + letter.
    pan_digits = np.char.zfill(rng.integers(0, 10_000, n).astype(str), 4)
    pan = np.char.add(np.char.add(np.char.add(
        np.char.add(np.char.add(rng.choice(letters, n), rng.choice(letters, n)), rng.choice(letters, n)), "P"),
        np.char.add(np.array([s[0].upper() for s in last]), pan_digits)), rng.choice(letters, n))

    # Aadhaar: 11-digit unique base with first digit 2-9, then Verhoeff check digit.
    span = 80_000_000_000  # 2e10 .. 1e11-1
    stride = 7_919_000_003  # coprime with span, so i -> base is a bijection
    base = (ids * stride + int(rng.integers(0, span))) % span + 20_000_000_000
    aadhaar = base * 10 + verhoeff_check_digit(base)

    city = rng.choice(CITIES, n)
    plan = rng.choice(PLANS, n, p=[0.45, 0.25, 0.18, 0.08, 0.04])
    signup = (np.datetime64("2018-01-01T00:00:00").astype("datetime64[s]").astype(np.int64)
              + rng.integers(0, 8 * 365 * 86400, n)).astype("datetime64[s]").astype("datetime64[us]")

    emails = df["email"].to_numpy()
    sha = np.array([hashlib.sha256(e.encode()).hexdigest() for e in emails])

    notes = np.char.add(np.char.add(np.char.add(np.char.add(
        rng.choice(NOTE_OPEN, n), " "), rng.choice(NOTE_TOPIC, n)), " - "), rng.choice(NOTE_CLOSE, n))
    notes = np.char.add(np.char.add(notes, " #"), rng.integers(10_000, 100_000, n).astype(str))
    embed = rng.random(n) < 0.05
    other = emails[rng.integers(0, n, n)]
    notes = np.where(
        embed,
        np.char.add(np.char.add(np.char.add("Asked us to send invoices to ", other), " instead; "), notes),
        notes,
    )

    out = pl.DataFrame({
        "customer_id": ids,
        "full_name": df["full_name"],
        "email": df["email"],
        "contact": contact,
        "dob": dob,
        "pan": pan,
        "c9": aadhaar.astype(str),
        "city": city,
        "plan": plan,
        "email_sha256": sha,
        "signup_ts": signup,
        "notes": notes,
    })
    truth = {
        "customer_id": (None, None), "full_name": ("PERSON_NAME", True), "email": ("EMAIL", True),
        "contact": ("PHONE", False), "dob": ("DATE_OF_BIRTH", True), "pan": ("IN_PAN", True),
        "c9": ("IN_AADHAAR", False), "city": (None, None), "plan": (None, None),
        "email_sha256": (None, None), "signup_ts": (None, None), "notes": ("EMAIL_EMBEDDED", False),
    }
    return out, truth, int(embed.sum())


def uuid4_strings(n, rng):
    raw = rng.integers(0, 256, (n, 16), dtype=np.uint8)
    raw[:, 6] = (raw[:, 6] & 0x0F) | 0x40
    raw[:, 8] = (raw[:, 8] & 0x3F) | 0x80
    hexchars = np.frombuffer(b"0123456789abcdef", dtype=np.uint8)
    hi, lo = hexchars[raw >> 4], hexchars[raw & 0x0F]
    pairs = np.stack([hi, lo], axis=2).reshape(n, 32)
    dash = np.full((n, 1), ord("-"), dtype=np.uint8)
    full = np.concatenate([pairs[:, :8], dash, pairs[:, 8:12], dash, pairs[:, 12:16], dash,
                           pairs[:, 16:20], dash, pairs[:, 20:]], axis=1)
    return np.ascontiguousarray(full).view("S36").ravel().astype(str)


def events(n, customer_emails, rng):
    pool = len(customer_emails)
    idx = np.concatenate([np.arange(pool), rng.integers(0, pool, n - pool)])
    rng.shuffle(idx)
    customer_email = customer_emails[idx]

    is_v6 = rng.random(n) < 0.2
    v4 = np.char.add(np.char.add(np.char.add(np.char.add(np.char.add(np.char.add(
        rng.integers(1, 224, n).astype(str), "."), rng.integers(0, 256, n).astype(str)), "."),
        rng.integers(0, 256, n).astype(str)), "."), rng.integers(1, 255, n).astype(str))
    k = int(is_v6.sum())
    hextets = rng.integers(0, 65536, (k, 6))
    v6 = np.array(["2001:db8:" + ":".join(f"{h:x}" for h in row) for row in hextets])
    src = v4.copy().astype(object)
    src[is_v6] = v6
    src = src.astype(str)

    # Cards: Visa 16, Mastercard 16, Amex 15, Luhn-valid; 25% grouped with spaces.
    kind = rng.random(n)
    body15 = rng.integers(0, 10, (n, 15))
    body15[:, 0] = 4
    mc = kind >= 0.5
    body15[mc, 0] = 5
    body15[mc, 1] = rng.integers(1, 6, int(mc.sum()))
    visa_mc = np.concatenate([body15, luhn_check_digit(body15)[:, None]], axis=1)
    amex = kind >= 0.85
    body14 = body15[:, :14].copy()
    body14[:, 0] = 3
    body14[:, 1] = rng.choice([4, 7], n)
    amex_digits = np.concatenate([body14, luhn_check_digit(body14)[:, None]], axis=1)
    card16 = digits_to_str(visa_mc)
    card15 = digits_to_str(amex_digits)
    card = np.where(amex, card15, card16)
    grouped = rng.random(n) < 0.25
    card_g = np.array([" ".join(c[i:i + 4] for i in range(0, len(c), 4)) for c in card[grouped]])
    card = card.astype(object)
    card[grouped] = card_g
    card = card.astype(str)

    # Decoy: 12-digit numbers shaped like Aadhaar whose last digit is NOT the Verhoeff digit.
    base = rng.integers(20_000_000_000, 100_000_000_000, n)
    good = verhoeff_check_digit(base)
    wrong = (good + rng.integers(1, 10, n)) % 10
    order_ref = (base * 10 + wrong).astype(str)

    out = pl.DataFrame({
        "event_id": uuid4_strings(n, rng),
        "customer_email": customer_email,
        "src": src,
        "card": card,
        "order_ref": order_ref,
        "amount": np.round(rng.gamma(2.0, 40.0, n), 2),
        "status": rng.choice(STATUSES, n, p=[0.8, 0.1, 0.05, 0.05]),
        "user_agent": rng.choice(USER_AGENTS, n),
        "country": rng.choice(COUNTRIES, n),
    })
    truth = {
        "event_id": (None, None), "customer_email": ("EMAIL", True), "src": ("IP_ADDRESS", False),
        "card": ("CARD_NUMBER", True), "order_ref": (None, None), "amount": (None, None),
        "status": (None, None), "user_agent": (None, None), "country": (None, None),
    }
    return out, truth


def write_all(df, name, out_dir):
    table = df.to_arrow()
    paths = {}
    for writer in ("pyarrow", "polars", "duckdb"):
        path = out_dir / writer / f"{name}.parquet"
        path.parent.mkdir(parents=True, exist_ok=True)
        t0 = time.time()
        if writer == "pyarrow":
            pq.write_table(table, path)
        elif writer == "polars":
            df.write_parquet(path)
        else:
            con = duckdb.connect()
            con.register("t", table)
            con.execute(f"COPY t TO '{path}' (FORMAT PARQUET)")
            con.close()
        print(f"  {writer:8s} {name:15s} {path.stat().st_size / 1e6:8.1f} MB  {time.time() - t0:5.1f}s",
              flush=True)
        paths[writer] = path
    return paths


def main():
    out_dir = Path(sys.argv[1]).resolve()
    out_dir.mkdir(parents=True, exist_ok=True)
    versions = {"pyarrow": pa.__version__, "polars": pl.__version__, "duckdb": duckdb.__version__,
                "numpy": np.__version__, "python": sys.version.split()[0]}
    manifest = {"versions": versions, "files": []}
    start = time.time()

    def record(paths, dataset, rows, truth, extra=None):
        for writer, path in paths.items():
            manifest["files"].append({
                "path": str(path.relative_to(out_dir)), "writer": writer, "dataset": dataset,
                "rows": rows,
                "columns": {c: {"type": t, "name_honest": h} for c, (t, h) in truth.items()},
                **(extra or {}),
            })

    rng = np.random.default_rng(20261013)
    print("customers_1m", flush=True)
    cust, truth, embedded = customers(1_000_000, rng)
    record(write_all(cust, "customers_1m", out_dir), "customers", 1_000_000, truth,
           {"embedded_email_rows": embedded})

    print("events_2m", flush=True)
    ev, ev_truth = events(2_000_000, cust["email"].to_numpy(), rng)
    del cust
    record(write_all(ev, "events_2m", out_dir), "events", 2_000_000, ev_truth)
    del ev

    print("customers_10k", flush=True)
    small, truth, embedded = customers(10_000, np.random.default_rng(7))
    record(write_all(small, "customers_10k", out_dir), "customers", 10_000, truth,
           {"embedded_email_rows": embedded})

    (out_dir / "manifest.json").write_text(json.dumps(manifest, indent=2))
    print(f"done in {time.time() - start:.0f}s; versions {versions}", flush=True)


if __name__ == "__main__":
    main()
