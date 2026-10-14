"""Round 2 datasets for the parquet-pii spike: messy values, a free-text sweep
and a small-file lake.

Writes, for pyarrow, polars and duckdb at their default settings:

- customers_1m: round 1's customers, messy, with high-cardinality names
- events_2m:    round 1's events, messy
- tickets_1m:   free-text columns embedding emails in 5%, 1%, 0.1% and 0.01%
                of rows, plus a free-text decoy with no emails
- lake/customers_NNN: customers_1m split into 100 files of 10,000 rows

It also writes the same tables to _spark_src/ for gen/spark_write.py, which
rewrites them with Spark's defaults into spark/, and the ground-truth
manifest (including the spark/ paths).

    python gen/generate_r2.py <out_dir>
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

from generate import (
    CITIES, COUNTRIES, DOMAINS, FIRST, LAST, NOTE_CLOSE, NOTE_OPEN, NOTE_TOPIC, PLANS,
    STATUSES, USER_AGENTS, digits_to_str, luhn_check_digit, uuid4_strings, verhoeff_check_digit,
)

PLACEHOLDERS = ["N/A", "unknown", "-", "0000000000", "test@test.com"]
WHITESPACE = [" ", "  ", "\t", " \t "]
SYLLABLES = (
    "ka ra an vi ja ya sh ri de la mi no sa ta ne ru po li ma ha be ke lo da ze mo ti ve ro "
    "na si le ga ba fi ar en is or um el in ul ho ku ni pa re so tu wa yo zu chi kri pra"
).split()

# Shares of all rows; nulls are per column (10-30%).
EMPTY, BLANK, PLACEHOLDER, MALFORMED, PADDED = 0.015, 0.01, 0.02, 0.02, 0.05
LAKE_FILES, LAKE_ROWS = 100, 10_000
WRITERS = ("pyarrow", "polars", "duckdb")


def name_list(rng, base, k):
    """`base` plus syllable-built names, `k` distinct in all."""
    out = set(base)
    while len(out) < k:
        out.add("".join(rng.choice(SYLLABLES, rng.integers(2, 4))).capitalize())
    return np.array(sorted(out))


def mess(clean, rng, null_rate, malform=None, recase=None, recase_rate=0.0):
    """Mess up a clean string column. Returns an object array (None = null)
    and the number of rows of each kind."""
    n = len(clean)
    out = clean.astype(object)
    u = rng.random(n)
    b_null = null_rate
    b_empty = b_null + EMPTY
    b_blank = b_empty + BLANK
    b_place = b_blank + PLACEHOLDER
    b_malf = b_place + (MALFORMED if malform else 0.0)
    rest = u >= b_malf
    if recase:
        sel = rest & (rng.random(n) < recase_rate)
        out[sel] = [recase(v, i) for i, v in enumerate(clean[sel])]
    pad = rest & (rng.random(n) < PADDED)
    pads = [(" ", ""), ("", "  "), ("\t", " "), ("  ", "\t")]
    out[pad] = [pads[i % 4][0] + v + pads[i % 4][1] for i, v in enumerate(out[pad])]
    m = (u >= b_place) & (u < b_malf)
    if malform:
        out[m] = [malform(v, i) for i, v in enumerate(clean[m])]
    sel = (u >= b_blank) & (u < b_place)
    out[sel] = rng.choice(PLACEHOLDERS, int(sel.sum()))
    sel = (u >= b_empty) & (u < b_blank)
    out[sel] = rng.choice(WHITESPACE, int(sel.sum()))
    out[(u >= b_null) & (u < b_empty)] = ""
    out[u < b_null] = None
    counts = {
        "null": int((u < b_null).sum()),
        "empty": int(((u >= b_null) & (u < b_empty)).sum()),
        "whitespace": int(((u >= b_empty) & (u < b_blank)).sum()),
        "placeholder": int(((u >= b_blank) & (u < b_place)).sum()),
        "malformed": int(m.sum()),
        "padded": int(pad.sum()),
    }
    return out, counts


def recase_title_or_upper(v, i):
    return v.upper() if i % 2 else v[:1].upper() + v[1:]


def recase_upper_or_lower(v, i):
    return v.upper() if i % 2 else v.lower()


def malform_email(v, i):
    return v.replace("@", "", 1)


def malform_phone(v, i):
    digits = "".join(c for c in v if c.isdigit())
    return digits[-(5 + i % 4):]  # 5-8 digits: too short


def drop_last(v, i):
    return v[:-1]


def malform_card(v, i):
    return v.replace(" ", "")[:-4]  # 11-12 digits: too short


def malform_ip(v, i):
    return v + ":zz9" if ":" in v else ".".join(v.split(".")[:3])


def to_series(name, values):
    return pl.Series(name, values.tolist(), dtype=pl.Utf8)


def note_text(rng, n):
    notes = np.char.add(np.char.add(np.char.add(np.char.add(
        rng.choice(NOTE_OPEN, n), " "), rng.choice(NOTE_TOPIC, n)), " - "), rng.choice(NOTE_CLOSE, n))
    return np.char.add(np.char.add(notes, " #"), rng.integers(10_000, 100_000, n).astype(str))


EMBED_TEMPLATES = [
    ("Asked us to send invoices to ", " instead; "),
    ("", " wrote in: "),
    ("Customer (", ") reports: "),
]


def embed_emails(notes, rows, emails, rng):
    out = notes.astype(object)
    for j, (row, email) in enumerate(zip(rows, rng.choice(emails, len(rows)))):
        email = email.upper() if j % 5 == 0 else email
        pre, post = EMBED_TEMPLATES[j % len(EMBED_TEMPLATES)]
        out[row] = pre + email + post + notes[row] if j % 2 else notes[row] + " Contact: " + email + "."
    return out


def customers(n, rng):
    first_names = name_list(rng, FIRST, 3000)
    middle_names = name_list(rng, FIRST[:60], 1000)
    last_names = name_list(rng, LAST, 3000)
    ids = np.arange(1, n + 1, dtype=np.int64)
    first = rng.choice(first_names, n)
    middle = np.where(rng.random(n) < 0.6, np.char.add(rng.choice(middle_names, n), " "), "")
    last = rng.choice(last_names, n)
    full_name = np.char.add(np.char.add(np.char.add(first, " "), middle), last)
    domain = rng.choice(DOMAINS, n)
    email = np.char.add(np.char.add(np.char.add(np.char.add(np.char.add(
        np.char.lower(first), "."), np.char.lower(last)), ids.astype(str)), "@"), domain)

    mobile = (rng.integers(6, 10, n) * 1_000_000_000 + rng.integers(0, 1_000_000_000, n)).astype(str)
    fmt = rng.random(n)
    us = np.char.add(np.char.add("+1", rng.integers(201, 990, n).astype(str)),
                     rng.integers(2_000_000, 9_999_999, n).astype(str))
    spaced = np.char.add(np.char.add(np.array([m[:5] for m in mobile]), " "), np.array([m[5:] for m in mobile]))
    contact = np.char.add("+91 ", spaced)
    contact = np.where((fmt >= 0.40) & (fmt < 0.65), np.char.add("+91", mobile), contact)
    contact = np.where((fmt >= 0.65) & (fmt < 0.90), mobile, contact)
    contact = np.where(fmt >= 0.90, us, contact)

    dob = rng.integers(np.datetime64("1950-01-01").astype(int), np.datetime64("2006-12-31").astype(int),
                       n).astype("datetime64[D]")
    letters = np.array(list("ABCDEFGHIJKLMNOPQRSTUVWXYZ"))
    pan = np.char.add(np.char.add(np.char.add(np.char.add(np.char.add(
        rng.choice(letters, n), rng.choice(letters, n)), rng.choice(letters, n)), "P"),
        np.char.add(np.array([s[0].upper() for s in last]), np.char.zfill(rng.integers(0, 10_000, n).astype(str), 4))),
        rng.choice(letters, n))
    span, stride = 80_000_000_000, 7_919_000_003
    base = (ids * stride + int(rng.integers(0, span))) % span + 20_000_000_000
    aadhaar = (base * 10 + verhoeff_check_digit(base)).astype(str)
    sha = np.array([hashlib.sha256(e.encode()).hexdigest() for e in email])

    embed = np.flatnonzero(rng.random(n) < 0.05)
    notes = embed_emails(note_text(rng, n), embed, email, rng)

    stats = {}
    cols = {}
    cols["full_name"], stats["full_name"] = mess(full_name, rng, 0.12, recase=recase_upper_or_lower, recase_rate=0.10)
    cols["email"], stats["email"] = mess(email, rng, 0.10, malform_email, recase_title_or_upper, 0.10)
    cols["contact"], stats["contact"] = mess(contact, rng, 0.20, malform_phone)
    cols["pan"], stats["pan"] = mess(pan, rng, 0.30, drop_last, lambda v, i: v.lower(), 0.05)
    cols["c9"], stats["c9"] = mess(aadhaar, rng, 0.25, drop_last)
    cols["notes"], stats["notes"] = mess(notes.astype(str), rng, 0.15)
    dob_null = rng.random(n) < 0.15
    stats["dob"] = {"null": int(dob_null.sum())}
    embedded_mask = np.zeros(n, dtype=bool)
    embedded_mask[[r for r in embed if cols["notes"][r] == notes[r]]] = True
    embedded_rows = int(embedded_mask.sum())

    signup = (np.datetime64("2018-01-01T00:00:00").astype("datetime64[s]").astype(np.int64)
              + rng.integers(0, 8 * 365 * 86400, n)).astype("datetime64[s]").astype("datetime64[us]")
    out = pl.DataFrame([
        pl.Series("customer_id", ids),
        to_series("full_name", cols["full_name"]),
        to_series("email", cols["email"]),
        to_series("contact", cols["contact"]),
        pl.Series("dob", dob).set(pl.Series(dob_null), None),
        to_series("pan", cols["pan"]),
        to_series("c9", cols["c9"]),
        pl.Series("city", rng.choice(CITIES, n)),
        pl.Series("plan", rng.choice(PLANS, n, p=[0.45, 0.25, 0.18, 0.08, 0.04])),
        pl.Series("email_sha256", sha),
        pl.Series("signup_ts", signup),
        to_series("notes", cols["notes"]),
    ])
    truth = {
        "customer_id": (None, None), "full_name": ("PERSON_NAME", True), "email": ("EMAIL", True),
        "contact": ("PHONE", False), "dob": ("DATE_OF_BIRTH", True), "pan": ("IN_PAN", True),
        "c9": ("IN_AADHAAR", False), "city": (None, None), "plan": (None, None),
        "email_sha256": (None, None), "signup_ts": (None, None), "notes": ("EMAIL_EMBEDDED", False),
    }
    extra = {"notes": {"embedded_rows": embedded_rows, "embedded_rate": embedded_rows / n}}
    return out, truth, extra, stats, email, embedded_mask


def events(n, customer_emails, rng):
    pool = len(customer_emails)
    idx = np.concatenate([np.arange(pool), rng.integers(0, pool, n - pool)])
    rng.shuffle(idx)
    customer_email = customer_emails[idx]

    is_v6 = rng.random(n) < 0.2
    v4 = np.char.add(np.char.add(np.char.add(np.char.add(np.char.add(np.char.add(
        rng.integers(1, 224, n).astype(str), "."), rng.integers(0, 256, n).astype(str)), "."),
        rng.integers(0, 256, n).astype(str)), "."), rng.integers(1, 255, n).astype(str))
    hextets = rng.integers(0, 65536, (int(is_v6.sum()), 6))
    src = v4.astype(object)
    src[is_v6] = ["2001:db8:" + ":".join(f"{h:x}" for h in row) for row in hextets]
    src = src.astype(str)

    kind = rng.random(n)
    body15 = rng.integers(0, 10, (n, 15))
    body15[:, 0] = 4
    mc = kind >= 0.5
    body15[mc, 0] = 5
    body15[mc, 1] = rng.integers(1, 6, int(mc.sum()))
    visa_mc = np.concatenate([body15, luhn_check_digit(body15)[:, None]], axis=1)
    body14 = body15[:, :14].copy()
    body14[:, 0] = 3
    body14[:, 1] = rng.choice([4, 7], n)
    amex = np.concatenate([body14, luhn_check_digit(body14)[:, None]], axis=1)
    card = np.where(kind >= 0.85, digits_to_str(amex), digits_to_str(visa_mc)).astype(object)
    grouped = rng.random(n) < 0.25
    card[grouped] = [" ".join(c[i:i + 4] for i in range(0, len(c), 4)) for c in card[grouped]]
    card = card.astype(str)

    base = rng.integers(20_000_000_000, 100_000_000_000, n)
    wrong = (verhoeff_check_digit(base) + rng.integers(1, 10, n)) % 10
    order_ref = (base * 10 + wrong).astype(str)

    stats = {}
    ce, stats["customer_email"] = mess(customer_email, rng, 0.10, malform_email, recase_title_or_upper, 0.10)
    src, stats["src"] = mess(src, rng, 0.20, malform_ip, lambda v, i: v.upper(), 0.10)
    card, stats["card"] = mess(card, rng, 0.30, malform_card)
    out = pl.DataFrame([
        pl.Series("event_id", uuid4_strings(n, rng)),
        to_series("customer_email", ce),
        to_series("src", src),
        to_series("card", card),
        pl.Series("order_ref", order_ref),
        pl.Series("amount", np.round(rng.gamma(2.0, 40.0, n), 2)),
        pl.Series("status", rng.choice(STATUSES, n, p=[0.8, 0.1, 0.05, 0.05])),
        pl.Series("user_agent", rng.choice(USER_AGENTS, n)),
        pl.Series("country", rng.choice(COUNTRIES, n)),
    ])
    truth = {
        "event_id": (None, None), "customer_email": ("EMAIL", True), "src": ("IP_ADDRESS", False),
        "card": ("CARD_NUMBER", True), "order_ref": (None, None), "amount": (None, None),
        "status": (None, None), "user_agent": (None, None), "country": (None, None),
    }
    return out, truth, {}, stats


SUMMARY_OPEN = [
    "Ping @ops-team about", "@rahul please check", "Escalate to @billing for", "cc @support-l2 on",
    "Reach support at acme dot com about", "User says price @ 499/month is wrong for",
    "Repro steps attached for", "Customer shared a screenshot of",
]
# Free-text sweep: column -> share of rows embedding an email.
SWEEP = {"agent_notes": 0.05, "customer_reply": 0.01, "internal_comment": 0.001, "resolution": 0.0001}


def tickets(n, emails, rng):
    cols = [pl.Series("ticket_id", np.arange(1, n + 1, dtype=np.int64)),
            pl.Series("opened_ts", (np.datetime64("2024-01-01T00:00:00").astype("datetime64[s]").astype(np.int64)
                                    + rng.integers(0, 2 * 365 * 86400, n)).astype("datetime64[s]")
                      .astype("datetime64[us]"))]
    truth = {"ticket_id": (None, None), "opened_ts": (None, None)}
    extra, stats = {}, {}
    for name, rate in SWEEP.items():
        k = round(rate * n)
        rows = rng.choice(n, k, replace=False)
        text = note_text(rng, n)
        embedded = embed_emails(text, rows, emails, rng)
        messy, stats[name] = mess(text, rng, 0.10)
        messy[rows] = embedded[rows]  # the embedding rows stay intact
        cols.append(to_series(name, messy))
        truth[name] = ("EMAIL_EMBEDDED", False)
        extra[name] = {"embedded_rows": k, "embedded_rate": rate}
    summary = np.char.add(np.char.add(np.char.add(np.char.add(
        rng.choice(SUMMARY_OPEN, n), " "), rng.choice(NOTE_TOPIC, n)), "; "), rng.choice(NOTE_CLOSE, n))
    messy, stats["summary"] = mess(summary, rng, 0.10)
    cols.append(to_series("summary", messy))
    truth["summary"] = (None, None)
    return pl.DataFrame(cols), truth, extra, stats


def write(df, writer, path):
    path.parent.mkdir(parents=True, exist_ok=True)
    if writer == "pyarrow":
        pq.write_table(df.to_arrow(), path)
    elif writer == "polars":
        df.write_parquet(path)
    else:
        con = duckdb.connect()
        con.register("t", df.to_arrow())
        con.execute(f"COPY t TO '{path}' (FORMAT PARQUET)")
        con.close()


def main():
    out_dir = Path(sys.argv[1]).resolve()
    out_dir.mkdir(parents=True, exist_ok=True)
    versions = {"pyarrow": pa.__version__, "polars": pl.__version__, "duckdb": duckdb.__version__,
                "numpy": np.__version__, "python": sys.version.split()[0]}
    manifest = {"versions": versions, "files": [], "mess": {}}
    start = time.time()

    def record(name, dataset, rows, truth, extra, writers=WRITERS + ("spark",), sub=""):
        for writer in writers:
            manifest["files"].append({
                "path": f"{writer}/{sub}{name}.parquet", "writer": writer, "dataset": dataset,
                "rows": rows,
                "columns": {c: {"type": t, "name_honest": h, **extra.get(c, {})} for c, (t, h) in truth.items()},
            })

    def emit(df, name):
        for writer in WRITERS:
            t0 = time.time()
            path = out_dir / writer / f"{name}.parquet"
            write(df, writer, path)
            print(f"  {writer:8s} {name:14s} {path.stat().st_size / 1e6:7.1f} MB {time.time() - t0:5.1f}s", flush=True)
        src = out_dir / "_spark_src" / f"{name}.parquet"
        src.parent.mkdir(parents=True, exist_ok=True)
        pq.write_table(df.to_arrow(), src)

    rng = np.random.default_rng(20261014)
    print("customers_1m", flush=True)
    cust, truth, extra, stats, emails, embedded_mask = customers(1_000_000, rng)
    manifest["mess"]["customers"] = stats
    emit(cust, "customers_1m")
    record("customers_1m", "customers", 1_000_000, truth, extra)

    print(f"lake: {LAKE_FILES} x {LAKE_ROWS}", flush=True)
    for i in range(LAKE_FILES):
        part = cust.slice(i * LAKE_ROWS, LAKE_ROWS)
        embedded = int(embedded_mask[i * LAKE_ROWS:(i + 1) * LAKE_ROWS].sum())
        for writer in WRITERS:
            write(part, writer, out_dir / writer / "lake" / f"customers_{i:03d}.parquet")
        record(f"customers_{i:03d}", "customers_lake", LAKE_ROWS, truth,
               {"notes": {"embedded_rows": embedded, "embedded_rate": embedded / LAKE_ROWS}}, sub="lake/")
    del cust

    print("events_2m", flush=True)
    ev, truth, extra, stats = events(2_000_000, emails, rng)
    manifest["mess"]["events"] = stats
    emit(ev, "events_2m")
    record("events_2m", "events", 2_000_000, truth, extra)
    del ev

    print("tickets_1m", flush=True)
    tk, truth, extra, stats = tickets(1_000_000, emails, rng)
    manifest["mess"]["tickets"] = stats
    emit(tk, "tickets_1m")
    record("tickets_1m", "tickets", 1_000_000, truth, extra)

    (out_dir / "manifest.json").write_text(json.dumps(manifest, indent=2))
    print(f"done in {time.time() - start:.0f}s; versions {versions}", flush=True)


if __name__ == "__main__":
    main()
