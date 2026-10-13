//! The demo bucket's contents: exactly what `examples/seed_local.rs` writes
//! and what `tests/e2e.rs` expects to find.
//!
//! Shared by `#[path]` include rather than duplicated, so the seeder and the
//! test cannot drift apart on what was written. What the rules should *say*
//! about these objects is deliberately not derived from here: `tests/e2e.rs`
//! states its expected finding counts on its own.

/// The bucket the seeder (re)creates.
pub(crate) const BUCKET: &str = "lakescan-demo";

/// How many ordinary, finding-free `STANDARD` objects to write: enough that
/// a 1000-key `ListObjectsV2` page size spans three pages.
const ORDINARY_OBJECTS: usize = 2400;

/// The prefixes the ordinary objects are spread across, round-robin.
const ORDINARY_PREFIXES: [&str; 3] = ["data/events/", "logs/app/", "images/"];

/// Keys built to break naive handling: an ANSI escape sequence, a
/// right-to-left override, and the characters URL decoding treats
/// specially. All are written with empty bodies, so each is a
/// `zero-byte-object` finding whose key must survive the round trip.
///
/// A key containing a newline belongs here too, but moto (5.2.3) cannot
/// store one: its Werkzeug router answers 404 to any object path with a
/// `%0A` in it, so the upload never reaches S3 emulation. Newlines are
/// covered by the unit tests instead (the key decoder's `%0A` case and the
/// findings writer's dangerous-key round trip).
pub(crate) const HOSTILE_KEYS: [&str; 3] = [
    "hostile/\u{1b}[31mred-alert.txt",
    "hostile/\u{202e}txt.exe",
    "plus+and%percent space.txt",
];

/// One object to write.
pub(crate) struct SeedObject {
    pub(crate) key: String,
    pub(crate) body: Vec<u8>,
    /// The storage class's S3 wire name, e.g. `"STANDARD"`.
    pub(crate) storage_class: &'static str,
}

/// Every object the seeder writes, in upload order.
pub(crate) fn objects() -> Vec<SeedObject> {
    let mut objects: Vec<SeedObject> = ORDINARY_PREFIXES
        .iter()
        .cycle()
        .take(ORDINARY_OBJECTS)
        .enumerate()
        .map(|(n, prefix)| {
            let key = format!("{prefix}object-{n:04}.dat");
            // Distinct content per key, so the distinct-content estimate
            // has something to count.
            let body = format!("lakescan demo object {key}\n").into_bytes();
            standard(key, body)
        })
        .collect();

    let note = |what: &str| format!("lakescan demo: {what}, not a real secret\n").into_bytes();
    objects.extend([
        // sensitive-key, High.
        standard("id_rsa".to_owned(), note("SSH key")),
        standard(".env.production".to_owned(), note("dotenv")),
        standard("infra/terraform.tfstate".to_owned(), note("tfstate")),
        // sensitive-key, Medium.
        standard("app/.git/config".to_owned(), note("git config")),
        standard("certs/server.pem".to_owned(), note("certificate")),
        // Storage-class findings.
        SeedObject {
            key: "backups/old.tar".to_owned(),
            body: note("archive"),
            storage_class: "REDUCED_REDUNDANCY",
        },
        SeedObject {
            key: "cold/thumb.jpg".to_owned(),
            body: vec![b'j'; 1000],
            storage_class: "GLACIER",
        },
        SeedObject {
            key: "cold/tiny.csv".to_owned(),
            body: b"id,value\n1,2\n".to_vec(),
            storage_class: "STANDARD_IA",
        },
        // zero-byte-object, and a folder marker that must not be one.
        standard("placeholder/empty.txt".to_owned(), Vec::new()),
        standard("folder-marker/".to_owned(), Vec::new()),
    ]);
    objects.extend(
        HOSTILE_KEYS
            .iter()
            .map(|key| standard((*key).to_owned(), Vec::new())),
    );

    objects
}

fn standard(key: String, body: Vec<u8>) -> SeedObject {
    SeedObject {
        key,
        body,
        storage_class: "STANDARD",
    }
}
