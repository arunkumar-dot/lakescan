//! A real interrupt, end to end, with no network and no extra crates.
//!
//! A fake S3/STS built on `std::net` answers the preflight and then never
//! answers the listing, so the `lakescan` binary is stuck in its scan with
//! its output files open as temporary files. The test sends the process a
//! real SIGINT or SIGTERM (through the `kill` command) and checks what the
//! person is left with: the exit status, no output on stderr, no temporary
//! file, and any earlier output file untouched.

#![cfg(unix)]

use std::fs;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

const STS_BODY: &str = "<GetCallerIdentityResponse xmlns=\"https://sts.amazonaws.com/doc/2011-06-15/\">\
    <GetCallerIdentityResult><Arn>arn:aws:iam::123456789012:user/test</Arn>\
    <UserId>AIDATEST</UserId><Account>123456789012</Account></GetCallerIdentityResult>\
    <ResponseMetadata><RequestId>r</RequestId></ResponseMetadata></GetCallerIdentityResponse>";

type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;

/// Reads from `stream` into `buf` until `done` says enough; `None` if the
/// client went away first.
fn read_until(
    stream: &mut TcpStream,
    buf: &mut Vec<u8>,
    done: impl Fn(&[u8]) -> Option<usize>,
) -> Option<usize> {
    let mut chunk = [0u8; 4096];
    loop {
        if let Some(at) = done(buf) {
            return Some(at);
        }
        match stream.read(&mut chunk) {
            Ok(0) | Err(_) => return None,
            Ok(n) => buf.extend_from_slice(chunk.get(..n)?),
        }
    }
}

/// Serves one connection: STS (POST) and `HeadBucket` (HEAD) succeed, the
/// listing (GET) is held open until the client goes away.
fn serve(mut stream: TcpStream) -> Option<()> {
    let mut buf = Vec::new();
    let head_end = read_until(&mut stream, &mut buf, |b| {
        b.windows(4).position(|w| w == b"\r\n\r\n").map(|at| at + 4)
    })?;
    let head = String::from_utf8_lossy(buf.get(..head_end)?).to_string();
    let length: usize = head
        .lines()
        .find_map(|line| {
            line.to_ascii_lowercase()
                .strip_prefix("content-length:")
                .map(|v| v.trim().parse().unwrap_or(0))
        })
        .unwrap_or(0);
    read_until(&mut stream, &mut buf, |b| {
        (b.len() >= head_end + length).then_some(0)
    })?;
    if head.starts_with("POST") {
        let _ = write!(
            stream,
            "HTTP/1.1 200 OK\r\ncontent-type: text/xml\r\ncontent-length: {}\r\n\
             connection: close\r\n\r\n{STS_BODY}",
            STS_BODY.len()
        );
    } else if head.starts_with("HEAD") {
        let _ = write!(
            stream,
            "HTTP/1.1 200 OK\r\ncontent-length: 0\r\nconnection: close\r\n\r\n"
        );
    } else {
        // The listing: never answered. Hold the connection until the
        // client leaves (or a minute passes).
        let _ = stream.set_read_timeout(Some(Duration::from_secs(60)));
        let _ = stream.read(&mut [0u8; 64]);
    }
    Some(())
}

fn fake_s3() -> Result<u16> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let port = listener.local_addr()?.port();
    thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            thread::spawn(move || serve(stream));
        }
    });
    Ok(port)
}

fn temp_files(dir: &Path) -> Result<Vec<String>> {
    let mut names: Vec<String> = fs::read_dir(dir)?
        .flatten()
        .map(|entry| entry.file_name().to_string_lossy().into_owned())
        .filter(|name| name.ends_with(".lakescan-tmp"))
        .collect();
    names.sort();
    Ok(names)
}

/// What an interrupted run left behind.
struct Aftermath {
    code: Option<i32>,
    stderr: String,
    dir: PathBuf,
}

/// Runs a scan that hangs in its listing, sends `signal`, and returns the
/// exit status, stderr, and the directory it wrote to.
fn interrupted_run(signal: &str, label: &str) -> Result<Aftermath> {
    let port = fake_s3()?;
    let dir = std::env::temp_dir().join(format!(
        "lakescan-interrupt-e2e-{label}-{}",
        std::process::id()
    ));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir)?;
    // An earlier report that a failed run must not disturb.
    fs::write(dir.join("report.html"), "earlier complete report")?;

    let mut child = Command::new(env!("CARGO_BIN_EXE_lakescan"))
        .args(["scan", "s3://some-bucket", "--endpoint-url"])
        .arg(format!("http://127.0.0.1:{port}"))
        .args([
            "--output",
            "summary.txt",
            "--html",
            "report.html",
            "--findings",
            "findings.jsonl",
        ])
        .current_dir(&dir)
        .env("AWS_ACCESS_KEY_ID", "test")
        .env("AWS_SECRET_ACCESS_KEY", "test")
        .env("AWS_REGION", "us-east-1")
        .env_remove("AWS_PROFILE")
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()?;

    // Wait until the run is in its scan: all three temporary files exist.
    let deadline = Instant::now() + Duration::from_secs(20);
    while temp_files(&dir)?.len() < 3 {
        assert!(Instant::now() < deadline, "scan never opened its outputs");
        assert!(child.try_wait()?.is_none(), "lakescan exited early");
        thread::sleep(Duration::from_millis(20));
    }
    // Give it a moment to reach the listing request.
    thread::sleep(Duration::from_millis(300));

    let sent = Command::new("kill")
        .args([signal, &child.id().to_string()])
        .status()?;
    assert!(sent.success());

    let mut stderr = String::new();
    if let Some(mut pipe) = child.stderr.take() {
        pipe.read_to_string(&mut stderr)?;
    }
    let status = child.wait()?;
    Ok(Aftermath {
        code: status.code(),
        stderr,
        dir,
    })
}

#[test]
fn sigint_exits_130_silently_and_leaves_no_temporary_file() -> Result {
    let run = interrupted_run("-INT", "int")?;
    assert_eq!(run.code, Some(130), "stderr: {}", run.stderr);
    assert_eq!(run.stderr, "", "an interrupt prints nothing");
    assert_eq!(temp_files(&run.dir)?, Vec::<String>::new());
    assert_eq!(
        fs::read_to_string(run.dir.join("report.html"))?,
        "earlier complete report"
    );
    for new in ["summary.txt", "findings.jsonl"] {
        assert!(!run.dir.join(new).exists(), "{new} must not appear");
    }
    Ok(fs::remove_dir_all(run.dir)?)
}

#[test]
fn sigterm_exits_143_silently_and_leaves_no_temporary_file() -> Result {
    let run = interrupted_run("-TERM", "term")?;
    assert_eq!(run.code, Some(143), "stderr: {}", run.stderr);
    assert_eq!(run.stderr, "");
    assert_eq!(temp_files(&run.dir)?, Vec::<String>::new());
    assert_eq!(
        fs::read_to_string(run.dir.join("report.html"))?,
        "earlier complete report"
    );
    Ok(fs::remove_dir_all(run.dir)?)
}
