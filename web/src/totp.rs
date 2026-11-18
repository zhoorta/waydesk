//! Time-based one-time codes (RFC 6238: HMAC-SHA1, 6 digits, 30 seconds), their storage, and the limits on guessing them.
//!
//! A code is accepted once: the step it belongs to has to be later than the last one accepted for the account, so a code that was seen (over a
//! shoulder, in a log) cannot be used again within its half minute. Steps one before and one after the present are accepted (clocks differ).
//! Recovery codes are one-time as well and stored as hashes.

use std::collections::HashMap;
use std::fmt::Write as _;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use anyhow::{bail, Context as _, Result};
use hmac::{Hmac, KeyInit as _, Mac};
use sha1::Sha1;
use sha2::{Digest as _, Sha256};
use subtle::ConstantTimeEq as _;

pub const STEP_SECONDS: u64 = 30;
pub const DIGITS: usize = 6;
pub const SECRET_BYTES: usize = 20;
pub const RECOVERY_CODES: usize = 8;

fn hotp(secret: &[u8], counter: u64) -> u32 {
    let mut mac = Hmac::<Sha1>::new_from_slice(secret).expect("HMAC takes a key of any size");
    mac.update(&counter.to_be_bytes());
    let h = mac.finalize().into_bytes();
    let offset = usize::from(h[19] & 0x0f);
    let bin = u32::from_be_bytes([h[offset] & 0x7f, h[offset + 1], h[offset + 2], h[offset + 3]]);
    bin % 10u32.pow(DIGITS as u32)
}

/// The code for the step that holds `unix_seconds`.
#[cfg_attr(not(test), allow(dead_code))]
pub fn code_at(secret: &[u8], unix_seconds: u64) -> String {
    format!("{:0width$}", hotp(secret, unix_seconds / STEP_SECONDS), width = DIGITS)
}

/// The step `input` is a valid code for (the present one or a neighbour), if it is later than `last_step`.
pub fn verify(secret: &[u8], input: &str, unix_seconds: u64, last_step: Option<u64>) -> Option<u64> {
    let input: String = input.chars().filter(|c| !c.is_whitespace()).collect();
    if input.len() != DIGITS || !input.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let now = unix_seconds / STEP_SECONDS;
    let mut found = None;
    // Every candidate is compared, whether or not an earlier one matched, so that the time taken does not say which step was close.
    for step in now.saturating_sub(1)..=now + 1 {
        let expected = format!("{:0width$}", hotp(secret, step), width = DIGITS);
        if bool::from(expected.as_bytes().ct_eq(input.as_bytes())) && last_step.is_none_or(|last| step > last) {
            found = Some(step);
        }
    }
    found
}

pub fn new_secret() -> Result<[u8; SECRET_BYTES]> {
    let mut s = [0u8; SECRET_BYTES];
    getrandom::fill(&mut s).map_err(|e| anyhow::anyhow!("no random numbers: {e}"))?;
    Ok(s)
}

pub fn base32(bytes: &[u8]) -> String {
    data_encoding::BASE32_NOPAD.encode(bytes)
}

fn from_base32(text: &str) -> Option<Vec<u8>> {
    data_encoding::BASE32_NOPAD.decode(text.trim().to_ascii_uppercase().as_bytes()).ok()
}

/// What an authenticator app reads from a QR code.
pub fn otpauth_uri(issuer: &str, account: &str, secret: &[u8]) -> String {
    let enc = |s: &str| s.bytes().fold(String::new(), |mut out, b| {
        if b.is_ascii_alphanumeric() || b"-_.~".contains(&b) {
            out.push(b as char);
        } else {
            let _ = write!(out, "%{b:02X}");
        }
        out
    });
    format!("otpauth://totp/{}:{}?secret={}&issuer={}&algorithm=SHA1&digits={DIGITS}&period={STEP_SECONDS}", enc(issuer), enc(account), base32(secret), enc(issuer))
}

fn hash_recovery(code: &str) -> String {
    let normalized: String = code.chars().filter(|c| c.is_ascii_alphanumeric()).map(|c| c.to_ascii_lowercase()).collect();
    Sha256::digest(normalized.as_bytes()).iter().fold(String::new(), |mut s, b| {
        let _ = write!(s, "{b:02x}");
        s
    })
}

/// New recovery codes, as the user sees them (`abcde-fghij`).
pub fn new_recovery_codes() -> Result<Vec<String>> {
    const ALPHABET: &[u8] = b"abcdefghjkmnpqrstuvwxyz23456789"; // no look-alikes
    (0..RECOVERY_CODES)
        .map(|_| {
            let mut raw = [0u8; 10];
            getrandom::fill(&mut raw).map_err(|e| anyhow::anyhow!("no random numbers: {e}"))?;
            let chars: Vec<char> = raw.iter().map(|b| ALPHABET[usize::from(*b) % ALPHABET.len()] as char).collect();
            Ok(format!("{}-{}", chars[..5].iter().collect::<String>(), chars[5..].iter().collect::<String>()))
        })
        .collect()
}

/// What is kept for an account.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Record {
    pub secret: Vec<u8>,
    pub last_step: Option<u64>,
    /// Hashes of the recovery codes that are still good.
    pub recovery: Vec<String>,
}

impl Record {
    fn to_text(&self) -> String {
        let mut t = format!("secret = {}\n", base32(&self.secret));
        if let Some(s) = self.last_step {
            let _ = writeln!(t, "last_step = {s}");
        }
        for r in &self.recovery {
            let _ = writeln!(t, "recovery = {r}");
        }
        t
    }

    fn from_text(text: &str) -> Option<Self> {
        let (mut secret, mut last_step, mut recovery) = (None, None, Vec::new());
        for line in text.lines() {
            let Some((k, v)) = line.split_once('=') else { continue };
            match k.trim() {
                "secret" => secret = from_base32(v),
                "last_step" => last_step = v.trim().parse().ok(),
                "recovery" => recovery.push(v.trim().to_string()),
                _ => {}
            }
        }
        Some(Self { secret: secret.filter(|s| !s.is_empty())?, last_step, recovery })
    }
}

/// An account name that is safe to use as a file name: what Linux accounts are made of, and not a path.
pub fn valid_account(name: &str) -> bool {
    crate::daemon_gateway::valid_account(name)
}

/// The accounts' records, one file each in a directory.
pub struct Store {
    dir: PathBuf,
    lock: Mutex<()>,
}

impl Store {
    pub fn new(dir: &Path) -> Self {
        Self { dir: dir.to_owned(), lock: Mutex::new(()) }
    }

    fn path(&self, account: &str) -> Option<PathBuf> {
        valid_account(account).then(|| self.dir.join(format!("{account}.totp")))
    }

    pub fn load(&self, account: &str) -> Option<Record> {
        Record::from_text(&std::fs::read_to_string(self.path(account)?).ok()?)
    }

    pub fn exists(&self, account: &str) -> bool {
        self.load(account).is_some()
    }

    /// Writes through a temporary file, so that a crash leaves the old record whole.
    pub fn save(&self, account: &str, record: &Record) -> Result<()> {
        use std::os::unix::fs::PermissionsExt as _;
        let path = self.path(account).with_context(|| format!("{account:?} is not a usable account name"))?;
        std::fs::create_dir_all(&self.dir).with_context(|| format!("cannot create {}", self.dir.display()))?;
        let tmp = path.with_extension("tmp");
        std::fs::write(&tmp, record.to_text())?;
        std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600))?;
        std::fs::rename(&tmp, &path)?;
        // Made by root (`waydesk-web totp add`) in a directory that belongs to the portal's account: the record has to belong to that account too, or the portal
        // cannot read it, and cannot record the codes it uses.
        {
            use std::os::unix::fs::MetadataExt as _;
            let (file, dir) = (std::fs::metadata(&path)?, std::fs::metadata(&self.dir)?);
            if file.uid() != dir.uid() {
                // Only root can give a file away; for anybody else this is a no-op that fails, and the record stays theirs.
                let _ = std::os::unix::fs::chown(&path, Some(dir.uid()), Some(dir.gid()));
            }
        }
        Ok(())
    }

    pub fn remove(&self, account: &str) -> Result<bool> {
        let path = self.path(account).with_context(|| format!("{account:?} is not a usable account name"))?;
        match std::fs::remove_file(path) {
            Ok(()) => Ok(true),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(e) => Err(e.into()),
        }
    }

    pub fn list(&self) -> Vec<String> {
        let mut names: Vec<String> = std::fs::read_dir(&self.dir)
            .into_iter()
            .flatten()
            .flatten()
            .filter_map(|e| e.file_name().to_str()?.strip_suffix(".totp").map(str::to_owned))
            .filter(|n| valid_account(n))
            .collect();
        names.sort();
        names
    }

    /// Makes a record for a new secret (or a new one for an account that has one), with fresh recovery codes. Returns the record to show the user
    /// and the recovery codes in the clear (they are kept as hashes, and cannot be shown again).
    pub fn enroll(&self, account: &str) -> Result<(Record, Vec<String>)> {
        let _guard = self.lock.lock().unwrap_or_else(|e| e.into_inner());
        let codes = new_recovery_codes()?;
        let record = Record { secret: new_secret()?.to_vec(), last_step: None, recovery: codes.iter().map(|c| hash_recovery(c)).collect() };
        self.save(account, &record)?;
        Ok((record, codes))
    }

    /// Makes the record for a secret the person has already proved they hold (they typed a valid code), with fresh recovery codes; `last_step` is the
    /// step of that code, so it cannot be used again to sign in. Refuses an account that has an authenticator (take it away first).
    pub fn enroll_with(&self, account: &str, secret: &[u8], last_step: u64) -> Result<Vec<String>> {
        let _guard = self.lock.lock().unwrap_or_else(|e| e.into_inner());
        anyhow::ensure!(self.load(account).is_none(), "{account} has an authenticator already");
        let codes = new_recovery_codes()?;
        let record = Record { secret: secret.to_vec(), last_step: Some(last_step), recovery: codes.iter().map(|c| hash_recovery(c)).collect() };
        self.save(account, &record)?;
        Ok(codes)
    }

    pub fn new_recovery(&self, account: &str) -> Result<Vec<String>> {
        let _guard = self.lock.lock().unwrap_or_else(|e| e.into_inner());
        let mut record = self.load(account).with_context(|| format!("{account} has no authenticator set up"))?;
        let codes = new_recovery_codes()?;
        record.recovery = codes.iter().map(|c| hash_recovery(c)).collect();
        self.save(account, &record)?;
        Ok(codes)
    }

    /// Checks a code (an authenticator code or a recovery code) for an account and uses it up. The whole check and the update happen under one
    /// lock, so two requests with the same code cannot both succeed.
    pub fn check_and_use(&self, account: &str, input: &str, unix_seconds: u64) -> CodeCheck {
        let _guard = self.lock.lock().unwrap_or_else(|e| e.into_inner());
        let Some(mut record) = self.load(account) else { return CodeCheck::NoAuthenticator };
        if let Some(step) = verify(&record.secret, input, unix_seconds, record.last_step) {
            record.last_step = Some(step);
            return match self.save(account, &record) {
                Ok(()) => CodeCheck::Good,
                Err(e) => {
                    // A code that cannot be recorded as used is not accepted; say why, because this is a setup problem (the directory is not writable).
                    tracing::warn!("cannot record a used code for {account}: {e:#}");
                    CodeCheck::Wrong
                }
            };
        }
        let hashed = hash_recovery(input);
        if let Some(pos) = record.recovery.iter().position(|h| bool::from(h.as_bytes().ct_eq(hashed.as_bytes()))) {
            record.recovery.remove(pos);
            return match self.save(account, &record) {
                Ok(()) => CodeCheck::GoodRecovery(record.recovery.len()),
                Err(_) => CodeCheck::Wrong,
            };
        }
        CodeCheck::Wrong
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum CodeCheck {
    Good,
    /// A recovery code was used; this many are left.
    GoodRecovery(usize),
    Wrong,
    NoAuthenticator,
}

/// How many wrong codes are allowed. The per-account limit stops a spread-out guess (many addresses, one account); the per-address-and-account
/// one stops one client, and costs the real user little.
pub struct Guesses {
    per_account: usize,
    per_pair: usize,
    window: Duration,
    lock: Mutex<GuessState>,
}

#[derive(Default)]
struct GuessState {
    account: HashMap<String, Vec<Instant>>,
    pair: HashMap<(IpAddr, String), Vec<Instant>>,
}

impl Guesses {
    pub fn new(per_account: usize, per_pair: usize, window: Duration) -> Self {
        Self { per_account, per_pair, window, lock: Mutex::new(GuessState::default()) }
    }

    pub fn blocked(&self, ip: IpAddr, account: &str, now: Instant) -> bool {
        let mut s = self.lock.lock().unwrap_or_else(|e| e.into_inner());
        let w = self.window;
        let recent = |v: &mut Vec<Instant>| {
            v.retain(|t| now.duration_since(*t) < w);
            v.len()
        };
        s.account.get_mut(account).is_some_and(|v| recent(v) >= self.per_account) || s.pair.get_mut(&(crate::limits::key(ip), account.to_owned())).is_some_and(|v| recent(v) >= self.per_pair)
    }

    pub fn failed(&self, ip: IpAddr, account: &str, now: Instant) {
        let mut s = self.lock.lock().unwrap_or_else(|e| e.into_inner());
        // A bound on the memory: when the tables are large, old entries go first.
        if s.account.len() > 50_000 || s.pair.len() > 50_000 {
            let w = self.window;
            s.account.retain(|_, v| v.last().is_some_and(|t| now.duration_since(*t) < w));
            s.pair.retain(|_, v| v.last().is_some_and(|t| now.duration_since(*t) < w));
        }
        s.account.entry(account.to_owned()).or_default().push(now);
        s.pair.entry((crate::limits::key(ip), account.to_owned())).or_default().push(now);
    }

    pub fn succeeded(&self, ip: IpAddr, account: &str) {
        let mut s = self.lock.lock().unwrap_or_else(|e| e.into_inner());
        s.pair.remove(&(crate::limits::key(ip), account.to_owned()));
    }
}

/// `waydesk-web totp ...`: set up and take away the authenticator of an account. Run it as root; it hands the files to the gateway's account.
pub fn cli(args: &[String]) -> Result<()> {
    let mut dir = PathBuf::from("/etc/waydesk/totp");
    let mut issuer = "Waydesk".to_string();
    let mut rest = Vec::new();
    let mut it = args.iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "--dir" => dir = PathBuf::from(it.next().context("--dir needs a value")?),
            "--issuer" => issuer = it.next().context("--issuer needs a value")?.clone(),
            other => rest.push(other.to_owned()),
        }
    }
    let store = Store::new(&dir);
    let usage = "usage: waydesk-web totp add ACCOUNT | recovery ACCOUNT | remove ACCOUNT | list   [--dir DIR] [--issuer NAME]";
    match rest.iter().map(String::as_str).collect::<Vec<_>>().as_slice() {
        ["add", account] => {
            if !valid_account(account) {
                bail!("{account:?} is not a usable account name");
            }
            let existed = store.exists(account);
            let (record, codes) = store.enroll(account)?;
            hand_over(&dir, &store, account);
            let uri = otpauth_uri(&issuer, account, &record.secret);
            println!("{} for {account}{}", if existed { "New authenticator" } else { "Authenticator set up" }, if existed { " (the old one no longer works)" } else { "" });
            println!("\nScan this in an authenticator app (or type the key by hand):\n");
            if let Ok(out) = std::process::Command::new("qrencode").args(["-t", "ANSIUTF8", &uri]).output() {
                if out.status.success() {
                    println!("{}", String::from_utf8_lossy(&out.stdout));
                }
            }
            println!("  key: {}\n  uri: {uri}\n", base32(&record.secret));
            println!("Recovery codes (each works once; keep them somewhere safe, they are not shown again):\n");
            for c in codes {
                println!("  {c}");
            }
            Ok(())
        }
        ["recovery", account] => {
            let codes = store.new_recovery(account)?;
            hand_over(&dir, &store, account);
            println!("New recovery codes for {account} (the old ones no longer work):\n");
            for c in codes {
                println!("  {c}");
            }
            Ok(())
        }
        ["remove", account] => {
            println!("{}", if store.remove(account)? { format!("{account} no longer needs a code") } else { format!("{account} had no authenticator") });
            Ok(())
        }
        ["list"] => {
            for n in store.list() {
                println!("{n}");
            }
            Ok(())
        }
        _ => bail!("{usage}"),
    }
}

/// Gives the directory and the account's file to the gateway's account (`waydesk`), if it exists and this runs as root: the gateway has to write
/// the record (the last step used, the recovery codes used up).
fn hand_over(dir: &Path, store: &Store, account: &str) {
    use std::os::unix::fs::PermissionsExt as _;
    let Some((uid, gid)) = std::fs::read_to_string("/etc/passwd").ok().and_then(|p| {
        p.lines().find_map(|l| {
            let f: Vec<&str> = l.split(':').collect();
            (f.first() == Some(&"waydesk") && f.len() > 3).then(|| Some((f[2].parse::<u32>().ok()?, f[3].parse::<u32>().ok()?)))?
        })
    }) else {
        return;
    };
    let _ = std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700));
    let _ = std::os::unix::fs::chown(dir, Some(uid), Some(gid));
    if let Some(p) = store.path(account) {
        let _ = std::os::unix::fs::chown(p, Some(uid), Some(gid));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // RFC 6238, appendix B: the SHA-1 secret "12345678901234567890"; the RFC lists 8 digits, these are the last 6.
    const RFC_SECRET: &[u8] = b"12345678901234567890";

    #[test]
    fn the_codes_of_the_rfc() {
        for (t, code) in [(59, "287082"), (1_111_111_109, "081804"), (1_111_111_111, "050471"), (1_234_567_890, "005924"), (2_000_000_000, "279037"), (20_000_000_000, "353130")] {
            assert_eq!(code_at(RFC_SECRET, t), code, "at {t}");
        }
    }

    #[test]
    fn neighbouring_steps_are_accepted_and_others_are_not() {
        let t = 1_111_111_111;
        let now = code_at(RFC_SECRET, t);
        assert_eq!(verify(RFC_SECRET, &now, t, None), Some(t / 30));
        assert_eq!(verify(RFC_SECRET, &code_at(RFC_SECRET, t - 30), t, None), Some(t / 30 - 1), "a clock a little slow");
        assert_eq!(verify(RFC_SECRET, &code_at(RFC_SECRET, t + 30), t, None), Some(t / 30 + 1), "a clock a little fast");
        assert_eq!(verify(RFC_SECRET, &code_at(RFC_SECRET, t - 90), t, None), None, "three steps old");
        assert_eq!(verify(RFC_SECRET, "000000", t, None).is_some(), now == "000000" || code_at(RFC_SECRET, t - 30) == "000000" || code_at(RFC_SECRET, t + 30) == "000000");
    }

    #[test]
    fn a_code_works_once() {
        let t = 1_111_111_111;
        let code = code_at(RFC_SECRET, t);
        let step = verify(RFC_SECRET, &code, t, None).unwrap();
        assert_eq!(verify(RFC_SECRET, &code, t, Some(step)), None, "the same step again");
        assert_eq!(verify(RFC_SECRET, &code, t + 5, Some(step)), None, "and a few seconds later");
        assert!(verify(RFC_SECRET, &code_at(RFC_SECRET, t + 30), t + 30, Some(step)).is_some(), "the next step is fine");
    }

    #[test]
    fn input_that_is_not_six_digits_is_refused_whatever_it_is() {
        for bad in ["", "12345", "1234567", "12345a", "１２３４５６", "123 45", "-12345"] {
            let r = verify(RFC_SECRET, bad, 59, None);
            // "123 45" is five digits once the blank is gone; none of these is a valid code.
            assert_eq!(r, None, "{bad:?}");
        }
        let code = code_at(RFC_SECRET, 59);
        let spaced = format!("{} {}", &code[..3], &code[3..]);
        assert!(verify(RFC_SECRET, &spaced, 59, None).is_some(), "a code typed with a blank in the middle (apps show it so)");
    }

    #[test]
    fn the_uri_for_an_authenticator_app() {
        let uri = otpauth_uri("Waydesk", "ana lima", RFC_SECRET);
        assert_eq!(uri, "otpauth://totp/Waydesk:ana%20lima?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=Waydesk&algorithm=SHA1&digits=6&period=30");
        assert_eq!(from_base32("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ").unwrap(), RFC_SECRET);
        assert_eq!(from_base32("gezdgnbvgy3tqojqgezdgnbvgy3tqojq").unwrap(), RFC_SECRET, "lower case is read too");
    }

    #[test]
    fn account_names_cannot_be_paths() {
        for ok in ["ana", "ana.lima", "a_b-c", "User1"] {
            assert!(valid_account(ok), "{ok}");
        }
        for bad in ["", ".hidden", "-x", "a/b", "../x", "a b", "a\0b", &"x".repeat(33), "ana:lima"] {
            assert!(!valid_account(bad), "{bad:?}");
        }
    }

    fn temp_store(name: &str) -> (Store, PathBuf) {
        let dir = std::env::temp_dir().join(format!("waydesk-totp-test-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        (Store::new(&dir), dir)
    }

    #[test]
    fn enrolling_and_checking_codes_end_to_end() {
        let (store, dir) = temp_store("flow");
        assert!(!store.exists("ana"));
        assert_eq!(store.check_and_use("ana", "123456", 1000), CodeCheck::NoAuthenticator);
        let (record, recovery) = store.enroll("ana").unwrap();
        assert_eq!(recovery.len(), RECOVERY_CODES);
        assert!(store.exists("ana"));
        let t = 1_700_000_000;
        let code = code_at(&record.secret, t);
        assert_eq!(store.check_and_use("ana", &code, t), CodeCheck::Good);
        assert_eq!(store.check_and_use("ana", &code, t), CodeCheck::Wrong, "the same code twice");
        assert_eq!(store.check_and_use("ana", "000000x", t), CodeCheck::Wrong);
        // A recovery code works once.
        assert_eq!(store.check_and_use("ana", &recovery[0], t), CodeCheck::GoodRecovery(RECOVERY_CODES - 1));
        assert_eq!(store.check_and_use("ana", &recovery[0], t), CodeCheck::Wrong);
        let upper = recovery[1].to_ascii_uppercase().replace('-', " ");
        assert_eq!(store.check_and_use("ana", &upper, t), CodeCheck::GoodRecovery(RECOVERY_CODES - 2), "typed in capitals and with a blank");
        // The record is on disk, and not readable by others.
        use std::os::unix::fs::PermissionsExt as _;
        assert_eq!(std::fs::metadata(dir.join("ana.totp")).unwrap().permissions().mode() & 0o777, 0o600);
        // A new set-up replaces the secret and the recovery codes.
        let (again, _) = store.enroll("ana").unwrap();
        assert_ne!(again.secret, record.secret);
        assert_eq!(store.check_and_use("ana", &code_at(&record.secret, t + 60), t + 60), CodeCheck::Wrong, "the old secret is gone");
        assert_eq!(store.list(), vec!["ana".to_string()]);
        assert!(store.remove("ana").unwrap());
        assert!(!store.remove("ana").unwrap());
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn a_bad_account_name_never_reaches_the_disk() {
        let (store, dir) = temp_store("names");
        assert!(store.enroll("../evil").is_err());
        assert!(store.load("../evil").is_none());
        assert_eq!(store.check_and_use("../evil", "123456", 0), CodeCheck::NoAuthenticator);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn wrong_codes_block_by_account_and_by_address_and_account() {
        let g = Guesses::new(6, 3, Duration::from_secs(600));
        let (a, b): (IpAddr, IpAddr) = ("203.0.113.1".parse().unwrap(), "203.0.113.2".parse().unwrap());
        let t0 = Instant::now();
        for _ in 0..3 {
            assert!(!g.blocked(a, "ana", t0));
            g.failed(a, "ana", t0);
        }
        assert!(g.blocked(a, "ana", t0), "three wrong from one address for one account");
        assert!(!g.blocked(b, "ana", t0), "another address can still try");
        assert!(!g.blocked(a, "bob", t0), "and this address can try another account");
        for _ in 0..3 {
            g.failed(b, "ana", t0);
        }
        assert!(g.blocked(b, "ana", t0) && g.blocked("203.0.113.9".parse().unwrap(), "ana", t0), "six in all: the account itself is blocked, for every address");
        assert!(!g.blocked(a, "ana", t0 + Duration::from_secs(601)), "and it passes");
        g.failed(a, "ana", t0 + Duration::from_secs(700));
        g.succeeded(a, "ana");
        assert!(!g.blocked(a, "ana", t0 + Duration::from_secs(701)));
    }
}
