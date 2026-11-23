//! The people the portal owns (stage 3, slice 3 of docs/PORTAL-DESIGN.md): accounts of the portal itself, with a password kept as an argon2id hash,
//! the servers each person is assigned to, and whether they administer the portal.
//!
//! A portal user is not a system account: nothing here gives access to the portal's own machine through the root helper. On a server the person
//! gets a system account of the same name (made by the server's agent when they are assigned), with a password nobody is told, or the app password
//! the person asked for. Two-step codes (TOTP) are kept per person in their own directory, apart from the host accounts' (`web.rs`).
//!
//! The file (`people.json`) is written through a temporary file, mode 0600, and a failed save changes nothing in memory. Passwords and the app
//! password are never kept in the clear; the app password is not kept at all (the servers hold it as their account's password).
#![cfg_attr(not(test), allow(dead_code))]

use std::fs;
use std::io::Write as _;
use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _, PermissionsExt as _};
use std::path::PathBuf;
use std::sync::{Mutex, OnceLock};

use anyhow::{bail, Context as _, Result};
use argon2::password_hash::{PasswordHash, PasswordHasher as _, PasswordVerifier as _, SaltString};
use argon2::Argon2;
use serde::{Deserialize, Serialize};

pub const MAX_PEOPLE: usize = 5000;
/// Most servers one person may be assigned to.
pub const MAX_ASSIGNMENTS: usize = 50;
pub const MIN_PASSWORD: usize = 8;
pub const MAX_PASSWORD: usize = 128;

/// One server a person may use, with the settings that apply to them there (`None`: the server's own setting).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Assignment {
    pub server: String,
    pub desktop: Option<String>,
    pub gpu: Option<String>,
    pub memory: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct Person {
    name: String,
    display: String,
    /// Where the account comes from: `local` now; a directory or a single sign-on provider later (no migration needed).
    origin: String,
    /// argon2id, with its salt and parameters (a PHC string).
    hash: String,
    admin: bool,
    disabled: bool,
    created: u64,
    app_password_set: Option<u64>,
    servers: Vec<Assignment>,
    /// Servers where the portal itself made this person's system account. Only there may the portal switch the account on again or set its
    /// password: an account of that name that was already on a server belongs to somebody else.
    #[serde(default)]
    made_on: Vec<String>,
}

/// What pages and the API show about a person: never the hash.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct View {
    pub name: String,
    pub display: String,
    pub origin: String,
    pub admin: bool,
    pub disabled: bool,
    pub created: u64,
    pub app_password_set: Option<u64>,
    pub servers: Vec<Assignment>,
}

impl From<&Person> for View {
    fn from(p: &Person) -> Self {
        View { name: p.name.clone(), display: p.display.clone(), origin: p.origin.clone(), admin: p.admin, disabled: p.disabled, created: p.created, app_password_set: p.app_password_set, servers: p.servers.clone() }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum Verdict {
    /// The password is right and the account may sign in.
    Good(View),
    /// Wrong password, unknown name or a switched-off account. The caller says the same to everybody; the log may tell them apart.
    Refused(&'static str),
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct Data {
    people: Vec<Person>,
}

pub struct People {
    path: Option<PathBuf>,
    data: Mutex<Data>,
    /// When the file was last read or written by this process: a change from outside (`waydesk-web people add`, run as root next to a running portal)
    /// is picked up on the next look, without a restart.
    stamp: Mutex<Option<std::time::SystemTime>>,
}

/// The same rule as `adminaction::valid_name`: what `useradd` takes. A portal name becomes the name of the system account on every server.
pub fn valid_name(name: &str) -> bool {
    let mut chars = name.chars();
    let Some(first) = chars.next() else { return false };
    name.len() <= 32 && (first.is_ascii_lowercase() || first == '_') && name.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_' || c == '-')
}

pub fn valid_display(d: &str) -> bool {
    d.chars().count() <= 60 && d == d.trim() && !d.chars().any(char::is_control) && !d.contains(['<', '>', '&', '"'])
}

pub fn valid_password(p: &str) -> bool {
    (MIN_PASSWORD..=MAX_PASSWORD).contains(&p.chars().count()) && p.len() <= MAX_PASSWORD * 4 && !p.contains(['\n', '\r', '\0'])
}

/// 16 characters of a 32 letter alphabet (80 bits) in groups of four: easy to read out and to type. Used for first passwords and app passwords.
pub fn generate_password() -> Result<String> {
    const ALPHABET: &[u8; 32] = b"abcdefghijklmnopqrstuvwxyz234567";
    let mut raw = [0u8; 16];
    getrandom::fill(&mut raw).map_err(|e| anyhow::anyhow!("no randomness: {e}"))?;
    let letters: Vec<char> = raw.iter().map(|b| ALPHABET[usize::from(*b) % 32] as char).collect();
    Ok(letters.chunks(4).map(|c| c.iter().collect::<String>()).collect::<Vec<_>>().join("-"))
}

fn hash(password: &str) -> Result<String> {
    let mut salt = [0u8; 16];
    getrandom::fill(&mut salt).map_err(|e| anyhow::anyhow!("no randomness: {e}"))?;
    let salt = SaltString::encode_b64(&salt).map_err(|e| anyhow::anyhow!("salt: {e}"))?;
    Ok(Argon2::default().hash_password(password.as_bytes(), &salt).map_err(|e| anyhow::anyhow!("hashing: {e}"))?.to_string())
}

fn verify_hash(password: &str, phc: &str) -> bool {
    PasswordHash::new(phc).is_ok_and(|h| Argon2::default().verify_password(password.as_bytes(), &h).is_ok())
}

/// A hash nobody knows the password of, checked when the name is unknown or switched off, so that those take as long as a wrong password.
fn decoy() -> &'static str {
    static DECOY: OnceLock<String> = OnceLock::new();
    DECOY.get_or_init(|| hash(&generate_password().unwrap_or_else(|_| "decoy-password".into())).unwrap_or_default())
}

impl People {
    pub fn open(path: PathBuf) -> Result<Self> {
        let data = match fs::read_to_string(&path) {
            Ok(text) => serde_json::from_str(&text).with_context(|| format!("{} is not a valid people file", path.display()))?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Data::default(),
            Err(e) => return Err(e).with_context(|| format!("reading {}", path.display())),
        };
        let stamp = fs::metadata(&path).and_then(|m| m.modified()).ok();
        Ok(People { path: Some(path), data: Mutex::new(data), stamp: Mutex::new(stamp) })
    }

    pub fn in_memory() -> Self {
        People { path: None, data: Mutex::new(Data::default()), stamp: Mutex::new(None) }
    }

    /// Reads the file again when somebody else changed it. A file that does not parse is ignored (the people already in memory stay).
    fn refresh(&self) {
        let Some(path) = &self.path else { return };
        let Ok(modified) = fs::metadata(path).and_then(|m| m.modified()) else { return };
        let (Ok(mut stamp), Ok(mut data)) = (self.stamp.lock(), self.data.lock()) else { return };
        if *stamp == Some(modified) {
            return;
        }
        if let Some(fresh) = fs::read_to_string(path).ok().and_then(|t| serde_json::from_str::<Data>(&t).ok()) {
            *data = fresh;
            *stamp = Some(modified);
        }
    }

    fn save(&self, data: &Data) -> Result<()> {
        let Some(path) = &self.path else { return Ok(()) };
        if let Some(dir) = path.parent() {
            fs::create_dir_all(dir)?;
        }
        let tmp = path.with_extension("tmp");
        let mut f = fs::OpenOptions::new().write(true).create(true).truncate(true).mode(0o600).open(&tmp)?;
        f.write_all(&serde_json::to_vec_pretty(data)?)?;
        f.sync_all()?;
        fs::set_permissions(&tmp, fs::Permissions::from_mode(0o600))?;
        fs::rename(&tmp, path)?;
        // Made by root (`waydesk-web people add`) in the portal's directory: the file has to belong to the portal's account, or the portal cannot write it.
        if let Some(dir) = path.parent() {
            if let (Ok(file), Ok(d)) = (fs::metadata(path), fs::metadata(dir)) {
                if file.uid() != d.uid() {
                    let _ = std::os::unix::fs::chown(path, Some(d.uid()), Some(d.gid()));
                }
            }
        }
        Ok(())
    }

    fn edit<T>(&self, change: impl FnOnce(&mut Data) -> Result<T>) -> Result<T> {
        self.refresh();
        let mut g = self.data.lock().map_err(|_| anyhow::anyhow!("people lock poisoned"))?;
        let mut copy = Data { people: g.people.clone() };
        let out = change(&mut copy)?;
        self.save(&copy)?;
        *g = copy;
        if let (Some(path), Ok(mut stamp)) = (&self.path, self.stamp.lock()) {
            *stamp = fs::metadata(path).and_then(|m| m.modified()).ok();
        }
        Ok(out)
    }

    /// A new person with a first password, returned once. Needs no hashing time from the caller's thread budget beyond one argon2 run.
    pub fn add(&self, name: &str, display: &str, admin: bool, now: u64) -> Result<String> {
        if !valid_name(name) {
            bail!("the name must be lower case letters, digits, _ and -, starting with a letter, at most 32");
        }
        if !valid_display(display) {
            bail!("the display name is too long or has characters that are not allowed");
        }
        let password = generate_password()?;
        let phc = hash(&password)?;
        self.edit(|d| {
            if d.people.len() >= MAX_PEOPLE {
                bail!("too many people");
            }
            if d.people.iter().any(|p| p.name == name) {
                bail!("that name is taken");
            }
            d.people.push(Person { name: name.into(), display: display.into(), origin: "local".into(), hash: phc, admin, disabled: false, created: now, app_password_set: None, servers: Vec::new(), made_on: Vec::new() });
            Ok(())
        })?;
        Ok(password)
    }

    /// Checks a password. Always does the hashing work, whatever the name.
    pub fn verify(&self, name: &str, password: &str) -> Verdict {
        self.refresh();
        let found = self.data.lock().ok().and_then(|g| g.people.iter().find(|p| p.name == name).cloned());
        match found {
            None => {
                let _ = verify_hash(password, decoy());
                Verdict::Refused("unknown account")
            }
            Some(p) => {
                let right = verify_hash(password, &p.hash);
                if !right {
                    Verdict::Refused("wrong password")
                } else if p.disabled {
                    Verdict::Refused("account switched off")
                } else {
                    Verdict::Good(View::from(&p))
                }
            }
        }
    }

    pub fn exists(&self, name: &str) -> bool {
        self.refresh();
        self.data.lock().is_ok_and(|g| g.people.iter().any(|p| p.name == name))
    }

    pub fn get(&self, name: &str) -> Option<View> {
        self.refresh();
        self.data.lock().ok()?.people.iter().find(|p| p.name == name).map(View::from)
    }

    pub fn list(&self) -> Vec<View> {
        self.refresh();
        let Ok(g) = self.data.lock() else { return Vec::new() };
        let mut v: Vec<View> = g.people.iter().map(View::from).collect();
        v.sort_by(|a, b| a.name.cmp(&b.name));
        v
    }

    /// Whether `name` is a person who may administer the portal now (not switched off).
    pub fn is_admin(&self, name: &str) -> bool {
        self.refresh();
        self.data.lock().is_ok_and(|g| g.people.iter().any(|p| p.name == name && p.admin && !p.disabled))
    }

    fn with<T>(d: &mut Data, name: &str, f: impl FnOnce(&mut Person) -> Result<T>) -> Result<T> {
        f(d.people.iter_mut().find(|p| p.name == name).context("no such person")?)
    }

    /// Administrators that can sign in, not counting `except`.
    fn other_admins(d: &Data, except: &str) -> usize {
        d.people.iter().filter(|p| p.admin && !p.disabled && p.name != except).count()
    }

    /// A new password chosen by an administrator's reset (returned once) or `Some(new)` for the person's own change.
    pub fn set_password(&self, name: &str, new: Option<&str>) -> Result<String> {
        let password = match new {
            Some(p) if valid_password(p) => p.to_string(),
            Some(_) => bail!("the password must be {MIN_PASSWORD} to {MAX_PASSWORD} characters, on one line"),
            None => generate_password()?,
        };
        let phc = hash(&password)?;
        self.edit(|d| Self::with(d, name, |p| {
            p.hash = phc;
            Ok(())
        }))?;
        Ok(password)
    }

    /// The person's own change: the old password has to be right (the caller counts failures).
    pub fn change_password(&self, name: &str, old: &str, new: &str) -> Result<()> {
        if !valid_password(new) {
            bail!("the new password must be {MIN_PASSWORD} to {MAX_PASSWORD} characters, on one line");
        }
        if new == old {
            bail!("the new password is the same as the old one");
        }
        match self.verify(name, old) {
            Verdict::Good(_) => {}
            Verdict::Refused(_) => bail!("the current password is not right"),
        }
        self.set_password(name, Some(new)).map(|_| ())
    }

    pub fn set_admin(&self, name: &str, admin: bool) -> Result<()> {
        self.edit(|d| {
            if !admin && Self::other_admins(d, name) == 0 {
                bail!("somebody has to stay an administrator");
            }
            Self::with(d, name, |p| {
                p.admin = admin;
                Ok(())
            })
        })
    }

    pub fn set_disabled(&self, name: &str, disabled: bool) -> Result<()> {
        self.edit(|d| {
            if disabled && Self::other_admins(d, name) == 0 && d.people.iter().any(|p| p.name == name && p.admin) {
                bail!("somebody has to stay an administrator");
            }
            Self::with(d, name, |p| {
                p.disabled = disabled;
                Ok(())
            })
        })
    }

    /// Removes the person's record. Their assignments have to be taken away first (so that their accounts on servers are switched off, not forgotten).
    pub fn remove(&self, name: &str) -> Result<()> {
        self.edit(|d| {
            let i = d.people.iter().position(|p| p.name == name).context("no such person")?;
            if !d.people[i].servers.is_empty() {
                bail!("take their servers away first");
            }
            if d.people[i].admin && Self::other_admins(d, name) == 0 {
                bail!("somebody has to stay an administrator");
            }
            d.people.remove(i);
            Ok(())
        })
    }

    /// Assigns a server (or changes the settings of an assignment).
    pub fn assign(&self, name: &str, a: Assignment) -> Result<()> {
        self.edit(|d| Self::with(d, name, |p| {
            match p.servers.iter_mut().find(|s| s.server == a.server) {
                Some(s) => *s = a,
                None => {
                    if p.servers.len() >= MAX_ASSIGNMENTS {
                        bail!("too many servers for one person");
                    }
                    p.servers.push(a);
                }
            }
            Ok(())
        }))
    }

    pub fn unassign(&self, name: &str, server: &str) -> Result<()> {
        self.edit(|d| Self::with(d, name, |p| {
            let before = p.servers.len();
            p.servers.retain(|s| s.server != server);
            if p.servers.len() == before {
                bail!("that server is not assigned");
            }
            Ok(())
        }))
    }

    /// The portal made this person's system account on `server`.
    pub fn mark_made(&self, name: &str, server: &str) -> Result<()> {
        self.edit(|d| Self::with(d, name, |p| {
            if !p.made_on.iter().any(|s| s == server) {
                p.made_on.push(server.to_string());
            }
            Ok(())
        }))
    }

    /// A server was removed from the portal: forget it in every person's record of where the portal made accounts.
    pub fn forget_server(&self, server: &str) -> Result<()> {
        self.edit(|d| {
            for p in d.people.iter_mut() {
                p.made_on.retain(|s| s != server);
            }
            Ok(())
        })
    }

    pub fn made_on(&self, name: &str, server: &str) -> bool {
        self.refresh();
        self.data.lock().is_ok_and(|g| g.people.iter().any(|p| p.name == name && p.made_on.iter().any(|s| s == server)))
    }

    pub fn mark_app_password(&self, name: &str, now: u64) -> Result<()> {
        self.edit(|d| Self::with(d, name, |p| {
            p.app_password_set = Some(now);
            Ok(())
        }))
    }

    /// Names of the people assigned to a server (to be told when it is removed).
    pub fn assigned_to(&self, server: &str) -> Vec<String> {
        self.list().into_iter().filter(|p| p.servers.iter().any(|s| s.server == server)).map(|p| p.name).collect()
    }
}

/// `waydesk-web people add NAME [--admin] [--display TEXT] | list | passwd NAME | remove NAME`: run as root on the portal's machine; the first administrator
/// is made this way. The password is printed once.
pub fn cli(args: &[String], dir: &std::path::Path) -> Result<()> {
    let people = People::open(dir.join("people.json"))?;
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_secs());
    match args.iter().map(String::as_str).collect::<Vec<_>>().as_slice() {
        ["list"] => {
            for p in people.list() {
                println!("{}{}{}\t{}", p.name, if p.admin { "\tadmin" } else { "" }, if p.disabled { "\toff" } else { "" }, p.display);
            }
            Ok(())
        }
        ["add", name, rest @ ..] => {
            let admin = rest.contains(&"--admin");
            let display = rest.iter().position(|a| *a == "--display").and_then(|i| rest.get(i + 1)).copied().unwrap_or("");
            let password = people.add(name, display, admin, now)?;
            println!("made {name}{}; the password is shown once: {password}", if admin { " (administrator)" } else { "" });
            Ok(())
        }
        ["passwd", name] => {
            let password = people.set_password(name, None)?;
            println!("new password for {name}, shown once: {password}");
            Ok(())
        }
        ["remove", name] => {
            people.remove(name)?;
            println!("removed {name}");
            Ok(())
        }
        _ => bail!("usage: waydesk-web people add NAME [--admin] [--display TEXT] | list | passwd NAME | remove NAME"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const T: u64 = 1_000;

    fn two() -> (People, String, String) {
        let p = People::in_memory();
        let boss = p.add("boss", "The Boss", true, T).unwrap();
        let ana = p.add("ana", "", false, T).unwrap();
        (p, boss, ana)
    }

    #[test]
    fn a_person_signs_in_with_the_password_they_were_given_and_no_other() {
        let (p, boss, _) = two();
        assert!(matches!(p.verify("boss", &boss), Verdict::Good(v) if v.admin && v.display == "The Boss"));
        assert_eq!(p.verify("boss", "wrong-password"), Verdict::Refused("wrong password"));
        assert_eq!(p.verify("nobody", &boss), Verdict::Refused("unknown account"));
        assert_eq!(p.verify("boss", ""), Verdict::Refused("wrong password"));
    }

    #[test]
    fn the_hash_is_argon2id_salted_and_the_password_is_not_in_the_file() {
        let dir = std::env::temp_dir().join(format!("wd-people-{}", std::process::id()));
        let path = dir.join("people.json");
        let _ = fs::remove_dir_all(&dir);
        let pw = {
            let p = People::open(path.clone()).unwrap();
            p.add("ana", "", false, T).unwrap()
        };
        let text = fs::read_to_string(&path).unwrap();
        assert!(text.contains("$argon2id$v=19$"), "{text}");
        assert!(!text.contains(&pw));
        assert_eq!(fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600);
        // Kept between runs.
        assert!(matches!(People::open(path.clone()).unwrap().verify("ana", &pw), Verdict::Good(_)));
        // Two people with one password get different hashes (salt).
        let p = People::in_memory();
        p.add("a", "", false, T).unwrap();
        p.set_password("a", Some("same password here")).unwrap();
        p.add("b", "", false, T).unwrap();
        p.set_password("b", Some("same password here")).unwrap();
        let (ha, hb) = { let g = p.data.lock().unwrap(); (g.people[0].hash.clone(), g.people[1].hash.clone()) };
        assert_ne!(ha, hb);
        fs::write(&path, "not json").unwrap();
        assert!(People::open(path).is_err(), "a broken file is an error, not an empty list");
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn a_switched_off_account_cannot_sign_in_and_is_not_an_administrator() {
        let (p, boss, ana) = two();
        p.set_disabled("ana", true).unwrap();
        assert_eq!(p.verify("ana", &ana), Verdict::Refused("account switched off"));
        p.set_admin("ana", true).unwrap();
        assert!(!p.is_admin("ana"), "switched off");
        p.set_disabled("ana", false).unwrap();
        assert!(p.is_admin("ana") && p.is_admin("boss"));
        assert!(matches!(p.verify("boss", &boss), Verdict::Good(_)));
    }

    #[test]
    fn somebody_always_stays_an_administrator() {
        let (p, _, _) = two();
        assert!(p.set_admin("boss", false).is_err());
        assert!(p.set_disabled("boss", true).is_err());
        assert!(p.remove("boss").is_err());
        p.set_admin("ana", true).unwrap();
        p.set_admin("boss", false).unwrap();
        assert!(p.set_disabled("ana", true).is_err(), "ana is the last one now");
        p.set_disabled("boss", true).unwrap(); // not an admin any more: fine
    }

    #[test]
    fn a_person_changes_their_own_password_only_with_the_old_one() {
        let (p, _, ana) = two();
        assert!(p.change_password("ana", "not-the-old-one", "a new password!").is_err());
        assert!(p.change_password("ana", &ana, "short").is_err());
        assert!(p.change_password("ana", &ana, &ana).is_err());
        p.change_password("ana", &ana, "a new password!").unwrap();
        assert_eq!(p.verify("ana", &ana), Verdict::Refused("wrong password"));
        assert!(matches!(p.verify("ana", "a new password!"), Verdict::Good(_)));
    }

    #[test]
    fn an_administrators_reset_makes_a_new_password_shown_once() {
        let (p, _, ana) = two();
        let new = p.set_password("ana", None).unwrap();
        assert_ne!(new, ana);
        assert_eq!(new.len(), 19, "four groups of four");
        assert!(matches!(p.verify("ana", &new), Verdict::Good(_)));
        assert_eq!(p.verify("ana", &ana), Verdict::Refused("wrong password"));
    }

    #[test]
    fn names_and_passwords_are_checked() {
        let p = People::in_memory();
        for bad in ["", "Ana", "9a", "a b", "../x", "a;b", &"a".repeat(33)] {
            assert!(p.add(bad, "", false, T).is_err(), "{bad:?}");
        }
        assert!(p.add("ok", "<b>", false, T).is_err());
        assert!(p.add("ok", "bad\nname", false, T).is_err());
        p.add("ok", "José M.", false, T).unwrap();
        assert!(p.add("ok", "", false, T).is_err(), "taken");
        assert!(p.set_password("ok", Some("two\nlines of text")).is_err());
        assert!(p.set_password("ok", Some(&"x".repeat(129))).is_err());
        assert!(!valid_password("1234567") && valid_password("12345678"));
    }

    #[test]
    fn servers_are_assigned_changed_and_taken_away_and_a_person_with_servers_is_not_removed() {
        let (p, _, _) = two();
        let a = |s: &str, d: Option<&str>| Assignment { server: s.into(), desktop: d.map(Into::into), gpu: None, memory: None };
        p.assign("ana", a("s-1", None)).unwrap();
        p.assign("ana", a("s-2", Some("plasma"))).unwrap();
        p.assign("ana", a("s-1", Some("sway"))).unwrap(); // a change, not a second entry
        let v = p.get("ana").unwrap();
        assert_eq!(v.servers.len(), 2);
        assert_eq!(v.servers[0].desktop.as_deref(), Some("sway"));
        assert_eq!(p.assigned_to("s-2"), ["ana"]);
        assert!(p.remove("ana").is_err());
        assert!(p.unassign("ana", "s-9").is_err());
        p.unassign("ana", "s-1").unwrap();
        p.unassign("ana", "s-2").unwrap();
        p.remove("ana").unwrap();
        assert!(!p.exists("ana"));
        assert!(p.assign("ana", a("s-1", None)).is_err());
    }

    #[test]
    fn the_portal_remembers_where_it_made_an_account() {
        let (p, _, _) = two();
        assert!(!p.made_on("ana", "s-1"));
        p.mark_made("ana", "s-1").unwrap();
        p.mark_made("ana", "s-1").unwrap();
        assert!(p.made_on("ana", "s-1") && !p.made_on("ana", "s-2") && !p.made_on("boss", "s-1"));
        // Removing a server forgets it everywhere.
        p.mark_made("boss", "s-1").unwrap();
        p.forget_server("s-1").unwrap();
        assert!(!p.made_on("ana", "s-1") && !p.made_on("boss", "s-1"));
        // An older file without the list still opens.
        let old = r#"{"people":[{"name":"a","display":"","origin":"local","hash":"x","admin":false,"disabled":false,"created":1,"app_password_set":null,"servers":[]}]}"#;
        assert!(serde_json::from_str::<Data>(old).is_ok());
    }

    #[test]
    fn the_view_never_carries_the_hash() {
        let (p, boss, _) = two();
        let shown = serde_json::to_string(&p.list()).unwrap();
        assert!(!shown.contains("argon2") && !shown.contains("hash") && !shown.contains(&boss));
    }

    #[test]
    fn a_change_made_from_outside_is_seen_without_a_restart() {
        let dir = std::env::temp_dir().join(format!("wd-people-out-{}", std::process::id()));
        let path = dir.join("people.json");
        let _ = fs::remove_dir_all(&dir);
        let running = People::open(path.clone()).unwrap();
        assert!(!running.exists("ana"));
        // `waydesk-web people add` is another process with its own handle on the same file.
        let pw = People::open(path.clone()).unwrap().add("ana", "", false, T).unwrap();
        assert!(running.exists("ana"));
        assert!(matches!(running.verify("ana", &pw), Verdict::Good(_)));
        // And the running one keeps editing on top of what it saw.
        running.add("bo", "", false, T).unwrap();
        assert_eq!(People::open(path).unwrap().list().len(), 2);
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn a_failed_save_changes_nothing() {
        let p = People { path: Some(PathBuf::from("/dev/null/people.json")), data: Mutex::new(Data::default()), stamp: Mutex::new(None) };
        assert!(p.add("ana", "", false, T).is_err());
        assert!(!p.exists("ana"));
    }
}
