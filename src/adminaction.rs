//! The changes an administrator may make from the portal, as a closed list. Shared by the root helper (which checks the administrator and forwards) and
//! `waydesk-admin serve-request` (the runner, which checks again and runs the command line). Nothing here is free text: every field is checked against
//! a short rule, and the command line is built from the action, never from what the browser sent.
//!
//! Not in the list on purpose: removing an account, and putting an account in the `sudo`/`wheel` or `waydesk-admins` group. Those stay on the command line.

use serde_json::{json, Value};

/// The most a request may be (the helper protocol caps strings at 1 KiB anyway).
pub const MAX_REQUEST: usize = 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AdminAction {
    /// A new account in the RDP group, with a random password shown once.
    UserAdd { name: String },
    UserEnable { name: String },
    UserDisable { name: String, keep_session: bool },
    /// A new random password, shown once.
    UserPasswd { name: String },
    /// A password chosen by the portal (the app password of a portal user, the same on every server): read from standard input by the command,
    /// never on its command line. Only a server's agent may ask for this (`carries_secret`); the helper refuses it, so it never passes through the
    /// helper's logs.
    UserSetPassword { name: String, password: String },
    /// The desktop and graphics of the account's sessions; `None` leaves the setting as it is.
    UserSet { name: String, desktop: Option<String>, gpu: Option<String> },
    /// The memory limit of the account's session (`6G`), or `reset`.
    UserLimit { name: String, memory: String },
    SessionEnd { name: String },
    /// Who can reach the RDP port: `local`, `lan` or `vpn` (the same words as `waydesk-admin access`). The daemon restarts.
    Access { mode: String },
}

/// A name `useradd` accepts on Debian (its default NAME_REGEX): lower case letters, digits, `_` and `-`, not starting with a digit or `-`, at most 32.
pub fn valid_name(name: &str) -> bool {
    let mut chars = name.chars();
    let Some(first) = chars.next() else { return false };
    name.len() <= 32 && (first.is_ascii_lowercase() || first == '_') && name.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_' || c == '-')
}

const DESKTOPS: [&str; 5] = ["sway", "cosmic", "plasma", "hyprland", "default"];

fn valid_desktop(d: &str) -> bool {
    DESKTOPS.contains(&d)
}

/// `auto`, `balance`, `off`, `default` or a render node (`renderD128`).
fn valid_gpu(g: &str) -> bool {
    matches!(g, "auto" | "balance" | "off" | "default") || g.strip_prefix("renderD").is_some_and(|n| !n.is_empty() && n.len() <= 4 && n.chars().all(|c| c.is_ascii_digit()))
}

/// `reset`, or a number with an optional unit: `6G`, `512M`, `1.5G`. No sign, so it can never be read as an option.
fn valid_memory(m: &str) -> bool {
    if m == "reset" {
        return true;
    }
    let digits = m.trim_end_matches(|c: char| c.is_ascii_alphabetic());
    let unit = &m[digits.len()..];
    !digits.is_empty() && digits.len() <= 8 && digits.chars().all(|c| c.is_ascii_digit() || c == '.') && digits.chars().next().is_some_and(|c| c.is_ascii_digit()) && digits.matches('.').count() <= 1
        && matches!(unit, "" | "K" | "M" | "G" | "T" | "KB" | "MB" | "GB" | "TB" | "KiB" | "MiB" | "GiB" | "TiB")
}

impl AdminAction {
    /// The account the action is about (none for the machine-wide ones).
    pub fn name(&self) -> &str {
        match self {
            Self::Access { .. } => "",
            Self::UserAdd { name } | Self::UserEnable { name } | Self::UserDisable { name, .. } | Self::UserPasswd { name } | Self::UserSetPassword { name, .. } | Self::UserSet { name, .. } | Self::UserLimit { name, .. } | Self::SessionEnd { name } => name,
        }
    }

    /// Whether the action carries a secret that must not pass through the helper (and its logs): only a server's agent may relay it.
    pub fn carries_secret(&self) -> bool {
        matches!(self, Self::UserSetPassword { .. })
    }

    /// What the command reads on standard input, when it does.
    pub fn stdin(&self) -> Option<String> {
        match self {
            Self::UserSetPassword { password, .. } => Some(format!("{password}\n")),
            _ => None,
        }
    }

    /// Whether the request is one the list allows, with a reason in plain words when it is not.
    pub fn validate(&self) -> Result<(), String> {
        if !matches!(self, Self::Access { .. }) && !valid_name(self.name()) {
            return Err("that is not a valid account name (lower case letters, digits, _ and -, at most 32)".into());
        }
        match self {
            Self::UserSetPassword { password, .. } if password.chars().count() < 8 || password.len() > 128 || password.contains(['\n', '\r', '\0']) => return Err("the password must be 8 to 128 characters, on one line".into()),
            Self::Access { mode } if !matches!(mode.as_str(), "local" | "lan" | "vpn") => return Err("the access setting must be local, lan or vpn".into()),
            Self::UserSet { desktop, gpu, .. } => {
                if desktop.is_none() && gpu.is_none() {
                    return Err("nothing to change".into());
                }
                if desktop.as_deref().is_some_and(|d| !valid_desktop(d)) {
                    return Err("the desktop must be sway, cosmic, plasma, hyprland or default".into());
                }
                if gpu.as_deref().is_some_and(|g| !valid_gpu(g)) {
                    return Err("the graphics setting must be auto, balance, off, default or a render node such as renderD128".into());
                }
            }
            Self::UserLimit { memory, .. } if !valid_memory(memory) => return Err("the memory limit must be like 6G or 512M, or reset".into()),
            _ => {}
        }
        Ok(())
    }

    /// The `waydesk-admin` command line for the action (after `validate`). `--json` only where the command has it.
    pub fn args(&self) -> Vec<String> {
        let s = |v: &str| v.to_owned();
        match self {
            Self::UserAdd { name } => vec![s("users"), s("add"), s(name), s("--json")],
            Self::UserEnable { name } => vec![s("users"), s("enable"), s(name)],
            Self::UserDisable { name, keep_session } => {
                let mut v = vec![s("users"), s("disable"), s(name)];
                if *keep_session {
                    v.push(s("--keep-session"));
                }
                v
            }
            Self::UserPasswd { name } => vec![s("users"), s("passwd"), s(name), s("--json")],
            Self::UserSetPassword { name, .. } => vec![s("users"), s("passwd"), s(name), s("--stdin")],
            Self::UserSet { name, desktop, gpu } => {
                let mut v = vec![s("users"), s("set"), s(name)];
                if let Some(d) = desktop {
                    v.extend([s("--desktop"), s(d)]);
                }
                if let Some(g) = gpu {
                    v.extend([s("--gpu"), s(g)]);
                }
                v
            }
            Self::UserLimit { name, memory } => {
                if memory == "reset" {
                    vec![s("users"), s("limit"), s(name), s("reset")]
                } else {
                    vec![s("users"), s("limit"), s(name), s("--memory"), s(memory)]
                }
            }
            Self::SessionEnd { name } => vec![s("sessions"), s("end"), s(name)],
            Self::Access { mode } => vec![s("access"), s(mode)],
        }
    }

    pub fn to_json(&self) -> Value {
        match self {
            Self::UserAdd { name } => json!({ "action": "user_add", "name": name }),
            Self::UserEnable { name } => json!({ "action": "user_enable", "name": name }),
            Self::UserDisable { name, keep_session } => json!({ "action": "user_disable", "name": name, "keep_session": keep_session }),
            Self::UserPasswd { name } => json!({ "action": "user_passwd", "name": name }),
            // The password is not written out: this is the form that is logged and shown.
            Self::UserSetPassword { name, .. } => json!({ "action": "user_setpw", "name": name }),
            Self::UserSet { name, desktop, gpu } => json!({ "action": "user_set", "name": name, "desktop": desktop, "gpu": gpu }),
            Self::UserLimit { name, memory } => json!({ "action": "user_limit", "name": name, "memory": memory }),
            Self::SessionEnd { name } => json!({ "action": "session_end", "name": name }),
            Self::Access { mode } => json!({ "action": "access", "mode": mode }),
        }
    }

    /// Reads an action from JSON; anything it does not know is an error, never ignored. Validates.
    pub fn from_json(v: &Value) -> Result<Self, String> {
        let text = |k: &str| v.get(k).and_then(Value::as_str).map(str::to_owned);
        let opt = |k: &str| match v.get(k) {
            None | Some(Value::Null) => Ok(None),
            Some(Value::String(s)) => Ok(Some(s.clone())),
            Some(_) => Err(format!("{k} must be text")),
        };
        let kind = text("action").ok_or("an action is needed")?;
        if kind == "access" {
            let action = Self::Access { mode: text("mode").ok_or("a mode is needed")? };
            action.validate()?;
            return Ok(action);
        }
        let name = text("name").ok_or("a name is needed")?;
        let action = match kind.as_str() {
            "user_add" => Self::UserAdd { name },
            "user_enable" => Self::UserEnable { name },
            "user_disable" => Self::UserDisable { name, keep_session: v.get("keep_session").and_then(Value::as_bool).unwrap_or(false) },
            "user_passwd" => Self::UserPasswd { name },
            "user_setpw" => Self::UserSetPassword { name, password: text("password").ok_or("a password is needed")? },
            "user_set" => Self::UserSet { name, desktop: opt("desktop")?, gpu: opt("gpu")? },
            "user_limit" => Self::UserLimit { name, memory: text("memory").ok_or("a memory limit is needed")? },
            "session_end" => Self::SessionEnd { name },
            _ => return Err("unknown action".into()),
        };
        action.validate()?;
        Ok(action)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(s: &str) -> Result<AdminAction, String> {
        AdminAction::from_json(&serde_json::from_str(s).unwrap())
    }

    #[test]
    fn names_are_what_useradd_takes_and_never_look_like_options() {
        for ok in ["alice", "a", "_svc", "dev-1", "x_y9"] {
            assert!(valid_name(ok), "{ok}");
        }
        for bad in ["", "-rf", "Alice", "9lives", "a b", "a;b", "a/b", "../x", "root\n", "ünï", &"a".repeat(33)] {
            assert!(!valid_name(bad), "{bad:?}");
        }
    }

    #[test]
    fn a_chosen_password_goes_on_standard_input_never_on_the_command_line_or_in_the_logged_form() {
        let a = parse(r#"{"action":"user_setpw","name":"eva","password":"correct horse battery"}"#).unwrap();
        assert_eq!(a.args(), ["users", "passwd", "eva", "--stdin"]);
        assert_eq!(a.stdin().as_deref(), Some("correct horse battery\n"));
        assert!(a.carries_secret());
        assert!(!a.to_json().to_string().contains("horse"));
        for bad in [r#"{"action":"user_setpw","name":"eva"}"#, r#"{"action":"user_setpw","name":"eva","password":"short"}"#, r#"{"action":"user_setpw","name":"eva","password":"two\nlines-long"}"#, r#"{"action":"user_setpw","name":"Eva","password":"long enough pw"}"#] {
            assert!(parse(bad).is_err(), "{bad}");
        }
        assert!(parse(r#"{"action":"user_passwd","name":"eva"}"#).unwrap().stdin().is_none());
    }

    #[test]
    fn each_action_becomes_one_fixed_command_line() {
        assert_eq!(parse(r#"{"action":"user_add","name":"frida"}"#).unwrap().args(), ["users", "add", "frida", "--json"]);
        assert_eq!(parse(r#"{"action":"user_disable","name":"eva","keep_session":true}"#).unwrap().args(), ["users", "disable", "eva", "--keep-session"]);
        assert_eq!(parse(r#"{"action":"user_disable","name":"eva"}"#).unwrap().args(), ["users", "disable", "eva"]);
        assert_eq!(parse(r#"{"action":"user_passwd","name":"eva"}"#).unwrap().args(), ["users", "passwd", "eva", "--json"]);
        assert_eq!(parse(r#"{"action":"user_set","name":"eva","desktop":"plasma","gpu":"renderD128"}"#).unwrap().args(), ["users", "set", "eva", "--desktop", "plasma", "--gpu", "renderD128"]);
        assert_eq!(parse(r#"{"action":"user_set","name":"eva","gpu":"off"}"#).unwrap().args(), ["users", "set", "eva", "--gpu", "off"]);
        assert_eq!(parse(r#"{"action":"user_limit","name":"eva","memory":"6G"}"#).unwrap().args(), ["users", "limit", "eva", "--memory", "6G"]);
        assert_eq!(parse(r#"{"action":"user_limit","name":"eva","memory":"reset"}"#).unwrap().args(), ["users", "limit", "eva", "reset"]);
        assert_eq!(parse(r#"{"action":"session_end","name":"eva"}"#).unwrap().args(), ["sessions", "end", "eva"]);
        for mode in ["local", "lan", "vpn"] {
            assert_eq!(parse(&format!(r#"{{"action":"access","mode":"{mode}"}}"#)).unwrap().args(), ["access", mode]);
        }
    }

    #[test]
    fn nothing_outside_the_list_gets_through() {
        for bad in [
            r#"{"action":"user_remove","name":"eva"}"#,
            r#"{"action":"user_sudo","name":"eva"}"#,
            r#"{"action":"user_add"}"#,
            r#"{"name":"eva"}"#,
            r#"{"action":"user_add","name":"-rf"}"#,
            r#"{"action":"user_add","name":"a b"}"#,
            r#"{"action":"user_set","name":"eva"}"#,
            r#"{"action":"user_set","name":"eva","desktop":"gnome"}"#,
            r#"{"action":"user_set","name":"eva","desktop":"plasma --gpu x"}"#,
            r#"{"action":"user_set","name":"eva","gpu":"renderD"}"#,
            r#"{"action":"user_set","name":"eva","gpu":"../dev"}"#,
            r#"{"action":"user_set","name":"eva","gpu":5}"#,
            r#"{"action":"user_limit","name":"eva","memory":"-1"}"#,
            r#"{"action":"user_limit","name":"eva","memory":"--help"}"#,
            r#"{"action":"user_limit","name":"eva","memory":"6G;x"}"#,
            r#"{"action":"user_limit","name":"eva","memory":"G"}"#,
            r#"{"action":"user_limit","name":"eva","memory":"1.2.3G"}"#,
            r#"{"action":"user_limit","name":"eva"}"#,
            r#"{"action":"access","mode":"custom"}"#,
            r#"{"action":"access","mode":"lan --allow any"}"#,
            r#"{"action":"access","mode":"--bind"}"#,
            r#"{"action":"access"}"#,
        ] {
            assert!(parse(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn an_action_survives_the_trip_through_json() {
        for a in [
            AdminAction::UserAdd { name: "a".into() },
            AdminAction::UserDisable { name: "a".into(), keep_session: true },
            AdminAction::UserSet { name: "a".into(), desktop: Some("sway".into()), gpu: None },
            AdminAction::UserLimit { name: "a".into(), memory: "512M".into() },
            AdminAction::SessionEnd { name: "a".into() },
            AdminAction::Access { mode: "vpn".into() },
        ] {
            assert_eq!(AdminAction::from_json(&a.to_json()).unwrap(), a);
        }
    }
}
