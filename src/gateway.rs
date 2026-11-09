//! The line a web gateway (`waydesk-web`) sends first on a connection to the daemon's gateway port, before anything else:
//!
//! ```text
//! WAYDESK-GATEWAY 1 KEY ACCOUNT CLIENT-ADDRESS\n
//! ```
//!
//! It says which account the gateway checked a code for, and which address the client really has. The daemon then lets that connection log in as
//! that account and no other, and records the client's address instead of the gateway's. The key is a secret that only the gateway and the daemon
//! (both run as the `waydesk` account) can read; a connection without it is refused. The port listens on this machine only.
//!
//! This file has no dependencies, so the daemon and the gateway use the same code for writing and reading the line.

use std::net::IpAddr;

/// The longest line the daemon reads (the longest account name is 32 characters).
pub const MAX_LINE: usize = 512;

#[derive(Debug, PartialEq, Eq)]
pub struct Assertion {
    pub account: String,
    pub ip: IpAddr,
}

/// An account name the line can carry: what Linux accounts are made of in practice, and not a path or an option.
pub fn valid_account(name: &str) -> bool {
    !name.is_empty() && name.len() <= 32 && !name.starts_with(['.', '-']) && name.bytes().all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
}

/// The line for `account` and `ip`, with the newline.
pub fn line(key: &str, account: &str, ip: IpAddr) -> String {
    format!("WAYDESK-GATEWAY 1 {key} {account} {ip}\n")
}

/// Compares in time that does not depend on where the texts differ.
fn same(a: &str, b: &str) -> bool {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    let mut diff = a.len() ^ b.len();
    for i in 0..a.len().max(b.len()) {
        diff |= usize::from(a.get(i).copied().unwrap_or(0) ^ b.get(i).copied().unwrap_or(0));
    }
    diff == 0
}

/// Reads a line (without its newline). Refuses it with a short reason, for the log, if it is not exactly what a gateway with `key` sends.
pub fn parse(text: &str, key: &str) -> Result<Assertion, &'static str> {
    let text = text.strip_suffix('\n').ok_or("no end of line")?;
    let fields: Vec<&str> = text.split(' ').collect();
    let [tag, version, given, account, ip] = fields.as_slice() else { return Err("not five fields") };
    if *tag != "WAYDESK-GATEWAY" || *version != "1" {
        return Err("not a gateway line of version 1");
    }
    if !same(given, key) {
        return Err("wrong key");
    }
    if !valid_account(account) {
        return Err("not a usable account name");
    }
    let ip = ip.parse::<IpAddr>().map_err(|_| "not an address")?;
    Ok(Assertion { account: (*account).to_owned(), ip })
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: &str = "a-long-enough-gateway-key";

    #[test]
    fn what_the_gateway_writes_the_daemon_reads() {
        for ip in ["203.0.113.9", "2001:db8::7", "127.0.0.1"] {
            let ip: IpAddr = ip.parse().unwrap();
            let written = line(KEY, "ana.lima", ip);
            assert_eq!(parse(&written, KEY), Ok(Assertion { account: "ana.lima".into(), ip }));
        }
    }

    #[test]
    fn a_line_that_is_not_exactly_right_is_refused() {
        let ok = line(KEY, "ana", "203.0.113.9".parse().unwrap());
        assert!(parse(&ok, KEY).is_ok());
        assert_eq!(parse(&ok, "another-gateway-key-xx"), Err("wrong key"));
        assert_eq!(parse(&ok, ""), Err("wrong key"));
        assert_eq!(parse(&ok[..ok.len() - 1], KEY), Err("no end of line"));
        assert_eq!(parse("", KEY), Err("no end of line"));
        for bad in [
            format!("WAYDESK-GATEWAY 2 {KEY} ana 203.0.113.9\n"),
            format!("WAYDESK-GATEWAY 1 {KEY} ana\n"),
            format!("WAYDESK-GATEWAY 1 {KEY} ana 203.0.113.9 extra\n"),
            format!("WAYDESK-GATEWAY 1 {KEY}  ana 203.0.113.9\n"),
            format!("GET / HTTP/1.1 {KEY} ana 203.0.113.9\n"),
            format!("WAYDESK-GATEWAY 1 {KEY} ana not-an-address\n"),
            format!("WAYDESK-GATEWAY 1 {KEY} ../root 203.0.113.9\n"),
            format!("WAYDESK-GATEWAY 1 {KEY} -oProxyCommand 203.0.113.9\n"),
            format!("WAYDESK-GATEWAY 1 {KEY} an\ta 203.0.113.9\n"),
        ] {
            assert!(parse(&bad, KEY).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn the_comparison_looks_at_every_character() {
        assert!(same("abc", "abc"));
        assert!(!same("abc", "abd"));
        assert!(!same("abc", "abcd"));
        assert!(!same("abcd", "abc"));
        assert!(same("", ""));
    }
}
