//! Which GPU a session gets when the setting is `balance` (docs/GPU-PLACEMENT-DESIGN.md). Used by `waydesk-admin gpu place UID`, which the session unit runs as root before
//! the session starts: it takes a lock, counts the sessions already placed, picks a card and writes `/run/waydesk/gpu/UID.env` (`WAYDESK_GPU=<node>`), which the unit reads
//! last. The decision is plain functions over plain values so that it can be tested without a GPU.
#![allow(dead_code)]

use std::collections::HashMap;
use std::path::Path;

pub use crate::gpuroles::{effective_roles, inference_line, card_note, encoder_card_warning, parse_roles, reserved_nodes, role_warning, short_name, Role};

/// Where the placements are (one `UID.env` per account that is placed by `balance`).
pub const DIR: &str = "/run/waydesk/gpu";
/// Held while a placement is made, so that sessions starting together see each other's choice.
pub const LOCK: &str = "/run/waydesk/gpu.lock";

/// What the placement knows about one render node.
#[derive(Clone, Debug, PartialEq)]
pub struct Candidate {
    /// `/dev/dri/renderD129`.
    pub node: String,
    /// A card with memory of its own (not an integrated one, which draws from the system memory).
    pub discrete: bool,
    /// Percent busy when known (not for Intel integrated cards, whose figure needs a sampling interval); a tie-break only.
    pub busy: Option<f64>,
    /// Free video memory in MB, when the driver says (NVIDIA, AMD).
    pub free_vram_mb: Option<u64>,
    /// The node can be opened for reading and writing.
    pub usable: bool,
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct Policy {
    /// Render node names kept out of `balance` (`renderD129`).
    pub reserve: Vec<String>,
    /// Weight per node name; a node without one gets 4 when discrete, 1 when integrated.
    pub weights: HashMap<String, f64>,
    /// A card with less free video memory than this (MB) gets no new session; 0 switches the check off.
    pub min_free_vram_mb: u64,
}

#[derive(Clone, Debug, PartialEq)]
pub struct Decision {
    /// The node to use; `None`: no card can take the session, so it is made in software.
    pub node: Option<String>,
    /// Why, one line for the log and the audit trail.
    pub reason: String,
}

/// `renderD128=1,renderD129=4`; entries that are not `name=positive number` are ignored.
pub fn parse_weights(text: &str) -> HashMap<String, f64> {
    text.split([',', ' '])
        .filter_map(|e| {
            let (name, w) = e.trim().split_once('=')?;
            let w: f64 = w.trim().parse().ok()?;
            (w.is_finite() && w > 0.0).then(|| (short_name(name.trim()).to_owned(), w))
        })
        .collect()
}

fn weight(p: &Policy, c: &Candidate) -> f64 {
    p.weights.get(short_name(&c.node)).copied().unwrap_or(if c.discrete { 4.0 } else { 1.0 })
}

/// The card for the next session. `sessions` is how many sessions each node already has (by node path).
/// Lowest `(sessions + 1) / weight` wins; a tie goes to the card that is less busy, then to the lower node name.
pub fn decide(cands: &[Candidate], sessions: &HashMap<String, usize>, policy: &Policy) -> Decision {
    if cands.is_empty() {
        return Decision { node: None, reason: "no render node: software".into() };
    }
    let mut skipped = Vec::new();
    let mut best: Option<(f64, f64, &Candidate)> = None;
    for c in cands {
        let name = short_name(&c.node);
        if policy.reserve.iter().any(|r| r == name) {
            skipped.push(format!("{name} reserved"));
            continue;
        }
        if !c.usable {
            skipped.push(format!("{name} cannot be opened"));
            continue;
        }
        if let (true, Some(free)) = (policy.min_free_vram_mb > 0, c.free_vram_mb) {
            if free < policy.min_free_vram_mb {
                skipped.push(format!("{name} has {free} MB free, {} needed", policy.min_free_vram_mb));
                continue;
            }
        }
        let n = sessions.get(&c.node).copied().unwrap_or(0);
        let score = (n as f64 + 1.0) / weight(policy, c);
        let busy = c.busy.unwrap_or(0.0);
        let better = match best {
            None => true,
            Some((s, b, _)) => score < s - 1e-9 || ((score - s).abs() <= 1e-9 && busy < b - 1e-9),
        };
        if better {
            best = Some((score, busy, c));
        }
    }
    let skipped_text = if skipped.is_empty() { String::new() } else { format!(" (skipped: {})", skipped.join(", ")) };
    match best {
        Some((score, _, c)) => {
            let n = sessions.get(&c.node).copied().unwrap_or(0);
            Decision { node: Some(c.node.clone()), reason: format!("{} has {n} session(s), weight {}, score {score:.2}{skipped_text}", short_name(&c.node), weight(policy, c)) }
        }
        None => Decision { node: None, reason: format!("no card can take the session: software{skipped_text}") },
    }
}

/// The text of the file the unit reads: the node, or `off` for software.
pub fn render_claim(node: Option<&str>) -> String {
    format!("# Written by `waydesk-admin gpu place` (WAYDESK_GPU=balance); read by the session unit after the account's own settings.\nWAYDESK_GPU={}\n", node.unwrap_or("off"))
}

/// The node a claim file names (`None` for software, and for text that holds no setting).
pub fn parse_claim(text: &str) -> Option<String> {
    let v = text.lines().filter_map(|l| l.trim().strip_prefix("WAYDESK_GPU=")).map(|v| v.trim().trim_matches(['"', '\'']).to_owned()).last()?;
    (!v.is_empty() && v != "off").then_some(v)
}

/// How many sessions each node has: the claim files of accounts whose session is alive (`alive(uid)`), except `except` (the one being placed).
pub fn read_claims(dir: &Path, alive: impl Fn(u32) -> bool, except: u32) -> HashMap<String, usize> {
    let mut out = HashMap::new();
    let Ok(entries) = std::fs::read_dir(dir) else { return out };
    for e in entries.flatten() {
        let name = e.file_name().to_string_lossy().into_owned();
        let Some(uid) = name.strip_suffix(".env").and_then(|u| u.parse::<u32>().ok()) else { continue };
        if uid == except || !alive(uid) {
            continue;
        }
        if let Some(node) = std::fs::read_to_string(e.path()).ok().and_then(|t| parse_claim(&t)) {
            *out.entry(node).or_insert(0) += 1;
        }
    }
    out
}

/// A session that draws in software although its account's setting asks for a GPU and the machine has one: the sentence for `status`, else `None`.
/// `setting` is the account's GPU setting (`auto`, `balance`, `off` or a node), `render` what the session reports (`None`: software).
pub fn software_warning(name: &str, setting: &str, render: Option<&str>, gpus: usize) -> Option<String> {
    (gpus > 0 && render.is_none() && setting != "off").then(|| {
        format!("{name} renders in software although the GPU setting is {setting}: no card could take the session, or it did not start on one (waydesk-admin audit --event gpu, and the session's log)")
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cand(node: &str, discrete: bool) -> Candidate {
        Candidate { node: format!("/dev/dri/{node}"), discrete, busy: None, free_vram_mb: None, usable: true }
    }

    fn sessions(list: &[(&str, usize)]) -> HashMap<String, usize> {
        list.iter().map(|(n, c)| (format!("/dev/dri/{n}"), *c)).collect()
    }

    #[test]
    fn the_discrete_card_takes_four_sessions_for_each_one_of_the_integrated() {
        let cands = vec![cand("renderD128", false), cand("renderD129", true)];
        let p = Policy::default();
        let mut have: HashMap<String, usize> = HashMap::new();
        let mut placed = Vec::new();
        for _ in 0..10 {
            let d = decide(&cands, &have, &p);
            let node = d.node.unwrap();
            *have.entry(node.clone()).or_insert(0) += 1;
            placed.push(node);
        }
        let on = |n: &str| placed.iter().filter(|p| p.ends_with(n)).count();
        assert_eq!((on("renderD128"), on("renderD129")), (2, 8), "4:1, as the weights say");
    }

    #[test]
    fn the_first_session_goes_to_the_stronger_card_and_a_tie_to_the_lower_name() {
        let d = decide(&[cand("renderD128", false), cand("renderD129", true)], &HashMap::new(), &Policy::default());
        assert_eq!(d.node.as_deref(), Some("/dev/dri/renderD129"));
        let d = decide(&[cand("renderD129", true), cand("renderD130", true)], &HashMap::new(), &Policy::default());
        assert_eq!(d.node.as_deref(), Some("/dev/dri/renderD129"));
    }

    #[test]
    fn a_tie_goes_to_the_card_that_is_less_busy() {
        let mut a = cand("renderD129", true);
        let mut b = cand("renderD130", true);
        a.busy = Some(60.0);
        b.busy = Some(10.0);
        assert_eq!(decide(&[a, b], &HashMap::new(), &Policy::default()).node.as_deref(), Some("/dev/dri/renderD130"));
    }

    #[test]
    fn weights_from_the_settings_replace_the_defaults() {
        let p = Policy { weights: parse_weights("renderD128=3, /dev/dri/renderD129=1, bad=x, zero=0"), ..Default::default() };
        assert_eq!(p.weights.len(), 2);
        let cands = vec![cand("renderD128", false), cand("renderD129", true)];
        assert_eq!(decide(&cands, &HashMap::new(), &p).node.as_deref(), Some("/dev/dri/renderD128"), "3 against 1");
    }

    #[test]
    fn a_reserved_card_gets_no_session_and_neither_does_one_that_cannot_be_opened() {
        let mut closed = cand("renderD130", true);
        closed.usable = false;
        let cands = vec![cand("renderD128", false), cand("renderD129", true), closed];
        let p = Policy { reserve: vec!["renderD129".to_owned()], ..Default::default() };
        let d = decide(&cands, &HashMap::new(), &p);
        assert_eq!(d.node.as_deref(), Some("/dev/dri/renderD128"));
        assert!(d.reason.contains("renderD129 reserved") && d.reason.contains("renderD130 cannot be opened"), "{}", d.reason);
    }

    #[test]
    fn a_card_short_of_video_memory_is_skipped_but_an_unknown_amount_is_not() {
        let mut low = cand("renderD129", true);
        low.free_vram_mb = Some(2000);
        let p = Policy { min_free_vram_mb: 4096, ..Default::default() };
        let d = decide(&[cand("renderD128", false), low.clone()], &HashMap::new(), &p);
        assert_eq!(d.node.as_deref(), Some("/dev/dri/renderD128"));
        assert!(d.reason.contains("2000 MB free, 4096 needed"));
        low.free_vram_mb = None;
        assert_eq!(decide(&[low], &HashMap::new(), &p).node.as_deref(), Some("/dev/dri/renderD129"));
        let off = Policy::default();
        let mut low = cand("renderD129", true);
        low.free_vram_mb = Some(1);
        assert_eq!(decide(&[low], &HashMap::new(), &off).node.as_deref(), Some("/dev/dri/renderD129"), "0 switches the check off");
    }

    #[test]
    fn nothing_that_can_take_the_session_means_software_with_the_reason() {
        let d = decide(&[], &HashMap::new(), &Policy::default());
        assert_eq!(d.node, None);
        let p = Policy { reserve: vec!["renderD129".into()], ..Default::default() };
        let d = decide(&[cand("renderD129", true)], &sessions(&[]), &p);
        assert_eq!(d.node, None);
        assert!(d.reason.contains("software") && d.reason.contains("reserved"));
    }

    #[test]
    fn sessions_already_there_count_against_a_card() {
        let cands = vec![cand("renderD129", true), cand("renderD130", true)];
        let d = decide(&cands, &sessions(&[("renderD129", 3), ("renderD130", 1)]), &Policy::default());
        assert_eq!(d.node.as_deref(), Some("/dev/dri/renderD130"));
    }

    #[test]
    fn claims_count_only_live_sessions_and_not_the_account_being_placed() {
        let dir = std::env::temp_dir().join(format!("waydesk-gpuplace-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("1000.env"), render_claim(Some("/dev/dri/renderD129"))).unwrap();
        std::fs::write(dir.join("1001.env"), render_claim(Some("/dev/dri/renderD129"))).unwrap();
        std::fs::write(dir.join("1002.env"), render_claim(Some("/dev/dri/renderD128"))).unwrap();
        std::fs::write(dir.join("1003.env"), render_claim(None)).unwrap();
        std::fs::write(dir.join("notes.txt"), "x").unwrap();
        let counts = read_claims(&dir, |uid| uid != 1001, 1002);
        assert_eq!(counts, sessions(&[("renderD129", 1)]), "1001 is not running, 1002 is the one being placed, 1003 is software");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn the_placement_leaves_inference_cards_alone_and_uses_both() {
        let cands = vec![cand("renderD128", false), cand("renderD129", true), cand("renderD130", true)];
        let p = Policy { reserve: reserved_nodes(Some("renderD129=inference,renderD130=both")), ..Default::default() };
        let mut have: HashMap<String, usize> = HashMap::new();
        for _ in 0..6 {
            let n = decide(&cands, &have, &p).node.unwrap();
            assert!(!n.ends_with("renderD129"), "never the inference card");
            *have.entry(n).or_insert(0) += 1;
        }
        assert!(have.get("/dev/dri/renderD130").copied().unwrap_or(0) > 0, "the both card takes sessions");
    }

    #[test]
    fn software_is_a_warning_only_when_a_gpu_was_asked_for_and_there_is_one() {
        assert!(software_warning("alice", "balance", None, 2).is_some());
        assert!(software_warning("alice", "auto", None, 1).is_some());
        assert_eq!(software_warning("alice", "off", None, 2), None, "asked for software");
        assert_eq!(software_warning("alice", "balance", None, 0), None, "no GPU on the machine");
        assert_eq!(software_warning("alice", "balance", Some("/dev/dri/renderD129"), 2), None);
    }

    #[test]
    fn a_claim_is_read_back() {
        assert_eq!(parse_claim(&render_claim(Some("/dev/dri/renderD129"))).as_deref(), Some("/dev/dri/renderD129"));
        assert_eq!(parse_claim(&render_claim(None)), None);
    }
}
