//! CLI ergonomics (idea 3): shell completion + short command aliases. These
//! need no store or daemon.

use std::process::Command;

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_mati")
}

#[test]
fn completion_emits_scripts_for_each_shell() {
    for (shell, marker) in [("bash", "_mati"), ("zsh", "#compdef"), ("fish", "complete")] {
        let out = Command::new(bin())
            .args(["completion", shell])
            .output()
            .expect("run completion");
        assert!(out.status.success(), "{shell} completion exited non-zero");
        let s = String::from_utf8_lossy(&out.stdout);
        assert!(
            !s.is_empty() && s.contains(marker),
            "{shell} script should contain `{marker}`; got start:\n{}",
            &s[..s.len().min(120)]
        );
    }
}

#[test]
fn completion_rejects_unknown_shell() {
    let out = Command::new(bin())
        .args(["completion", "tcsh"])
        .output()
        .expect("run completion");
    assert!(!out.status.success(), "an unknown shell should be rejected");
}

#[test]
fn aliases_resolve_to_their_commands() {
    // `mati s` is `status`; `mati i` is `init` — proven via each command's help.
    let s = Command::new(bin())
        .args(["s", "--help"])
        .output()
        .expect("run alias s");
    assert!(s.status.success());
    assert!(String::from_utf8_lossy(&s.stdout)
        .to_lowercase()
        .contains("dashboard"));

    let i = Command::new(bin())
        .args(["i", "--help"])
        .output()
        .expect("run alias i");
    assert!(i.status.success());
    assert!(String::from_utf8_lossy(&i.stdout)
        .to_lowercase()
        .contains("project memory"));
}
