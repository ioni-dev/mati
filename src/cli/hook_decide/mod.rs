//! CLI adapter for `mati hook-decide <variant>`.
//!
//! Owns daemon readiness, stdin parsing, and platform-specific output.
//! Delegates the pure enforcement decision to `hooks::decide::evaluate()`.

use anyhow::Result;
use clap::{Args, ValueEnum};
use globset::{Glob, GlobSet, GlobSetBuilder};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::cli::daemon::{
    daemon_result, daemon_v2, mati_root_for, mati_root_for_ident, DaemonResult,
};
use mati_core::hooks::decide::{self, Decision, EnforcementInput, HookEvent};

mod config;
mod entry;
mod events_output;
mod flows;
mod path;
mod policy;

#[cfg(test)]
mod tests;

pub use entry::*;

pub(super) use super::{daemon, sandbox};

pub(super) use config::run_config_change;
pub(super) use events_output::{
    apply_consult_mandate, check_eval_data, consult_globset, consulted_flag, daemon_data,
    emit_allow, escape_json_string, fire_events, format_decision, log_fail_open,
    log_fail_open_named, platform_events, process_eval_response, AdapterResult, EvalDataCheck,
};
pub(super) use flows::{
    ensure_daemon, lockdown_owed_key, run_apply_patch, run_pathless_lockdown, run_post_bash,
    run_post_bash_introspection, run_post_memget, run_post_task, run_seal_guard, run_seal_sweep,
};
pub(super) use path::{
    canonical_rel_path, discover_repo_root, discover_repo_root_for, extract_path,
    file_exists_for_deleted_signal,
};
pub(super) use policy::{
    evaluate_governed_policy, merge_policy_result, policy_block_exempt, policy_verdicts_for_action,
    run_fileless_policy, PolicyEvaluationOptions,
};

#[cfg(test)]
pub(super) use events_output::{
    allow_output, consult_globset_from, decision_basis_hash, log_fail_open_at, session_command,
};
#[cfg(test)]
pub(super) use flows::{accepts_db_introspection, post_bash_succeeded, receipt_actor};
#[cfg(test)]
pub(super) use policy::policy_core_verdicts;
