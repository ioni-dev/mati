// Hook script templates written to .claude/hooks/ by mati init (M-09)
// Each module exports a `pub const SCRIPT: &str` with the bash script content.

pub mod codex_post_bash;
pub mod codex_pre_apply_patch;
pub mod codex_pre_bash;
pub mod codex_session_start;
pub mod claude_stop;
pub mod codex_stop;
pub mod codex_user_prompt;
pub mod decide;
pub mod post_compliance;
pub mod post_edit;
pub mod pre_bash;
pub mod post_compact;
pub mod pre_compact;
pub mod subagent_start;
pub mod pre_edit;
pub mod pre_read;
pub mod session_end;

#[cfg(test)]
mod compliance;
