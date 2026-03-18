// Hook script templates written to .claude/hooks/ by mati init (M-09)
// Each module exports a `pub const SCRIPT: &str` with the bash script content.

pub mod post_compliance;
pub mod post_edit;
pub mod pre_bash;
pub mod pre_compact;
pub mod pre_read;
pub mod session_end;
