/// ANSI 24-bit colour constants — spec: CLAUDE.md §CLI Color Semantics.
///
/// Import with `use super::colors;` and reference as `colors::RED` etc., or
/// glob-import inside a function to enable conditional-color rebinding:
/// ```ignore
/// let (red, reset) = if use_color { (colors::RED, colors::RESET) } else { ("", "") };
/// ```
pub const RED: &str = "\x1b[38;2;248;81;73m";
pub const YELLOW: &str = "\x1b[38;2;210;153;34m";
pub const GREEN: &str = "\x1b[38;2;63;185;80m";
pub const BLUE: &str = "\x1b[38;2;88;166;255m";
pub const PURPLE: &str = "\x1b[38;2;188;140;255m";
pub const GRAY: &str = "\x1b[38;2;139;148;158m";
pub const CYAN: &str = "\x1b[38;2;57;211;83m";
pub const WHITE: &str = "\x1b[38;2;230;237;243m";
pub const BOLD: &str = "\x1b[1m";
pub const RESET: &str = "\x1b[0m";
