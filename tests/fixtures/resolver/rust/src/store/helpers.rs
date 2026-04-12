use crate::store;

pub fn format_key(key: &str) -> String {
    format!("store:{key}")
}
