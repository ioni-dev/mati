use super::*;

// ── File-record link sync ────────────────────────────────────────────────────

/// Synchronize `gotcha_keys` in file records with the current affected-file set.
///
/// Adds the gotcha key to files in `new_files` that are not in `old_files`,
/// and removes it from files in `old_files` that are not in `new_files`.
pub async fn sync_gotcha_file_links(
    store: &Store,
    gotcha_key: &str,
    old_files: &[String],
    new_files: &[String],
) -> Result<()> {
    let old_set: HashSet<&str> = old_files.iter().map(String::as_str).collect();
    let new_set: HashSet<&str> = new_files.iter().map(String::as_str).collect();

    for file_path in new_set.difference(&old_set) {
        update_file_gotcha_key(store, file_path, gotcha_key, true).await?;
    }

    for file_path in old_set.difference(&new_set) {
        update_file_gotcha_key(store, file_path, gotcha_key, false).await?;
    }

    Ok(())
}

async fn update_file_gotcha_key(
    store: &Store,
    file_path: &str,
    gotcha_key: &str,
    add: bool,
) -> Result<()> {
    let file_key = format!("file:{file_path}");

    // Bounded retry on optimistic-concurrency write conflicts. Concurrent
    // gotcha writes touching the same file:<path> record (e.g. parallel
    // `mati gotcha add` to one file in direct mode) race on this
    // read-modify-write under SurrealKV MVCC. Re-read on each attempt so we
    // re-apply against the latest gotcha_keys rather than clobbering a
    // sibling's concurrent add. Without this, the conflict falls through to
    // the caller's best-effort dirty-marker path and needs `mati repair`.
    const MAX_RETRIES: usize = 4;
    for attempt in 0..MAX_RETRIES {
        let existing = store.get(&file_key).await?;
        let Some(record) = stage_file_link_update(existing, file_path, gotcha_key, add) else {
            return Ok(());
        };

        match store.put(&file_key, &record).await {
            Ok(()) => return Ok(()),
            Err(e)
                if attempt + 1 < MAX_RETRIES
                    && e.to_string().to_lowercase().contains("write conflict") =>
            {
                // Another writer committed file:<path> between our get and put.
                // Back off briefly (5/10/20ms) and retry against a fresh read.
                tokio::time::sleep(std::time::Duration::from_millis(5u64 << attempt)).await;
                continue;
            }
            Err(e) => return Err(e),
        }
    }

    Ok(())
}

/// Build the file-record mutation for one `add`/`remove` of `gotcha_key` on
/// `file_path`, given the caller's most recent read of `file:<path>`
/// (`None` when the file was never indexed). Returns the record to persist,
/// or `None` if nothing changed. Pure — the caller decides how and when to
/// persist the result, which is what lets the direct-store path (write
/// immediately, retry on conflict) and the daemon path (stage into
/// `transact_knowledge`) share this without sharing a transaction model.
///
/// A missing file gets a fresh Layer 0 stub on `add` so the gotcha enforces
/// immediately instead of waiting for the next `mati init` — see
/// `update_file_gotcha_key`'s create-on-write note.
pub(crate) fn stage_file_link_update(
    existing: Option<Record>,
    file_path: &str,
    gotcha_key: &str,
    add: bool,
) -> Option<Record> {
    let now = now_secs();

    let mut record = match existing {
        Some(r) => r,
        None => {
            if !add {
                return None;
            }
            let mut stub = Record::layer0_file_stub(
                format!("file:{file_path}"),
                crate::store::stable_device_id(),
                1,
                now,
            );
            let mut fr = FileRecord::layer0_stub(
                file_path,
                vec![],
                vec![],
                vec![],
                0,
                0,
                0,
                None,
                false,
                0,
                now,
            );
            fr.gotcha_keys = vec![gotcha_key.to_string()];
            stub.payload = serde_json::to_value(&fr).ok();
            return Some(stub);
        }
    };

    let changed = if add {
        add_gotcha_key(&mut record, gotcha_key)
    } else {
        remove_gotcha_key(&mut record, gotcha_key)
    };
    if !changed {
        return None;
    }

    record.updated_at = now;
    record.version.logical_clock += 1;
    record.version.wall_clock = now;
    Some(record)
}

fn add_gotcha_key(record: &mut Record, gotcha_key: &str) -> bool {
    let Some(payload) = record.payload.as_mut() else {
        record.payload = Some(serde_json::json!({ "gotcha_keys": [gotcha_key] }));
        return true;
    };

    if let Some(obj) = payload.as_object_mut() {
        match obj.get_mut("gotcha_keys") {
            Some(existing) => {
                if let Some(arr) = existing.as_array_mut() {
                    if arr.iter().any(|v| v.as_str() == Some(gotcha_key)) {
                        false
                    } else {
                        arr.push(serde_json::Value::String(gotcha_key.to_string()));
                        true
                    }
                } else {
                    *existing = serde_json::json!([gotcha_key]);
                    true
                }
            }
            None => {
                obj.insert("gotcha_keys".into(), serde_json::json!([gotcha_key]));
                true
            }
        }
    } else {
        record.payload = Some(serde_json::json!({ "gotcha_keys": [gotcha_key] }));
        true
    }
}

fn remove_gotcha_key(record: &mut Record, gotcha_key: &str) -> bool {
    let Some(payload) = record.payload.as_mut() else {
        return false;
    };
    let Some(obj) = payload.as_object_mut() else {
        return false;
    };
    let Some(existing) = obj.get_mut("gotcha_keys") else {
        return false;
    };
    let Some(arr) = existing.as_array_mut() else {
        return false;
    };

    let before = arr.len();
    arr.retain(|v| v.as_str() != Some(gotcha_key));
    arr.len() != before
}
