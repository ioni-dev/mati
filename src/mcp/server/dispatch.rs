use super::*;

pub(crate) async fn socket_dispatch(
    graph: &Arc<tokio::sync::RwLock<Graph>>,
    repo_root: &Path,
    req: &SocketRequest,
) -> SocketResponse {
    use crate::store::session as sess;

    match req.cmd.as_str() {
        "ping" => SocketResponse::ok(serde_json::Value::String("pong".into())),

        // Live daemon metrics snapshot — per-command counters, error rates,
        // and p50/p95/p99 latencies. Pure read, no side effects, no audit.
        // Returns `null` if the global metrics handle was never initialized
        // (which only happens in tests that bypass `serve`).
        "metrics" => match super::metrics::snapshot() {
            Some(snap) => match serde_json::to_value(&snap) {
                Ok(v) => SocketResponse::ok(v),
                Err(e) => SocketResponse::err(format!("metrics serialize: {e}")),
            },
            None => SocketResponse::ok(serde_json::Value::Null),
        },

        // ── MCP tool commands ────────────────────────────────────────────
        //
        // γ-C4: the wire layer (`socket_handle_connection`) accepts only v2
        // requests, which route MemGet / MemQuery / MemBootstrap / MemSet
        // through `dispatch_v2` to the native handlers in `mcp::handlers`.
        // These v1 arms are reachable only via in-process callers — they
        // dispatch directly to the same canonical handlers so v1 and v2
        // paths cannot drift.
        "mem_get" => {
            let params = match serde_json::from_value::<MemGetParams>(req.args.clone()) {
                Ok(p) => p,
                Err(e) => return SocketResponse::err(format!("invalid mem_get args: {e}")),
            };
            let input = super::protocol::MemGetInput { key: params.key };
            let ctx = build_v1_dispatch_ctx(repo_root);
            let g = graph.read().await;
            match super::handlers::handle_mem_get(
                g.store(),
                graph,
                &ctx,
                uuid::Uuid::new_v4(),
                &input,
            )
            .await
            {
                Ok(v) => SocketResponse::ok(serde_json::Value::String(
                    serde_json::to_string_pretty(&v).unwrap_or_else(|_| "{}".into()),
                )),
                Err((_code, msg)) => SocketResponse::err(msg),
            }
        }

        "mem_query" => {
            let params = match serde_json::from_value::<MemQueryParams>(req.args.clone()) {
                Ok(p) => p,
                Err(e) => return SocketResponse::err(format!("invalid mem_query args: {e}")),
            };
            let mode = match params.mode.as_str() {
                "text" => super::protocol::QueryMode::Text,
                "tag" => super::protocol::QueryMode::Tag,
                "graph" => super::protocol::QueryMode::Graph,
                "dir_gotchas" => super::protocol::QueryMode::DirGotchas,
                "semantic" => super::protocol::QueryMode::Semantic,
                "policy_observations" => super::protocol::QueryMode::PolicyObservations,
                "policy_activity" => super::protocol::QueryMode::PolicyActivity,
                "analytics" => super::protocol::QueryMode::Analytics,
                other => {
                    return SocketResponse::err(format!(
                        "unknown mode: {other}. Valid modes: text, tag, graph, dir_gotchas, \
                         semantic, policy_observations, policy_activity, analytics"
                    ));
                }
            };
            let input = super::protocol::MemQueryInput {
                query: params.query,
                mode,
                limit: params.limit as u32,
                since: params.since,
            };
            let g = graph.read().await;
            match super::handlers::handle_mem_query(g.store(), &g, &input).await {
                Ok(v) => SocketResponse::ok(serde_json::Value::String(
                    serde_json::to_string_pretty(&v).unwrap_or_else(|_| "{}".into()),
                )),
                Err((_code, msg)) => SocketResponse::err(msg),
            }
        }

        "mem_bootstrap" => {
            let params = match serde_json::from_value::<MemBootstrapParams>(req.args.clone()) {
                Ok(p) => p,
                Err(e) => return SocketResponse::err(format!("invalid mem_bootstrap args: {e}")),
            };
            let input = super::protocol::MemBootstrapInput {
                context_files: params.context_files,
            };
            let ctx = build_v1_dispatch_ctx(repo_root);
            let g = graph.read().await;
            match super::handlers::handle_mem_bootstrap(
                g.store(),
                &g,
                graph,
                &ctx,
                uuid::Uuid::new_v4(),
                &input,
            )
            .await
            {
                Ok(s) => SocketResponse::ok(serde_json::Value::String(s)),
                Err((_code, msg)) => SocketResponse::err(msg),
            }
        }

        // ── Hook commands (store-only) ─────────────────────────────────
        // Acquire a short-lived read lock for store access. The lock is
        // released at the end of each arm — no risk of deadlock.
        "get" => {
            let key = match req.args.get("key").and_then(|v| v.as_str()) {
                Some(k) => k,
                None => return SocketResponse::err("missing args.key"),
            };
            let g = graph.read().await;
            let store = g.store();
            match store.get(key).await {
                Ok(Some(record)) => {
                    let confirmed = record
                        .payload_as::<crate::store::GotchaRecord>()
                        .map(|g| g.confirmed)
                        .unwrap_or(false);
                    match serde_json::to_value(&record) {
                        Ok(mut val) => {
                            if let Some(obj) = val.as_object_mut() {
                                obj.insert(
                                    "confirmed".to_string(),
                                    serde_json::Value::Bool(confirmed),
                                );
                            }
                            SocketResponse::ok(val)
                        }
                        Err(e) => SocketResponse::err(format!("serialize: {e}")),
                    }
                }
                Ok(None) => SocketResponse::ok(serde_json::Value::Null),
                Err(e) => SocketResponse::err(format!("store: {e}")),
            }
        }

        // ── Internal hook-decide bulk command ────────────────────────────
        // Returns file record + all linked gotcha records + consultation
        // status in a single round-trip. NOT an MCP tool.
        "hook_evaluate" => {
            let file_key = match req.args.get("file_key").and_then(|v| v.as_str()) {
                Some(k) => k,
                None => return SocketResponse::err("missing args.file_key"),
            };
            let include_recent = req
                .args
                .get("include_recent")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            let actor = req.args.get("actor").and_then(|v| v.as_str());

            let g = graph.read().await;
            let store = g.store();

            // 1. Fetch file record. Distinguish Ok(None) from Err.
            let (file_record, store_error) = match store.get(file_key).await {
                Ok(Some(r)) => (serde_json::to_value(&r).ok(), false),
                Ok(None) => (None, false),
                Err(e) => {
                    tracing::warn!("hook_evaluate: store.get({file_key}) failed: {e}");
                    (None, true)
                }
            };

            // 2. Fetch all linked gotcha records.
            //
            // The canonical link is `file_record.payload.gotcha_keys`, written
            // atomically by `compute_file_link_updates`. But CLAUDE.md flags
            // this field as a *derived* index that can drift from the
            // canonical `gotcha:*` records (e.g. if a gotcha was created
            // before the file record existed, or if a partial-write left the
            // file link stale). To make enforcement robust against that
            // drift, we union three sources:
            //   (a) `file_record.payload.gotcha_keys`               (primary)
            //   (b) in-memory graph edges `HasGotcha` from file_key  (secondary)
            //   (c) reverse scan of `gotcha:*` records whose
            //       `affected_files` contains the relative path     (fallback)
            // Source (c) is bounded by the active-gotcha count and
            // short-circuited when (a) or (b) already produced results, so
            // it does not add cost on the hot path.
            let mut gotcha_records = serde_json::Map::new();
            let mut gotcha_error = false;
            let mut linked_keys: std::collections::BTreeSet<String> =
                std::collections::BTreeSet::new();

            if let Some(ref fr) = file_record {
                if let Some(keys) = fr
                    .pointer("/payload/gotcha_keys")
                    .and_then(|v| v.as_array())
                {
                    for gk in keys {
                        if let Some(key_str) = gk.as_str() {
                            linked_keys.insert(key_str.to_string());
                        }
                    }
                }
            }

            // (b) Graph-edge fallback. Loaded at boot from `graph:edge:*`,
            // independent of the file record's denormalized list.
            for nkey in g.neighbors(file_key, &crate::graph::EdgeKind::HasGotcha) {
                linked_keys.insert(nkey);
            }

            // (c) Canonical reverse-lookup fallback. Only run when both
            // derived indexes were empty AND a file record exists — covers
            // the "file record present but gotcha_keys never synced" drift
            // path that CLAUDE.md documents as a known trap. Bounded scan
            // strips the relative path from the file_key once.
            if linked_keys.is_empty() && file_record.is_some() {
                let rel_path = file_key.strip_prefix("file:").unwrap_or(file_key);
                if let Ok(all_gotchas) = store.scan_prefix("gotcha:").await {
                    for r in all_gotchas {
                        if !matches!(r.lifecycle, crate::store::RecordLifecycle::Active) {
                            continue;
                        }
                        if let Some(g) = r.payload_as::<crate::store::GotchaRecord>() {
                            if g.affected_files.iter().any(|af| af == rel_path) {
                                linked_keys.insert(r.key.clone());
                            }
                        }
                    }
                }
            }

            for key_str in &linked_keys {
                match store.get(key_str).await {
                    Ok(Some(grec)) => {
                        // Skip tombstoned gotchas so they never feed into enforcement.
                        if !matches!(grec.lifecycle, crate::store::RecordLifecycle::Active) {
                            continue;
                        }
                        // Inline confirmed flag (same as "get" handler).
                        let confirmed = grec
                            .payload_as::<crate::store::GotchaRecord>()
                            .map(|g| g.confirmed)
                            .unwrap_or(false);
                        if let Ok(mut val) = serde_json::to_value(&grec) {
                            if let Some(obj) = val.as_object_mut() {
                                obj.insert(
                                    "confirmed".to_string(),
                                    serde_json::Value::Bool(confirmed),
                                );
                            }
                            gotcha_records.insert(key_str.clone(), val);
                        }
                    }
                    Ok(None) => {}
                    Err(e) => {
                        tracing::warn!("hook_evaluate: store.get({key_str}) failed: {e}");
                        gotcha_error = true;
                    }
                }
            }

            // Project the unified gotcha_keys back into the returned
            // file_record so decide.rs::evaluate (which iterates
            // `payload.gotcha_keys`) sees every gotcha we just unioned —
            // not just the ones the canonical link recorded.
            let file_record = if let Some(mut fr) = file_record {
                if !gotcha_records.is_empty() {
                    if let Some(payload) = fr.pointer_mut("/payload") {
                        if let Some(obj) = payload.as_object_mut() {
                            let keys: Vec<serde_json::Value> = gotcha_records
                                .keys()
                                .map(|k| serde_json::Value::String(k.clone()))
                                .collect();
                            obj.insert("gotcha_keys".to_string(), serde_json::Value::Array(keys));
                        }
                    }
                }
                Some(fr)
            } else {
                None
            };

            // 3. Consultation status.
            let consulted = sess::check_consulted(store, file_key, actor)
                .await
                .unwrap_or(false);
            let consulted_recent = if include_recent {
                sess::check_consulted_recent(store, file_key, 900, actor)
                    .await
                    .unwrap_or(false)
            } else {
                false
            };

            SocketResponse::ok(serde_json::json!({
                "file_key": file_key,
                "file_record": file_record,
                "gotcha_records": gotcha_records,
                "consulted": consulted,
                "consulted_recent": consulted_recent,
                "store_error": store_error,
                "gotcha_error": gotcha_error,
            }))
        }

        "log_hit" => {
            let key = match req.args.get("key").and_then(|v| v.as_str()) {
                Some(k) => k,
                None => return SocketResponse::err("missing args.key"),
            };
            let g = graph.read().await;
            if let Err(e) = sess::log_hit(g.store(), key).await {
                tracing::warn!("daemon socket log_hit: {e}");
            }
            SocketResponse::ok(serde_json::Value::Null)
        }

        "log_miss" => {
            let key = match req.args.get("key").and_then(|v| v.as_str()) {
                Some(k) => k,
                None => return SocketResponse::err("missing args.key"),
            };
            let g = graph.read().await;
            if let Err(e) = sess::log_miss(g.store(), key).await {
                tracing::warn!("daemon socket log_miss: {e}");
            }
            SocketResponse::ok(serde_json::Value::Null)
        }

        "log_compliance_miss" => {
            let key = match req.args.get("key").and_then(|v| v.as_str()) {
                Some(k) => k,
                None => return SocketResponse::err("missing args.key"),
            };
            let g = graph.read().await;
            let store = g.store();
            if let Err(e) = sess::log_compliance_miss(store, key).await {
                tracing::warn!("daemon socket log_compliance_miss: {e}");
            }
            // Record Deny enforcement event — best-effort
            let _ = crate::store::enforcement::record_event(
                store,
                crate::store::enforcement::EnforcementEventType::Deny,
                crate::store::enforcement::SubjectKind::File,
                key.to_string(),
                "claude".to_string(),
                None,
                "gotcha_above_threshold".to_string(),
                None,
            )
            .await;
            SocketResponse::ok(serde_json::Value::Null)
        }

        "log_compliance_hit" => {
            let key = match req.args.get("key").and_then(|v| v.as_str()) {
                Some(k) => k,
                None => return SocketResponse::err("missing args.key"),
            };
            let g = graph.read().await;
            let store = g.store();
            if let Err(e) = sess::log_compliance_hit(store, key).await {
                tracing::warn!("daemon socket log_compliance_hit: {e}");
            }
            // Record AllowAfterReceipt enforcement event — best-effort
            let _ = crate::store::enforcement::record_event(
                store,
                crate::store::enforcement::EnforcementEventType::AllowAfterReceipt,
                crate::store::enforcement::SubjectKind::File,
                key.to_string(),
                "claude".to_string(),
                None,
                "receipt_valid".to_string(),
                None,
            )
            .await;
            SocketResponse::ok(serde_json::Value::Null)
        }

        "log_codex_shell_miss" => {
            let key = match req.args.get("key").and_then(|v| v.as_str()) {
                Some(k) => k,
                None => return SocketResponse::err("missing args.key"),
            };
            let g = graph.read().await;
            if let Err(e) = sess::log_codex_shell_miss(g.store(), key).await {
                tracing::warn!("daemon socket log_codex_shell_miss: {e}");
            }
            SocketResponse::ok(serde_json::Value::Null)
        }

        "log_bootstrap" => {
            let key = match req.args.get("key").and_then(|v| v.as_str()) {
                Some(k) => k,
                None => return SocketResponse::err("missing args.key"),
            };
            let g = graph.read().await;
            if let Err(e) = sess::log_bootstrap(g.store(), key).await {
                tracing::warn!("daemon socket log_bootstrap: {e}");
            }
            SocketResponse::ok(serde_json::Value::Null)
        }

        "log_prompt_nudge" => {
            let key = match req.args.get("key").and_then(|v| v.as_str()) {
                Some(k) => k,
                None => return SocketResponse::err("missing args.key"),
            };
            let g = graph.read().await;
            if let Err(e) = sess::log_prompt_nudge(g.store(), key).await {
                tracing::warn!("daemon socket log_prompt_nudge: {e}");
            }
            SocketResponse::ok(serde_json::Value::Null)
        }

        "session_check_consulted" => {
            let key = match req.args.get("key").and_then(|v| v.as_str()) {
                Some(k) => k,
                None => return SocketResponse::err("missing args.key"),
            };
            let g = graph.read().await;
            match sess::check_consulted(g.store(), key, None).await {
                Ok(found) => SocketResponse::ok(serde_json::Value::Bool(found)),
                Err(e) => SocketResponse::err(format!("store: {e}")),
            }
        }

        "session_check_consulted_recent" => {
            let key = match req.args.get("key").and_then(|v| v.as_str()) {
                Some(k) => k,
                None => return SocketResponse::err("missing args.key"),
            };
            let ttl_secs = req
                .args
                .get("ttl_secs")
                .and_then(|v| v.as_u64())
                .unwrap_or(900);
            let g = graph.read().await;
            match sess::check_consulted_recent(g.store(), key, ttl_secs, None).await {
                Ok(found) => SocketResponse::ok(serde_json::Value::Bool(found)),
                Err(e) => SocketResponse::err(format!("store: {e}")),
            }
        }

        "session_flush" => {
            let g = graph.read().await;
            if let Err(e) = sess::session_flush(g.store()).await {
                tracing::warn!("daemon socket session_flush: {e}");
            }
            SocketResponse::ok(serde_json::Value::Null)
        }

        "session_harvest" => {
            let g = graph.read().await;
            if let Err(e) = sess::session_harvest(g.store(), repo_root).await {
                tracing::warn!("daemon socket session_harvest: {e}");
            }
            SocketResponse::ok(serde_json::Value::Null)
        }

        "reparse" => {
            let path = match req.args.get("path").and_then(|v| v.as_str()) {
                Some(p) => p,
                None => return SocketResponse::err("missing args.path"),
            };
            let g = graph.read().await;
            if let Err(e) = crate::analysis::reparse::reparse_impl(g.store(), repo_root, path).await
            {
                tracing::warn!("daemon socket reparse: {e}");
            }
            SocketResponse::ok(serde_json::Value::Null)
        }

        "edit_hook" => {
            let path = match req.args.get("path").and_then(|v| v.as_str()) {
                Some(p) => p,
                None => return SocketResponse::err("missing args.path"),
            };
            let file_key = format!("file:{path}");
            let g = graph.read().await;
            let store = g.store();
            if let Err(e) = sess::log_hit(store, &file_key).await {
                tracing::warn!("daemon socket edit_hook: log_hit failed: {e}");
            }
            if let Err(e) = crate::analysis::reparse::reparse_impl(store, repo_root, path).await {
                tracing::warn!("daemon socket edit_hook: reparse failed (non-fatal): {e}");
            }

            // Incremental blast radius update: recompute for the modified file,
            // its direct importers, and the files it imports.
            {
                use crate::analysis::blast_radius::BlastRadius;
                use crate::graph::edges::EdgeKind;

                let mut keys_to_update = vec![file_key.clone()];
                // Files that import this file (their blast radius may change if
                // this file's import list changed).
                keys_to_update.extend(g.neighbors_incoming(&file_key, &EdgeKind::Imports));
                // Files this file imports (this file now counts as an importer).
                keys_to_update.extend(g.neighbors(&file_key, &EdgeKind::Imports));

                for key in keys_to_update {
                    let br = BlastRadius::compute(&key, &g);
                    if let Ok(Some(mut rec)) = store.get(&key).await {
                        if let Some(mut fr) = rec.payload_as::<crate::store::record::FileRecord>() {
                            fr.blast_radius = Some(br);
                            rec.payload = serde_json::to_value(&fr).ok();
                            let _ = store.put(&key, &rec).await;
                        }
                    }
                }
            }

            // Incremental staleness propagation: recompute for the edited
            // file's direct importers and their importers (depth 2 only).
            // Does NOT recompute the full repo — keeps the hook fast.
            {
                let mut affected_keys = vec![file_key.clone()];
                let d1 = g.neighbors_incoming(&file_key, &EdgeKind::Imports);
                for d1k in &d1 {
                    affected_keys.push(d1k.clone());
                    affected_keys.extend(g.neighbors_incoming(d1k, &EdgeKind::Imports));
                }
                // Collect records for just the affected neighborhood
                let mut neighborhood_recs = Vec::new();
                for key in &affected_keys {
                    if let Ok(Some(rec)) = store.get(key).await {
                        neighborhood_recs.push(rec);
                    }
                }
                // Also include the edited file itself as a potential source
                if let Ok(Some(rec)) = store.get(&file_key).await {
                    if !neighborhood_recs.iter().any(|r| r.key == file_key) {
                        neighborhood_recs.push(rec);
                    }
                }
                let propagation =
                    crate::analysis::propagation::compute_propagation(&neighborhood_recs, &g);
                for (key, prop) in &propagation {
                    if let Ok(Some(mut rec)) = store.get(key).await {
                        if let Some(mut fr) = rec.payload_as::<crate::store::record::FileRecord>() {
                            fr.propagated_staleness = Some(prop.clone());
                            rec.payload = serde_json::to_value(&fr).ok();
                            let _ = store.put(key, &rec).await;
                        }
                    }
                }
            }

            SocketResponse::ok(serde_json::Value::Null)
        }

        "doc_capture" => {
            let path = match req.args.get("path").and_then(|v| v.as_str()) {
                Some(p) => p,
                None => return SocketResponse::err("missing args.path"),
            };
            let content = req
                .args
                .get("content")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let g = graph.read().await;
            if let Err(e) = sess::doc_capture(g.store(), path, content).await {
                tracing::warn!("daemon socket doc_capture: {e}");
            }
            SocketResponse::ok(serde_json::Value::Null)
        }

        "scan_prefix" => {
            let prefix = match req.args.get("prefix").and_then(|v| v.as_str()) {
                Some(p) => p,
                None => return SocketResponse::err("missing args.prefix"),
            };
            let g = graph.read().await;
            match g.store().scan_prefix(prefix).await {
                Ok(records) => match serde_json::to_value(&records) {
                    Ok(val) => SocketResponse::ok(val),
                    Err(e) => SocketResponse::err(format!("serialize: {e}")),
                },
                Err(e) => SocketResponse::err(format!("store: {e}")),
            }
        }

        "scan_keys" => {
            let prefix = match req.args.get("prefix").and_then(|v| v.as_str()) {
                Some(p) => p,
                None => return SocketResponse::err("missing args.prefix"),
            };
            let g = graph.read().await;
            match g.store().scan_keys(prefix).await {
                Ok(keys) => match serde_json::to_value(&keys) {
                    Ok(val) => SocketResponse::ok(val),
                    Err(e) => SocketResponse::err(format!("serialize: {e}")),
                },
                Err(e) => SocketResponse::err(format!("store: {e}")),
            }
        }

        "scan_enforcement_events" => {
            let since_seq = req
                .args
                .get("since_seq")
                .and_then(|v| v.as_u64())
                .unwrap_or(0);
            let until_seq = req
                .args
                .get("until_seq")
                .and_then(|v| v.as_u64())
                .unwrap_or(u64::MAX);
            let g = graph.read().await;
            match crate::store::enforcement::scan_enforcement_events(
                g.store(),
                since_seq,
                until_seq,
            )
            .await
            {
                Ok(events) => match serde_json::to_value(&events) {
                    Ok(val) => SocketResponse::ok(val),
                    Err(e) => SocketResponse::err(format!("serialize: {e}")),
                },
                Err(e) => SocketResponse::err(format!("store: {e}")),
            }
        }

        "scan_enforcement_events_since_ms" => {
            let since_ms = req
                .args
                .get("since_ms")
                .and_then(|v| v.as_u64())
                .unwrap_or(0);
            let until_ms = req
                .args
                .get("until_ms")
                .and_then(|v| v.as_u64())
                .unwrap_or(u64::MAX);
            let g = graph.read().await;
            match crate::store::enforcement::scan_enforcement_events_since_ms(
                g.store(),
                since_ms,
                until_ms,
            )
            .await
            {
                Ok(scan) => match serde_json::to_value(&scan) {
                    Ok(val) => SocketResponse::ok(val),
                    Err(e) => SocketResponse::err(format!("serialize: {e}")),
                },
                Err(e) => SocketResponse::err(format!("store: {e}")),
            }
        }

        "put" => {
            use crate::store::Record;
            let key = match req.args.get("key").and_then(|v| v.as_str()) {
                Some(k) => k,
                None => return SocketResponse::err("missing args.key"),
            };
            let record: Record = match req
                .args
                .get("record")
                .and_then(|v| serde_json::from_value(v.clone()).ok())
            {
                Some(r) => r,
                None => return SocketResponse::err("put: invalid record"),
            };
            let g = graph.read().await;
            match g.store().put(key, &record).await {
                Ok(()) => SocketResponse::ok(serde_json::Value::Null),
                Err(e) => SocketResponse::err(format!("store put: {e}")),
            }
        }

        "delete" => {
            let key = match req.args.get("key").and_then(|v| v.as_str()) {
                Some(k) => k,
                None => return SocketResponse::err("missing args.key"),
            };
            let g = graph.read().await;
            match g.store().delete(key).await {
                Ok(()) => SocketResponse::ok(serde_json::Value::Null),
                Err(e) => SocketResponse::err(format!("delete: {e}")),
            }
        }

        "history" => {
            let key = match req.args.get("key").and_then(|v| v.as_str()) {
                Some(k) => k,
                None => return SocketResponse::err("missing args.key"),
            };
            let limit = req.args.get("limit").and_then(|v| v.as_u64()).unwrap_or(50) as usize;
            let g = graph.read().await;
            match g.store().history(key, limit) {
                Ok(entries) => match serde_json::to_value(&entries) {
                    Ok(val) => SocketResponse::ok(val),
                    Err(e) => SocketResponse::err(format!("serialize: {e}")),
                },
                Err(e) => SocketResponse::err(format!("history: {e}")),
            }
        }

        "history_since" => {
            let key = match req.args.get("key").and_then(|v| v.as_str()) {
                Some(k) => k,
                None => return SocketResponse::err("missing args.key"),
            };
            let since_ts = req
                .args
                .get("since_ts")
                .and_then(|v| v.as_u64())
                .unwrap_or(0);
            let limit = req.args.get("limit").and_then(|v| v.as_u64()).unwrap_or(50) as usize;
            let g = graph.read().await;
            match g.store().history_since(key, since_ts, limit) {
                Ok(entries) => match serde_json::to_value(&entries) {
                    Ok(val) => SocketResponse::ok(val),
                    Err(e) => SocketResponse::err(format!("serialize: {e}")),
                },
                Err(e) => SocketResponse::err(format!("history_since: {e}")),
            }
        }

        "gotcha_write" => {
            use crate::store::gotcha_ops::apply_gotcha_write;
            use crate::store::Record;

            let record: Record = match req
                .args
                .get("record")
                .and_then(|v| serde_json::from_value(v.clone()).ok())
            {
                Some(r) => r,
                None => return SocketResponse::err("missing or invalid args.record"),
            };
            // Normalize up front, not just inside `apply_gotcha_write`: the
            // in-memory graph sync below keys its edges off this list, and a
            // raw spelling here would diverge from the edges just persisted.
            let new_files: Vec<String> = crate::store::gotcha_ops::normalize_affected_files(
                &req.args
                    .get("new_files")
                    .and_then(|v| serde_json::from_value::<Vec<String>>(v.clone()).ok())
                    .unwrap_or_default(),
            );
            let old_files: Vec<String> = req
                .args
                .get("old_files")
                .and_then(|v| serde_json::from_value(v.clone()).ok())
                .unwrap_or_default();
            let is_new = req
                .args
                .get("is_new")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);

            {
                let g = graph.read().await;
                match apply_gotcha_write(g.store(), &record, &old_files, &new_files, is_new).await {
                    Ok(()) => {}
                    Err(e) => return SocketResponse::err(format!("{e}")),
                }
            }

            // Sync the in-memory graph: add HasGotcha edges for newly-affected files,
            // remove edges for files no longer affected. The persistent store was already
            // updated by apply_gotcha_write above; this keeps the in-memory adjacency list
            // in sync so that assemble_context_packet (bootstrap) sees the edges immediately
            // without requiring a daemon restart.
            let record_key = record.key.clone();
            let old_set: std::collections::HashSet<&str> =
                old_files.iter().map(String::as_str).collect();
            let new_set: std::collections::HashSet<&str> =
                new_files.iter().map(String::as_str).collect();
            {
                let mut g = graph.write().await;
                for file_path in new_set.difference(&old_set) {
                    let file_key = format!("file:{file_path}");
                    let _ = g
                        .add_edge(&file_key, EdgeKind::HasGotcha, &record_key)
                        .await;
                }
                for file_path in old_set.difference(&new_set) {
                    let file_key = format!("file:{file_path}");
                    let _ = g
                        .remove_edge(&file_key, &EdgeKind::HasGotcha, &record_key)
                        .await;
                }
            }

            SocketResponse::ok(serde_json::Value::String("written".into()))
        }

        "gotcha_tombstone" => {
            use crate::store::gotcha_ops::apply_gotcha_tombstone;

            let key = match req.args.get("key").and_then(|v| v.as_str()) {
                Some(k) => k,
                None => return SocketResponse::err("missing args.key"),
            };
            if !key.starts_with("gotcha:") {
                return SocketResponse::err("delete action only applies to gotcha: keys");
            }
            // Read affected_files from args if provided, otherwise look up the
            // record to get them. The MCP proxy sends delete without affected_files.
            let mut affected_files: Vec<String> = req
                .args
                .get("affected_files")
                .and_then(|v| serde_json::from_value(v.clone()).ok())
                .unwrap_or_default();

            let g = graph.read().await;
            if affected_files.is_empty() {
                if let Ok(Some(record)) = g.store().get(key).await {
                    if let Some(gotcha) = record.payload_as::<crate::store::GotchaRecord>() {
                        affected_files = gotcha.affected_files;
                    }
                }
            }
            match apply_gotcha_tombstone(g.store(), key, &affected_files).await {
                Ok(()) => SocketResponse::ok(serde_json::Value::String("tombstoned".into())),
                Err(e) => SocketResponse::err(format!("{e}")),
            }
        }

        "gotcha_confirm" => {
            let key = match req.args.get("key").and_then(|v| v.as_str()) {
                Some(k) => k,
                None => return SocketResponse::err("missing args.key"),
            };

            // Read record
            let g = graph.read().await;
            let store = g.store();
            let mut record = match store.get(key).await {
                Ok(Some(r)) => r,
                Ok(None) => return SocketResponse::err(format!("record not found: {key}")),
                Err(e) => return SocketResponse::err(format!("store get: {e}")),
            };

            if record.category != crate::store::record::Category::Gotcha {
                return SocketResponse::err(format!("{key} is not a gotcha record"));
            }

            if !matches!(
                record.lifecycle,
                crate::store::record::RecordLifecycle::Active
            ) {
                return SocketResponse::err(format!(
                    "{key} is tombstoned — cannot confirm a deleted record"
                ));
            }

            // Set confirmed + normalize severity
            if let Some(ref mut payload) = record.payload {
                if let Some(obj) = payload.as_object_mut() {
                    if let Some(sev) = obj
                        .get("severity")
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_lowercase())
                    {
                        obj.insert("severity".to_string(), serde_json::Value::String(sev));
                    }
                    obj.insert("confirmed".to_string(), serde_json::Value::Bool(true));
                }
            }

            record.source = crate::store::record::RecordSource::DeveloperManual;
            record.confidence.value = crate::store::record::ConfidenceScore::base_for_source(
                &crate::store::record::RecordSource::DeveloperManual,
            );
            record.confidence.confirmation_count += 1;
            record.quality = crate::health::quality::analyze(&record);

            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            record.updated_at = now;
            record.version.logical_clock += 1;
            record.version.wall_clock = now;

            // Extract affected_files for file-link sync
            let affected_files: Vec<String> = record
                .payload_as::<crate::store::record::GotchaRecord>()
                .map(|g| g.affected_files)
                .unwrap_or_default();

            if let Err(e) = store.put(key, &record).await {
                return SocketResponse::err(format!("store put: {e}"));
            }

            // Sync file:*.gotcha_keys — best-effort
            for file_path in &affected_files {
                let file_key = format!("file:{file_path}");
                if let Ok(Some(mut file_record)) = store.get(&file_key).await {
                    let needs_link = file_record
                        .payload
                        .as_ref()
                        .and_then(|p| p.get("gotcha_keys"))
                        .and_then(|v| v.as_array())
                        .map(|arr| !arr.iter().any(|v| v.as_str() == Some(key)))
                        .unwrap_or(true);
                    if needs_link {
                        if let Some(ref mut payload) = file_record.payload {
                            if let Some(obj) = payload.as_object_mut() {
                                let arr = obj.entry("gotcha_keys").or_insert(serde_json::json!([]));
                                if let Some(arr) = arr.as_array_mut() {
                                    arr.push(serde_json::Value::String(key.to_string()));
                                }
                            }
                        }
                        let _ = store.put(&file_key, &file_record).await;
                    }
                }
            }

            // Propagate confirmation_count to linked file records
            crate::store::gotcha_ops::propagate_confirmation_to_files(store, &affected_files).await;

            // Record ControlChanged::Confirmed enforcement event — best-effort.
            let _ = crate::store::enforcement::record_event(
                store,
                crate::store::enforcement::EnforcementEventType::ControlChanged {
                    change_kind: crate::store::enforcement::ControlChangeKind::Confirmed,
                },
                crate::store::enforcement::SubjectKind::Control,
                key.to_string(),
                "developer".to_string(),
                None,
                "control_confirmed".to_string(),
                None,
            )
            .await;

            SocketResponse::ok(serde_json::json!({"confirmed": true, "key": key}))
        }

        other => SocketResponse::err(format!("unknown command: {other}")),
    }
}
