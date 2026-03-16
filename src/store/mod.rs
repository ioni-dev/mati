// Storage layer — SurrealKV (M-03)
// Implements Store::get, Store::put, Store::delete, Store::scan_prefix
// Two trees: knowledge.db (Immediate durability) + sessions.db (Eventual)
// Path: ~/.mati/<slug>/knowledge.db
