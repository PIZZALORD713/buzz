# SQLite backend inventory

Generated from `#[sqlite_backend(...)]` declarations in `crates/buzz-db/src/lib.rs`.

> ⚠️ **PROVISIONAL — classification in progress.** Most declarations are mechanical placeholders and this table is not yet valid S6 input.

Regenerate after changing declarations with:

```sh
cargo test -p buzz-db backend_inventory_is_current -- --nocapture
```

| Method | SQLite status | Reason |
| --- | --- | --- |
| `usage_community_count` | unsupported | usage analytics is PostgreSQL-only |
