# Phase 0 local-mode breakage catalogue

Base: `origin/main` c104eecfb38620de2c35c7e20a716f8658b5a6b1. Spike branch: `spike/local-mode-relay`.

## Result

`BUZZ_LOCAL_MODE=1 BUZZ_BIND_ADDR=127.0.0.1:4317 BUZZ_RELAY_URL=ws://127.0.0.1:4317 BUZZ_LOCAL_DB=sqlite:///tmp/buzz-phase0.sqlite target/debug/buzz-relay` boots without Postgres, Redis, or S3. The real `buzz-test-client` proves NIP-42, SQLite event insertion, historical REQ filtering (including across relay restart), and two-client live fan-out. This is a deliberately separate tracer-bullet path, not the production `AppState` and not mergeable architecture.

## Worked as-is

| Module | Evidence | Result |
|---|---|---|
| NIP-01 frame parsing/formatting | `crates/buzz-relay/src/protocol.rs:15-175,177-217` reused by `local_mode.rs:22,99-143` | EVENT, REQ, CLOSE, COUNT and AUTH wire shapes required no changes. |
| Nostr signature/filter implementation | `local_mode.rs:113-127,159-176` | Signature verification, dedupe by event ID, and `Filter::match_event` work in memory. |
| Axum/WebSocket runtime | `local_mode.rs:64-76` | Same binary serves WebSocket plus liveness/readiness on loopback. |
| Existing client | `crates/buzz-test-client/src/bin/local_mode_smoke.rs` | Real NIP-42 client exercised auth/store/history/fan-out. |

## Worked with shim

| Module | Evidence | Fidelity / breakage |
|---|---|---|
| Event store + REQ | `local_mode.rs:56-80,130-163,199-207` | SQLite via sqlx; a two-column `events(id,event_json)` table gives durable insert/dedupe and restart history. REQ deserializes all rows then applies `Filter::match_event` in Rust: O(n), no replacement/deletion/tenant/channel visibility semantics. |
| Pubsub | `local_mode.rs:53,58-63,93-94,126,146-154` | `tokio::broadcast`; fan-out works in one process. Redis topic scoping, reconnect, cross-pod invalidation and connection control absent. Existing Redis-only shape is explicit at `crates/buzz-pubsub/src/lib.rs:99-139`. |
| NIP-42 | `local_mode.rs:79-111,159-170` | Crypto challenge/relay/signature verification works. Moderation, allowlist, relay membership, and NIP-OA backfill are bypassed; production coupling starts at `handlers/auth.rs:94-260`. |
| Health | `local_mode.rs:64-70` | Static OK; does not inspect backend health. |

## Stubbed / bypassed

| Module | Evidence | Spike behavior |
|---|---|---|
| Presence + typing | Redis modules enumerated at `crates/buzz-pubsub/src/lib.rs:30-43` | No-op / absent. |
| Rate limiting + NIP-98 replay | Production fields at `state.rs:576-584`; Redis construction `state.rs:711-713` | Permissive no-op / absent. |
| Media | S3-only concrete `MediaStorage` at `crates/buzz-media/src/storage.rs:18-70`; startup at `main.rs:448-454` | HTTP media routes absent. No fs shim attempted because bypassing `AppState` removed the route surface. |
| Search | PG pool constructed at `main.rs:403-419` | Route/service absent; expected unsupported. |
| Audit/workflows/git | PG/S3 construction at `main.rs:355-367,422-423`; `state.rs:692-713` | Absent. |
| Channel/membership/moderation | Production auth DB calls begin `handlers/auth.rs:94`; Db has 50 channel and 23 relay-members query call sites | Open-relay behavior: any valid NIP-42 identity can publish/read; channel tags are filter data only. |
| Replica fence, partition, usage, push, mesh | DB boot invokes partitions/fence `main.rs:200-222`; excluded by brief | Skipped entirely. |

## Hard boundary found

The production router cannot be retained while swapping only the core store. `AppState` is a concrete service aggregate, not a seam: concrete `Db`, Redis pool/manager, `SearchService`, and `MediaStorage` are mandatory fields (`state.rs:488-502,554-584`) and constructor parameters (`state.rs:637-648`). Constructor body also creates S3-backed git storage plus Redis replay/rate-limit services (`state.rs:692-713`). Startup eagerly connects Postgres (`main.rs:172-192`), Redis (`main.rs:369-399`), search Postgres (`main.rs:403-419`), and S3 (`main.rs:448-454`) before router construction.

Therefore a SQLite port of `event.rs` alone cannot boot the existing handler/router path. Phase 1 must first separate a local profile/router service aggregate or add backend traits/configurable optional services. **SECURITY WARNING — OPEN RELAY:** the tracer accepts any cryptographically valid NIP-42 identity and allows it to publish/read every stored event. This is spike-only behavior and must not survive into Phase 1 without an explicit unsafe flag.

The tracer bullet confirms protocol/client compatibility and minimal SQLite durability but **does not yet meet the desktop+agent/channel success criterion**.

## Phase 2 estimate refinement

SQLite datum: enabling sqlx SQLite compiled without source changes outside the tracer. Basic durable event JSON uses portable table creation plus SQLite `INSERT OR IGNORE`; the production `event.rs` cannot be mechanically reused because its 39 queries assume the production schema, typed columns, community/channel fences, replacement rules, deletion, and PG-specific query composition. This cheap datum shows driver/toolchain viability, not a completed `event.rs` port.

Core SQL count is not the main blocker. `event.rs` has 39 `sqlx::query` call sites; unavoidable auth/chat widening immediately adds approximately channel (50), relay_members (23), moderation (15), user (11), reaction (8), thread (19), DM (12), and feed (2), before shared `lib.rs` queries. A useful real-client slice is thus roughly 179 module-level query sites, not 39, plus creating the AppState/service seam. Recommended next tracer bullet: land the service aggregate/profile seam first, then port event + tenant/community + auth moderation/membership + channel as one vertical slice.

## Commands and observed output

```text
cargo check -p buzz-relay
# PASS

cargo test -p buzz-relay --lib
# 792 passed; 10 failed; 35 ignored
# Failures require external DB/media/mesh and are present in untouched production tests.

BUZZ_LOCAL_MODE=1 ... target/debug/buzz-relay
# BUZZ_LOCAL_MODE active: SQLite store and in-process fan-out; external services bypassed

target/debug/local_mode_smoke ws://127.0.0.1:4317
# PASS nip42,event_insert,req_history,live_fanout

# after relay restart against same BUZZ_LOCAL_DB
target/debug/local_mode_smoke ws://127.0.0.1:4317 history-only
# PASS sqlite_restart_history
```
