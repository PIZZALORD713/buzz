# SQLite relay handler test classification

S4.2 inventory for relay handler, API, and workflow tests that were originally
`#[ignore = "requires Postgres"]` at harness commit `60c067e`. SQLite runs the
25 implemented-only tests through `BUZZ_TEST_BACKEND=sqlite`; the nine remaining
PostgreSQL tests carry the same greppable `SQLite skip:` reason in their
`#[ignore]` attribute.

Reasons are copied from [`buzz-db`'s SQLite backend
inventory](../buzz-db/SQLITE_BACKEND_INVENTORY.md).

## Runs on both backends (25)

| Test module | Tests converted to shared harness | SQLite methods exercised |
| --- | --- | --- |
| `api::bridge` | four HTTP rejection-counter tests | `ensure_configured_community` |
| `api::git::policy` | `push_gate_denies_owner_through_broken_binding` | `ensure_configured_community`, `insert_event`, read-gate queries |
| `api::git::transport` | four read-gate tests | community/user/channel/member/event lifecycle methods |
| `api::invites` | 11 invite validation/claim/policy/document tests | relay-member and invite methods; side-effect publication is separately skipped below |
| `api::operator` | `non_allowlisted_operator_key_gets_403`, `post_operator_body_requires_payload_tag`, and two malformed transfer-request tests | no community lifecycle mutation; request/auth validation only |
| `handlers::relay_admin` | two kind-9033 admission tests | `ensure_configured_community`, relay-member and icon methods |

## SQLite skips (9)

| Test | S2 unsupported method | Inventory reason |
| --- | --- | --- |
| `api::invites::bounded_v2_claims_publish_side_effects_only_for_joined` | `publish_nip43_membership_locked` | relay membership maintenance is PostgreSQL-only |
| `api::operator::unmapped_management_host_can_check_availability` | `lookup_community_by_host_for_management` | community lifecycle management is PostgreSQL-only |
| `api::operator::unmapped_management_host_can_list_owned_communities` | `list_communities_owned_by` | community lifecycle management is PostgreSQL-only |
| `api::operator::unarchive_restores_admission_and_is_idempotent_without_changing_ownership` | `unarchive_community_owned_by` | community lifecycle management is PostgreSQL-only |
| `api::operator::archive_publish_failure_is_retryable_and_preserves_timestamp` | `archive_community_owned_by` | community lifecycle management is PostgreSQL-only |
| `api::operator::happy_path_create_returns_created_and_bootstraps_owner` | `create_community_with_owner` | community lifecycle management is PostgreSQL-only |
| `api::operator::fresh_host_at_owner_limit_returns_limit_reached_conflict` | `create_community_with_owner` | community lifecycle management is PostgreSQL-only |
| `api::operator::happy_path_transfer_swaps_owner_and_demotes_old_to_member` | `transfer_ownership` | relay membership maintenance is PostgreSQL-only |
| `workflow_sink::integration_tests::workflow_send_message_p_tags_mentioned_member` | `create_community_with_owner` | community lifecycle management is PostgreSQL-only |

## Known PostgreSQL-side failures (not changed here)

The existing PostgreSQL integration run has three known failures: the
`product_feedback`, `relay_members`, and owner-limit suites. They reproduce at
the S4.1 base and are not SQLite-harness regressions.
