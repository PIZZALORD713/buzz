//! Startup backfill of NIP-OA auth tags for legacy managed-agent records.
//!
//! Local-workspace agent records created before NIP-OA support have no
//! `auth_tag`; this derives one from the workspace owner keys so those agents
//! can authenticate against the local relay.

use tauri::AppHandle;

use crate::{
    app_state::AppState,
    managed_agents::{load_managed_agents, save_managed_agents},
    util::now_iso,
};

pub(super) fn backfill_missing_agent_auth_tags(
    app: &AppHandle,
    state: &AppState,
) -> Result<usize, String> {
    let owner_keys = state.signing_keys()?;
    let compat_owner = nostr::Keys::parse(&owner_keys.secret_key().to_secret_hex())
        .map_err(|e| format!("failed to bridge owner keys: {e}"))?;
    let _store_guard = state
        .managed_agents_store_lock
        .lock()
        .map_err(|e| e.to_string())?;
    let mut records = load_managed_agents(app)?;
    let mut changed = 0;
    for record in &mut records {
        if record.auth_tag.is_some()
            || record
                .pubkey
                .eq_ignore_ascii_case(&owner_keys.public_key().to_hex())
        {
            continue;
        }
        let agent = nostr::PublicKey::from_hex(&record.pubkey)
            .map_err(|e| format!("invalid managed agent pubkey {}: {e}", record.pubkey))?;
        record.auth_tag = Some(
            buzz_sdk_pkg::nip_oa::compute_auth_tag(&compat_owner, &agent, "").map_err(|e| {
                format!(
                    "failed to compute NIP-OA auth tag for {}: {e}",
                    record.pubkey
                )
            })?,
        );
        record.updated_at = now_iso();
        changed += 1;
    }
    if changed > 0 {
        save_managed_agents(app, &records)?;
    }
    Ok(changed)
}
