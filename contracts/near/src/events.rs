//! NEP-297 events: `EVENT_JSON:{"standard":"plr","version":"1.0.0","event":"<name>","data":[...]}` (SPEC §7).

use near_sdk::env;
use near_sdk::serde_json::{json, Value};

pub const STANDARD: &str = "plr";
pub const VERSION: &str = "1.0.0";

pub const COMPOSE_ALLOWED: &str = "compose_allowed";
pub const COMPOSE_REVOKED: &str = "compose_revoked";
pub const OS_ALLOWED: &str = "os_allowed";
pub const OS_REVOKED: &str = "os_revoked";
pub const ROOT_SET: &str = "root_set";
pub const OWNER_PROPOSED: &str = "owner_proposed";
pub const OWNER_ACCEPTED: &str = "owner_accepted";
pub const INSTANCE_REGISTERED: &str = "instance_registered";
pub const RECEIPTS_ANCHORED: &str = "receipts_anchored";
pub const OPERATOR_APPROVED: &str = "operator_approved";
pub const OPERATOR_REVOKED: &str = "operator_revoked";
/// rev 1.3 `migrate`: every compose approval of the rev ≤ 1.2 state was dropped.
pub const COMPOSE_ALLOWLIST_RESET: &str = "compose_allowlist_reset";

/// Logs one NEP-297 event with a single data entry.
pub fn emit(event: &str, data: Value) {
    let body = json!({ "standard": STANDARD, "version": VERSION, "event": event, "data": [data] });
    env::log_str(&format!("EVENT_JSON:{body}"));
}
