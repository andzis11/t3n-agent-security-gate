use serde::{Deserialize, Serialize};

wit_bindgen::generate!({
    world: "agent-security-gate",
    path: "wit",
    additional_derives: [serde::Deserialize, serde::Serialize],
    generate_all,
});

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ActionRequest {
    tenant_did: String,
    agent_did: String,
    action: String,
    resource: String,
    amount_minor: u64,
    currency: String,
    nonce: String,
}

#[derive(Debug, PartialEq, Serialize)]
struct Decision {
    decision: &'static str,
    reason: &'static str,
}

fn decide(req: &ActionRequest) -> Decision {
    if !req.tenant_did.starts_with("did:t3n:") {
        return Decision { decision: "deny", reason: "invalid_tenant_did" };
    }
    if !req.agent_did.starts_with("did:t3n:") {
        return Decision { decision: "deny", reason: "invalid_agent_did" };
    }
    if req.resource.is_empty() || req.resource.len() > 256 || req.nonce.len() < 8 || req.nonce.len() > 128 {
        return Decision { decision: "deny", reason: "invalid_request_binding" };
    }
    if !matches!(req.action.as_str(), "vendor.quote.read" | "purchase.reserve") {
        return Decision { decision: "deny", reason: "action_not_allowed" };
    }
    if req.currency != "USD" {
        return Decision { decision: "deny", reason: "currency_mismatch" };
    }
    if req.amount_minor > 100_000 {
        return Decision { decision: "deny", reason: "budget_exceeded" };
    }
    if req.amount_minor > 50_000 {
        return Decision { decision: "require_approval", reason: "approval_threshold_exceeded" };
    }
    Decision { decision: "allow", reason: "policy_satisfied" }
}

pub fn evaluate_bytes(input: &[u8]) -> Result<Vec<u8>, String> {
    let req: ActionRequest = serde_json::from_slice(input)
        .map_err(|_| "invalid_request_json".to_string())?;
    serde_json::to_vec(&decide(&req)).map_err(|_| "response_encoding_failed".to_string())
}

struct Component;

#[cfg(target_arch = "wasm32")]
impl exports::z::agent_security_gate::contracts::Guest for Component {
    fn evaluate_action(
        req: exports::z::agent_security_gate::contracts::GenericInput,
    ) -> Result<Vec<u8>, String> {
        let input = req.input.ok_or_else(|| "evaluate-action: missing input".to_string())?;
        evaluate_bytes(&input)
    }
}

#[cfg(target_arch = "wasm32")]
export!(Component);

#[cfg(test)]
mod tests {
    use super::*;

    fn request(action: &str, amount: u64) -> Vec<u8> {
        format!(r#"{{"tenant_did":"did:t3n:tenant","agent_did":"did:t3n:agent","action":"{action}","resource":"order/42","amount_minor":{amount},"currency":"USD","nonce":"nonce-0001"}}"#).into_bytes()
    }

    fn result(action: &str, amount: u64) -> Decision {
        let bytes = evaluate_bytes(&request(action, amount)).unwrap();
        serde_json::from_slice::<serde_json::Value>(&bytes).map(|v| Decision {
            decision: match v["decision"].as_str().unwrap() { "allow" => "allow", "deny" => "deny", _ => "require_approval" },
            reason: match v["reason"].as_str().unwrap() {
                "policy_satisfied" => "policy_satisfied",
                "action_not_allowed" => "action_not_allowed",
                "budget_exceeded" => "budget_exceeded",
                _ => "approval_threshold_exceeded",
            },
        }).unwrap()
    }

    #[test]
    fn allows_bounded_action() {
        assert_eq!(result("purchase.reserve", 20_000), Decision { decision: "allow", reason: "policy_satisfied" });
    }

    #[test]
    fn requires_approval_above_threshold() {
        assert_eq!(result("purchase.reserve", 60_000).decision, "require_approval");
    }

    #[test]
    fn denies_unknown_action_and_over_budget() {
        assert_eq!(result("secret.export", 0).reason, "action_not_allowed");
        assert_eq!(result("purchase.reserve", 100_001).reason, "budget_exceeded");
    }

    #[test]
    fn rejects_malformed_or_extra_fields() {
        assert!(evaluate_bytes(b"not-json").is_err());
        let extra = br#"{"tenant_did":"did:t3n:t","agent_did":"did:t3n:a","action":"purchase.reserve","resource":"x","amount_minor":1,"currency":"USD","nonce":"nonce-0001","unexpected":true}"#;
        assert!(evaluate_bytes(extra).is_err());
    }
}
