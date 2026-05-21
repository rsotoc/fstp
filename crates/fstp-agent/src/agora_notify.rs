//! Accountability webhooks to Ágora (whitepaper §4.2 protocol-level privacy audit).
//! POST presentations / federation events after SA processes federation messages.

use chrono::Utc;
use fstp_core::message::EventClass;
use fstp_core::types::{ContextualId, Sha256Hash};

/// Notify Ágora after an inbound federated present-credential (Phase 2 callback).
pub async fn notify_presentation(
    counterpart_url: &str,
    subject_id: &str,
    credential_type: &str,
    subject_cii: &ContextualId,
) {
    let (Ok(base), Ok(key)) = (std::env::var("FSTP_AGORA_BASE_URL"), pod_agent_key()) else {
        return;
    };
    let url = format!(
        "{}/api/pod-agent/v1/presentations",
        base.trim_end_matches('/')
    );
    let body = serde_json::json!({
        "recipientKind": "pod",
        "recipientLabel": counterpart_url,
        "initiatedBy": "platform",
        "contextType": "FSTP_PRESENT_CREDENTIAL",
        "contextDetail": format!("subject_cii={};subject_id={}", subject_cii.0, subject_id),
        "credentialType": credential_type,
    });
    post_agora(&url, &key, &body).await;
}

/// Notify Ágora after a federation control block is recorded (Phase 4).
pub async fn notify_federation_event(
    event_class: EventClass,
    instance_cii: &str,
    event_hash: &Sha256Hash,
    link_id: uuid::Uuid,
) {
    let (Ok(base), Ok(key)) = (std::env::var("FSTP_AGORA_BASE_URL"), pod_agent_key()) else {
        return;
    };
    let url = format!(
        "{}/api/pod-agent/v1/federation/events",
        base.trim_end_matches('/')
    );
    let body = serde_json::json!({
        "eventClass": format!("{:?}", event_class).to_lowercase(),
        "instanceCii": instance_cii,
        "eventHash": event_hash.to_hex(),
        "linkId": link_id.to_string(),
        "occurredAt": Utc::now().to_rfc3339(),
    });
    post_agora(&url, &key, &body).await;
}

async fn post_agora(url: &str, key: &str, body: &serde_json::Value) {
    if let Err(e) = reqwest::Client::new()
        .post(url)
        .header("X-Pod-Agent-Key", key)
        .json(body)
        .send()
        .await
    {
        tracing::warn!(url = %url, error = %e, "Agora webhook failed (non-fatal)");
    }
}

fn pod_agent_key() -> Result<String, std::env::VarError> {
    std::env::var("FSTP_POD_AGENT_KEY").or_else(|_| std::env::var("FSTP_AGORA_POD_AGENT_KEY"))
}
