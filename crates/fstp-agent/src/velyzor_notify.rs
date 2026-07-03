//! Accountability webhooks to Velyzor (whitepaper §4.2 protocol-level privacy audit).
//! POST presentations / federation events after SA processes federation messages.

use chrono::Utc;
use fstp_core::message::EventClass;
use fstp_core::types::{ContextualId, Sha256Hash};

fn velyzor_base_url() -> Option<String> {
    std::env::var("FSTP_VELYZOR_BASE_URL")
        .ok()
        .filter(|u| !u.trim().is_empty())
        .or_else(|| {
            std::env::var("FSTP_AGORA_BASE_URL")
                .ok()
                .filter(|u| !u.trim().is_empty())
        })
}

/// Notify Velyzor after an inbound federated present-credential (Phase 2 callback).
pub async fn notify_presentation(
    counterpart_url: &str,
    subject_id: &str,
    credential_type: &str,
    subject_cii: &ContextualId,
) {
    let (Some(base), Ok(key)) = (velyzor_base_url(), pod_agent_key()) else {
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
    post_velyzor(&url, &key, &body).await;
}

/// Notify Velyzor after a federation control block is recorded (Phase 4).
pub async fn notify_federation_event(
    event_class: EventClass,
    instance_cii: &str,
    event_hash: &Sha256Hash,
    link_id: uuid::Uuid,
) {
    let (Some(base), Ok(key)) = (velyzor_base_url(), pod_agent_key()) else {
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
    post_velyzor(&url, &key, &body).await;
}

async fn post_velyzor(url: &str, key: &str, body: &serde_json::Value) {
    if let Err(e) = reqwest::Client::new()
        .post(url)
        .header("X-Pod-Agent-Key", key)
        .json(body)
        .send()
        .await
    {
        tracing::warn!(url = %url, error = %e, "Velyzor webhook failed (non-fatal)");
    }
}

fn pod_agent_key() -> Result<String, std::env::VarError> {
    std::env::var("FSTP_POD_AGENT_KEY").or_else(|_| std::env::var("FSTP_VELYZOR_POD_AGENT_KEY"))
}
