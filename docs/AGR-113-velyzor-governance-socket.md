# AGR-113 — Velyzor → Sync Agent governance socket

## Boundary

Velyzor (Spring Boot / JVM) sends **only** `GovernanceEventNotification` (protobuf) to the Rust sync agent. Event content never crosses this interface — only `content_hash` (SHA-256) and aggregate metadata.

Schema: [`crates/fstp-core/schema/gen-notification.proto`](../crates/fstp-core/schema/gen-notification.proto) (mirror: [`schema/gen-notification.proto`](../schema/gen-notification.proto))

## Framing

```
[4 bytes BE length][protobuf payload]
```

Defaults:

| Setting | Value |
|---------|--------|
| Socket path (dev) | `/tmp/velizor-sync/agent.sock` or `{VELYZOR_POD_ROOT}/agent.sock` |
| Connect timeout | 5s (`FSTP` / `velizor.sync-agent.connect-timeout-ms`) |
| Write timeout | 2s per message |

## Rust SA

- Listener: `fstp-agent::velyzor_socket` (spawned at startup)
- Processing: `governance_notify::process_governance_notification`
- Validates schema, verifies `instance_signature` over `content_hash`, appends Blocklace `EventHash` block
- Returns `GovernanceEventAck` on the same connection

Env:

- `FSTP_AGORA_SOCKET_PATH` — override socket path
- `VELYZOR_POD_ROOT` — pod root; default socket `{root}/agent.sock`

## Velyzor (JVM)

- `VelyzorSyncAgentClient` — builds protobuf DTO + signs hash
- `VelyzorSyncAgentSocketClient` — framed send/receive
- `BlocklaceBridgeService` — prefers socket when `velizor.sync-agent.socket-enabled=true`

```properties
velizor.sync-agent.socket-enabled=true
velizor.sync-agent.socket-path=/tmp/agora-sync/agent.sock
velizor.blocklace.append-enabled=true
```

## Verification

```bash
cd fstp
CARGO_TARGET_DIR=./target cargo test -p fstp-core governance_notification
CARGO_TARGET_DIR=./target cargo check -p fstp-agent
```

```bash
cd sos-backend
./gradlew compileJava
```

## Invariant (audit)

The protobuf schema must not declare D_raw field names (`content`, `votes`, `email`, …). Tests in `fstp-core::governance_notification` enforce this on `gen-notification.proto`.

## Signature layers (acta vs socket)

| Layer | Where | `content_hash` | Signature |
|-------|--------|----------------|-----------|
| **Acta** | PostgreSQL `governance_audit_logs` | SHA-256 hex of canonical JSON | **HmacSHA256** over the hex string (`governance.audit.signing-secret`) |
| **FSTP socket** | `GovernanceEventNotification` | Same digest as **32 raw bytes** | **Ed25519** institutional issuer over those bytes (`instance_signature`) |

Velyzor bridges layer 1 → layer 2 after each signed acta row via `GovernanceAuditFstpBridge` (default action: `DECISION_RESOLUTION_RECORDED`). The SA verifies only Ed25519 on the socket; HMAC remains for acta chain verification in JVM.

See `GovernanceAuditSignatureLayers` (Java) and `fstp-core::governance_notification::verify_instance_signature`.

```properties
velizor.governance.audit.fstp-bridge.enabled=true
velizor.governance.audit.fstp-bridge.actions=DECISION_RESOLUTION_RECORDED
```
