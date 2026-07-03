# FSTP — mapa código ↔ whitepaper

**Fuente normativa:** [`FSTP-techPaper.tex`](./FSTP-techPaper.tex) (v12).  
**Alcance:** archivos fuente en `crates/fstp-core` y `crates/fstp-agent` (no `target/`, no generados salvo `build.rs`).

Cada módulo Rust lleva un encabezado `//!` con la misma referencia de sección; este documento es la vista consolidada para revisores y operadores.

---

## §1 Introduction — motivación y confinamiento

| Archivo | Rol en código | Whitepaper |
|---------|---------------|------------|
| — | (solo documentación) | §1.1 Gap in existing federation protocols |
| — | (solo documentación) | §1.2 FSTP: confinement as protocol property |
| — | (solo documentación) | §1.3 Motivating context (Velyzor / Pods) |
| — | (solo documentación) | §1.4 Paper organization |

---

## §2 System model and related work

| Archivo | Rol en código | Whitepaper |
|---------|---------------|------------|
| [`types.rs`](../crates/fstp-core/src/types.rs) | Tipos de dominio (`Did`, `LinkId`, `FederationEndpoint`, errores) | §2.1 Architecture and information partition |
| [`audit.rs`](../crates/fstp-core/src/audit.rs) | Log estructurado de operaciones federadas | §2.1, §4.2 Protocol-level privacy audit |
| — | (amenaza operativa en despliegue) | §2.2 Threat model |
| — | (comparativa; no código) | §2.3 Comparison with existing approaches |

---

## §3 Protocol design

### §3.1 Synchronization Agent and data confinement (Property 2.1)

| Archivo | Rol en código | Whitepaper |
|---------|---------------|------------|
| [`message.rs`](../crates/fstp-core/src/message.rs) | Enumeración cerrada `FstpMessage` — vocabulario emitible | §3.1, Definition (synchronization confinement) |
| [`sa_machine.rs`](../crates/fstp-core/src/sa_machine.rs) | Máquina de estados del SA (`Idle` → `Validating` → …) | §3.1, Property 2.1 |
| [`handlers.rs`](../crates/fstp-agent/src/server/handlers.rs) | HTTP `/fstp/sync/*`, `present-credential`, `federation/control` | §3.1 |
| [`server/federation.rs`](../crates/fstp-agent/src/server/federation.rs) | `ServerState`, registro de peers, router Axum mTLS | §3.1 |
| [`server/auth.rs`](../crates/fstp-agent/src/server/auth.rs) | mTLS peer auth + rutas plataforma (`X-Pod-Agent-Key`) | §3.1, §5 Deployment |
| [`server/grpc.rs`](../crates/fstp-agent/src/server/grpc.rs) | Gateway gRPC local (`VerifyCredential`, …) | §3.1 |
| [`server/verify_credential.rs`](../crates/fstp-agent/src/server/verify_credential.rs) | Verificación VC / emisor (HU-03 Velyzor) | §3.1, §4 Case study |
| [`registry.rs`](../crates/fstp-core/src/registry.rs) | `IssuerRegistry` — DIDs confiables | §3.1 |
| [`integration.rs`](../crates/fstp-agent/src/server/integration.rs) | Rutas `/pod-agent/v1/*`, `present-passport`, admin sync | §3.1, §4 |
| [`outbound.rs`](../crates/fstp-agent/src/outbound.rs) | Cliente HTTP firmado hacia peer (`present-credential`) | §3.1 |
| [`residence.rs`](../crates/fstp-agent/src/residence.rs) | Grant/revoke residencia (CII por HKDF) | §3.1, §4 |
| [`platform_util.rs`](../crates/fstp-agent/src/platform_util.rs) | `link_id_from_pair` determinista | §3.1 |
| [`production.rs`](../crates/fstp-agent/src/production.rs) | Perfil `FSTP_PROFILE=production` — rechaza flags dev | §5 Deployment |
| [`main.rs`](../crates/fstp-agent/src/main.rs) | Arranque SA, IKM/GII, TLS, schedulers | §3.1, §5 |
| [`build.rs`](../crates/fstp-agent/build.rs) | Compilación protobuf gRPC | §3.1 (superficie RPC) |
| [`client.rs`](../crates/fstp-agent/src/client.rs) | Cliente de prueba / utilidad frontier sync | §3.1 |
| [`persistence.rs`](../crates/fstp-agent/src/persistence.rs) | Persistencia Blocklace en disco | §3.1, §3.3 |
| [`velyzor_notify.rs`](../crates/fstp-agent/src/velyzor_notify.rs) | Webhooks accountability → Velyzor | §4.2 audit |
| [`sync_scheduler.rs`](../crates/fstp-agent/src/sync_scheduler.rs) | Sync periódico O(Δ) con peers | §3.1, Remark O(Δ) |

### §3.2 Contextual identity model (Property 3.1)

| Archivo | Rol en código | Whitepaper |
|---------|---------------|------------|
| [`identity.rs`](../crates/fstp-core/src/identity.rs) | `GlobalInstanceId`, `FederationContext`, HKDF → `ContextualId` | §3.2, Property 3.1 |
| [`crypto.rs`](../crates/fstp-core/src/crypto.rs) | `NodeSigner`, firmas Ed25519 request/response | §3.2 |
| [`utils.rs`](../crates/fstp-core/src/utils.rs) | Huella certificado TLS, helpers tiempo | §3.2, §5 |

### §3.3 Blocklace event substrate (Property 3.3)

| Archivo | Rol en código | Whitepaper |
|---------|---------------|------------|
| [`blocklace.rs`](../crates/fstp-core/src/blocklace.rs) | DAG, frontier export, borrado compatible | §3.3, Property 3.3 |
| [`persistence.rs`](../crates/fstp-agent/src/persistence.rs) | Serialización del store | §3.3 |

### Tests y ejemplos (validación de propiedades)

| Archivo | Rol | Whitepaper |
|---------|-----|------------|
| [`simulation_test.rs`](../crates/fstp-core/tests/simulation_test.rs) | Simulación multi-nodo | §6 Empirical sync |
| [`blocklace_stress.rs`](../crates/fstp-core/benches/blocklace_stress.rs) | Estrés Blocklace | §6 |
| [`two_nodes.rs`](../crates/fstp-core/examples/two_nodes.rs) | Ejemplo dos nodos | §4 Coordination scenarios |

---

## §4 Security and privacy properties

| Archivo | Rol | Whitepaper |
|---------|-----|------------|
| [`message.rs`](../crates/fstp-core/src/message.rs) | Cierre de tipos = no correlación de `D_raw` | §4.1 Security properties |
| [`audit.rs`](../crates/fstp-core/src/audit.rs) | Trazabilidad sin payload crudo | §4.2 Protocol-level privacy audit |
| — | (GDPR: política operativa) | §4.3 Regulatory compatibility |

---

## §5 Deployment considerations

| Archivo / doc | Rol | Whitepaper |
|---------------|-----|------------|
| [`production.rs`](../crates/fstp-agent/src/production.rs) | Guardrails producción | §5 |
| [`.env.example`](../.env.example) | Variables TLS, peers, sync | §5 |
| [`MTLS-PRODUCTION.md`](./MTLS-PRODUCTION.md) | mTLS Velyzor ↔ SA y entre peers | §5 |
| [`PEER-BOOTSTRAP.md`](./PEER-BOOTSTRAP.md) | `pod_directory` → `POST /fstp/admin/peers` | §5 |
| [`IDENTIDAD-HU03.md`](./IDENTIDAD-HU03.md) | Pasaporte a Velyzor Common (HU-03) | §4, §5 |

---

## §6 Empirical synchronization performance

| Archivo | Rol | Whitepaper |
|---------|-----|------------|
| [`client.rs`](../crates/fstp-agent/src/client.rs) | Mediciones frontier/blocks | §6.1 Methodology |
| [`blocklace_stress.rs`](../crates/fstp-core/benches/blocklace_stress.rs) | Benchmarks | §6.2 Results |

---

## Contratos externos (fuera del crate, referenciados en §4)

| Documento | Relación |
|-----------|----------|
| [`velizor-dev-docs/contracts/agora-pod-agent-v1.md`](../../velizor-dev-docs/contracts/agora-pod-agent-v1.md) | Superficie HTTP Velyzor ↔ SA |
| `sos-backend` `PassportService`, `PodFederationService` | HU-03 / HU-06 en plataforma Java |

---

*Última revisión: mayo 2026 — alineado a FSTP-techPaper v12 y fases 1–4 del agente.*
