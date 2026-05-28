# Bootstrap automático de peers en el SA (IP-03)

**Índice:** IP-03 en [`INDICE-ESTADO-2026-05.md`](../../docs/tickets/INDICE-ESTADO-2026-05.md) §3.1  
**Whitepaper:** §5 Deployment, §3.2 contextual identity (un `link_id` por relación)  
**Endpoint SA:** `POST /fstp/admin/peers` ([`handlers.rs`](../crates/fstp-agent/src/server/handlers.rs))

---

## Objetivo

Al arrancar Ágora Common, registrar en el **SA local** todos los Pods externos del directorio que tengan metadatos de federación completos, sin reiniciar el agente Rust.

---

## Modelo de datos (`pod_directory`)

Columnas añadidas (HU-06 / IP-03):

| Columna | Tipo | Descripción |
|---------|------|-------------|
| `federation_agent_url` | `VARCHAR(1024)` | Base HTTPS del SA remoto (sin `/` final) |
| `federation_tls_fingerprint` | `VARCHAR(128)` | Huella SHA-256 del certificado cliente del peer |
| `federation_peer_pubkey_hex` | `VARCHAR(128)` | Ed25519 32 bytes en hex (64 caracteres) |
| `federation_link_id` | `UUID` | Opcional; si null → derivado `link_id_from_pair(agora-common, pod_key)` |

Campos ya existentes usados: `pod_key`, `external_did`, `active`, `is_platform_common`.

---

## Algoritmo de arranque (Ágora)

Componente: `FstpPeerBootstrapService` (`ApplicationRunner`, `@Order(55)`).

1. Si `agora.fstp.peer-bootstrap.enabled=false` → no-op.
2. Si `agora.pod-agent.outbound-enabled=false` o URL vacía → log y no-op.
3. Para cada `pod_directory` con `active=true`, `platform_common=false` y URL + fingerprint + pubkey presentes:
4. `POST {outbound-base-url}/../fstp/admin/peers` — en la práctica la URL del SA es la base sin sufijo `/pod-agent/v1`; usar propiedad dedicada `agora.fstp.admin-base-url` (default: derivar quitando `/pod-agent/v1` del outbound base).
5. Cuerpo JSON:

```json
{
  "peer_cii": "cii:directory:<podKey>",
  "link_id": "<uuid>",
  "cert_fingerprint": "<federation_tls_fingerprint>",
  "endpoint_url": "<federation_agent_url>",
  "peer_pubkey_hex": "<64 hex>",
  "peer_did": "<external_did>"
}
```

6. Header `X-Pod-Agent-Key` = `agora.pod-agent.inbound-api-key` (misma que `FSTP_POD_AGENT_KEY`).
7. Idempotencia: respuesta `409` → peer ya registrado (OK).

### Derivación de `link_id`

Alineado a [`platform_util::link_id_from_pair`](../crates/fstp-agent/src/platform_util.rs):

`SHA256("agora-common:" + podKey)` → primeros 16 bytes → UUID.

---

## Poblado del directorio

### Demo (desarrollo)

`PodDirectoryBootstrapService` siembra `pod-demo-alpha` / `pod-demo-beta` con DIDs; completar manualmente URL, fingerprint y pubkey antes de bootstrap real.

### Producción

1. Operador del Pod remoto entrega: URL SA, huella TLS, pubkey Ed25519, DID institucional.
2. INSERT/UPDATE en `pod_directory` (o pantalla admin futura).
3. Reinicio Ágora o `ApplicationRunner` en cold start registra peers.

---

## Seguridad

- `POST /fstp/admin/peers` no usa mTLS de peer; protegido por **`X-Pod-Agent-Key`** y red privada ([`auth.rs`](../crates/fstp-agent/src/server/auth.rs) `is_platform_route`).
- No exponer el admin API a Internet sin mTLS de red o allowlist.
- Rotar clave si se filtra.

---

## Variables

| Variable / property | Descripción |
|---------------------|-------------|
| `agora.fstp.peer-bootstrap.enabled` | `true` para ejecutar bootstrap al arranque |
| `agora.fstp.admin-base-url` | Base del SA, p.ej. `https://fstp-common.internal:8443` |
| `agora.pod-agent.inbound-api-key` | Clave hacia admin API |
| `FSTP_POD_AGENT_KEY` | Misma clave en el agente |

---

## Re-ejecutar sin reinicio (dev)

```http
POST /api/dev/fstp/peer-bootstrap/run
```

Perfil `dev` únicamente. Respuesta: `{ registered, skipped }`.

## Verificación automática (P5)

```bash
./scripts/smoke-p5-peer-bootstrap.sh
```

Requiere PKI en `fstp/certs/p5-dev` y fstp-agent en `FSTP_PROFILE=production`.

## Verificación manual

```bash
curl -sk -X POST "https://localhost:8080/fstp/admin/peers" \
  -H "Content-Type: application/json" \
  -H "X-Pod-Agent-Key: ${FSTP_POD_AGENT_KEY}" \
  -d @peer.json
```

Luego `POST /fstp/admin/sync?link_id=<uuid>` o esperar `FSTP_SYNC_INTERVAL_SECS`.

---

*Mayo 2026 — ver implementación Java en `FstpPeerBootstrapService`.*
