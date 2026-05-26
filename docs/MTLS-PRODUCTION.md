# mTLS en producción — retiro de flags dev (IP-02)

**Índice:** IP-02 en [`INDICE-ESTADO-2026-05.md`](../../docs/tickets/INDICE-ESTADO-2026-05.md) §3.1  
**Whitepaper:** §5 Deployment considerations, §2.2 Threat model

---

## Principio

En producción **no** deben estar activos:

| Variable | Efecto dev | Producción |
|----------|------------|------------|
| `FSTP_DEV_INSECURE_OUTBOUND` | `reqwest` sin verificar certificado peer | **Ausente** o `false` |
| `FSTP_DEV_TRUST_PRESENT_CREDENTIAL` | `present-credential` sin mTLS, solo `X-Pod-Agent-Key` | **Ausente** o `false` |
| `FSTP_GRPC_TRUST_CALLER_PUBKEY` | Acepta pubkey del caller sin registro | **Ausente** o `false` |

El binario `fstp-agent` con `FSTP_PROFILE=production` **aborta el arranque** si alguna de las tres está en `true`/`1` (ver [`production.rs`](../crates/fstp-agent/src/production.rs)).

---

## Capas TLS

### 1. Peers federados (SA ↔ SA)

- **Servidor:** `FSTP_CERT_PATH` / `FSTP_KEY_PATH` (certificado servidor).
- **Cliente entrante:** middleware [`auth.rs`](../crates/fstp-agent/src/server/auth.rs) resuelve peer por huella del certificado cliente (`cert_fingerprint`).
- **Cliente saliente:** [`outbound.rs`](../crates/fstp-agent/src/outbound.rs) carga **misma** identidad cliente desde `FSTP_CERT_PATH` + `FSTP_KEY_PATH` como `reqwest::Identity` (mTLS).
- **Registro:** cada peer en `POST /fstp/admin/peers` con `cert_fingerprint` y `endpoint_url` HTTPS.

### 2. Ágora ↔ SA (plataforma)

Rutas bajo `/pod-agent/v1/` y `/fstp/admin/` usan **`X-Pod-Agent-Key`**, no mTLS de aplicación en v1.

Recomendación producción:

- Red privada o service mesh mTLS **además** de la clave.
- Rotar `FSTP_POD_AGENT_KEY` / `POD_AGENT_API_KEY` por entorno.
- Java (P5): perfil `fstp-production` + `PodAgentHttpClientSupport` con:
  - `agora.pod-agent.tls.trust-store-path` / `AGORA_POD_AGENT_TRUST_STORE`
  - `agora.pod-agent.tls.key-store-path` / `AGORA_POD_AGENT_KEY_STORE` (mTLS cliente opcional)
  - `PodAgentTlsProductionValidator` aborta si `insecure-skip-verify=true` o HTTPS sin trust store.

### 3. Verify-credential (HU-03)

- `POST /rpc/verify-credential` **sin** mTLS de peer; expuesto solo en red de confianza.
- En producción: bind `FSTP_GRPC_ADDR` loopback; HTTP proxy solo desde Ágora.

### 4. Liveness / health

| Ruta | Auth en `FSTP_PROFILE=production` |
|------|-----------------------------------|
| `GET /fstp/admin/blocklace/status` | `X-Pod-Agent-Key` (ruta plataforma) — usar en probes/smoke |
| `GET /fstp/health` | Certificado cliente mTLS registrado en `POST /fstp/admin/peers` |

Un `curl` solo con `--cacert` a `/fstp/health` devuelve **401** (comportamiento esperado).

---

## Matriz de configuración

| Entorno | `FSTP_PROFILE` | Dev flags | `agora.pod-agent.stub-mode` | Peers |
|---------|----------------|-----------|------------------------------|-------|
| Local | *(vacío)* | opcionales en `.env` | `true` | manual / demo |
| Staging | `production` | off | `false` | `POST /fstp/admin/peers` o bootstrap |
| Producción | `production` | off | `false` | bootstrap + rotación certificados |

---

## Generación de certificados (operador)

No versionar `certs/` ni `.env`. Ejemplo con OpenSSL (ajustar CN/SAN):

```bash
# CA interna (una vez por federación)
openssl req -x509 -newkey rsa:4096 -days 3650 -nodes -keyout ca.key -out ca.crt -subj "/CN=FSTP Dev CA"

# Servidor SA
openssl req -newkey rsa:4096 -nodes -keyout server.key -out server.csr -subj "/CN=fstp-agent.local"
openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out server.crt -days 825

# Ágora como cliente mTLS (mismo par para outbound SA si comparte identidad)
# Importar ca.crt en truststore JVM: javax.net.ssl.trustStore
```

Huella para `POST /fstp/admin/peers`:

```bash
openssl x509 -in peer.crt -outform DER | openssl dgst -sha256 | awk '{print $2}'
```

(formato esperado por el agente: ver `fstp_core::utils::cert_fingerprint`)

---

## Migración desde dev

1. Registrar todos los peers con huellas reales ([`PEER-BOOTSTRAP.md`](./PEER-BOOTSTRAP.md)).
2. Poblar `FSTP_TRUSTED_ISSUERS_JSON` en cada SA.
3. Quitar `FSTP_DEV_*` del `.env` y establecer `FSTP_PROFILE=production`.
4. Ágora: `outbound-enabled=true`, `stub-mode=false`, URL HTTPS del SA.
5. Probar `present-passport` y `verify-credential` sin flags dev.

---

*Mayo 2026*
