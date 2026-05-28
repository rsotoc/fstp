# AGR-106 — Quórum M-de-N (Shamir) en el Sync Agent

## Resumen

Recuperación del DID institucional del nodo SA mediante **Shamir secret sharing** (`sharks` crate): el seed Ed25519 (32 bytes) se divide en **N** partes; se necesitan **M** para reconstruir.

## Archivos en el pod

| Ruta | Contenido |
|------|-----------|
| `config/quorum.json` | Política M-de-N + admins (pubkey Ed25519) |
| `pod/keys/quorum_share_{i}.enc` | Parte Shamir cifrada (AES del pod) |
| `pod/succession/{recordId}.json` | Acta de sucesión tras recuperación |

## API (plataforma `X-Pod-Agent-Key`)

| Método | Ruta | Uso |
|--------|------|-----|
| GET | `/fstp/admin/quorum/status` | Estado del quórum |
| POST | `/fstp/admin/quorum/setup` | Inicializar 2-de-3 (una vez) |
| GET | `/fstp/admin/quorum/share/{index}` | Exportar parte para custodio |
| POST | `/fstp/admin/quorum/unlock` | M partes → token 15 min |
| POST | `/fstp/admin/quorum/recover` | M partes + firmas → acta sucesión |

### Header de operaciones protegidas

`X-Fstp-Quorum-Token: <token>` — emitido por `unlock` o `recover`.

Operaciones que lo exigen (con quórum inicializado):

- `POST /fstp/federation/control` con evento `Terminate` o `Reject`

## Producción

```properties
FSTP_PROFILE=production
# Obligatorio: quorum inicializado (salvo emergencia local):
# FSTP_QUORUM_DEV_SKIP=true
```

## Ejemplo `config/quorum.json`

Ver [`config/quorum.example.json`](../config/quorum.example.json).

## Tests

```bash
cd fstp
cargo test -p fstp-core quorum
```
