# x-pass — Secret Access Broker

A Node.js/TypeScript service that brokers access to HashiCorp Vault secrets with human-in-the-loop approval via Keycloak + Duo MFA.

## How It Works

1. **Bot requests a secret** — An automated client (bot) sends `POST /v1/requests` with a service name, reason, and its identity. The bot authenticates with a Keycloak-issued JWT (Bearer token).

2. **Broker initiates headless login** — The broker launches a headless Chromium browser (Playwright), navigates to the Keycloak OIDC authorization endpoint for a dedicated "approver" user, fills in credentials, and submits.

3. **Duo MFA push** — Keycloak's Browser authentication flow triggers a Duo push notification to the approver's phone. The human taps "Approve" in Duo Mobile. No codes, no browser windows — just a push notification.

4. **Token exchange** — After Duo approval, Keycloak redirects with an authorization code. The broker exchanges it for an access token (Authorization Code + PKCE S256).

5. **Vault read with response wrapping** — The broker authenticates to Vault via Kubernetes service account auth, reads the requested KV v2 secret with `X-Vault-Wrap-TTL`, and receives a single-use wrapping token.

6. **Encrypted storage and delivery** — The wrapping token is encrypted at rest (AES-256-GCM) and stored in memory. The bot polls `GET /v1/requests/{id}` and receives the wrap token once approved.

The broker **never** sees or returns plaintext secrets — only Vault wrapping tokens.

## API

### `POST /v1/requests`

Create a new secret access request.

**Headers:** `Authorization: Bearer <JWT>`

**Body:**
```json
{
  "service": "payroll-db",
  "reason": "Automated deployment rotation",
  "requester": "ci-bot-prod",
  "wrap_ttl": "5m"
}
```

**Response (202):**
```json
{
  "request_id": "550e8400-e29b-41d4-a716-446655440000",
  "status": "PENDING_APPROVAL"
}
```

### `GET /v1/requests/{id}`

Check request status. Once approved, includes the wrap token.

**Headers:** `Authorization: Bearer <JWT>`

**Response (200):**
```json
{
  "request_id": "550e8400-e29b-41d4-a716-446655440000",
  "service": "payroll-db",
  "requester": "ci-bot-prod",
  "status": "APPROVED",
  "created_at": "2025-01-15T10:30:00.000Z",
  "wrap_token": "hvs.CAESI...",
  "wrap_expires_at": "2025-01-15T10:35:00.000Z"
}
```

**Terminal statuses:** `APPROVED`, `DENIED`, `EXPIRED`, `FAILED`

### `GET /healthz`

Liveness probe. Always returns `200 OK`.

### `GET /readyz`

Readiness probe. Returns `200` if Keycloak OIDC discovery and Vault `sys/health` are reachable, `503` otherwise.

## Configuration Reference

### Environment Variables

| Variable | Required | Default | Description |
|---|---|---|---|
| `KEYCLOAK_ISSUER_URL` | Yes | — | Keycloak realm issuer URL |
| `KEYCLOAK_REALM` | No | `""` | Keycloak realm name |
| `KEYCLOAK_CLIENT_ID` | Yes | — | Broker's Keycloak client ID |
| `KEYCLOAK_CLIENT_SECRET` | Yes | — | Broker's Keycloak client secret |
| `KEYCLOAK_AUDIENCE` | No | `""` | Expected JWT audience claim |
| `VAULT_ADDR` | Yes | — | Vault server address |
| `VAULT_K8S_AUTH_PATH` | No | `auth/kubernetes` | Vault Kubernetes auth mount path |
| `VAULT_K8S_ROLE` | Yes | — | Vault Kubernetes auth role |
| `VAULT_K8S_JWT_PATH` | No | `/var/run/secrets/kubernetes.io/serviceaccount/token` | Path to SA token |
| `WRAPTOKEN_ENC_KEY` | Yes | — | 64 hex chars (32 bytes) for AES-256-GCM encryption |
| `BROKER_LISTEN_ADDR` | No | `:8080` | Listen address |
| `BROKER_CONFIG_PATH` | No | `/etc/x-pass/config.yaml` | Path to service registry |
| `KC_APPROVER_USERNAME` | Yes | — | Keycloak user for headless login |
| `KC_APPROVER_PASSWORD` | Yes | — | Password for the approver user |
| `KC_OIDC_REDIRECT_URI` | No | `http://localhost:8080/oidc/callback` | OIDC redirect URI |
| `KC_LOGIN_TIMEOUT` | No | `2m` | Timeout for Keycloak login page |
| `KC_DUO_TIMEOUT` | No | `5m` | Timeout waiting for Duo push approval |
| `PLAYWRIGHT_HEADLESS` | No | `true` | Run Chromium headless |
| `PLAYWRIGHT_BROWSER` | No | `chromium` | Browser engine |
| `LOG_LEVEL` | No | `info` | Log level (debug, info, warn, error) |

### Service Registry (`config.yaml`)

Mounted at `/etc/x-pass/config.yaml` via ConfigMap:

```yaml
services:
  payroll-db:
    vault:
      kv2_mount: "secret"
      kv2_path: "prod/payroll/db"
    authz:
      keycloak:
        resource_id: "vault:payroll-db"
        scope: "read"
    wrap:
      max_ttl: "10m"
      default_ttl: "5m"
```

The `authz` block is retained for backward compatibility but is not used for gating in this version; approval is via Duo push.

## Security Notes

- **No plaintext secrets** — The broker never returns Vault secret data. Only single-use Vault wrapping tokens are returned.
- **Wrap tokens encrypted at rest** — AES-256-GCM with a random 12-byte nonce prepended to ciphertext. Key provided via `WRAPTOKEN_ENC_KEY`.
- **Bot JWT validation** — All API requests require a valid JWT signed by the Keycloak realm, validated against JWKS with issuer and audience checks.
- **Rate limiting** — `POST /v1/requests` is rate-limited (30 req/min per IP).
- **Request IDs** — UUIDv4, cryptographically random and unguessable.
- **Wrap TTL capping** — Requested TTLs are capped to the service's `max_ttl`.
- **Request expiry** — Pending requests expire after 15 minutes. Old requests are cleaned up after 1 hour.
- **No sensitive data in logs** — Passwords, tokens, and secrets are never logged.
- **Headless browser isolation** — Each request gets a fresh browser context, closed after use.

### Risk: Storing Approver Credentials

The broker stores a real Keycloak user's password (`KC_APPROVER_PASSWORD`) in a Kubernetes Secret. Recommendations:

- Use a **dedicated service account user** with minimal permissions (only the ability to authenticate and trigger Duo).
- Set **short Keycloak session timeouts** for this user.
- Restrict the Kubernetes Secret with RBAC so only the broker pod can read it.
- Rotate the password regularly.
- Consider using Vault itself to store the password and bootstrapping via a different auth method.

## Development

```bash
# Install dependencies
npm install

# Build
npm run build

# Run tests
npm test

# Run only unit tests
npm run test:unit

# Run only integration tests
npm run test:integration

# Lint
npm run lint

# Format
npm run format
```

### E2E Tests

E2E tests require a real Keycloak instance with Duo configured:

```bash
export E2E_KEYCLOAK_BASE_URL=https://keycloak.example.com
export E2E_KEYCLOAK_REALM=myrealm
export E2E_KEYCLOAK_CLIENT_ID=x-pass
export E2E_KEYCLOAK_CLIENT_SECRET=...
export E2E_APPROVER_USERNAME=approver
export E2E_APPROVER_PASSWORD=...
npm run test:e2e
```

## Docker

```bash
docker build -t x-pass:latest .
```

## Deployment (Helm)

```bash
# Create the secret first
kubectl create secret generic x-pass-secrets \
  --from-literal=KEYCLOAK_CLIENT_SECRET='...' \
  --from-literal=WRAPTOKEN_ENC_KEY="$(openssl rand -hex 32)" \
  --from-literal=KC_APPROVER_USERNAME='approver' \
  --from-literal=KC_APPROVER_PASSWORD='...'

# Install
helm install x-pass ./helm \
  --set keycloak.issuerURL=https://keycloak.example.com/realms/myrealm \
  --set keycloak.clientID=x-pass \
  --set keycloak.realm=myrealm \
  --set vault.addr=https://vault.example.com \
  --set vault.k8sRole=x-pass \
  --set existingSecret=x-pass-secrets
```

## Operational Notes

- **Single replica assumption** — The in-memory request store means only one replica should run. If scaling beyond one replica, use sticky sessions (e.g., Ingress session affinity) so the bot's GET poll hits the same pod that processed its POST.
- **Duo timeout** — The `KC_DUO_TIMEOUT` (default 5m) determines how long the broker waits for the human to approve the Duo push. Adjust based on your organization's response time expectations.
- **Browser resource usage** — Each pending request spawns a headless Chromium instance. Monitor memory usage and set appropriate resource limits in the Helm values.
- **Request cleanup** — Expired and completed requests are automatically cleaned up after 1 hour.
