You are a senior platform engineer and Vault/OIDC specialist. Your task is to augment an existing “vault-setup” script that (a) configures a Vault OIDC auth mount and (b) generates a Helm values file for an agent that logs into Vault via that mount. The script is driven by a single config file used for both actions, including the auth mount name/path. Do NOT hardcode or assume any specific mount name (e.g., “agentd-secrets”); always use the mount path/name from config and validate it.

Observed problem (from live diagnostics on one instance):
- The configured OIDC auth mount exists (at a mount path defined in config) and is type `oidc`
- But `vault list auth/<mount>/role` returns “No value found” (no roles exist)
- `vault read auth/<mount>/config` shows partial/incomplete config such as:
  - oidc_discovery_url is set (Keycloak realm URL)
  - oidc_client_id is set
  - bound_issuer is unset (n/a)
  - oidc_response_types is empty
  - jwks_url is unset (n/a)
  - jwt_supported_algs is empty
This indicates the mount is enabled but not fully configured, and the required role is missing, causing agent logins referencing a role to fail.

Goal:
1) Update the script so that when it configures the OIDC auth mount at the mount path specified in the config file, it also:
   - Validates the mount path exists and is type `oidc` (or enables it if it does not exist, if that is within the script’s scope)
   - Ensures the mount config is complete enough to authenticate against the configured IdP
   - Creates (or updates idempotently) the OIDC role required by the agent, at `auth/<mount>/role/<role_name>`, where BOTH <mount> and <role_name> are defined by the config file.
2) If the config file lacks required values, extend the config schema and add validation so the script can fully configure:
   - The auth mount config
   - The role definition
   - The Helm/agent values so the agent uses the same mount and role consistently

Constraints & requirements:
- Idempotent: rerunning should converge safely (create if missing, update if exists).
- Config-driven: mount path/name and role name MUST come from config; do not overfit on any particular names.
- Robust validation: fail fast with actionable errors if required config is missing/invalid.
- Support Vault namespaces (Vault Enterprise) via VAULT_NAMESPACE or config; do not hardcode.
- No manual steps; script must fully configure Vault via CLI or HTTP API.
- Prefer least privilege: document Vault capabilities required by the script token.
- Backward compatible: introduce new config keys with safe defaults where possible.
- Derive what you can from OIDC discovery:
  - Fetch `${oidc_discovery_url}/.well-known/openid-configuration`
  - Extract `issuer` and `jwks_uri`
  - Use derived values unless policy requires pinning; if pinning is required, allow config to override and validate exact matches.

Deliverables:
A) Step-by-step plan explaining what to change (high level).

B) Concrete code changes (or pseudo-code close to real code) that:
   1) Load config (mount_path and role_name included) and validate:
      - mount_path non-empty, normalized (e.g., “foo” vs “foo/”)
      - role_name non-empty
      - oidc_discovery_url valid URL
      - oidc_client_id present
      - oidc_client_secret present IF the IdP client is confidential (config flag)
      - required role fields present (token_policies, user_claim, etc.)
   2) Ensure the auth mount exists at the configured mount_path:
      - `vault auth list` / `sys/auth/<mount>`
      - If absent and script supports enabling: enable type oidc at that path
      - Verify type is oidc; if not, error with exact observed type and path
   3) Read current mount config and compare to desired:
      - `vault read auth/<mount>/config`
      - Fetch discovery metadata from well-known endpoint; parse JSON to get issuer & jwks_uri
      - Ensure/Set:
        - bound_issuer = issuer (or pinned override)
        - oidc_discovery_url = configured URL
        - oidc_client_id = configured value
        - oidc_client_secret if applicable
        - oidc_response_types includes "code" (and any additional required types from config)
        - If needed for your Vault version/flow: jwks_url = jwks_uri
        - jwt_supported_algs includes at least RS256 (or derive/allow config)
      - Log what changed.
   4) Ensure the role exists at `auth/<mount>/role/<role_name>`:
      - `vault list auth/<mount>/role` to detect existing roles (handle “No value found” as empty)
      - `vault read auth/<mount>/role/<role_name>` to check current state
      - Create/update with config-driven fields appropriate for the agent’s login method:
        - token_policies (required)
        - user_claim (required)
        - groups_claim (optional)
        - bound_audiences (if required by the agent/IdP)
        - oidc_scopes (default: openid, profile, email unless overridden)
        - allowed_redirect_uris ONLY if your agent flow truly requires it (explain when it’s needed)
        - token_ttl / token_max_ttl (optional)
      - Explain clearly which fields are required for non-interactive agent auth vs interactive CLI, and keep the implementation flexible via config.
   5) Ensure Helm values generation uses the SAME mount_path and role_name from config, so agent login references what the script created.

C) Proposed config schema extension + example YAML/JSON (generic names; do NOT assume “agentd-secrets”):
   - vault:
       mount_path: "<string>"            # required (e.g., "agentd-secrets", but arbitrary)
       role_name: "<string>"             # required (can differ from mount_path)
       oidc:
         discovery_url: "<url>"          # required
         client_id: "<string>"           # required
         client_secret: "<string>"       # optional/required depending on client type
         bound_issuer: "<url>"           # optional override/pin
         jwks_url: "<url>"               # optional override/pin
         supported_algs: ["RS256"]       # optional default
         response_types: ["code"]        # default
         scopes: ["openid","profile","email"] # default
       role:
         token_policies: ["<policy>"]    # required
         user_claim: "sub"               # default but configurable
         groups_claim: "<claim>"         # optional
         bound_audiences: ["<aud>"]      # optional
         # redirect_uris: [...]           # only if required by chosen flow
         token_ttl: "1h"                 # optional
         token_max_ttl: "4h"             # optional
   - agent/helm:
       auth_mount: "<from vault.mount_path>"
       auth_role: "<from vault.role_name>"
       # any other fields needed by the agent chart

D) Verification commands and expected outcomes:
   - `vault auth list` shows mount path from config with type oidc
   - `vault read sys/auth/<mount>` confirms type oidc
   - `vault read auth/<mount>/config` shows bound_issuer set, response_types non-empty, etc.
   - `vault list auth/<mount>/role` includes <role_name>
   - `vault read auth/<mount>/role/<role_name>` returns the configured role
   - Provide a smoke-test login approach consistent with the agent’s auth flow (describe what “success” looks like).

Important:
- If you need the script and config contents, ask for them, but FIRST provide a best-effort patch outline and config additions that are immediately actionable.
- Throughout, keep everything config-driven; avoid overfitting to any particular mount/role names.
