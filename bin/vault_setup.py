#!/usr/bin/env python3
from __future__ import annotations

import argparse
import sys
from typing import Any, Dict, List, Optional
from pathlib import Path
import hvac

try:
    import yaml  # type: ignore
except Exception:
    yaml = None


def normalize_mount(mount: str) -> str:
    return mount.strip().rstrip("/")


def listify(value: Optional[str]) -> List[str]:
    if not value:
        return []
    parts = [v.strip() for v in value.split(",") if v.strip()]
    return parts


def deep_get(d: Dict[str, Any], path: str, default: Any = None) -> Any:
    cur: Any = d
    for p in path.split("."):
        if not isinstance(cur, dict) or p not in cur:
            return default
        cur = cur[p]
    return cur


def load_yaml_config(path: str) -> Dict[str, Any]:
    if yaml is None:
        raise SystemExit("pyyaml is not installed. Run: pip install pyyaml")
    with open(path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f) or {}


def get_enabled_auths(client: hvac.Client) -> Dict[str, Any]:
    return client.sys.list_auth_methods() or {}


def ensure_oidc_auth_enabled(client: hvac.Client, mount_point: str) -> None:
    auths = get_enabled_auths(client)
    key = f"{mount_point}/"
    if key in auths:
        current_type = (auths[key] or {}).get("type")
        if current_type != "oidc":
            raise SystemExit(
                f"Auth mount '{mount_point}/' exists but is type '{current_type}', not 'oidc'. "
                f"Choose a different --oidc-mount."
            )
        print(f"[ok] auth enabled: {mount_point}/ (type=oidc)")
        return

    print(f"[change] enabling oidc auth at: {mount_point}/")
    client.sys.enable_auth_method(method_type="oidc", path=mount_point)


def ensure_policy(client: hvac.Client, policy_name: str, policy_hcl: str) -> None:
    existing = None
    try:
        existing = client.sys.read_policy(name=policy_name)
    except Exception:
        existing = None

    current = ""
    if isinstance(existing, dict):
        current = existing.get("rules") or ""

    if current.strip() == policy_hcl.strip():
        print(f"[ok] policy unchanged: {policy_name}")
        return

    action = "[change] updating" if current else "[change] creating"
    print(f"{action} policy: {policy_name}")
    client.sys.create_or_update_policy(name=policy_name, policy=policy_hcl)


def read_oidc_config(client: hvac.Client, mount_point: str) -> Optional[Dict[str, Any]]:
    try:
        r = client.read(f"auth/{mount_point}/config")
        if r and "data" in r:
            return r["data"]
    except Exception:
        pass
    return None


def ensure_oidc_config(
    client: hvac.Client,
    mount_point: str,
    discovery_url: str,
    client_id: str,
    client_secret: str,
    default_role: str,
) -> None:
    desired = {
        "oidc_discovery_url": discovery_url,
        "oidc_client_id": client_id,
        "oidc_client_secret": client_secret,
        "default_role": default_role,
    }

    current = read_oidc_config(client, mount_point) or {}

    same_non_secret = (
        current.get("oidc_discovery_url") == desired["oidc_discovery_url"]
        and current.get("oidc_client_id") == desired["oidc_client_id"]
        and current.get("default_role") == desired["default_role"]
    )
    if same_non_secret:
        print(f"[ok] oidc config looks correct (non-secret fields) at auth/{mount_point}/config")
        return

    print(f"[change] writing oidc config at auth/{mount_point}/config")
    client.write(f"auth/{mount_point}/config", **desired)


def read_oidc_role(client: hvac.Client, mount_point: str, role_name: str) -> Optional[Dict[str, Any]]:
    try:
        r = client.read(f"auth/{mount_point}/role/{role_name}")
        if r and "data" in r:
            return r["data"]
    except Exception:
        pass
    return None


def norm_list(x: Any) -> List[str]:
    if x is None:
        return []
    if isinstance(x, list):
        return x
    if isinstance(x, str):
        return [p.strip() for p in x.split(",") if p.strip()]
    return [str(x)]


def ensure_oidc_role(
    client: hvac.Client,
    mount_point: str,
    role_name: str,
    allowed_redirect_uris: List[str],
    bound_audiences: List[str],
    user_claim: str,
    bound_claims: Dict[str, str],
    policies: List[str],
    ttl: str,
) -> None:
    desired = {
        "role_type": "oidc",
        "allowed_redirect_uris": allowed_redirect_uris,
        "bound_audiences": bound_audiences,
        "user_claim": user_claim,
        "bound_claims": bound_claims,
        "policies": policies,
        "ttl": ttl,
        "oidc_scopes": ["openid", "profile", "email"],
    }

    current = read_oidc_role(client, mount_point, role_name) or {}

    comparable_current = {
        "allowed_redirect_uris": sorted(norm_list(current.get("allowed_redirect_uris"))),
        "bound_audiences": sorted(norm_list(current.get("bound_audiences"))),
        "user_claim": current.get("user_claim"),
        "bound_claims": current.get("bound_claims") or {},
        "policies": sorted(norm_list(current.get("policies"))),
        "ttl": current.get("ttl"),
    }
    comparable_desired = {
        "allowed_redirect_uris": sorted(desired["allowed_redirect_uris"]),
        "bound_audiences": sorted(desired["bound_audiences"]),
        "user_claim": desired["user_claim"],
        "bound_claims": desired["bound_claims"],
        "policies": sorted(desired["policies"]),
        "ttl": desired["ttl"],
    }

    if comparable_current == comparable_desired:
        print(f"[ok] oidc role unchanged: {role_name}")
        return

    print(f"[change] writing oidc role: {role_name}")
    client.write(f"auth/{mount_point}/role/{role_name}", **desired)


def build_policy_hcl(kv_mount: str, secret_prefix: str) -> str:
    # KV v2 paths
    return f'''\
path "{kv_mount}/data/{secret_prefix}/*" {{
  capabilities = ["read"]
}}

path "{kv_mount}/metadata/{secret_prefix}/*" {{
  capabilities = ["list"]
}}
'''

def write_init_config(path: str, data: Dict[str, Any], force: bool) -> None:
    if yaml is None:
        raise SystemExit("pyyaml is required for --init-config. Run: pip install pyyaml")

    out = Path(path)
    if out.exists() and not force:
        raise SystemExit(f"Refusing to overwrite existing file: {out} (use --force)")

    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open("w", encoding="utf-8") as f:
        yaml.safe_dump(data, f, sort_keys=False)
    print(f"[done] wrote config template: {out}")

def build_init_template(args: argparse.Namespace) -> Dict[str, Any]:
    # Prefer user-provided values, else defaults/placeholders
    return {
        "vault": {
            "addr": args.vault_addr or "https://vault.example.com",
            "token": args.vault_token or "REPLACE_ME",
            "oidc_mount": args.oidc_mount or "oidc",
            "role_name": args.vault_role_name or "wyrd-x-pass",
            "policy_name": args.vault_policy_name or "wyrd-x-pass-read",
            "allowed_redirect_uris": args.allowed_redirect_uris or "https://broker.example.com/oidc/callback",
            "user_claim": args.user_claim or "preferred_username",
            "bound_claim_key": args.bound_claim_key or "preferred_username",
            "bound_claim_value": args.bound_claim_value or "wyrd-x-pass-approver",
            "token_ttl": args.token_ttl or "15m",
            "kv_mount": args.kv_mount or "secret",
            "secret_prefix": args.secret_prefix or "xpass",
        },
        "keycloak": {
            "discovery_url": args.keycloak_discovery_url or "https://keycloak.example.com/realms/<REALM>",
            "client_id": args.keycloak_client_id or "wyrd-x-pass",
            "client_secret": args.keycloak_client_secret or "REPLACE_ME",
        },
    }

def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Idempotently configure Vault OIDC auth against Keycloak (hvac).")

    p.add_argument("--config", help="Optional YAML config file. CLI flags override file values.", default=None)

    p.add_argument("--vault-addr", required=False, help="Vault URL, e.g. https://vault.example.com")
    p.add_argument("--vault-token", required=False, help="Vault admin token (or a token with sys/auth+policy rights)")

    p.add_argument("--oidc-mount", default="oidc", help="Auth mount path (default: oidc)")
    p.add_argument("--vault-role-name", default="wyrd-x-pass", help="Vault OIDC role name")
    p.add_argument("--vault-policy-name", default="wyrd-x-pass-read", help="Vault policy name")

    p.add_argument("--keycloak-discovery-url", required=False, help="Keycloak realm URL, e.g. https://kc/realms/R")
    p.add_argument("--keycloak-client-id", required=False, help="OIDC client id, e.g. wyrd-x-pass")
    p.add_argument("--keycloak-client-secret", required=False, help="OIDC client secret")

    p.add_argument("--allowed-redirect-uris", required=False,
                   help="Comma-separated allowed redirect URIs for the Vault OIDC role (broker callback).")

    p.add_argument("--user-claim", default="preferred_username",
                   help="Which claim identifies the user (default: preferred_username)")
    p.add_argument("--bound-claim-key", default="preferred_username",
                   help="Claim key to bind (default: preferred_username)")
    p.add_argument("--bound-claim-value", default="wyrd-x-pass-approver",
                   help="Claim value to bind (default: wyrd-x-pass-approver)")

    p.add_argument("--token-ttl", default="15m", help="Vault token TTL for this role (default: 15m)")

    p.add_argument("--kv-mount", default="secret", help="KV mount (default: secret)")
    p.add_argument("--secret-prefix", default="xpass", help="Prefix under KV mount (default: xpass)")

    p.add_argument("--init-config", default=None, help="Write a starter YAML config to this path and exit.")
    p.add_argument("--force", action="store_true", help="Overwrite existing config file when used with --init-config.")

    return p.parse_args()


def merge_config(args: argparse.Namespace) -> Dict[str, Any]:
    cfg: Dict[str, Any] = {}
    if args.config:
        cfg = load_yaml_config(args.config)

    def pick(cli_val: Any, keypath: str, default: Any = None) -> Any:
        # CLI value wins if not None and not empty string
        if cli_val is not None and (not isinstance(cli_val, str) or cli_val.strip() != ""):
            return cli_val
        return deep_get(cfg, keypath, default)

    merged = {
        "vault_addr": pick(args.vault_addr, "vault.addr"),
        "vault_token": pick(args.vault_token, "vault.token"),
        "oidc_mount": pick(args.oidc_mount, "vault.oidc_mount", "oidc"),
        "vault_role_name": pick(args.vault_role_name, "vault.role_name", "wyrd-x-pass"),
        "vault_policy_name": pick(args.vault_policy_name, "vault.policy_name", "wyrd-x-pass-read"),

        "keycloak_discovery_url": pick(args.keycloak_discovery_url, "keycloak.discovery_url"),
        "keycloak_client_id": pick(args.keycloak_client_id, "keycloak.client_id"),
        "keycloak_client_secret": pick(args.keycloak_client_secret, "keycloak.client_secret"),

        "allowed_redirect_uris": pick(args.allowed_redirect_uris, "vault.allowed_redirect_uris"),

        "user_claim": pick(args.user_claim, "vault.user_claim", "preferred_username"),
        "bound_claim_key": pick(args.bound_claim_key, "vault.bound_claim_key", "preferred_username"),
        "bound_claim_value": pick(args.bound_claim_value, "vault.bound_claim_value", "wyrd-x-pass-approver"),

        "token_ttl": pick(args.token_ttl, "vault.token_ttl", "15m"),

        "kv_mount": pick(args.kv_mount, "vault.kv_mount", "secret"),
        "secret_prefix": pick(args.secret_prefix, "vault.secret_prefix", "xpass"),
    }
    return merged


def require_fields(m: Dict[str, Any], fields: List[str]) -> None:
    missing = [f for f in fields if not m.get(f)]
    if missing:
        raise SystemExit(f"Missing required config fields: {', '.join(missing)}")


def main() -> None:
    args = parse_args()

    if args.init_config:
        tmpl = build_init_template(args)
        write_init_config(args.init_config, tmpl, args.force)
        return
    m = merge_config(args)

    require_fields(m, [
        "vault_addr", "vault_token",
        "keycloak_discovery_url", "keycloak_client_id", "keycloak_client_secret",
        "allowed_redirect_uris",
    ])

    mount_point = normalize_mount(str(m["oidc_mount"]))

    allowed_redirect_uris = listify(str(m["allowed_redirect_uris"]))
    if not allowed_redirect_uris:
        raise SystemExit("--allowed-redirect-uris must contain at least one URI")

    policy_hcl = build_policy_hcl(str(m["kv_mount"]), str(m["secret_prefix"]))

    client = hvac.Client(url=str(m["vault_addr"]), token=str(m["vault_token"]))
    if not client.is_authenticated():
        raise SystemExit("Vault authentication failed (check vault addr/token).")

    print("[info] connected to Vault")

    ensure_oidc_auth_enabled(client, mount_point)
    ensure_policy(client, str(m["vault_policy_name"]), policy_hcl)
    ensure_oidc_config(
        client,
        mount_point,
        str(m["keycloak_discovery_url"]),
        str(m["keycloak_client_id"]),
        str(m["keycloak_client_secret"]),
        str(m["vault_role_name"]),
    )
    ensure_oidc_role(
        client=client,
        mount_point=mount_point,
        role_name=str(m["vault_role_name"]),
        allowed_redirect_uris=allowed_redirect_uris,
        bound_audiences=[str(m["keycloak_client_id"])],
        user_claim=str(m["user_claim"]),
        bound_claims={str(m["bound_claim_key"]): str(m["bound_claim_value"])},
        policies=[str(m["vault_policy_name"])],
        ttl=str(m["token_ttl"]),
    )

    print("\n[done] Vault OIDC configuration complete.")
    print(f"  auth mount:    {mount_point}/")
    print(f"  role:          {m['vault_role_name']}")
    print(f"  policy:        {m['vault_policy_name']}")
    print(f"  bound claim:   {m['bound_claim_key']} == {m['bound_claim_value']}")
    print(f"  redirect uris: {', '.join(allowed_redirect_uris)}")


if __name__ == "__main__":
    main()
