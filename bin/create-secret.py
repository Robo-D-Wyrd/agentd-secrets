#!/usr/bin/env python3
"""
x-pass - Create Kubernetes Secret

Creates the Kubernetes Secret referenced by the Helm chart's
existingSecret value.  The secret contains four keys:

    KEYCLOAK_CLIENT_SECRET  – Keycloak confidential-client secret
    WRAPTOKEN_ENC_KEY       – Hex-encoded 32-byte AES-256 key
    KC_APPROVER_USERNAME    – Keycloak user for headless Duo approval
    KC_APPROVER_PASSWORD    – Password for the approver user

Usage:
    bin/create-secret.py x-pass-secrets \\
        --namespace prod \\
        --keycloak-client-secret 's3cret' \\
        --wraptoken-enc-key "$(openssl rand -hex 32)" \\
        --approver-username approver \\
        --approver-password 'P@ssw0rd'

    # Auto-generate the encryption key
    bin/create-secret.py x-pass-secrets \\
        --keycloak-client-secret 's3cret' \\
        --generate-enc-key \\
        --approver-username approver \\
        --approver-password 'P@ssw0rd'
"""

import argparse
import base64
import re
import secrets
import sys

from kubernetes import client, config as k8s_config
from kubernetes.client.rest import ApiException


def current_namespace() -> str:
    """Return the namespace from the active kubeconfig context, or 'default'."""
    try:
        _, active_context = k8s_config.list_kube_config_contexts()
        return active_context["context"].get("namespace", "default")
    except (k8s_config.ConfigException, KeyError, TypeError):
        return "default"


def generate_enc_key() -> str:
    """Generate a cryptographically random hex-encoded 32-byte key."""
    return secrets.token_hex(32)


def validate_enc_key(value: str) -> str:
    """Validate that a string is a 64-character hex string (32 bytes)."""
    if not re.fullmatch(r"[0-9a-fA-F]{64}", value):
        raise argparse.ArgumentTypeError(
            "WRAPTOKEN_ENC_KEY must be exactly 64 hex characters (32 bytes)"
        )
    return value


def build_secret(name: str, namespace: str, data: dict[str, str]) -> client.V1Secret:
    """Construct a V1Secret object from plain-text key/value pairs."""
    return client.V1Secret(
        api_version="v1",
        kind="Secret",
        metadata=client.V1ObjectMeta(
            name=name,
            namespace=namespace,
            labels={"app.kubernetes.io/managed-by": "x-pass-create-secret"},
        ),
        type="Opaque",
        data={
            k: base64.b64encode(v.encode()).decode() for k, v in data.items()
        },
    )


def create_secret(
    api: client.CoreV1Api,
    secret: client.V1Secret,
) -> client.V1Secret:
    """Create the secret in the cluster.  Raises ApiException on conflict."""
    return api.create_namespaced_secret(
        namespace=secret.metadata.namespace,
        body=secret,
    )


def collect_values(args: argparse.Namespace) -> dict[str, str]:
    """Resolve the secret values from parsed arguments."""
    data: dict[str, str] = {}

    data["KEYCLOAK_CLIENT_SECRET"] = args.keycloak_client_secret
    print("  KEYCLOAK_CLIENT_SECRET: (provided)")

    if args.generate_enc_key:
        enc_key = generate_enc_key()
        print(f"  WRAPTOKEN_ENC_KEY: (generated) {enc_key}")
    else:
        enc_key = args.wraptoken_enc_key
        print("  WRAPTOKEN_ENC_KEY: (provided)")
    data["WRAPTOKEN_ENC_KEY"] = enc_key

    data["KC_APPROVER_USERNAME"] = args.approver_username
    print(f"  KC_APPROVER_USERNAME: {args.approver_username}")

    data["KC_APPROVER_PASSWORD"] = args.approver_password
    print("  KC_APPROVER_PASSWORD: (provided)")

    return data


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Create the Kubernetes Secret for x-pass Helm deployment",
    )
    parser.add_argument(
        "name",
        help="Name of the Kubernetes Secret to create (must match existingSecret in values.yaml)",
    )
    parser.add_argument(
        "--namespace", "-n",
        default=None,
        help="Kubernetes namespace (default: current kubeconfig context namespace)",
    )
    parser.add_argument(
        "--keycloak-client-secret",
        required=True,
        help="Keycloak confidential-client secret",
    )

    enc_key_group = parser.add_mutually_exclusive_group(required=True)
    enc_key_group.add_argument(
        "--wraptoken-enc-key",
        type=validate_enc_key,
        help="Hex-encoded 32-byte AES-256 key (64 hex characters)",
    )
    enc_key_group.add_argument(
        "--generate-enc-key",
        action="store_true",
        help="Auto-generate WRAPTOKEN_ENC_KEY instead of providing one",
    )

    parser.add_argument(
        "--approver-username",
        required=True,
        help="Keycloak username for the headless Duo approval login",
    )
    parser.add_argument(
        "--approver-password",
        required=True,
        help="Password for the approver user (never logged)",
    )

    parser.add_argument(
        "--force",
        action="store_true",
        help="Replace the secret if it already exists",
    )

    args = parser.parse_args(argv)

    # Load kubeconfig
    try:
        k8s_config.load_incluster_config()
    except k8s_config.ConfigException:
        k8s_config.load_kube_config()

    namespace = args.namespace or current_namespace()
    print(f"=== x-pass - Create Secret ===")
    print(f"  Secret:    {args.name}")
    print(f"  Namespace: {namespace}")

    data = collect_values(args)
    secret = build_secret(args.name, namespace, data)
    api = client.CoreV1Api()

    try:
        create_secret(api, secret)
        print(f"\nSecret '{args.name}' created in namespace '{namespace}'")
    except ApiException as e:
        if e.status == 409:
            if not args.force:
                print(f"\nError: Secret '{args.name}' already exists in namespace '{namespace}'",
                      file=sys.stderr)
                return 1
            api.replace_namespaced_secret(
                name=args.name,
                namespace=namespace,
                body=secret,
            )
            print(f"\nSecret '{args.name}' replaced in namespace '{namespace}'")
        else:
            raise
    print(f"\nSet in your Helm values:")
    print(f"  existingSecret: \"{args.name}\"")
    return 0


if __name__ == "__main__":
    sys.exit(main())
