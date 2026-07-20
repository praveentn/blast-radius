"""Find the authority an agent can reach, not just the authority you handed it.

Two surfaces:

  declared  the tools listed in the manifest you gave the agent
  ambient   the credentials sitting in the working tree and the environment,
            which the agent will find on its own the moment a declared tool fails

Most audits stop at the declared surface. The ambient surface is where the
expensive incidents come from, because nobody wrote it down anywhere.
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field
from pathlib import Path

from .classify import (
    Capability,
    EXFILTRATING,
    IRREVERSIBLE,
    SPENDING,
    classify,
)

# Files that hold credentials often enough to be worth opening.
CREDENTIAL_FILES = (
    ".env", ".env.local", ".env.development", ".env.production", ".env.staging",
    "credentials", "credentials.json", "client_secret.json", "service-account.json",
    ".npmrc", ".pypirc", ".netrc", ".git-credentials", ".dockercfg",
    "secrets.json", "secrets.yaml", "secrets.yml", "terraform.tfvars",
)
CREDENTIAL_SUFFIXES = (".pem", ".key", ".p12", ".pfx", ".keystore")

# Templates that ship in the repo on purpose. They name the variables but hold
# placeholders, so counting them as live credentials doubles the score and
# teaches people to ignore the tool.
TEMPLATE_MARKERS = (".example", ".sample", ".template", ".dist", ".tpl")

# Directories never worth walking. Cheap win: keeps the scan fast on real repos.
SKIP_DIRS = {
    ".git", "node_modules", "__pycache__", ".venv", "venv", "env",
    "dist", "build", ".next", ".nuxt", "target", ".mypy_cache",
    ".pytest_cache", ".tox", "vendor", ".terraform", "site-packages",
}

_SECRETISH = re.compile(
    r"(TOKEN|SECRET|KEY|PASSWORD|PASSWD|CREDENTIAL|API[_\-]?KEY|ACCESS[_\-]?KEY|"
    r"PRIVATE[_\-]?KEY|CLIENT[_\-]?SECRET|DSN|CONNECTION[_\-]?STRING|DATABASE[_\-]?URL)",
    re.I,
)

# The heart of it.
#
# Each entry maps a credential to the authority it ACTUALLY carries at the
# provider, regardless of what the variable is named. `implies` is the set of
# tiers the holder of this credential can reach. `narrow_name` lists name
# fragments that make a reader assume the scope is small when it is not.
#
# This is the PocketOS shape: a token named for domain management that carried
# blanket authority across the whole API, including volume deletion.
PROVIDER_AUTHORITY: list[dict] = [
    {
        "provider": "Railway",
        "match": re.compile(r"RAILWAY", re.I),
        "implies": [IRREVERSIBLE, SPENDING, EXFILTRATING],
        "reach": "whole-account GraphQL API including volume and service deletion",
        "narrow_name": ["DOMAIN", "DNS", "STATIC", "PREVIEW"],
        "note": "Railway account tokens are not scoped per resource by default.",
    },
    {
        "provider": "AWS",
        "match": re.compile(r"AWS_(ACCESS_KEY|SECRET|SESSION)", re.I),
        "implies": [IRREVERSIBLE, SPENDING, EXFILTRATING],
        "reach": "every service the attached IAM policy allows, commonly far more than intended",
        "narrow_name": ["S3", "READ", "RO", "BACKUP", "LOG"],
        "note": "Check the attached policy, not the variable name. Wildcards are common.",
    },
    {
        "provider": "GitHub",
        "match": re.compile(r"(GITHUB|GH)_(TOKEN|PAT)", re.I),
        "implies": [IRREVERSIBLE, EXFILTRATING],
        "reach": "every repo the token can see, including force push and repo deletion",
        "narrow_name": ["READ", "CI", "ACTIONS", "PAGES"],
        "note": "Classic PATs are account-wide. Fine-grained tokens are not, check which.",
    },
    {
        "provider": "Stripe",
        "match": re.compile(r"STRIPE", re.I),
        "implies": [SPENDING, EXFILTRATING],
        "reach": "charges, refunds, and full customer PII",
        "narrow_name": ["TEST", "PUBLIC", "PK"],
        "note": "sk_live and sk_test look nearly identical in a config file.",
    },
    {
        "provider": "database",
        "match": re.compile(r"(DATABASE_URL|POSTGRES|MYSQL|MONGO|REDIS)", re.I),
        "implies": [IRREVERSIBLE, EXFILTRATING],
        "reach": "read and write, and usually DROP, on the connected database",
        "narrow_name": ["READ", "REPLICA", "RO", "ANALYTICS"],
        "note": "A replica URL with a superuser role still drops tables.",
    },
    {
        "provider": "cloud/k8s",
        "match": re.compile(r"(KUBE|GCP|GOOGLE_APPLICATION|AZURE|DO_TOKEN|DIGITALOCEAN)", re.I),
        "implies": [IRREVERSIBLE, SPENDING],
        "reach": "cluster or project level control, including namespace deletion",
        "narrow_name": ["DEV", "STAGING", "SANDBOX"],
        "note": "Staging-named contexts frequently point at shared production infrastructure.",
    },
    {
        "provider": "messaging",
        "match": re.compile(r"(SLACK|DISCORD|TWILIO|SENDGRID|MAILGUN|RESEND|SES)", re.I),
        "implies": [EXFILTRATING],
        "reach": "can send messages to real humans as you",
        "narrow_name": ["BOT", "TEST", "DEV"],
        "note": "Outbound messaging is irreversible in the social sense. You cannot unsend.",
    },
]


@dataclass
class Credential:
    """A secret the agent can reach without being given it."""

    name: str
    where: str  # env var, or a file path
    provider: str = "unknown"
    reach: str = "unknown authority"
    implies: list[str] = field(default_factory=list)
    note: str = ""
    authority_gap: bool = False  # the name reads narrow, the authority is not


def _authority_for(var_name: str) -> dict | None:
    for entry in PROVIDER_AUTHORITY:
        if entry["match"].search(var_name):
            return entry
    return None


def _make_credential(var_name: str, where: str) -> Credential:
    entry = _authority_for(var_name)
    if entry is None:
        return Credential(
            name=var_name,
            where=where,
            provider="unknown",
            reach="unknown authority, assume broad until proven otherwise",
            implies=[EXFILTRATING],
            note="Unrecognised credential. Unknown scope is not the same as small scope.",
        )

    upper = var_name.upper()
    gap = any(frag in upper for frag in entry["narrow_name"])
    return Credential(
        name=var_name,
        where=where,
        provider=entry["provider"],
        reach=entry["reach"],
        implies=list(entry["implies"]),
        note=entry["note"],
        authority_gap=gap,
    )


def scan_environment(env: dict[str, str] | None = None) -> list[Credential]:
    """Credentials visible in the process environment the agent inherits."""
    env = os.environ if env is None else env
    found = []
    for key, value in env.items():
        if not value or not _SECRETISH.search(key):
            continue
        found.append(_make_credential(key, "environment"))
    return found


def scan_tree(root: str | Path, max_files: int = 20000) -> list[Credential]:
    """Credentials sitting in files under the agent's working directory."""
    root = Path(root)
    found: list[Credential] = []
    seen = 0

    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS and not d.startswith(".venv")]
        for filename in filenames:
            seen += 1
            if seen > max_files:
                return found

            path = Path(dirpath) / filename
            lowered = filename.lower()
            if any(marker in lowered for marker in TEMPLATE_MARKERS):
                continue

            is_cred_file = filename in CREDENTIAL_FILES or filename.startswith(".env")
            is_key_file = path.suffix.lower() in CREDENTIAL_SUFFIXES

            if is_key_file:
                found.append(
                    Credential(
                        name=filename,
                        where=str(path.relative_to(root)),
                        provider="private key",
                        reach="whatever this key authenticates, commonly SSH or signing",
                        implies=[IRREVERSIBLE, EXFILTRATING],
                        note="A private key in the working tree is readable by any tool with file access.",
                    )
                )
                continue

            if not is_cred_file:
                continue

            try:
                text = path.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue

            rel = str(path.relative_to(root))
            for line in text.splitlines():
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                key = line.split("=", 1)[0].strip() if "=" in line else line
                if len(key) > 100 or not _SECRETISH.search(key):
                    continue
                found.append(_make_credential(key, rel))

    return found


def load_manifest(path: str | Path) -> list[Capability]:
    """Read a tool manifest and classify every tool in it.

    Accepts the two shapes people actually have:
      {"tools": [{"name": ..., "description": ...}]}          a plain tool list
      {"mcpServers": {"srv": {"tools": [...]}}}               an MCP config
    """
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    caps: list[Capability] = []

    def take(tools, prefix=""):
        for tool in tools:
            if isinstance(tool, str):
                caps.append(classify(f"{prefix}{tool}"))
            else:
                name = tool.get("name") or tool.get("tool") or "unnamed"
                cap = classify(f"{prefix}{name}", tool.get("description", ""))
                caps.append(cap)

    if isinstance(data, dict) and "mcpServers" in data:
        for server, cfg in data["mcpServers"].items():
            take(cfg.get("tools", []), prefix=f"{server}.")
    elif isinstance(data, dict) and "tools" in data:
        take(data["tools"])
    elif isinstance(data, list):
        take(data)
    else:
        raise ValueError(
            "Manifest must be a tool list, {'tools': [...]}, or {'mcpServers': {...}}"
        )

    return caps


def capabilities_from_credentials(creds: list[Credential]) -> list[Capability]:
    """Turn reachable credentials into the capabilities they actually grant.

    This is the step every tool-list audit skips. The agent does not need a
    delete_volume tool if it can find a token that speaks to an API that has one.
    """
    caps: list[Capability] = []
    for cred in creds:
        for tier in cred.implies:
            caps.append(
                Capability(
                    name=f"{cred.provider}: {tier} via {cred.name}",
                    tier=tier,
                    source=f"ambient ({cred.where})",
                    description=cred.reach,
                    gated=False,  # a found credential is by definition ungated
                    recoverable=False,
                )
            )
    return caps
