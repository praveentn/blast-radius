"""Classify what a capability can do, and whether the damage comes back.

The taxonomy is deliberately small. Five tiers, ordered by how hard the damage is
to undo, not by how scary the name sounds. A tool that spends money is worse than
a tool that edits a row, because the row has a previous value and the money does not.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field


# Tiers, worst first. The score is the weight used in the blast radius total.
IRREVERSIBLE = "irreversible"
SPENDING = "spending"
EXFILTRATING = "exfiltrating"
MUTATING = "mutating"
READONLY = "readonly"

TIER_WEIGHT = {
    IRREVERSIBLE: 40,
    SPENDING: 15,
    EXFILTRATING: 12,
    MUTATING: 4,
    READONLY: 0,
}

TIER_LABEL = {
    IRREVERSIBLE: "cannot be undone",
    SPENDING: "costs real money",
    EXFILTRATING: "leaves the building",
    MUTATING: "reversible with effort",
    READONLY: "safe",
}

_CAMEL = re.compile(r"(?<=[a-z0-9])(?=[A-Z])")


def _normalize(text: str) -> str:
    """volumeDelete and 'Deletes a volume' both become _-separated lowercase.

    Without this, camelCase tool names slip past every verb pattern.
    """
    return _CAMEL.sub("_", text).lower().replace(" ", "_").replace("-", "_")


def _verbs(*alternatives: str) -> re.Pattern[str]:
    """Match a verb as a whole word, not as a fragment inside a noun.

    This is what stops 'list_deployments' being scored as a deploy, and it is
    the difference between a tool people trust and a tool people mute.
    """
    body = "|".join(alternatives)
    return re.compile(rf"(?:^|_)(?:{body})(?=$|_)")


# Ordered most-destructive first: the first pattern that matches wins, so that
# "delete_backup" lands in IRREVERSIBLE and never falls through to MUTATING.
_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    (
        IRREVERSIBLE,
        _verbs(
            # unrecoverable state changes
            "delete", "deletes", "destroy", "destroys", "drop", "drops", "purge",
            "wipe", "truncate", "terminate", "terminates", "remove", "removes", "rm",
            "revoke", "revokes", "expire", "prune", "obliterate",
            "force_push", "reset_hard",
            "delete_(?:backup|snapshot|bucket|volume|cluster|namespace)",
            "volume_delete", "drop_(?:database|table|collection)",
            # arbitrary code execution. A shell inherits every credential in the
            # environment, so it is unbounded by definition, not merely mutating.
            "run_shell", "run_command", "exec", "execute", "eval", "shell",
            "bash", "sh", "subprocess", "spawn",
        ),
    ),
    (
        SPENDING,
        _verbs(
            "provision", "scale", "deploy", "deploys", "launch", "spin_up",
            "run_instance", "run_instances",
            "create_(?:instance|cluster|fleet|node|server)",
            "purchase", "charge", "refund", "transfer", "payout", "pay",
            "subscribe", "bid",
        ),
    ),
    (
        EXFILTRATING,
        _verbs(
            "send", "sends", "email", "emails", "mail", "post_message", "publish",
            "share", "invite", "upload", "export", "webhook", "notify", "tweet",
            "sms", "broadcast", "dump",
            "get_secret", "get_secrets", "read_secret", "read_secrets",
            "list_secret", "list_secrets",
        ),
    ),
    (
        MUTATING,
        _verbs(
            "create", "creates", "update", "updates", "patch", "put", "write",
            "writes", "set", "sets", "edit", "modify", "insert", "upsert",
            "rename", "move", "merge", "approve", "assign", "restart", "redeploy",
        ),
    ),
    (
        READONLY,
        _verbs(
            "get", "gets", "list", "lists", "read", "reads", "describe", "search",
            "query", "fetch", "show", "view", "count", "head", "stat", "diff", "log",
            "logs", "status",
        ),
    ),
]

# Phrases in a description that mean a human is in the path before the action lands.
_GATE = re.compile(
    r"requires? (?:explicit )?(?:human |user |operator )?(?:confirmation|approval|consent)"
    r"|confirmation required|human[_\- ]in[_\- ]the[_\- ]loop|dry[_\- ]?run only"
    r"|asks? (?:the )?user before|prompts? for confirmation",
    re.I,
)

# Phrases that mean the damage has a way back.
_RECOVERABLE = re.compile(
    r"soft[_\- ]delete|delayed delete|moves? to trash|recycle bin|retention"
    r"|restorable|recoverable|versioned|point[_\- ]in[_\- ]time|undo",
    re.I,
)


@dataclass
class Capability:
    """One thing the agent can do, and how badly it can go."""

    name: str
    tier: str
    source: str  # "declared" (in the manifest) or the credential it rides on
    description: str = ""
    gated: bool = False  # a human confirms before it lands
    recoverable: bool = False  # there is a documented way back

    @property
    def weight(self) -> int:
        w = TIER_WEIGHT[self.tier]
        # A gate does not remove the capability, it removes most of the risk.
        # It is a 90% discount, never 100%: humans approve things at 2am.
        if self.gated:
            w = round(w * 0.1)
        if self.recoverable:
            w = round(w * 0.5)
        return w

    @property
    def nine_second(self) -> bool:
        """Could this fire inside one uninterrupted tool loop and not come back?"""
        return self.tier == IRREVERSIBLE and not self.gated and not self.recoverable


def classify(name: str, description: str = "") -> Capability:
    """Map a tool name plus its description onto a tier."""
    haystack = _normalize(f"{name} {description}")
    for candidate, pattern in _PATTERNS:
        if pattern.search(haystack):
            tier = candidate
            break
    else:
        # Nothing matched at all. Unknown verbs are treated as mutating, not safe.
        # Defaulting unknown capability to harmless is how you get a 9 second outage.
        tier = MUTATING

    return Capability(
        name=name,
        tier=tier,
        source="declared",
        description=description,
        gated=bool(_GATE.search(description)),
        recoverable=bool(_RECOVERABLE.search(description)),
    )
