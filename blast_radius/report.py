"""Turn the two scans into something a human acts on in under a minute."""

from __future__ import annotations

import json
from dataclasses import dataclass, field

from .classify import (
    Capability,
    EXFILTRATING,
    IRREVERSIBLE,
    MUTATING,
    READONLY,
    SPENDING,
    TIER_LABEL,
)
from .scanner import Credential

TIER_ORDER = [IRREVERSIBLE, SPENDING, EXFILTRATING, MUTATING, READONLY]

BANDS = [
    (0, "CONTAINED", "Nothing here ends a company."),
    (40, "NOTABLE", "Recoverable, but somebody's evening is gone."),
    (120, "SEVERE", "A bad loop here is an incident with a customer email."),
    (250, "UNBOUNDED", "This agent can end the business in one uninterrupted loop."),
]


@dataclass
class Report:
    declared: list[Capability] = field(default_factory=list)
    ambient: list[Capability] = field(default_factory=list)
    credentials: list[Credential] = field(default_factory=list)
    root: str = "."

    @property
    def all_caps(self) -> list[Capability]:
        return self.declared + self.ambient

    @property
    def score(self) -> int:
        return sum(c.weight for c in self.all_caps)

    @property
    def band(self) -> tuple[str, str]:
        name, blurb = BANDS[0][1], BANDS[0][2]
        for threshold, label, text in BANDS:
            if self.score >= threshold:
                name, blurb = label, text
        return name, blurb

    @property
    def nine_second(self) -> list[Capability]:
        """Everything that could fire in one loop and never come back."""
        return [c for c in self.all_caps if c.nine_second]

    @property
    def authority_gaps(self) -> list[Credential]:
        return [c for c in self.credentials if c.authority_gap]

    def by_tier(self, caps: list[Capability]) -> dict[str, list[Capability]]:
        out: dict[str, list[Capability]] = {t: [] for t in TIER_ORDER}
        for cap in caps:
            out[cap.tier].append(cap)
        return out

    # ---------- rendering ----------

    def to_text(self, color: bool = True) -> str:
        def c(code: str, s: str) -> str:
            return f"\033[{code}m{s}\033[0m" if color else s

        band, blurb = self.band
        band_color = {
            "CONTAINED": "32",
            "NOTABLE": "33",
            "SEVERE": "31",
            "UNBOUNDED": "1;37;41",
        }[band]

        L: list[str] = []
        L.append("")
        L.append(c("1", "  BLAST RADIUS") + c("2", f"   {self.root}"))
        L.append(c("2", "  " + "-" * 62))
        L.append("")
        L.append(f"  {c(band_color, f' {band} ')}  score {self.score}")
        L.append(c("2", f"  {blurb}"))
        L.append("")

        nine = self.nine_second
        L.append(c("1", "  What this agent can do in 9 seconds, permanently"))
        if not nine:
            L.append(c("32", "    nothing irreversible is reachable ungated"))
        else:
            for cap in nine[:12]:
                L.append(f"    {c('31', 'x')} {cap.name}")
                L.append(c("2", f"      via {cap.source}"))
            if len(nine) > 12:
                L.append(c("2", f"    ... and {len(nine) - 12} more"))
        L.append("")

        if self.authority_gaps:
            L.append(c("1;33", "  Authority gaps"))
            L.append(c("2", "  the name reads narrow, the credential is not"))
            for cred in self.authority_gaps:
                L.append(f"    {c('33', '!')} {cred.name}  {c('2', f'({cred.where})')}")
                L.append(c("2", f"      actually reaches: {cred.reach}"))
            L.append("")

        L.append(c("1", "  Surfaces"))
        d_tiers = self.by_tier(self.declared)
        a_tiers = self.by_tier(self.ambient)
        L.append(
            f"    declared  {len(self.declared):>3} capabilities   "
            + c("2", f"irreversible {len(d_tiers[IRREVERSIBLE])}")
        )
        L.append(
            f"    ambient   {len(self.ambient):>3} capabilities   "
            + c("2", f"irreversible {len(a_tiers[IRREVERSIBLE])}")
        )
        L.append(
            c("2", f"              from {len(self.credentials)} reachable credentials")
        )
        L.append("")

        if self.credentials:
            L.append(c("1", "  Reachable credentials"))
            for cred in self.credentials[:15]:
                flag = c("33", " [gap]") if cred.authority_gap else ""
                L.append(
                    f"    {cred.name}{flag}  {c('2', f'{cred.where} -> {cred.provider}')}"
                )
            if len(self.credentials) > 15:
                L.append(c("2", f"    ... and {len(self.credentials) - 15} more"))
            L.append("")

        L.append(c("2", "  " + "-" * 62))
        L.append(c("2", "  Ungated irreversible capability is the number that matters."))
        L.append(c("2", "  Gate it, scope the credential, or delete the tool."))
        L.append("")
        return "\n".join(L)

    def to_dict(self) -> dict:
        band, blurb = self.band
        return {
            "root": self.root,
            "score": self.score,
            "band": band,
            "summary": blurb,
            "nine_second_irreversible": [
                {"name": c.name, "source": c.source} for c in self.nine_second
            ],
            "authority_gaps": [
                {"name": c.name, "where": c.where, "reach": c.reach, "provider": c.provider}
                for c in self.authority_gaps
            ],
            "declared": [
                {"name": c.name, "tier": c.tier, "gated": c.gated} for c in self.declared
            ],
            "ambient": [
                {"name": c.name, "tier": c.tier, "source": c.source} for c in self.ambient
            ],
            "credentials": [
                {"name": c.name, "where": c.where, "provider": c.provider,
                 "authority_gap": c.authority_gap}
                for c in self.credentials
            ],
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2)
