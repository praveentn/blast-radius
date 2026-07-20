"""blast-radius: score what an AI agent could destroy before anyone can stop it."""

from .classify import Capability, classify
from .report import Report
from .scanner import (
    Credential,
    capabilities_from_credentials,
    load_manifest,
    scan_environment,
    scan_tree,
)

__version__ = "0.1.0"

__all__ = [
    "Capability",
    "Credential",
    "Report",
    "classify",
    "load_manifest",
    "scan_tree",
    "scan_environment",
    "capabilities_from_credentials",
]
