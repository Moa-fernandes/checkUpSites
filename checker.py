"""Fachada retrocompatível do checkUp apontando para o pacote modular `checkup`."""

from checkup import (
    DEFAULT_LIVE_TARGETS,
    check_html,
    check_links,
    check_live_targets,
    check_site,
    check_site_steps,
    normalize_url,
)
from checkup.infra_audit import audit_infrastructure as _infrastructure_issues

__all__ = [
    "DEFAULT_LIVE_TARGETS",
    "_infrastructure_issues",
    "check_html",
    "check_links",
    "check_live_targets",
    "check_site",
    "check_site_steps",
    "normalize_url",
]
