"""Pacote modular de auditoria web do checkUp (compatível com Vercel e execução local)."""

from .dom_audit import check_html
from .network import DEFAULT_LIVE_TARGETS, check_links, check_live_targets, normalize_url
from .pipeline import check_site, check_site_steps

__all__ = [
    "DEFAULT_LIVE_TARGETS",
    "check_html",
    "check_links",
    "check_live_targets",
    "check_site",
    "check_site_steps",
    "normalize_url",
]
