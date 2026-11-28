"""Orquestração rápida e progressiva da auditoria do checkUp."""

from __future__ import annotations

from urllib.parse import urlparse

from .dom_audit import (
    audit_a11y_keyboard_and_landmarks,
    audit_html_deep_metrics,
    check_html,
    contrast_issues,
    js_dependency_issues,
    quality_issues,
    render_page,
)
from .infra_audit import audit_exposed_surface, audit_infrastructure, detect_tech_stack
from .network import check_links, fetch_raw_page, normalize_url
from .scorer import build_incapacitation_synthesis


def _build_result(raw_info: dict, rendered: dict, broken_links: list[str], checked_links: int) -> dict:
    q = rendered.get("quality") or {}
    failed_reqs = rendered.get("failed_requests") or []
    final_html = rendered.get("html") or raw_info.get("html") or ""

    a11y_extra = audit_a11y_keyboard_and_landmarks(final_html)
    surface_audit = raw_info.get("surface_audit") or audit_exposed_surface(
        raw_info["final_url"], raw_info.get("html") or ""
    )
    raw_info["surface_audit"] = surface_audit

    extra = (
        audit_infrastructure(raw_info)
        + contrast_issues(rendered.get("colors") or [])
        + js_dependency_issues(raw_info.get("html") or "", final_html, bool(rendered.get("rendered")))
        + quality_issues(rendered, broken_links)
        + a11y_extra["issues"]
        + surface_audit["issues"]
    )

    result = check_html(final_html, extra)
    result["url"] = raw_info["final_url"]
    result["execution_mode"] = "chromium" if rendered.get("rendered") else "serverless-html"

    ssl_info = raw_info.get("ssl") or {}
    result["metrics"] = {
        "ttfb_ms": raw_info["ttfb_ms"],
        "redirects": raw_info["redirects"],
        "is_https": raw_info["is_https"],
        "ssl_days_left": ssl_info.get("days_left"),
        "ssl_expires_at": ssl_info.get("expires_at"),
        "ssl_valid": ssl_info.get("valid", False),
        "ssl_issuer": ssl_info.get("issuer"),
        "tls_version": ssl_info.get("tls_version"),
        "server": raw_info.get("server", "Não informado"),
        "cdn": raw_info.get("cdn", "Direto"),
        "compressed": raw_info.get("compressed", False),
        "encoding": raw_info.get("encoding", "nenhuma"),
        "raw_kb": raw_info.get("raw_kb", 0),
        "rendered_kb": rendered.get("rendered_kb", 0),
        "script_count": q.get("scriptCount", 0),
        "stylesheet_count": q.get("stylesheetCount", 0),
        "failed_requests_count": len(failed_reqs),
        "has_canonical": q.get("hasCanonical", False),
        "has_og_tags": q.get("hasOgTags", False),
        "has_semantic_landmarks": bool(q.get("hasMain") and q.get("hasNav")),
        "checked_links": checked_links,
        "broken_links": len(broken_links),
        "total_images": q.get("totalImages", 0),
        "broken_images": q.get("brokenImages", 0),
        "contrast_elements": len(rendered.get("colors") or []),
        "high_count": sum(1 for i in result["issues"] if i["level"] == "alta"),
        "medium_count": sum(1 for i in result["issues"] if i["level"] == "media"),
        "low_count": sum(1 for i in result["issues"] if i["level"] == "baixa"),
        "infra_count": sum(1 for i in result["issues"] if i["category"] == "Infraestrutura"),
        "a11y_count": sum(1 for i in result["issues"] if i["category"] == "Acessibilidade"),
        "quality_count": sum(1 for i in result["issues"] if i["category"] == "Qualidade"),
    }

    deep_dom = audit_html_deep_metrics(final_html, raw_info["final_url"])
    result["deep_audit"] = {
        **deep_dom,
        "resolved_ips": surface_audit.get("resolved_ips", []),
        "robots_present": surface_audit.get("robots_present", False),
        "robots_disallows_all": surface_audit.get("robots_disallows_all", False),
        "security_txt_present": surface_audit.get("security_txt_present", False),
        "sitemap_present": surface_audit.get("sitemap_present", False),
        "manifest_present": surface_audit.get("manifest_present", False),
        "resolved_host": urlparse(raw_info["final_url"]).hostname,
        "server_header": raw_info.get("server", "Não informado"),
        "cdn_detected": raw_info.get("cdn", "Direto"),
    }

    result["tech_stack"] = detect_tech_stack(raw_info, rendered)
    result["synthesis"] = build_incapacitation_synthesis(
        raw_info["final_url"],
        result["score"],
        result["issues"],
        result["metrics"],
        result["deep_audit"],
    )
    return result


def check_site_steps(raw_url: str):
    """Executa diagnóstico aprofundado e emite eventos de progresso reais."""
    yield {"type": "progress", "percent": 10, "step": "Validando endereço, DNS e regras anti-SSRF..."}
    url = normalize_url(raw_url)

    yield {"type": "progress", "percent": 26, "step": "Consultando resposta HTTP, TLS/SSL, servidor, CDN e cabeçalhos..."}
    raw_info = fetch_raw_page(url)

    yield {"type": "progress", "percent": 46, "step": "Auditando superfície pública (robots.txt, security.txt, manifest, bundles) e OWASP..."}
    raw_info["surface_audit"] = audit_exposed_surface(raw_info["final_url"], raw_info.get("html") or "")

    yield {"type": "progress", "percent": 68, "step": "Analisando DOM, semântica ARIA, contraste, assinaturas de stack e recursos..."}
    rendered = render_page(raw_info["final_url"], raw_html=raw_info.get("html") or "")

    yield {"type": "progress", "percent": 86, "step": "Verificando links externos/internos e integridade estrutural..."}
    broken_links, checked_links = check_links((rendered.get("quality") or {}).get("links") or [])

    yield {"type": "progress", "percent": 95, "step": "Calculando pontuação ponderada por pilar e síntese final..."}
    result = _build_result(raw_info, rendered, broken_links, checked_links)

    yield {"type": "progress", "percent": 100, "step": "Diagnóstico concluído!"}
    yield {"type": "done", "result": result}


def check_site(raw_url: str) -> dict:
    final_result = None
    for event in check_site_steps(raw_url):
        if event["type"] == "done":
            final_result = event["result"]
    if final_result is None:
        raise ValueError("Não foi possível concluir a verificação.")
    return final_result
