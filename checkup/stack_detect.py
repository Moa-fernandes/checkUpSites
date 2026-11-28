"""Detecção de stack com níveis de confiança.

- confirmado: prova exclusiva (cabeçalho específico ou variável de runtime).
- provável: inferido por sinais independentes ou por tecnologia já confirmada.
Itens sem sinal suficiente não aparecem. Ausência de sinal nunca é afirmada como fato.
"""

from __future__ import annotations

import re
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urljoin, urlparse

from bs4 import BeautifulSoup

from .network import safe_probe_url

MIN_SCORE = 2
MAX_BUNDLES = 4
MAX_BUNDLE_CHARS = 350_000
BUNDLE_TIMEOUT_S = 3.5

NOTE_PT = (
    "Detecção por assinaturas públicas. Confirmado = prova exclusiva (cabeçalho ou variável de runtime). "
    "Provável = inferido por sinais independentes ou por tecnologia já confirmada. "
    "Itens sem sinal suficiente não aparecem."
)

_SERVER_LABELS = {"microsoft-iis": "IIS", "litespeed": "LiteSpeed", "openresty": "OpenResty"}


def _t(where: str, pattern: str, pts: int, proof: bool = False) -> dict:
    """Sinal textual: where = html | srcs | bundles | generator | cookies."""
    return {"where": where, "pattern": pattern, "pts": pts, "proof": proof}


def _h(key: str, value: str | None = None, pts: int = 2, proof: bool = False) -> dict:
    """Sinal de cabeçalho HTTP: key e value são regex (value None = apenas presença)."""
    return {"where": "header", "key": key, "value": value, "pts": pts, "proof": proof}


FRONTEND_LANGUAGES = [
    ("HTML5", "frontend", [_t("html", r"<!doctype html", 2)]),
    ("JavaScript", "frontend", [_t("html", r"<script(?![^>]*application/ld\+json)", 2)]),
    ("CSS", "frontend", [_t("html", r"<link[^>]+rel=[\"']?stylesheet", 2)]),
]

BACKEND_LANGUAGES = [
    ("PHP", "backend", [_h("^x-powered-by$", r"php", 3, proof=True), _t("cookies", r"phpsessid", 2)]),
    ("Node.js", "backend", [_h("^x-powered-by$", r"express|node", 3, proof=True)]),
    ("ASP.NET", "backend", [_h("^x-aspnet-version$", None, 3, proof=True), _h("^x-powered-by$", r"asp\.net", 3, proof=True), _t("html", r"__viewstate", 2)]),
    ("Python", "backend", [_h("^server$", r"gunicorn|uvicorn|werkzeug|waitress", 3, proof=True), _h("^x-powered-by$", r"python|flask|django", 3, proof=True)]),
    ("Ruby", "backend", [_h("^server$", r"phusion passenger|puma", 3, proof=True), _h("^x-runtime$", None, 1), _t("html", r"name=[\"']csrf-param", 2)]),
    ("Java", "backend", [_h("^server$", r"tomcat|jetty|wildfly|undertow", 3, proof=True), _h("^x-powered-by$", r"servlet|jsp", 3, proof=True), _t("cookies", r"jsessionid", 1)]),
    ("Go", "backend", [_h("^server$", r"go-http-server|golang", 3, proof=True)]),
    ("Erlang/Elixir", "backend", [_h("^server$", r"cowboy", 3, proof=True)]),
]

FRAMEWORK_RULES = [
    ("React", "frontend", [_t("html", r"data-reactroot|data-reactid|_reactrootcontainer", 2), _t("bundles", r"react-dom|__react_devtools|createroot\(", 2), _t("srcs", r"react(?:-dom)?(?:\.production|\.development)?(?:\.min)?\.js", 2)]),
    ("Next.js", "frontend", [_t("html", r"__next_data__", 3, proof=True), _h("^x-powered-by$", r"next\.js", 3, proof=True), _t("html", r"/_next/static/", 2), _t("srcs", r"/_next/", 1)]),
    ("Vue", "frontend", [_t("html", r"data-v-app|__vue_app__", 2), _t("bundles", r"createapp\(|vue\.runtime", 2), _t("srcs", r"vue(?:\.runtime)?(?:\.global)?(?:\.prod)?(?:\.min)?\.js", 2)]),
    ("Nuxt", "frontend", [_t("html", r"__nuxt__|/_nuxt/", 2)]),
    ("Angular", "frontend", [_t("html", r"ng-version=|<app-root", 2), _t("bundles", r"@angular/core", 2)]),
    ("Svelte", "frontend", [_t("html", r"svelte-[a-z0-9]{5,}", 1), _t("bundles", r"svelte/internal", 2)]),
    ("Astro", "frontend", [_t("html", r"astro-island|astro-slot", 2)]),
    ("Gatsby", "frontend", [_t("html", r"___gatsby", 2)]),
    ("Alpine.js", "frontend", [_t("html", r"\bx-data=", 1), _t("srcs", r"alpinejs|alpine\.js", 2)]),
    ("HTMX", "frontend", [_t("html", r"\bhx-(?:get|post|target|swap)=", 1), _t("srcs", r"htmx", 2)]),
    ("WordPress", "backend", [_t("html", r"wp-content/|wp-includes/", 2), _t("generator", r"wordpress", 3, proof=True)]),
    ("Shopify", "backend", [_t("html", r"cdn\.shopify\.com|shopify\.theme|window\.shopify", 2), _h("^x-shopid$", None, 3, proof=True)]),
    ("Wix", "backend", [_t("html", r"static\.wixstatic\.com", 2), _h("^x-wix-request-id$", None, 3, proof=True)]),
    ("Drupal", "backend", [_t("generator", r"drupal", 3, proof=True), _t("html", r"drupal\.settings|/sites/default/files", 2)]),
    ("Joomla", "backend", [_t("generator", r"joomla", 3, proof=True), _t("html", r"/media/system/js/", 1)]),
    ("Laravel", "backend", [_t("cookies", r"laravel_session", 2)]),
    ("Django", "backend", [_t("html", r"csrfmiddlewaretoken", 2), _t("cookies", r"csrftoken", 1)]),
    ("Ruby on Rails", "backend", [_t("html", r"name=[\"']csrf-param", 2), _h("^x-runtime$", None, 1)]),
    ("Express", "backend", [_h("^x-powered-by$", r"express", 3, proof=True)]),
]

LIBRARY_RULES = [
    ("jQuery", "library", [_t("srcs", r"jquery", 2), _t("bundles", r"jquery", 1)]),
    ("Bootstrap", "library", [_t("srcs", r"bootstrap", 2), _t("html", r"class=[\"'][^\"']*\bcontainer-fluid\b", 1)]),
    ("Tailwind CSS", "library", [_t("srcs", r"tailwind", 2), _t("html", r"class=[\"'][^\"']*\b(?:px|py|mt|mb|mx|my)-\d", 1)]),
    ("Font Awesome", "library", [_t("srcs", r"font-?awesome", 2), _t("html", r"\bfa-(?:solid|brands|regular|light)\b", 1)]),
    ("Swiper", "library", [_t("srcs", r"swiper", 2), _t("html", r"swiper-(?:container|wrapper|slide)", 1)]),
    ("Chart.js", "library", [_t("srcs", r"chart(?:\.umd)?(?:\.min)?\.js", 2), _t("bundles", r"new chart\(", 2)]),
    ("Highcharts", "library", [_t("srcs", r"highcharts", 2)]),
    ("D3", "library", [_t("srcs", r"/d3(?:\.min)?\.js|d3js\.org", 2), _t("bundles", r"d3\.select\(", 2)]),
    ("ApexCharts", "library", [_t("srcs", r"apexcharts", 2)]),
    ("ECharts", "library", [_t("srcs", r"echarts", 2)]),
    ("Google Tag Manager", "library", [_t("srcs", r"googletagmanager\.com/(?:gtm|ns)\.", 2), _t("html", r"googletagmanager\.com", 1)]),
    ("Google Analytics", "library", [_t("srcs", r"google-analytics\.com|googletagmanager\.com/gtag", 2), _t("html", r"gtag\(", 1)]),
    ("Meta Pixel", "library", [_t("srcs", r"connect\.facebook\.net", 2)]),
    ("Hotjar", "library", [_t("srcs", r"static\.hotjar\.com", 2)]),
    ("Microsoft Clarity", "library", [_t("srcs", r"clarity\.ms", 2)]),
]

MICROSERVICE_RULES = [
    ("Kong API Gateway", "microservices", [_h("^x-kong-", None, 3, proof=True), _h("^via$", r"kong", 3, proof=True)]),
    ("Envoy (service mesh/proxy)", "microservices", [_h("^server$", r"envoy", 3, proof=True), _h("^x-envoy-", None, 3, proof=True)]),
    ("AWS API Gateway", "microservices", [_h("^x-amz-apigw-id$", None, 3, proof=True), _h("^x-amzn-requestid$", None, 1)]),
    ("Azure API Management", "microservices", [_h("^(?:ocp-apim-|x-ms-apim)", None, 3, proof=True)]),
    ("Apigee", "microservices", [_h("^x-apigee", None, 3, proof=True)]),
    ("Tyk API Gateway", "microservices", [_h("^x-tyk", None, 3, proof=True)]),
    ("Kubernetes API server", "microservices", [_h("^x-kubernetes-pf-", None, 3, proof=True)]),
]

PLATFORM_RULES = [
    ("Cloudflare", "platform", [_h("^cf-ray$", None, 3, proof=True), _h("^server$", r"cloudflare", 3, proof=True)]),
    ("AWS CloudFront", "platform", [_h("^x-amz-cf-id$", None, 3, proof=True), _h("^via$", r"cloudfront", 3, proof=True)]),
    ("Fastly", "platform", [_h("^x-fastly-request-id$", None, 3, proof=True), _h("^x-served-by$", r"cache-", 1)]),
    ("Akamai", "platform", [_h("^x-akamai-", None, 3, proof=True), _h("^server$", r"akamaighost", 3, proof=True)]),
    ("Vercel", "platform", [_h("^x-vercel-id$", None, 3, proof=True)]),
    ("Netlify", "platform", [_h("^x-nf-request-id$", None, 3, proof=True)]),
    ("Google Cloud", "platform", [_h("^via$", r"google", 3, proof=True), _h("^server$", r"^esf$|google frontend", 3, proof=True)]),
    ("Azure", "platform", [_h("^x-azure-ref$", None, 3, proof=True)]),
    ("Render", "platform", [_h("^x-render-origin-server$", None, 3, proof=True)]),
    ("Heroku", "platform", [_h("^via$", r"vegur", 3, proof=True)]),
]


def _fetch_same_origin_bundles(html: str, base_url: str) -> str:
    """Baixa até MAX_BUNDLES scripts do próprio domínio e devolve o texto em minúsculas."""
    if not html or not base_url:
        return ""
    host = (urlparse(base_url).hostname or "").lower()
    soup = BeautifulSoup(html, "html.parser")
    urls: list[str] = []
    for tag in soup.find_all("script", src=True):
        absolute = urljoin(base_url, (tag.get("src") or "").strip())
        parsed = urlparse(absolute)
        if parsed.scheme in ("http", "https") and (parsed.hostname or "").lower() == host and absolute not in urls:
            urls.append(absolute)
        if len(urls) >= MAX_BUNDLES:
            break
    if not urls:
        return ""

    def _get(url: str) -> str:
        resp = safe_probe_url(url, timeout_s=BUNDLE_TIMEOUT_S)
        if resp is None or resp.status_code >= 400:
            return ""
        return (resp.text or "")[:MAX_BUNDLE_CHARS]

    with ThreadPoolExecutor(max_workers=len(urls)) as pool:
        return "\n".join(pool.map(_get, urls)).lower()


def _build_context(raw_info: dict, rendered: dict) -> dict:
    html = rendered.get("html") or raw_info.get("html") or ""
    soup = BeautifulSoup(html, "html.parser")
    src_values = []
    for tag in soup.find_all(["script", "link", "img", "iframe"]):
        value = tag.get("href") if tag.name == "link" else tag.get("src")
        if value:
            src_values.append(str(value))
    gen = soup.find("meta", attrs={"name": re.compile(r"^generator$", re.I)})
    return {
        "html": html.lower(),
        "srcs": " ".join(src_values).lower(),
        "generator": str(gen.get("content") or "").lower() if gen else "",
        "cookies": " ".join(raw_info.get("set_cookies") or []).lower(),
        "bundles": _fetch_same_origin_bundles(raw_info.get("html") or "", raw_info.get("final_url") or ""),
        "headers": {str(k).lower(): str(v).lower() for k, v in (raw_info.get("headers") or {}).items()},
    }


def _eval_signal(ctx: dict, sig: dict) -> str | None:
    if sig["where"] == "header":
        for name, value in ctx["headers"].items():
            if re.search(sig["key"], name) and (sig["value"] is None or re.search(sig["value"], value)):
                return f"cabeçalho {name}: {value[:40]}"
        return None
    match = re.search(sig["pattern"], ctx.get(sig["where"], ""))
    return f"{sig['where']}: {match.group(0)[:50]}" if match else None


def _run_rules(ctx: dict, rules: list) -> dict:
    """Retorna só os itens com prova exclusiva (confirmado) ou sinais suficientes (provável)."""
    found: dict = {}
    for name, layer, signals in rules:
        score, evidence, proof = 0, [], False
        for sig in signals:
            hit = _eval_signal(ctx, sig)
            if hit:
                score += sig["pts"]
                evidence.append(hit)
                proof = proof or sig.get("proof", False)
        if proof or score >= MIN_SCORE:
            found[name] = {
                "layer": layer,
                "evidence": evidence,
                "confidence": "confirmado" if proof else "provável",
            }
    return found


def _platforms(ctx: dict) -> tuple[list[str], dict]:
    names: list[str] = []
    evidence: dict[str, list[str]] = {}
    server = ctx["headers"].get("server", "")
    m = re.search(r"(nginx|apache|litespeed|openresty|caddy|microsoft-iis|traefik|envoy|tomcat|gunicorn|cowboy)(?:/([\d][\w.\-]*))?", server)
    if m:
        label = _SERVER_LABELS.get(m.group(1), m.group(1).title())
        if m.group(2):
            label = f"{label} {m.group(2)}"
        names.append(label)
        evidence[label] = [f"cabeçalho server: {server[:60]}"]
    for name, info in _run_rules(ctx, PLATFORM_RULES).items():
        names.append(name)
        evidence[name] = info["evidence"]
    seen, unique = set(), []
    for name in names:
        key = name.split()[0].lower()
        if key not in seen:
            seen.add(key)
            unique.append(name)
    return unique[:6], evidence


def _label(name: str, info: dict) -> str:
    return f"{name} ({info['confidence']})"


def detect_tech_stack(raw_info: dict, rendered: dict | None = None) -> dict:
    """Retorna a stack com nível de confiança e evidências por item."""
    ctx = _build_context(raw_info, rendered or {})

    frontend = _run_rules(ctx, FRONTEND_LANGUAGES)
    backend = _run_rules(ctx, BACKEND_LANGUAGES)
    frameworks = _run_rules(ctx, FRAMEWORK_RULES)
    libraries = _run_rules(ctx, LIBRARY_RULES)
    micro = _run_rules(ctx, MICROSERVICE_RULES)
    platforms, platform_ev = _platforms(ctx)

    nxt = frameworks.get("Next.js")
    if nxt:
        frameworks.setdefault("React", {
            "layer": "frontend",
            "confidence": "provável",
            "evidence": [f"inferido: Next.js ({nxt['confidence']}) usa React"],
        })
        backend.setdefault("Node.js", {
            "layer": "backend",
            "confidence": "provável",
            "evidence": [f"inferido: Next.js ({nxt['confidence']}) executa sobre Node.js"],
        })

    evidence: dict[str, list[str]] = dict(platform_ev)
    for group in (frontend, backend, frameworks, libraries, micro):
        for name, info in group.items():
            evidence[name] = info["evidence"]

    frontend_names = list(frontend)
    backend_labels = [_label(n, i) for n, i in backend.items()]
    micro_labels = [_label(n, i) for n, i in micro.items()]
    languages_by_layer = {
        "frontend": frontend_names,
        "backend": backend_labels,
        "microservices": micro_labels,
    }
    return {
        "languages_by_layer": languages_by_layer,
        "languages": frontend_names + backend_labels,
        "frameworks": [_label(n, i) for n, i in frameworks.items()],
        "libraries": [_label(n, i) for n, i in libraries.items()],
        "platforms": platforms,
        "evidence": evidence,
        "note": NOTE_PT,
    }