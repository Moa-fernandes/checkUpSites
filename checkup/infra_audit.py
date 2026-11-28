"""Auditoria de infraestrutura, cabeçalhos OWASP, cookies, superfície pública e stack tecnológica."""

from __future__ import annotations

import re
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urljoin, urlparse

from bs4 import BeautifulSoup

from .network import get_resolved_ips, safe_probe_url

CORE_SECURITY_HEADERS = [
    ("strict-transport-security", "HSTS (Strict-Transport-Security)",
     "Garante que o navegador sempre utilize conexão HTTPS."),
    ("x-content-type-options", "X-Content-Type-Options",
     "Evita MIME-sniffing e execução indevida de arquivos."),
    ("x-frame-options", "X-Frame-Options",
     "Protege contra embutimento malicioso em iframes (clickjacking)."),
    ("content-security-policy", "Content-Security-Policy (CSP)",
     "Restringe origens confiáveis de scripts, estilos e recursos."),
    ("referrer-policy", "Referrer-Policy",
     "Controla o envio de informações de origem em links externos."),
]

MODERN_OWASP_HEADERS = [
    ("permissions-policy", "Permissions-Policy",
     "Restringe acesso a câmera, microfone, geolocalização e APIs sensíveis do navegador."),
    ("cross-origin-opener-policy", "Cross-Origin-Opener-Policy (COOP)",
     "Isola o contexto de navegação contra ataques cross-origin."),
    ("cross-origin-resource-policy", "Cross-Origin-Resource-Policy (CORP)",
     "Define quais origens podem carregar este recurso."),
]


def audit_infrastructure(raw_info: dict) -> list[dict]:
    issues: list[dict] = []
    headers = raw_info.get("headers") or {}
    ssl_info = raw_info.get("ssl") or {}

    if raw_info.get("http_redirects_to_https") is False:
        issues.append({
            "id": "http-no-redirect",
            "level": "alta",
            "category": "Infraestrutura",
            "title": "Acesso HTTP não redireciona automaticamente para HTTPS",
            "count": 1,
            "location": "Redirecionamento HTTP -> HTTPS",
            "explanation": "O endereço em HTTP não redireciona automaticamente para HTTPS.",
            "fix": "Configure redirecionamento permanente (301/308) de HTTP para HTTPS.",
            "examples": [f"URL final: {raw_info.get('final_url', '')}"],
        })

    if not raw_info.get("is_https", True):
        issues.append({
            "id": "no-https",
            "level": "alta",
            "category": "Infraestrutura",
            "title": "Site não entrega o endereço final em HTTPS",
            "count": 1,
            "location": "Protocolo da URL final",
            "explanation": "Conexões sem HTTPS trafegam sem criptografia e geram alertas no navegador.",
            "fix": "Configure um certificado TLS/SSL válido e redirecione todo o tráfego para HTTPS.",
            "examples": [f"URL final: {raw_info.get('final_url', '')}"],
        })
    elif ssl_info.get("checked"):
        days_left = ssl_info.get("days_left")
        expires_at = ssl_info.get("expires_at")
        if not ssl_info.get("valid") or (days_left is not None and days_left < 0):
            issues.append({
                "id": "ssl-invalid",
                "level": "alta",
                "category": "Infraestrutura",
                "title": "Certificado SSL/TLS expirado ou inválido",
                "count": 1,
                "location": "Certificado TLS/SSL (porta 443)",
                "explanation": "Certificado inválido ou vencido bloqueia o acesso dos visitantes.",
                "fix": "Renove ou reinstale imediatamente o certificado SSL/TLS.",
                "examples": [f"Expiração: {expires_at or 'desconhecida'}"],
            })
        elif days_left is not None and days_left <= 30:
            issues.append({
                "id": "ssl-expiring",
                "level": "media",
                "category": "Infraestrutura",
                "title": "Certificado SSL/TLS próximo de vencer",
                "count": 1,
                "location": "Certificado TLS/SSL (porta 443)",
                "explanation": f"O certificado expira em {days_left} dia(s) ({expires_at}).",
                "fix": "Verifique a renovação automática para evitar indisponibilidade.",
                "examples": [f"Expira em {expires_at} ({days_left} dia(s) restantes)"],
            })

        tls_ver = ssl_info.get("tls_version") or ""
        if tls_ver in ("TLSv1", "TLSv1.1", "SSLv3"):
            issues.append({
                "id": "tls-outdated",
                "level": "alta",
                "category": "Infraestrutura",
                "title": "Protocolo TLS antigo em uso",
                "count": 1,
                "location": "Negociação TLS",
                "explanation": f"O servidor negociou {tls_ver}, considerado inseguro.",
                "fix": "Habilite TLS 1.2 e TLS 1.3 e desative versões legadas.",
                "examples": [f"Versão negociada: {tls_ver}"],
            })

    if raw_info.get("powered_by"):
        issues.append({
            "id": "exposed-powered-by",
            "level": "baixa",
            "category": "Infraestrutura",
            "title": "Cabeçalho X-Powered-By expõe tecnologia do servidor",
            "count": 1,
            "location": "Cabeçalhos HTTP da resposta",
            "explanation": "Expor linguagem ou framework facilita reconhecimento automatizado da stack.",
            "fix": "Remova ou oculte o cabeçalho X-Powered-By no servidor/proxy.",
            "examples": [f"X-Powered-By: {raw_info['powered_by']}"],
        })

    if not raw_info.get("compressed", True) and raw_info.get("raw_kb", 0) > 15:
        issues.append({
            "id": "no-compression",
            "level": "baixa",
            "category": "Infraestrutura",
            "title": "Resposta sem compressão HTTP (gzip/brotli)",
            "count": 1,
            "location": "Cabeçalho Content-Encoding",
            "explanation": f"HTML inicial de {raw_info['raw_kb']} KB trafegando sem compressão.",
            "fix": "Ative Brotli (br) ou Gzip no servidor web ou CDN.",
            "examples": [f"Content-Encoding: {raw_info.get('encoding', 'nenhuma')} ({raw_info.get('raw_kb', 0)} KB)"],
        })

    redirects = raw_info.get("redirects", 0)
    if redirects > 2:
        issues.append({
            "id": "long-redirect-chain",
            "level": "baixa",
            "category": "Infraestrutura",
            "title": "Cadeia longa de redirecionamentos",
            "count": redirects,
            "location": "Cadeia de redirecionamentos HTTP",
            "explanation": "Múltiplos redirecionamentos atrasam o início do carregamento.",
            "fix": "Aponte os links diretamente para a URL final.",
            "examples": [f"{redirects} redirecionamento(s) até {raw_info.get('final_url', '')}"],
        })

    ttfb_ms = raw_info.get("ttfb_ms", 0)
    if ttfb_ms > 1500:
        issues.append({
            "id": "high-ttfb",
            "level": "media",
            "category": "Infraestrutura",
            "title": "Tempo de resposta inicial do servidor alto",
            "count": 1,
            "location": "Resposta inicial do servidor (TTFB)",
            "explanation": f"O servidor levou {ttfb_ms} ms para responder inicialmente.",
            "fix": "Otimize consultas, aplique cache ou revise a região do servidor.",
            "examples": [f"Tempo de resposta inicial: {ttfb_ms} ms"],
        })

    raw_kb = float(raw_info.get("raw_kb") or 0)
    if raw_kb > 250:
        issues.append({
            "id": "heavy-initial-html",
            "level": "media",
            "category": "Infraestrutura",
            "title": "Documento HTML inicial muito pesado",
            "count": 1,
            "location": "Payload HTML inicial",
            "explanation": f"O HTML inicial possui {raw_kb} KB, elevando o tempo de download e parse.",
            "fix": "Reduza HTML inline excessivo e carregue dados pesados sob demanda.",
            "examples": [f"HTML bruto: {raw_kb} KB"],
        })

    missing_core = [
        (label, reason) for key, label, reason in CORE_SECURITY_HEADERS if key not in headers
    ]
    if missing_core:
        issues.append({
            "id": "missing-security-headers",
            "level": "media",
            "category": "Infraestrutura",
            "title": "Cabeçalhos de segurança HTTP ausentes",
            "count": len(missing_core),
            "location": "Cabeçalhos HTTP da resposta",
            "explanation": "Cabeçalhos de segurança reduzem riscos de XSS, clickjacking e downgrade.",
            "fix": "Configure os cabeçalhos ausentes no servidor web, Vercel (vercel.json) ou CDN.",
            "examples": [f"{label}: {reason}" for label, reason in missing_core[:5]],
        })

    missing_modern = [
        (label, desc) for key, label, desc in MODERN_OWASP_HEADERS if key not in headers
    ]
    if missing_modern:
        issues.append({
            "id": "missing-modern-owasp-headers",
            "level": "baixa",
            "category": "Infraestrutura",
            "title": "Cabeçalhos complementares de isolamento OWASP ausentes",
            "count": len(missing_modern),
            "location": "Cabeçalhos HTTP da resposta",
            "explanation": "Cabeçalhos modernos reforçam isolamento de origem e permissões de APIs do navegador.",
            "fix": "Avalie adicionar Permissions-Policy, COOP e CORP conforme a necessidade da aplicação.",
            "examples": [f"{label}: {desc}" for label, desc in missing_modern],
        })

    if not (headers.get("cache-control") or "").strip():
        issues.append({
            "id": "missing-cache-control",
            "level": "baixa",
            "category": "Infraestrutura",
            "title": "Diretiva Cache-Control não especificada",
            "count": 1,
            "location": "Cabeçalho Cache-Control",
            "explanation": "Sem política explícita de cache, proxies e navegadores podem armazenar recursos de forma subótima.",
            "fix": "Defina políticas claras de Cache-Control.",
            "examples": ["Cache-Control ausente"],
        })

    issues.extend(_audit_cookies(raw_info.get("set_cookies") or [], bool(raw_info.get("is_https", True))))
    return issues


def _audit_cookies(set_cookies: list[str], is_https: bool) -> list[dict]:
    issues: list[dict] = []
    weak_cookies: list[str] = []

    for raw in set_cookies:
        parts = [p.strip().lower() for p in raw.split(";")]
        name = raw.split("=", 1)[0].strip() or "cookie"
        has_secure = "secure" in parts
        has_httponly = "httponly" in parts
        has_samesite = any(p.startswith("samesite=") for p in parts)

        missing = []
        if is_https and not has_secure:
            missing.append("Secure")
        if not has_httponly:
            missing.append("HttpOnly")
        if not has_samesite:
            missing.append("SameSite")
        if missing:
            weak_cookies.append(f"{name}: sem {', '.join(missing)}")

        if name.lower().startswith("__host-") and not (is_https and has_secure and any(p == "path=/" for p in parts)):
            issues.append({
                "id": f"cookie-host-prefix-{name}",
                "level": "media",
                "category": "Infraestrutura",
                "title": f"Cookie {name} não atende aos requisitos do prefixo __Host-",
                "count": 1,
                "location": "Atributos Set-Cookie",
                "explanation": "Cookies __Host- exigem Secure, Path=/ e ausência de Domain.",
                "fix": "Garanta Secure, Path=/ e remova Domain.",
                "examples": [raw[:120]],
            })

    if weak_cookies:
        issues.append({
            "id": "weak-cookies",
            "level": "baixa",
            "category": "Infraestrutura",
            "title": "Cookies sem atributos completos de segurança",
            "count": len(weak_cookies),
            "location": "Cabeçalhos Set-Cookie HTTP",
            "explanation": "Cookies sem Secure, HttpOnly ou SameSite ficam mais expostos a XSS e CSRF.",
            "fix": "Configure HttpOnly, Secure (em HTTPS) e SameSite=Lax ou Strict.",
            "examples": weak_cookies[:5],
        })

    return issues


def audit_exposed_surface(base_url: str, raw_html: str) -> dict:
    """Audita DNS em cache, robots.txt, security.txt, sitemap/manifest e indícios de stack traces."""
    parsed = urlparse(base_url)
    host = parsed.hostname or ""
    scheme = parsed.scheme or "https"
    origin = f"{scheme}://{host}" if host else base_url
    issues: list[dict] = []

    ips = get_resolved_ips(host)
    soup = BeautifulSoup(raw_html or "", "html.parser")
    manifest_link = soup.find("link", rel=lambda v: v and "manifest" in [x.lower() for x in (v if isinstance(v, list) else [v])])
    manifest_url = urljoin(origin + "/", manifest_link["href"]) if (manifest_link and manifest_link.get("href")) else f"{origin}/manifest.json"

    asset_urls: list[str] = []
    local_asset_candidates: list[str] = []
    for tag_name, attr_name in [("script", "src"), ("link", "href")]:
        for el in soup.find_all(tag_name):
            raw_attr = (el.get(attr_name) or "").strip()
            if not raw_attr or raw_attr.startswith("data:"):
                continue
            resolved = urljoin(base_url, raw_attr)
            asset_urls.append(resolved)
            if urlparse(resolved).hostname == host and len(local_asset_candidates) < 4:
                local_asset_candidates.append(resolved)

    probe_tasks: list[tuple[str, str, float]] = []
    if host:
        probe_tasks.append(("robots", f"{origin}/robots.txt", 3.5))
        probe_tasks.append(("security", f"{origin}/.well-known/security.txt", 3.0))
        probe_tasks.append(("sitemap", f"{origin}/sitemap.xml", 3.0))
        probe_tasks.append(("manifest", manifest_url, 2.5))
        for asset_u in local_asset_candidates:
            probe_tasks.append((f"asset:{asset_u}", asset_u, 2.5))

    probed: dict[str, object] = {}
    if probe_tasks:
        with ThreadPoolExecutor(max_workers=min(6, len(probe_tasks))) as pool:
            futures = {
                key: pool.submit(safe_probe_url, target_u, t_out)
                for key, target_u, t_out in probe_tasks
            }
            for key, fut in futures.items():
                probed[key] = fut.result()

    robots_present = False
    robots_disallows_all = False
    r_robots = probed.get("robots")
    if r_robots is not None and r_robots.status_code == 200 and r_robots.text:
        robots_present = True
        for line in r_robots.text.splitlines():
            clean_line = line.split("#", 1)[0].strip().lower()
            if re.match(r"^disallow\s*:\s*/\s*$", clean_line):
                robots_disallows_all = True
                issues.append({
                    "id": "robots-disallow-all",
                    "level": "alta",
                    "category": "Infraestrutura",
                    "title": "robots.txt bloqueia o acesso geral ao site (Disallow: /)",
                    "count": 1,
                    "location": "/robots.txt",
                    "explanation": "A regra Disallow: / impede rastreadores de indexar o site.",
                    "fix": "Revise /robots.txt para liberar as rotas públicas.",
                    "examples": ["Detectado 'Disallow: /' em /robots.txt"],
                })
                break

    security_txt_present = False
    r_sec = probed.get("security")
    if r_sec is not None and r_sec.status_code == 200 and ("contact:" in (r_sec.text or "").lower()):
        security_txt_present = True
    else:
        issues.append({
            "id": "missing-security-txt",
            "level": "baixa",
            "category": "Infraestrutura",
            "title": "Arquivo /.well-known/security.txt não publicado",
            "count": 1,
            "location": "/.well-known/security.txt",
            "explanation": "Facilita o contato responsável em caso de reporte de vulnerabilidades.",
            "fix": "Publique /.well-known/security.txt com Contact e Expires.",
            "examples": [f"{origin}/.well-known/security.txt não encontrado"],
        })

    sitemap_present = False
    r_map = probed.get("sitemap")
    if r_map is not None and r_map.status_code == 200 and (
        "<urlset" in (r_map.text or "").lower() or "<sitemapindex" in (r_map.text or "").lower()
    ):
        sitemap_present = True

    manifest_present = False
    r_man = probed.get("manifest")
    if r_man is not None and r_man.status_code == 200 and ("{" in (r_man.text or "")):
        manifest_present = True

    asset_snippets: list[str] = []
    for asset_u in local_asset_candidates:
        r_asset = probed.get(f"asset:{asset_u}")
        if r_asset is not None and r_asset.status_code == 200 and r_asset.text:
            asset_snippets.append(r_asset.text[:4000])

    debug_patterns = ["werkzeug debugger", "traceback (most recent call last)", "stack trace", "sql syntax error"]
    html_low = (raw_html or "").lower()
    exposed_traces = [pat for pat in debug_patterns if pat in html_low]
    if exposed_traces:
        issues.append({
            "id": "exposed-stack-trace",
            "level": "alta",
            "category": "Qualidade",
            "title": "Indícios de stack trace ou depuração expostos no HTML",
            "count": len(exposed_traces),
            "location": "Resposta HTML pública",
            "explanation": "Mensagens internas de erro revelam caminhos e detalhes da arquitetura.",
            "fix": "Desative modo debug em produção e utilize páginas de erro genéricas.",
            "examples": exposed_traces[:5],
        })

    return {
        "resolved_host": host,
        "resolved_ips": ips[:6],
        "robots_present": robots_present,
        "robots_disallows_all": robots_disallows_all,
        "security_txt_present": security_txt_present,
        "sitemap_present": sitemap_present,
        "manifest_present": manifest_present,
        "asset_urls": list(dict.fromkeys(asset_urls))[:25],
        "asset_snippets": asset_snippets,
        "exposed_traces": exposed_traces,
        "issues": issues,
    }


def detect_tech_stack(raw_info: dict, rendered: dict | None = None) -> dict:
    """Identifica linguagens por camada (Frontend, Backend, Microsservi?os), frameworks/CMS, bibliotecas e servidor/CDN."""
    headers = {str(k).lower(): str(v) for k, v in ((raw_info or {}).get("headers") or {}).items()}
    server = str((raw_info or {}).get("server") or "").strip()
    cdn = str((raw_info or {}).get("cdn") or "").strip()
    powered_by = str((raw_info or {}).get("powered_by") or headers.get("x-powered-by") or "").strip()
    cookies_list = [str(c) for c in ((raw_info or {}).get("set_cookies") or [])]
    cookies_str = " | ".join(cookies_list)
    surface = (raw_info or {}).get("surface_audit") or {}

    html_raw = str((raw_info or {}).get("html") or "")
    html_ren = str((rendered or {}).get("html") or "")
    q = (rendered or {}).get("quality") or {}

    asset_urls_list: list[str] = list(surface.get("asset_urls") or [])
    for k in ("blockingHeadScripts", "links"):
        vals = q.get(k) or []
        if isinstance(vals, list):
            asset_urls_list.extend(str(x) for x in vals if x)

    soup_raw = BeautifulSoup(html_raw, "html.parser")
    soup_ren = BeautifulSoup(html_ren or html_raw, "html.parser")

    for soup_obj in (soup_raw, soup_ren):
        for tag_name, attr_name in [("script", "src"), ("link", "href"), ("iframe", "src")]:
            for el in soup_obj.find_all(tag_name):
                val = (el.get(attr_name) or "").strip()
                if val and not val.startswith(("data:", "javascript:", "mailto:", "tel:")):
                    asset_urls_list.append(urljoin(str((raw_info or {}).get("final_url") or ""), val))

    asset_urls_list = list(dict.fromkeys(asset_urls_list))
    asset_urls_str = "\n".join(asset_urls_list)
    asset_code_str = "\n".join(str(x) for x in (surface.get("asset_snippets") or []))

    combined_html = f"{html_raw}\n{html_ren}\n{asset_urls_str}"
    full_scan_blob = f"{combined_html}\n{asset_code_str}"
    low_all = full_scan_blob.lower()
    low_html_only = f"{html_raw}\n{html_ren}".lower()

    generators = " ".join(
        (m.get("content") or "")
        for s in (soup_raw, soup_ren)
        for m in s.find_all("meta", attrs={"name": re.compile(r"^generator$", re.I)})
    ).lower()

    low_headers = (
        f"{server} {cdn} {powered_by} {cookies_str} {generators} "
        + " ".join(f"{k}: {v}" for k, v in headers.items())
    ).lower()

    frontend_langs: list[str] = []
    backend_langs: list[str] = []
    microservice_langs: list[str] = []
    frameworks: list[str] = []
    libraries: list[str] = []
    platforms: list[str] = []
    evidence: list[str] = []

    def add_item(bucket: list[str], label: str, reason: str) -> None:
        if label and label not in bucket:
            bucket.append(label)
            evidence.append(f"{label}: {reason}")

    def rx(pattern: str, text: str = low_all) -> bool:
        return bool(re.search(pattern, text, re.IGNORECASE))

    if "<html" in low_html_only or "<!doctype html" in low_html_only:
        add_item(frontend_langs, "HTML5", "estrutura HTML detectada")
    if "<script" in low_html_only or rx(r"\.m?js(?:[\"\'?&#/]|$)", low_all) or "application/javascript" in low_all or "text/javascript" in low_all:
        add_item(frontend_langs, "JavaScript", "scripts/m?dulos JS presentes")
    if rx(r"\.tsx?(?:[\"\'?&#/]|$)", low_all) or "__next_data__" in low_all or "data-nextjs" in low_all or "typescript" in low_all:
        add_item(frontend_langs, "TypeScript", "ind?cios de bundle/tipos TypeScript")
    if "<style" in low_html_only or 'rel="stylesheet"' in low_html_only or "rel='stylesheet'" in low_html_only or rx(r"\.css(?:[\"\'?&#/]|$)", low_all):
        add_item(frontend_langs, "CSS", "estilos/folhas CSS detectados")

    if "/_next/" in low_all or "__next_data__" in low_all or "__next_f" in low_all or "x-nextjs-cache" in low_headers or "next/javascript" in low_all:
        add_item(frameworks, "Next.js", "rotas/payload/headers Next.js")
    if "/_nuxt/" in low_all or "__nuxt" in low_all or "nuxt" in generators:
        add_item(frameworks, "Nuxt", "assinatura Nuxt")
    if (
        "react-dom" in low_all
        or "_reactfiber" in low_all
        or "_reactprops" in low_all
        or "data-reactroot" in low_all
        or "data-reactid" in low_all
        or rx(r"\breact(?:\.production|\.development)?(?:\.min)?\.js", low_all)
        or "/_next/" in low_all
    ):
        add_item(frameworks, "React", "DOM/bundles/refer?ncias React")
    if "ng-version" in low_all or rx(r"_ng(?:host|content)-", low_all) or "angular" in low_all:
        add_item(frameworks, "Angular", "atributos/scripts Angular")
    if rx(r"\bdata-v-[a-f0-9]+\b", low_all) or "__vue" in low_all or "vue.global" in low_all or "vue.runtime" in low_all:
        add_item(frameworks, "Vue.js", "diretivas/bundles Vue.js")
    if "__sveltekit" in low_all or "sveltekit" in low_all or rx(r"\bsvelte-[a-z0-9_-]+\b", low_all):
        add_item(frameworks, "Svelte / SvelteKit", "assinatura Svelte/SvelteKit")
    if "astro-island" in low_all or "data-astro-cid" in low_all or "astro" in generators:
        add_item(frameworks, "Astro", "ilhas/atributos Astro")
    if "/wp-content/" in low_all or "/wp-includes/" in low_all or "wordpress" in generators or "wp-json" in low_all:
        add_item(frameworks, "WordPress", "caminhos/REST/meta WordPress")
    if "woocommerce" in low_all or "wc-blocks" in low_all or "wc_add_to_cart" in low_all:
        add_item(frameworks, "WooCommerce", "assinatura WooCommerce")
    if "cdn.shopify.com" in low_all or "myshopify.com" in low_all or "shopify" in low_all:
        add_item(frameworks, "Shopify", "assinatura Shopify")
    if "drupal" in generators or "/sites/default/files/" in low_all or "drupal.settings" in low_all:
        add_item(frameworks, "Drupal", "assinatura Drupal")
    if "w-webflow" in low_all or "webflow.js" in low_all or "webflow" in generators:
        add_item(frameworks, "Webflow", "assinatura Webflow")
    if "wixstatic.com" in low_all or "wix.com" in low_all or "parastorage.com" in low_all:
        add_item(frameworks, "Wix", "assinatura Wix")
    if "vtex" in low_all or "vtexassets" in low_all or "vteximg" in low_all or "x-vtex-" in low_headers:
        add_item(frameworks, "VTEX", "assets/headers VTEX")
    if "laravel_session" in low_headers or "xsrf-token" in low_headers or "livewire" in low_all:
        add_item(frameworks, "Laravel", "cookies/assinatura Laravel")
    if "csrftoken" in low_headers or "django" in low_headers or "csrfmiddlewaretoken" in low_all:
        add_item(frameworks, "Django", "cookies/CSRF/header Django")

    if (
        "tailwindcss" in low_all
        or rx(r'(?:class|className)=[\"\'][^\"\']*\b(?:flex|grid|hidden|block|relative|absolute|px-\d+|py-\d+|p-\d+|m-\d+|mx-auto|text-(?:xs|sm|base|lg|xl|2xl)|bg-(?:slate|gray|zinc|neutral|stone|red|amber|emerald|blue|indigo|violet|purple|pink|white|black)(?:-\d{2,3})?|rounded-(?:sm|md|lg|xl|2xl|full))\b', combined_html)
    ):
        add_item(libraries, "Tailwind CSS", "classes utilit?rias / Tailwind")
    if rx(r"\bbootstrap(?:\.bundle)?(?:\.min)?\.(?:js|css)", low_all) or rx(r'(?:class|className)=[\"\'][^\"\']*\b(?:container-fluid|col-(?:sm|md|lg|xl)-\d+|btn-(?:primary|secondary|outline-\w+)|carousel-item)\b', combined_html):
        add_item(libraries, "Bootstrap", "assets/classes Bootstrap")
    if rx(r"\bjquery[.-]?[\d.]*(?:\.min)?\.js", low_all) or rx(r"\b(?:jQuery|window\.\$)\b", full_scan_blob):
        add_item(libraries, "jQuery", "script/refer?ncia jQuery")
    if "gtag/js" in low_all or "googletagmanager.com" in low_all or "google-analytics.com" in low_all or rx(r"\bgtag\s*\(", full_scan_blob):
        add_item(libraries, "Google Tag Manager / Analytics", "scripts/tags de mensura??o")
    if "sentry" in low_all or "__sentry__" in low_all:
        add_item(libraries, "Sentry", "SDK/monitoramento Sentry")
    if "swiper" in low_all:
        add_item(libraries, "Swiper", "carrossel/m?dulo Swiper")
    if "slick" in low_all:
        add_item(libraries, "Slick Carousel", "carrossel Slick")
    if "font-awesome" in low_all or "fontawesome" in low_all or rx(r'(?:class|className)=[\"\'][^\"\']*\bfa-(?:solid|regular|brands|light)\b', combined_html):
        add_item(libraries, "Font Awesome", "?cones Font Awesome")
    if "lucide" in low_all or "data-lucide" in low_all:
        add_item(libraries, "Lucide Icons", "?cones Lucide")
    if "chart.js" in low_all or "highcharts" in low_all or "echarts" in low_all or "apexcharts" in low_all:
        add_item(libraries, "Biblioteca de Gr?ficos", "m?dulo de visualiza??o/gr?ficos")
    if "three.js" in low_all or "three.min.js" in low_all or "webglrenderer" in low_all:
        add_item(libraries, "Three.js", "WebGL / Three.js")

    if any(k in low_headers for k in ("php", "phpsessid")) or "/wp-content/" in low_all or rx(r"\.php(?:[\"\'?&#/]|$)", low_all):
        add_item(backend_langs, "PHP", "header/sess?o/rotas PHP")
    if any(k in low_headers for k in ("asp.net", "x-aspnet-version", "aspnet_sessionid")) or rx(r"\.aspx?(?:[\"\'?&#/]|$)", low_all):
        add_item(backend_langs, "C# / ASP.NET", "header/sess?o/rotas .NET")
    if any(k in low_all for k in ("__next_data__", "/_next/", "__nuxt")) or any(k in low_headers for k in ("node", "express", "next.js")):
        add_item(backend_langs, "JavaScript / Node.js", "SSR/runtime Node/Next")
    if any(k in low_headers for k in ("python", "werkzeug", "gunicorn", "uvicorn", "django", "flask", "fastapi", "csrftoken")):
        add_item(backend_langs, "Python", "header/framework Python")
    if any(k in low_headers for k in ("jsessionid", "spring", "tomcat", "servlet", "quarkus", "micronaut")):
        add_item(backend_langs, "Java", "runtime/sess?o JVM")
    if any(k in low_headers for k in ("phusion passenger", "ruby", "rails", "_rails_")):
        add_item(backend_langs, "Ruby", "runtime/sess?o Ruby/Rails")
    if any(k in low_headers for k in ("golang", "fiber", "gin", "echo")) or rx(r"\bgo\s+1\.\d+", low_all):
        add_item(backend_langs, "Go", "assinatura/runtime Go")

    api_endpoints = list(dict.fromkeys(
        re.findall(r"(?:https?://[^\s\"\'<>]+|/(?:api|v[1-9]|graphql|gql|ws|wss|webhook|health|metrics|auth|search|cdn)[a-zA-Z0-9_./-]*)", full_scan_blob)
    ))
    if api_endpoints or any(tok in low_all for tok in ("/graphql", "apollo", "trpc", "workers.dev", "edge-runtime")) or any(tok in low_headers for tok in ("x-envoy-", "x-kong-", "x-istio-", "cf-worker")):
        add_item(microservice_langs, "APIs / Edge / Servi?os", f"{len(api_endpoints)} endpoint(s)/rota(s) identificados")

    for plat in (cdn, server, powered_by):
        if plat and plat.lower() not in ("direto", "direto / n?o identificado", "n?o informado", "none"):
            add_item(platforms, plat, "cabe?alho de infraestrutura/CDN")

    languages: list[str] = []
    for item in frontend_langs + backend_langs + microservice_langs:
        if item not in languages:
            languages.append(item)

    return {
        "languages": languages,
        "languages_by_layer": {
            "frontend": frontend_langs,
            "backend": backend_langs,
            "microservices": microservice_langs,
        },
        "frameworks": frameworks,
        "libraries": libraries,
        "platforms": platforms,
        "evidence": evidence[:25],
        "note": "Detec??o baseada em assinaturas p?blicas estruturais (cabe?alhos HTTP, cookies, meta tags, HTML, DOM renderizado, bundles e endpoints).",
    }

