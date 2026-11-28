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
    ("permissions-policy", "Permissions-Policy", "baixa",
     "Restringe acesso a câmera, microfone, geolocalização e APIs sensíveis do navegador."),
    ("cross-origin-opener-policy", "Cross-Origin-Opener-Policy (COOP)", "baixa",
     "Isola o contexto de navegação contra ataques cross-origin."),
    ("cross-origin-resource-policy", "Cross-Origin-Resource-Policy (CORP)", "baixa",
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

    for key, label, lvl, desc in MODERN_OWASP_HEADERS:
        if key not in headers:
            issues.append({
                "id": f"missing-{key}",
                "level": lvl,
                "category": "Infraestrutura",
                "title": f"Cabeçalho {label} ausente",
                "count": 1,
                "location": "Cabeçalhos HTTP da resposta",
                "explanation": desc,
                "fix": f"Adicione o cabeçalho {label} na resposta HTTP.",
                "examples": [f"Ausente: {key}"],
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
    """Identifica linguagens separadas por Frontend, Backend e Microsserviços, além de stack e CDN."""
    headers = {k.lower(): str(v) for k, v in ((raw_info or {}).get("headers") or {}).items()}
    server = str((raw_info or {}).get("server") or "")
    cdn = str((raw_info or {}).get("cdn") or "")
    powered_by = str((raw_info or {}).get("powered_by") or headers.get("x-powered-by") or "")
    cookies_str = " | ".join((raw_info or {}).get("set_cookies") or [])
    surface = (raw_info or {}).get("surface_audit") or {}

    html_raw = str((raw_info or {}).get("html") or "")
    html_ren = str((rendered or {}).get("html") or "")
    asset_urls_list = surface.get("asset_urls") or []
    asset_urls_str = "\n".join(asset_urls_list)
    asset_code_str = "\n".join(surface.get("asset_snippets") or [])

    combined_html = f"{html_raw}\n{html_ren}\n{asset_urls_str}"
    full_scan_blob = f"{combined_html}\n{asset_code_str}"
    low_html = full_scan_blob.lower()

    soup = BeautifulSoup(html_ren or html_raw or "", "html.parser")
    generators = " ".join(
        (m.get("content") or "")
        for m in soup.find_all("meta", attrs={"name": re.compile(r"^generator$", re.I)})
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

    def add_list(target: list[str], label: str, reason: str) -> None:
        if label not in target:
            target.append(label)
            evidence.append(f"{label} ({reason})")

    def add_fe(label: str, reason: str) -> None:
        add_list(frontend_langs, label, reason)

    def add_be(label: str, reason: str) -> None:
        add_list(backend_langs, label, reason)

    def add_ms(label: str, reason: str) -> None:
        add_list(microservice_langs, label, reason)

    def has_rx(pattern: str, text: str = low_html) -> bool:
        return bool(re.search(pattern, text, re.IGNORECASE))

    if "<script" in low_html or 'type="module"' in low_html or has_rx(r"\.js(?:[\"'\?&#]|$)"):
        add_fe("JavaScript", "scripts/bundles no navegador")
    if has_rx(r"\.ts(?:x)?(?:[\"'\?&#]|$)") or "typescript" in low_html or "tsx" in low_html:
        add_fe("TypeScript", "bundles/referências TS/TSX")
    if "<style" in low_html or has_rx(r"\.css(?:[\"'\?&#]|$)") or "tailwindcss" in low_html:
        add_fe("CSS", "folhas de estilo/classes visuais")
    if "<html" in low_html or "<body" in low_html:
        add_fe("HTML5", "estrutura de marcação web")

    if any(k in low_headers for k in ("php", "phpsessid")) or "/wp-content/" in low_html or has_rx(r"\.php(?:[\"'\?&#]|$)"):
        add_be("PHP", "cabeçalho/sessão/rotas PHP")
    if any(k in low_headers for k in ("asp.net", "x-aspnet-version", "aspnet_sessionid")) or has_rx(r"\.aspx?(?:[\"'\?&#]|$)"):
        add_be("C# / ASP.NET", "cabeçalho/sessão/rotas .NET")
    if any(k in low_html for k in ("__next_data__", "/_next/", "__nuxt", "_sveltekit")) or any(k in low_headers for k in ("node", "express", "next.js")):
        add_be("JavaScript / Node.js", "SSR/runtime Node no servidor")
    if any(k in low_headers for k in ("python", "werkzeug", "gunicorn", "uvicorn", "django", "flask", "fastapi", "csrftoken")):
        add_be("Python", "servidor/framework Python")
    if any(k in low_headers for k in ("jsessionid", "spring", "tomcat", "servlet", "quarkus", "micronaut")):
        add_be("Java", "runtime/sessão JVM")
    if any(k in low_headers for k in ("phusion passenger", "ruby", "rails", "_rails_")):
        add_be("Ruby", "runtime/sessão Ruby/Rails")
    if any(k in low_headers for k in ("golang", "fiber", "gin", "echo")) or has_rx(r"\bgo\s+1\.\d+"):
        add_be("Go", "assinatura de serviço/runtime Go")

    current_host = (urlparse(str((raw_info or {}).get("final_url") or "")).hostname or "").lower()
    external_hosts = {
        (urlparse(u).hostname or "").lower()
        for u in asset_urls_list
        if (urlparse(u).hostname or "").lower() and (urlparse(u).hostname or "").lower() != current_host
    }
    api_or_ms_endpoints = list(dict.fromkeys(
        re.findall(r"(?:https?://[^\s\"'<>]+|/(?:api|v[1-9]|graphql|gql|ws|wss|webhook|health|metrics|auth|billing|search|media|cdn)[a-zA-Z0-9_./-]*)", full_scan_blob)
    ))

    has_api_surface = bool(api_or_ms_endpoints) or any(
        tok in low_html for tok in ("/graphql", "apollo", "trpc", "microservice", "micro-frontend", "module-federation", "workers.dev", "edge-runtime")
    ) or any(
        tok in low_headers for tok in ("x-envoy-", "x-kong-", "x-istio-", "x-grpc-", "x-worker-", "cf-worker")
    )

    if has_api_surface:
        if any(tok in low_html for tok in ("/api/go", "golang", "fiber", "gin")) or "golang" in low_headers:
            add_ms("Go", "endpoints/serviços de alta concorrência")
        if any(tok in low_html for tok in ("/api/py", "fastapi", "uvicorn", "celery", "flask", "django")) or any(tok in low_headers for tok in ("uvicorn", "fastapi")):
            add_ms("Python", "serviços/workers/API Python")
        if any(tok in low_html for tok in ("/api/", "graphql", "apollo", "trpc", "socket.io", "next.api", "edge-runtime")) or "node" in low_headers:
            add_ms("Node.js / TypeScript", "rotas API/BFF/Edge/serviços")
        if any(tok in low_html for tok in ("spring", "quarkus", "micronaut", "grpc")) or any(tok in low_headers for tok in ("spring", "quarkus")):
            add_ms("Java / JVM", "serviços/APIs corporativas")
        if not microservice_langs:
            add_ms("HTTP/REST APIs & Edge", f"{len(api_or_ms_endpoints)} rota(s)/endpoint(s) e {len(external_hosts)} host(s) auxiliares")

    languages: list[str] = []
    for item in frontend_langs + backend_langs + microservice_langs:
        if item not in languages:
            languages.append(item)

    if any(k in low_html for k in ("/_next/", "__next_data__", "__next_f")) or any(k in low_headers for k in ("x-nextjs-", "next.js")):
        add_list(frameworks, "Next.js", "estrutura /_next/ ou __NEXT_DATA__")
    if any(k in low_html for k in ("/__nuxt", "__nuxt__", "/_nuxt/")):
        add_list(frameworks, "Nuxt", "estrutura /_nuxt/ ou __NUXT__")
    if any(k in low_html for k in ("data-reactroot", "__react", "react-dom", "react.production.min.js", "react.development.js", "/_next/")):
        add_list(frameworks, "React", "assinaturas React/ReactDOM")
    if any(k in low_html for k in ("ng-version", "_nghost-", "_ngcontent-", "angular.min.js")):
        add_list(frameworks, "Angular", "atributos/scripts Angular")
    if any(k in low_html for k in ("data-v-", "__vue", "vue.global", "vue.runtime", "vue.min.js")):
        add_list(frameworks, "Vue.js", "assinaturas Vue.js")
    if any(k in low_html for k in ("__sveltekit", "svelte-", "svelte.js")):
        add_list(frameworks, "Svelte / SvelteKit", "assinaturas Svelte/SvelteKit")
    if any(k in low_html for k in ("data-astro-cid", "astro-island", "astro.build")):
        add_list(frameworks, "Astro", "ilhas/atributos Astro")
    if "/wp-content/" in low_html or "/wp-includes/" in low_html or "wordpress" in generators:
        add_list(frameworks, "WordPress", "estrutura/meta WordPress")
    if any(k in low_html for k in ("woocommerce", "wc-blocks", "wc-ajax")):
        add_list(frameworks, "WooCommerce", "assinaturas WooCommerce")
    if any(k in low_html for k in ("cdn.shopify.com", "myshopify.com", "shopify.theme")):
        add_list(frameworks, "Shopify", "assinaturas Shopify")
    if any(k in low_html for k in ("drupal.settings", "/sites/default/files/")) or "drupal" in generators:
        add_list(frameworks, "Drupal", "assinaturas Drupal")
    if any(k in low_html for k in ("w-webflow-badge", "data-wf-site", "webflow.js")):
        add_list(frameworks, "Webflow", "assinaturas Webflow")
    if any(k in low_html for k in ("wixstatic.com", "wix-warmup-data", "parastorage.com")):
        add_list(frameworks, "Wix", "assinaturas Wix")
    if any(k in low_headers for k in ("laravel_session", "xsrf-token")) or "livewire" in low_html:
        add_list(frameworks, "Laravel", "assinaturas Laravel")
    if "csrfmiddlewaretoken" in low_html or "django" in low_headers:
        add_list(frameworks, "Django", "assinaturas Django")

    if has_rx(r'class="[^"]*(?:sm:|md:|lg:|xl:|2xl:|px-\d|py-\d|mx-auto|bg-(?:slate|gray|zinc|indigo|blue|emerald|red)-\d{2,3}|text-(?:slate|gray|zinc|indigo|blue|white)|rounded-(?:xl|2xl|3xl|full))') or "tailwindcss" in low_html:
        add_list(libraries, "Tailwind CSS", "classes utilitárias / Tailwind")
    if has_rx(r'class="[^"]*(?:container-fluid|col-(?:xs|sm|md|lg|xl)-\d+|btn-(?:primary|secondary|success|danger)|navbar-nav)') or has_rx(r"bootstrap(?:\.bundle)?(?:\.min)?\.(?:js|css)"):
        add_list(libraries, "Bootstrap", "grid/componentes/assets Bootstrap")
    if has_rx(r"jquery[.-][\d.]*(?:\.min)?\.js") or has_rx(r"\b(?:window\.jquery|\$\.fn\.jquery)\b", full_scan_blob):
        add_list(libraries, "jQuery", "script/assinatura jQuery")
    if has_rx(r"three(?:\.module|\.min)?\.js") or ("three" in low_html and ("webglrenderer" in low_html or "perspectivecamera" in low_html)):
        add_list(libraries, "Three.js", "bundle/API Three.js")
    if has_rx(r"chart(?:\.umd|\.min)?\.js") or "echarts" in low_html or "apexcharts" in low_html:
        add_list(libraries, "Gráficos (Chart.js/ECharts)", "biblioteca de gráficos")
    if "gsap" in low_html or "scrolltrigger" in low_html:
        add_list(libraries, "GSAP", "animações GSAP")
    if has_rx(r"\bx-data=") or "alpinejs" in low_html:
        add_list(libraries, "Alpine.js", "diretivas Alpine.js")
    if has_rx(r"\bhx-(?:get|post|put|delete|swap)=") or "htmx" in low_html:
        add_list(libraries, "htmx", "atributos/script htmx")
    if has_rx(r'class="[^"]*\bfa-(?:solid|regular|brands|light|duotone)\b') or "fontawesome" in low_html or "font-awesome" in low_html:
        add_list(libraries, "Font Awesome", "ícones Font Awesome")
    if "lucide" in low_html or has_rx(r"\bdata-lucide="):
        add_list(libraries, "Lucide Icons", "ícones Lucide")
    if "/@vite/" in low_html or has_rx(r"/assets/index-[A-Za-z0-9_-]+\.js"):
        add_list(libraries, "Vite", "build/assets Vite")
    if "googletagmanager.com/gtm.js" in low_html or "gtag/js" in low_html or "google-analytics.com" in low_html:
        add_list(libraries, "Google Analytics / GTM", "tags de mensuração")
    if "sentry.io" in low_html or "__sentry__" in low_html:
        add_list(libraries, "Sentry", "monitoramento de erros")

    if cdn and cdn != "Direto / Não identificado":
        add_list(platforms, cdn, "cabeçalho CDN")
    if server and server != "Não informado":
        add_list(platforms, server, "cabeçalho Server")
    if powered_by:
        add_list(platforms, powered_by, "cabeçalho X-Powered-By")

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
        "evidence": evidence[:20],
        "note": "Detecção baseada em assinaturas públicas estruturais (cabeçalhos HTTP, cookies, meta tags, HTML, bundles e endpoints).",
    }
