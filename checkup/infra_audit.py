"""Auditoria de infraestrutura, cabeçalhos OWASP, cookies, superfície pública e stack tecnológica."""

from __future__ import annotations

import re
from urllib.parse import urlparse

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
    """Audita DNS em cache, robots.txt, security.txt e indícios de stack traces expostos."""
    parsed = urlparse(base_url)
    host = parsed.hostname or ""
    scheme = parsed.scheme or "https"
    origin = f"{scheme}://{host}" if host else base_url
    issues: list[dict] = []

    ips = get_resolved_ips(host)

    robots_present = False
    robots_disallows_all = False
    r_robots = safe_probe_url(f"{origin}/robots.txt", timeout_s=3.5) if host else None
    if r_robots is not None and r_robots.status_code == 200 and r_robots.text:
        robots_present = True
        low_txt = r_robots.text.lower()
        if "disallow: /" in low_txt and "disallow: /." not in low_txt:
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

    security_txt_present = False
    r_sec = safe_probe_url(f"{origin}/.well-known/security.txt", timeout_s=3.0) if host else None
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
        "exposed_traces": exposed_traces,
        "issues": issues,
    }


def detect_tech_stack(raw_info: dict, rendered: dict | None = None) -> dict:
    """Identifica linguagens, frameworks, bibliotecas e plataformas com assinaturas estruturais precisas."""
    headers = {k.lower(): str(v) for k, v in ((raw_info or {}).get("headers") or {}).items()}
    server = str((raw_info or {}).get("server") or "")
    cdn = str((raw_info or {}).get("cdn") or "")
    powered_by = str((raw_info or {}).get("powered_by") or headers.get("x-powered-by") or "")
    cookies_str = " | ".join((raw_info or {}).get("set_cookies") or [])

    html_raw = str((raw_info or {}).get("html") or "")
    html_ren = str((rendered or {}).get("html") or "")
    combined_html = f"{html_raw}\n{html_ren}"
    low_html = combined_html.lower()
    low_headers = f"{server} {cdn} {powered_by} {cookies_str} " + " ".join(
        f"{k}: {v}" for k, v in headers.items()
    )
    low_headers = low_headers.lower()

    languages: list[str] = []
    frameworks: list[str] = []
    libraries: list[str] = []
    platforms: list[str] = []
    evidence: list[str] = []

    def add(target: list[str], label: str, reason: str) -> None:
        if label not in target:
            target.append(label)
            evidence.append(f"{label} ({reason})")

    # Linguagens / Runtimes
    if "php" in low_headers or "phpsessid" in low_headers or "/wp-content/" in low_html or re.search(r'\.php(?:["\'?]|$)', low_html):
        add(languages, "PHP", "cabeçalho/sessão/rotas .php")
    if "asp.net" in low_headers or "x-aspnet-version" in headers or re.search(r'\.aspx(?:["\'?]|$)', low_html):
        add(languages, "C# / ASP.NET", "cabeçalho ASP.NET/.aspx")
    if "__next_data__" in low_html or "/_next/" in low_html or "node" in powered_by.lower() or "express" in low_headers:
        add(languages, "JavaScript / Node.js", "SSR/runtime Node")
    if any(tok in low_headers for tok in ("python", "werkzeug", "gunicorn", "uvicorn", "django", "flask", "fastapi")):
        add(languages, "Python", "assinatura de servidor/framework")
    if any(tok in low_headers for tok in ("jsessionid", "spring", "tomcat", "servlet")):
        add(languages, "Java", "cabeçalho/cookie JVM")
    if any(tok in low_headers for tok in ("phusion passenger", "ruby", "rails", "_rails_")):
        add(languages, "Ruby", "assinatura Rails/Passenger")
    if "golang" in low_headers or "go-http-client" in low_headers:
        add(languages, "Go", "cabeçalho Go")
    if "<script" in low_html or 'type="module"' in low_html:
        add(languages, "JavaScript", "scripts client-side")

    # Frameworks / CMS
    if "/_next/" in low_html or "__next_data__" in low_html or "x-nextjs-cache" in headers:
        add(frameworks, "Next.js", "bundle /_next/ ou __NEXT_DATA__")
    if "__nuxt" in low_html or "/_nuxt/" in low_html:
        add(frameworks, "Nuxt", "bundle /_nuxt/ ou __NUXT__")
    if any(sig in low_html for sig in ("data-reactroot", "__react", "react-dom", "/_next/")):
        add(frameworks, "React", "marcadores React/DOM")
    if "ng-version" in low_html or "_nghost-" in low_html or "_ngcontent-" in low_html:
        add(frameworks, "Angular", "atributos ng-version/_nghost")
    if "data-v-" in low_html or "__vue" in low_html or "vue.global" in low_html or "vue.runtime" in low_html:
        add(frameworks, "Vue.js", "atributos data-v-/runtime Vue")
    if "__sveltekit" in low_html or "svelte-" in low_html:
        add(frameworks, "Svelte / SvelteKit", "assinatura SvelteKit")
    if "data-astro-cid" in low_html or "astro-island" in low_html:
        add(frameworks, "Astro", "ilhas/atributos Astro")
    if "/wp-content/" in low_html or "/wp-includes/" in low_html:
        add(frameworks, "WordPress", "estrutura /wp-content/")
    if "woocommerce" in low_html or "wc-blocks" in low_html:
        add(frameworks, "WooCommerce", "classes/scripts WooCommerce")
    if "cdn.shopify.com" in low_html or "myshopify.com" in low_html:
        add(frameworks, "Shopify", "CDN Shopify")
    if "drupal.settings" in low_html or "/sites/default/files/" in low_html:
        add(frameworks, "Drupal", "estrutura Drupal")
    if "w-webflow-badge" in low_html or "data-wf-site" in low_html:
        add(frameworks, "Webflow", "atributos data-wf-site")
    if "wixstatic.com" in low_html or "wix-warmup-data" in low_html:
        add(frameworks, "Wix", "assets wixstatic")
    if "laravel_session" in low_headers or "xsrf-token" in low_headers:
        add(frameworks, "Laravel", "cookies de sessão Laravel")

    # Bibliotecas / UI
    if re.search(r'class="[^"]*(?:sm:|md:|lg:|xl:|px-\d|py-\d|bg-slate-|text-indigo-|rounded-)', combined_html):
        add(libraries, "Tailwind CSS", "classes utilitárias")
    if re.search(r'class="[^"]*(?:container-fluid|col-md-\d|btn-primary)', combined_html) or "bootstrap.min." in low_html:
        add(libraries, "Bootstrap", "grid/classes Bootstrap")
    if re.search(r"jquery[.-][\d.]*(?:\.min)?\.js", low_html):
        add(libraries, "jQuery", "script jquery.js")
    if any(sig in low_html for sig in ("three.min.js", "three.module.js", "three.js")):
        add(libraries, "Three.js", "bundle Three.js")
    if any(sig in low_html for sig in ("chart.min.js", "chart.umd.js", "chart.js")):
        add(libraries, "Chart.js", "bundle Chart.js")
    if "gsap" in low_html or "scrolltrigger" in low_html:
        add(libraries, "GSAP", "animações GSAP")
    if "x-data=" in low_html or "alpinejs" in low_html:
        add(libraries, "Alpine.js", "diretivas x-data")
    if "hx-get=" in low_html or "hx-post=" in low_html:
        add(libraries, "htmx", "atributos hx-*")
    if re.search(r'class="[^"]*\bfa-(?:solid|regular|brands|light)\b', combined_html) or "fontawesome" in low_html:
        add(libraries, "Font Awesome", "ícones fa-*")
    if "lucide" in low_html or "data-lucide=" in low_html:
        add(libraries, "Lucide Icons", "ícones Lucide")
    if "/@vite/" in low_html or "/assets/index-" in low_html:
        add(libraries, "Vite", "estrutura de build Vite")

    # Plataformas / CDN / Servidor
    if cdn and cdn != "Direto / Não identificado":
        add(platforms, cdn, "cabeçalho CDN")
    if server and server != "Não informado":
        add(platforms, server, "cabeçalho Server")
    if powered_by:
        add(platforms, powered_by, "cabeçalho X-Powered-By")

    return {
        "languages": languages,
        "frameworks": frameworks,
        "libraries": libraries,
        "platforms": platforms,
        "evidence": evidence[:15],
        "note": "Detecção baseada em assinaturas públicas estruturais (cabeçalhos HTTP, cookies, atributos e bundles).",
    }
