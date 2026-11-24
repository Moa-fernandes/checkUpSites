"""Verificações de qualidade, acessibilidade e infraestrutura do checkUp."""

import ipaddress
import math
import re
import socket
import ssl
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from urllib.parse import urlparse

import requests
from bs4 import BeautifulSoup
from playwright.sync_api import Error as PlaywrightError
from playwright.sync_api import sync_playwright

USER_AGENT = "checkUp/1.5"
REQUEST_TIMEOUT = 15
SSL_TIMEOUT = 6
LINK_TIMEOUT = 6
MAX_LINKS = 40
RENDER_TIMEOUT_MS = 25000
SETTLE_MS = 1500
WEIGHTS = {"alta": 10, "media": 5, "baixa": 2}
CAP_PER_ISSUE = {"alta": 24, "media": 14, "baixa": 7}

DEFAULT_LIVE_TARGETS = [
    {
        "name": "Open-Meteo (Clima Aberto)",
        "url": "https://api.open-meteo.com/v1/forecast?latitude=-22.9068&longitude=-43.1729&current_weather=true",
    },
    {
        "name": "ViaCEP (CEP Público BR)",
        "url": "https://viacep.com.br/ws/20270001/json/",
    },
    {
        "name": "BrasilAPI (Dados Públicos BR)",
        "url": "https://brasilapi.com.br/api/feriados/v1/2026",
    },
]

SECURITY_HEADERS = [
    ("strict-transport-security", "HSTS (Strict-Transport-Security)",
     "Ajuda a garantir que o navegador sempre use conexão segura HTTPS."),
    ("x-content-type-options", "X-Content-Type-Options",
     "Evita que o navegador adivinhe o tipo do arquivo e execute scripts indevidos."),
    ("x-frame-options", "X-Frame-Options",
     "Ajuda a proteger a página contra embutimento malicioso em iframes (clickjacking)."),
    ("content-security-policy", "Content-Security-Policy (CSP)",
     "Limita de onde scripts, estilos e recursos podem carregar na página."),
    ("referrer-policy", "Referrer-Policy",
     "Controla quantas informações de origem são enviadas ao abrir links externos."),
]

CONTRAST_JS = r"""
() => {
  const parse = (c) => {
    const m = c && c.match(/rgba?\(([^)]+)\)/);
    if (!m) return null;
    const p = m[1].split(',').map(s => parseFloat(s));
    return { r: p[0], g: p[1], b: p[2], a: p.length === 4 ? p[3] : 1 };
  };
  const over = (top, bottom) => ({
    r: top.r * top.a + bottom.r * (1 - top.a),
    g: top.g * top.a + bottom.g * (1 - top.a),
    b: top.b * top.a + bottom.b * (1 - top.a),
    a: 1,
  });
  const backgroundOf = (el) => {
    const layers = [];
    let node = el;
    while (node && node.nodeType === 1) {
      const c = parse(getComputedStyle(node).backgroundColor);
      if (c && c.a > 0) {
        layers.push(c);
        if (c.a >= 1) break;
      }
      node = node.parentElement;
    }
    let base = { r: 255, g: 255, b: 255, a: 1 };
    for (let i = layers.length - 1; i >= 0; i--) base = over(layers[i], base);
    return base;
  };
  const lum = (c) => {
    const f = (v) => {
      v /= 255;
      return v <= 0.03928 ? v / 12.92 : Math.pow((v + 0.055) / 1.055, 2.4);
    };
    return 0.2126 * f(c.r) + 0.7152 * f(c.g) + 0.0722 * f(c.b);
  };

  const results = [];
  for (const el of document.querySelectorAll('body *')) {
    const textNodes = Array.from(el.childNodes).filter(
      n => n.nodeType === 3 && n.textContent.trim().length > 0
    );
    if (textNodes.length === 0) continue;

    const cs = getComputedStyle(el);
    if (cs.visibility === 'hidden' || cs.display === 'none' || parseFloat(cs.opacity) === 0) continue;
    const rect = el.getBoundingClientRect();
    if (rect.width === 0 || rect.height === 0) continue;

    const bg = backgroundOf(el);
    let fg = parse(cs.color);
    if (!fg) continue;
    if (fg.a < 1) fg = over(fg, bg);

    const l1 = lum(fg);
    const l2 = lum(bg);
    const ratio = (Math.max(l1, l2) + 0.05) / (Math.min(l1, l2) + 0.05);

    results.push({
      ratio: ratio,
      fontSize: parseFloat(cs.fontSize),
      fontWeight: parseInt(cs.fontWeight, 10) || 400,
      text: textNodes.map(n => n.textContent.trim()).join(' ').slice(0, 60),
    });
    if (results.length >= 3000) break;
  }
  return results;
}
"""

QUALITY_JS = r"""
() => {
  const imgs = Array.from(document.images);
  const brokenImgEls = imgs.filter(i => i.complete && i.naturalWidth === 0 && i.getAttribute('src'));
  const brokenImages = brokenImgEls.length;
  const brokenImageExamples = brokenImgEls.slice(0, 4).map(i => i.getAttribute('src') || 'imagem sem src');

  const seen = {};
  let duplicateIds = 0;
  const dupIdNames = [];
  document.querySelectorAll('[id]').forEach(el => {
    if (el.id) {
      if (seen[el.id]) {
        duplicateIds++;
        if (dupIdNames.length < 4) dupIdNames.push(`#${el.id}`);
      }
      seen[el.id] = true;
    }
  });

  const text = document.body ? document.body.innerText : '';
  const badPattern = /lorem ipsum|undefined|\bNaN\b|\[object Object\]|\bTODO\b|xxx+/i;
  const match = text.match(badPattern);

  const links = Array.from(document.querySelectorAll('a[href]'))
    .map(a => a.href)
    .filter(h => /^https?:\/\//.test(h));

  const scripts = Array.from(document.querySelectorAll('script'));
  const stylesheets = Array.from(document.querySelectorAll('link[rel="stylesheet"]'));
  const blockingHeadScripts = Array.from(document.querySelectorAll('head script[src]')).filter(s => {
    const type = (s.getAttribute('type') || '').toLowerCase();
    return !s.defer && !s.async && type !== 'module';
  }).map(s => s.getAttribute('src'));

  const inlineScriptText = scripts
    .filter(s => !s.getAttribute('src'))
    .map(s => s.textContent || '')
    .join('\n');
  const hasDebugArtifacts = /\b(console\.log|debugger)\b/.test(inlineScriptText);

  const hasCanonical = !!document.querySelector('link[rel="canonical"]');
  const robotsMeta = document.querySelector('meta[name="robots"]');
  const robotsContent = robotsMeta ? (robotsMeta.getAttribute('content') || '').toLowerCase() : '';
  const hasNoIndex = /\bnoindex\b/.test(robotsContent);
  const hasOgTitle = !!document.querySelector('meta[property="og:title"]');
  const hasOgDescription = !!document.querySelector('meta[property="og:description"]');
  const hasMain = !!document.querySelector('main, [role="main"]');
  const hasNav = !!document.querySelector('nav, [role="navigation"]');

  return {
    totalImages: imgs.length,
    brokenImages: brokenImages,
    brokenImageExamples: brokenImageExamples,
    duplicateIds: duplicateIds,
    duplicateIdExamples: dupIdNames,
    placeholderText: match ? match[0] : null,
    hasDescription: !!document.querySelector('meta[name="description"]'),
    links: Array.from(new Set(links)),
    scriptCount: scripts.length,
    stylesheetCount: stylesheets.length,
    blockingHeadScripts: blockingHeadScripts.slice(0, 5),
    hasDebugArtifacts: hasDebugArtifacts,
    hasCanonical: hasCanonical,
    hasNoIndex: hasNoIndex,
    hasOgTags: hasOgTitle && hasOgDescription,
    hasMain: hasMain,
    hasNav: hasNav,
  };
}
"""

OVERFLOW_JS = r"""
() => document.documentElement.scrollWidth > window.innerWidth + 2
"""


def _is_safe_url(url: str) -> bool:
    """Bloqueia endereços que apontam para redes internas (proteção contra SSRF)."""
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        return False
    try:
        infos = socket.getaddrinfo(parsed.hostname, None)
    except socket.gaierror:
        return False
    for info in infos:
        ip = ipaddress.ip_address(info[4][0])
        if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved:
            return False
    return True


def normalize_url(raw: str) -> str:
    raw = (raw or "").strip()
    if not raw:
        raise ValueError("Digite o endereço do site.")
    if not raw.startswith(("http://", "https://")):
        raw = "https://" + raw
    if not _is_safe_url(raw):
        raise ValueError("Este endereço não pode ser verificado.")
    return raw


def _parse_cert_expiry(not_after: str) -> datetime:
    try:
        dt = parsedate_to_datetime(not_after)
    except Exception:
        dt = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def _format_issuer(cert: dict | None) -> str | None:
    if not cert:
        return None
    for item in reversed(cert.get("issuer") or []):
        for key, val in item:
            if key == "organizationName":
                return str(val)
            if key == "commonName":
                return str(val)
    return None


def inspect_ssl_certificate(url: str) -> dict:
    """Consulta o certificado TLS/SSL da porta 443 e retorna validade, expiração, emissor e protocolo."""
    parsed = urlparse(url)
    host = parsed.hostname
    if not host:
        return {
            "checked": False, "valid": False, "days_left": None,
            "expires_at": None, "issuer": None, "tls_version": None, "error": None,
        }

    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((host, 443), timeout=SSL_TIMEOUT) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                tls_version = ssock.version()
    except Exception as exc:
        return {
            "checked": True, "valid": False, "days_left": None,
            "expires_at": None, "issuer": None, "tls_version": None,
            "error": str(exc)[:140],
        }

    issuer = _format_issuer(cert)
    not_after = cert.get("notAfter") if cert else None
    if not not_after:
        return {
            "checked": True, "valid": False, "days_left": None,
            "expires_at": None, "issuer": issuer, "tls_version": tls_version,
            "error": "Certificado sem data de expiração informada.",
        }

    exp_dt = _parse_cert_expiry(not_after)
    now_dt = datetime.now(timezone.utc)
    days_left = (exp_dt - now_dt).days
    return {
        "checked": True,
        "valid": days_left >= 0,
        "days_left": days_left,
        "expires_at": exp_dt.strftime("%d/%m/%Y"),
        "issuer": issuer,
        "tls_version": tls_version,
        "error": None,
    }


def _detect_server_and_cdn(headers: dict) -> tuple[str, str]:
    server = headers.get("server") or "Não informado"
    cdn = "Direto / Não identificado"
    if "cf-ray" in headers or "cloudflare" in server.lower():
        cdn = "Cloudflare"
    elif "x-amz-cf-id" in headers or "cloudfront" in (headers.get("via") or "").lower():
        cdn = "AWS CloudFront"
    elif "x-vercel-id" in headers:
        cdn = "Vercel"
    elif "x-render-origin-server" in headers:
        cdn = "Render"
    elif "fastly" in (headers.get("via") or "").lower() or "x-fastly-request-id" in headers:
        cdn = "Fastly"
    elif "via" in headers:
        cdn = f"Proxy/CDN ({headers['via'][:45]})"
    return server[:60], cdn[:45]


def _extract_set_cookies(resp: requests.Response) -> list[str]:
    raw = getattr(resp.raw, "headers", None)
    if raw and hasattr(raw, "getlist"):
        return list(raw.getlist("Set-Cookie"))
    cookie_header = resp.headers.get("Set-Cookie")
    return [cookie_header] if cookie_header else []


def fetch_raw_page(url: str) -> dict:
    """Busca o HTML bruto e coleta métricas básicas de rede, SSL, servidor e cabeçalhos."""
    start = time.perf_counter()
    resp = requests.get(
        url,
        headers={
            "User-Agent": USER_AGENT,
            "Accept-Encoding": "gzip, deflate, br",
        },
        timeout=REQUEST_TIMEOUT,
        allow_redirects=True,
    )
    elapsed_ms = round((time.perf_counter() - start) * 1000)
    resp.raise_for_status()

    headers_lower = {k.lower(): v for k, v in resp.headers.items()}
    redirects = len(resp.history)
    final_url = resp.url or url
    is_https = urlparse(final_url).scheme == "https"
    ssl_info = inspect_ssl_certificate(final_url) if is_https else {
        "checked": False, "valid": False, "days_left": None,
        "expires_at": None, "issuer": None, "tls_version": None, "error": None,
    }

    server_hdr, cdn_name = _detect_server_and_cdn(headers_lower)
    encoding = (headers_lower.get("content-encoding") or "").lower()
    compressed = any(tok in encoding for tok in ("gzip", "br", "zstd", "deflate"))
    raw_bytes = len(resp.content or b"")
    set_cookies = _extract_set_cookies(resp)

    return {
        "html": resp.text,
        "raw_kb": round(raw_bytes / 1024, 1),
        "ttfb_ms": elapsed_ms,
        "redirects": redirects,
        "final_url": final_url,
        "is_https": is_https,
        "ssl": ssl_info,
        "headers": headers_lower,
        "server": server_hdr,
        "cdn": cdn_name,
        "compressed": compressed,
        "encoding": encoding or "nenhuma",
        "powered_by": headers_lower.get("x-powered-by"),
        "set_cookies": set_cookies,
    }


def _route_guard(route):
    """Durante a renderização, bloqueia requisições para redes internas."""
    url = route.request.url
    if urlparse(url).scheme not in ("http", "https") or _is_safe_url(url):
        route.continue_()
    else:
        route.abort()


def render_page(url: str) -> dict:
    """Abre a página em Chromium (desktop e celular) e coleta dados de renderização e rede."""
    failed_requests = []
    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            try:
                context = browser.new_context(
                    user_agent=USER_AGENT,
                    viewport={"width": 1280, "height": 900},
                    locale="pt-BR",
                )
                context.route("**/*", _route_guard)
                page = context.new_page()

                console_errors = []
                js_errors = []
                page.on("console", lambda m: console_errors.append(m.text)
                        if m.type == "error" else None)
                page.on("pageerror", lambda e: js_errors.append(str(e)))
                page.on(
                    "response",
                    lambda r: failed_requests.append(f"{r.status} {r.url[:110]}")
                    if r.status >= 400 else None,
                )
                page.on(
                    "requestfailed",
                    lambda req: failed_requests.append(f"FALHA {req.url[:110]}")
                    if req.failure and "ERR_ABORTED" not in (req.failure or "") else None,
                )

                page.goto(url, wait_until="load", timeout=RENDER_TIMEOUT_MS)
                page.wait_for_timeout(SETTLE_MS)
                rendered_html = page.content()
                colors = page.evaluate(CONTRAST_JS)
                quality = page.evaluate(QUALITY_JS)

                mobile = browser.new_context(
                    user_agent=USER_AGENT,
                    viewport={"width": 375, "height": 812},
                    locale="pt-BR",
                    is_mobile=True,
                )
                mobile.route("**/*", _route_guard)
                mpage = mobile.new_page()
                mpage.goto(url, wait_until="load", timeout=RENDER_TIMEOUT_MS)
                mpage.wait_for_timeout(SETTLE_MS)
                mobile_overflow = mpage.evaluate(OVERFLOW_JS)
                mobile.close()
            finally:
                browser.close()
    except PlaywrightError as exc:
        raise ValueError(
            "Não consegui abrir a página no navegador. Confira o endereço e tente de novo."
        ) from exc

    return {
        "html": rendered_html,
        "rendered_kb": round(len(rendered_html.encode("utf-8")) / 1024, 1),
        "colors": colors,
        "quality": quality,
        "console_errors": console_errors,
        "js_errors": js_errors,
        "failed_requests": list(dict.fromkeys(failed_requests)),
        "mobile_overflow": mobile_overflow,
    }


def _check_one_link(href: str) -> str | None:
    if not _is_safe_url(href):
        return None
    try:
        resp = requests.head(
            href,
            headers={"User-Agent": USER_AGENT},
            timeout=LINK_TIMEOUT,
            allow_redirects=True,
        )
        if resp.status_code in (403, 405, 429):
            resp = requests.get(
                href,
                headers={"User-Agent": USER_AGENT},
                timeout=LINK_TIMEOUT,
                allow_redirects=True,
                stream=True,
            )
            resp.close()
        if resp.status_code in (401, 403, 405, 429):
            return None
        if resp.status_code >= 400:
            return f"{resp.status_code} · {href}"
    except requests.RequestException:
        return f"Sem resposta · {href}"
    return None


def check_links(urls: list) -> tuple[list, int]:
    sample = urls[:MAX_LINKS]
    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(_check_one_link, sample))
    broken = [r for r in results if r]
    return broken, len(sample)


def _is_large_text(size: float, weight: int) -> bool:
    """Pela WCAG, texto grande é de 24px ou mais, ou 18,66px com negrito."""
    return size >= 24 or (size >= 18.66 and weight >= 700)


def _contrast_issues(color_items) -> list:
    failing = []
    for item in color_items:
        needed = 3.0 if _is_large_text(item["fontSize"], item["fontWeight"]) else 4.5
        if item["ratio"] < needed:
            failing.append((item, needed))

    if not failing:
        return []

    examples = [
        f'"{item["text"]}": contraste {item["ratio"]:.1f}:1 (mínimo {needed})'
        for item, needed in failing[:5]
    ]
    return [{
        "level": "alta",
        "category": "Acessibilidade",
        "title": "Contraste de cores insuficiente",
        "count": len(failing),
        "location": "Elementos de texto visíveis (WCAG AA)",
        "explanation": (
            "Texto com pouco contraste em relação ao fundo é difícil de ler "
            "para muita gente, inclusive em telas com muito brilho."
        ),
        "fix": (
            "Use cores com contraste de pelo menos 4,5:1 para textos normais "
            "e 3:1 para textos grandes."
        ),
        "examples": examples,
    }]


def _visible_word_count(html: str) -> int:
    soup = BeautifulSoup(html, "html.parser")
    for tag in soup(["script", "style", "noscript", "template"]):
        tag.decompose()
    return len(soup.get_text(" ", strip=True).split())


def _js_dependency_issues(raw_html: str, rendered_html: str) -> list:
    raw_words = _visible_word_count(raw_html)
    rendered_words = _visible_word_count(rendered_html)
    missing = rendered_words - raw_words
    if rendered_words and missing > 50 and missing / rendered_words > 0.3:
        return [{
            "level": "media",
            "category": "Qualidade",
            "title": "Parte do conteúdo só aparece com JavaScript",
            "count": 1,
            "location": "HTML inicial vs. DOM renderizado",
            "explanation": (
                f"Cerca de {missing} palavras só aparecem depois que o JavaScript "
                "roda. Buscadores e algumas tecnologias de acessibilidade podem "
                "não ler esse conteúdo."
            ),
            "fix": (
                "Entregue o conteúdo principal no HTML inicial, ou use renderização "
                "no servidor para as partes essenciais."
            ),
            "examples": [f"Palavras no HTML bruto: {raw_words} · Renderizadas: {rendered_words}"],
        }]
    return []


def _cookie_issues(set_cookies: list[str], is_https: bool) -> list:
    weak_cookies = []
    for raw_cookie in set_cookies:
        parts = [p.strip().lower() for p in raw_cookie.split(";")]
        cookie_name = raw_cookie.split("=", 1)[0].strip() or "cookie"
        missing = []
        if is_https and "secure" not in parts:
            missing.append("Secure")
        if "httponly" not in parts:
            missing.append("HttpOnly")
        if not any(p.startswith("samesite=") for p in parts):
            missing.append("SameSite")
        if missing:
            weak_cookies.append(f"{cookie_name}: sem {', '.join(missing)}")

    if not weak_cookies:
        return []

    return [{
        "level": "baixa",
        "category": "Infraestrutura",
        "title": "Cookies sem atributos completos de segurança",
        "count": len(weak_cookies),
        "location": "Cabeçalhos Set-Cookie HTTP",
        "explanation": "Cookies sem Secure, HttpOnly ou SameSite ficam mais expostos a roubo via script ou envio cruzado entre sites.",
        "fix": "Configure HttpOnly, Secure (em HTTPS) e SameSite=Lax ou Strict nos cookies emitidos pelo servidor.",
        "examples": weak_cookies[:5],
    }]


def _infrastructure_issues(raw_info: dict) -> list:
    issues = []
    headers = raw_info.get("headers") or {}

    if raw_info.get("http_redirects_to_https") is False:
        issues.append({
            "level": "alta",
            "category": "Infraestrutura",
            "title": "Acesso HTTP não redireciona automaticamente para HTTPS",
            "count": 1,
            "location": "Redirecionamento HTTP -> HTTPS",
            "explanation": "O endereço em HTTP não redireciona automaticamente para HTTPS, expondo a requisição inicial.",
            "fix": "Configure o servidor ou CDN para redirecionar permanentemente (301/308) HTTP para HTTPS.",
            "examples": [f"URL final: {raw_info.get('final_url', '')}"],
        })

    ssl_info = raw_info.get("ssl") or {}

    if not raw_info.get("is_https", True):
        issues.append({
            "level": "alta",
            "category": "Infraestrutura",
            "title": "Site não entrega o endereço final em HTTPS",
            "count": 1,
            "location": "Protocolo da URL final",
            "explanation": "Conexões sem HTTPS ficam expostas a alterações e reduzem a confiança do visitante.",
            "fix": "Configure um certificado TLS/SSL válido e redirecione todo o tráfego para HTTPS.",
            "examples": [f"URL final: {raw_info.get('final_url', '')}"],
        })
    elif ssl_info.get("checked"):
        days_left = ssl_info.get("days_left")
        expires_at = ssl_info.get("expires_at")
        if not ssl_info.get("valid") or (days_left is not None and days_left < 0):
            issues.append({
                "level": "alta",
                "category": "Infraestrutura",
                "title": "Certificado SSL/TLS expirado ou inválido",
                "count": 1,
                "location": "Certificado TLS/SSL (porta 443)",
                "explanation": "Um certificado vencido ou inválido gera avisos de segurança e bloqueia acessos no navegador.",
                "fix": "Renove ou reinstale imediatamente o certificado SSL/TLS no servidor ou provedor.",
                "examples": [f"Expiração: {expires_at or 'desconhecida'}"],
            })
        elif days_left is not None and days_left <= 30:
            issues.append({
                "level": "media",
                "category": "Infraestrutura",
                "title": "Certificado SSL/TLS próximo de vencer",
                "count": 1,
                "location": "Certificado TLS/SSL (porta 443)",
                "explanation": f"O certificado expira em {days_left} dia(s) ({expires_at}). Se não renovar a tempo, o site ficará fora ou com alerta.",
                "fix": "Verifique a renovação automática (Let's Encrypt / provedor) para evitar interrupção.",
                "examples": [f"Expira em {expires_at} ({days_left} dia(s) restantes)"],
            })

        tls_ver = ssl_info.get("tls_version") or ""
        if tls_ver in ("TLSv1", "TLSv1.1", "SSLv3"):
            issues.append({
                "level": "alta",
                "category": "Infraestrutura",
                "title": "Protocolo TLS antigo em uso",
                "count": 1,
                "location": "Negociação TLS",
                "explanation": f"O servidor negociou {tls_ver}, considerado inseguro pelos navegadores modernos.",
                "fix": "Habilite TLS 1.2 e TLS 1.3 no servidor ou CDN e desative versões antigas.",
                "examples": [f"Versão negociada: {tls_ver}"],
            })

    if raw_info.get("powered_by"):
        issues.append({
            "level": "baixa",
            "category": "Infraestrutura",
            "title": "Cabeçalho X-Powered-By expõe tecnologia do servidor",
            "count": 1,
            "location": "Cabeçalhos HTTP da resposta",
            "explanation": "Expor linguagem ou framework no cabeçalho facilita reconhecimento automatizado da stack.",
            "fix": "Remova ou oculte o cabeçalho X-Powered-By na aplicação ou proxy reverso.",
            "examples": [f"X-Powered-By: {raw_info['powered_by']}"],
        })

    if not raw_info.get("compressed", True) and raw_info.get("raw_kb", 0) > 15:
        issues.append({
            "level": "baixa",
            "category": "Infraestrutura",
            "title": "Resposta sem compressão HTTP (gzip/brotli)",
            "count": 1,
            "location": "Cabeçalho Content-Encoding",
            "explanation": f"O HTML inicial tem {raw_info['raw_kb']} KB sem compressão ativa, aumentando o tráfego e o tempo de transferência.",
            "fix": "Ative Brotli (br) ou Gzip no servidor web, proxy reverso ou CDN.",
            "examples": [f"Content-Encoding: {raw_info.get('encoding', 'nenhuma')} ({raw_info.get('raw_kb', 0)} KB)"],
        })

    redirects = raw_info.get("redirects", 0)
    if redirects > 2:
        issues.append({
            "level": "baixa",
            "category": "Infraestrutura",
            "title": "Cadeia longa de redirecionamentos",
            "count": redirects,
            "location": "Cadeia de redirecionamentos HTTP",
            "explanation": "Vários redirecionamentos seguidos atrasam o início do carregamento no navegador e no celular.",
            "fix": "Aponte os links diretamente para o endereço final sempre que possível.",
            "examples": [f"{redirects} redirecionamento(s) até {raw_info.get('final_url', '')}"],
        })

    ttfb_ms = raw_info.get("ttfb_ms", 0)
    if ttfb_ms > 1500:
        issues.append({
            "level": "media",
            "category": "Infraestrutura",
            "title": "Tempo de resposta inicial do servidor alto",
            "count": 1,
            "location": "Resposta inicial do servidor (TTFB)",
            "explanation": f"O servidor levou {ttfb_ms} ms para começar a responder, o que deixa a abertura lenta.",
            "fix": "Otimize consultas, use cache de resposta ou avalie a capacidade/região do servidor.",
            "examples": [f"Tempo de resposta inicial: {ttfb_ms} ms"],
        })

    missing_headers = []
    for header_key, label, reason in SECURITY_HEADERS:
        if header_key not in headers:
            missing_headers.append((label, reason))

    if missing_headers:
        issues.append({
            "level": "media",
            "category": "Infraestrutura",
            "title": "Cabeçalhos de segurança HTTP ausentes",
            "count": len(missing_headers),
            "location": "Cabeçalhos HTTP da resposta",
            "explanation": "Cabeçalhos HTTP de segurança ajudam a proteger o site e os visitantes contra ataques comuns no navegador.",
            "fix": "Configure os cabeçalhos ausentes no servidor web ou proxy reverso (Nginx, Apache, Cloudflare, etc.).",
            "examples": [f"{label}: {reason}" for label, reason in missing_headers[:5]],
        })

    issues.extend(_cookie_issues(raw_info.get("set_cookies") or [], bool(raw_info.get("is_https", True))))
    return issues


def _quality_issues(rendered: dict, broken_links: list) -> list:
    q = rendered["quality"]
    failed_reqs = rendered.get("failed_requests") or []
    blocking_scripts = q.get("blockingHeadScripts") or []
    issues = []

    def add(level, category, title, count, explanation, fix, location, examples=None):
        if count > 0:
            issues.append({
                "level": level,
                "category": category,
                "title": title,
                "count": count,
                "location": location,
                "explanation": explanation,
                "fix": fix,
                "examples": examples or [],
            })

    add(
        "alta", "Qualidade", "Imagens quebradas", q["brokenImages"],
        "A imagem não aparece para o visitante e deixa um espaço vazio ou um ícone de erro.",
        "Confira o caminho ou a URL da imagem e envie o arquivo novamente se necessário.",
        location="Tags <img> renderizadas",
        examples=q.get("brokenImageExamples") or [],
    )

    add(
        "media", "Qualidade", "Links quebrados", len(broken_links),
        "O visitante clica e cai em uma página de erro, o que prejudica a confiança no site.",
        "Atualize ou remova os links que retornam erro.",
        location="Links <a href> da página",
        examples=broken_links[:5],
    )

    add(
        "media", "Qualidade", "Requisições de rede falharam no carregamento", len(failed_reqs),
        "Recursos externos ou chamadas da página retornaram erro HTTP (4xx/5xx) ou falharam na rede.",
        "Inspecione a aba Rede do navegador (F12) e corrija URLs, permissões (CORS) ou endpoints instáveis.",
        location="Requisições HTTP no navegador",
        examples=failed_reqs[:5],
    )

    add(
        "baixa", "Qualidade", "Scripts bloqueantes no <head>", len(blocking_scripts),
        "Scripts externos no <head> sem defer, async ou type='module' podem atrasar a renderização inicial.",
        "Adicione defer ou async nos scripts não críticos ou mova para o final do <body>.",
        location="Seção <head> (<script src>)",
        examples=blocking_scripts[:5],
    )

    placeholder = q["placeholderText"]
    add(
        "alta", "Qualidade", "Texto de teste ou erro visível na página", 1 if placeholder else 0,
        "Textos como 'lorem ipsum', 'undefined' ou 'NaN' mostram que a página ficou incompleta.",
        "Substitua o texto de teste pelo conteúdo final.",
        location="Texto visível em <body>",
        examples=[f"Encontrado: '{placeholder}'"] if placeholder else [],
    )

    add(
        "baixa", "Qualidade", "Indícios de debug em scripts inline", 1 if q.get("hasDebugArtifacts") else 0,
        "Chamadas como console.log ou debugger ficaram visíveis em scripts inline da página.",
        "Remova logs de depuração e instruções debugger antes de publicar em produção.",
        location="Scripts inline (<script>)",
    )

    add(
        "alta", "Qualidade", "Layout quebra no celular (rolagem lateral)", 1 if rendered["mobile_overflow"] else 0,
        "Em telas pequenas, parte do conteúdo fica fora da tela e obriga a rolar para o lado.",
        "Ajuste elementos com largura fixa e use larguras relativas ou responsivas.",
        location="Viewport mobile (375×812)",
    )

    js_problems = len(rendered["js_errors"]) + len(rendered["console_errors"])
    examples = (rendered["js_errors"] + rendered["console_errors"])[:4]
    add(
        "media", "Qualidade", "Erros de JavaScript no console", js_problems,
        "Erros de script podem impedir funções como menus, formulários e botões.",
        "Abra o console do navegador (F12), corrija os erros e teste as funções da página.",
        location="Console / runtime JavaScript",
        examples=[e[:160] for e in examples],
    )

    add(
        "baixa", "Qualidade", "IDs duplicados no HTML", q["duplicateIds"],
        "IDs repetidos fazem alguns botões e links apontarem para o elemento errado.",
        "Garanta que cada id seja usado uma única vez na página.",
        location="Atributos id no DOM",
        examples=q.get("duplicateIdExamples") or [],
    )

    add(
        "baixa", "Qualidade", "Descrição da página ausente (meta description)", 0 if q["hasDescription"] else 1,
        "Sem descrição, o Google escolhe um trecho aleatório da página para mostrar nos resultados.",
        'Adicione <meta name="description" content="..."> no head, com 120 a 160 caracteres.',
        location="Seção <head> (meta description)",
    )

    add(
        "baixa", "Qualidade", "URL canônica ausente (link rel='canonical')", 0 if q.get("hasCanonical", True) else 1,
        "Sem canonical, variações de URL com parâmetros podem diluir a indexação nos buscadores.",
        'Adicione <link rel="canonical" href="..."> apontando para a URL principal.',
        location="Seção <head> (link canonical)",
    )

    add(
        "media", "Qualidade", "Página marcada com noindex", 1 if q.get("hasNoIndex") else 0,
        "A diretiva noindex impede que mecanismos de busca indexem esta página.",
        "Remova noindex se esta página pública deve aparecer nos resultados de busca.",
        location="Seção <head> (meta robots)",
    )

    return issues


def _compute_score(issues: list[dict]) -> int:
    """Calcula a pontuação de 0 a 100 com base na severidade e no volume de ocorrências."""
    total_penalty = 0.0
    for issue in issues:
        level = issue.get("level", "baixa")
        base_weight = WEIGHTS.get(level, 2)
        cap = CAP_PER_ISSUE.get(level, 7)
        count = max(1, int(issue.get("count") or 1))
        multiplier = 1.0 + 0.35 * math.log1p(count - 1)
        penalty = min(base_weight * multiplier, cap)
        total_penalty += penalty
    return max(0, min(100, round(100.0 - total_penalty)))


def check_html(html: str, extra_issues=None) -> dict:
    soup = BeautifulSoup(html, "html.parser")
    issues = list(extra_issues or [])

    def add(level, category, title, count, explanation, fix, location="Documento HTML"):
        if count > 0:
            issues.append({
                "level": level,
                "category": category,
                "title": title,
                "count": count,
                "location": location,
                "explanation": explanation,
                "fix": fix,
                "examples": [],
            })

    html_tag = soup.find("html")
    lang_missing = 0 if (html_tag and html_tag.get("lang")) else 1
    add(
        "alta", "Acessibilidade", "Idioma da página não definido", lang_missing,
        "Leitores de tela e tradutores não sabem em qual idioma ler o conteúdo.",
        'Adicione lang="pt-BR" na tag <html>.',
        location="Tag <html>",
    )

    title = soup.find("title")
    title_missing = 0 if (title and title.get_text(strip=True)) else 1
    add(
        "media", "Acessibilidade", "Título da página ausente", title_missing,
        "O título aparece na aba do navegador e nos resultados do Google.",
        "Adicione um <title> descritivo dentro do <head>.",
        location="Seção <head> (<title>)",
    )

    imgs_no_alt = [img for img in soup.find_all("img") if img.get("alt") is None]
    add(
        "alta", "Acessibilidade", "Imagens sem texto alternativo", len(imgs_no_alt),
        "Quem não enxerga a imagem não sabe o que ela mostra, e o Google também não.",
        'Adicione alt="descrição curta" ou alt="" se a imagem for só decorativa.',
        location="Tags <img>",
    )

    empty_links = 0
    for a in soup.find_all("a"):
        text = a.get_text(strip=True)
        has_img_alt = any(img.get("alt") for img in a.find_all("img"))
        if not text and not has_img_alt and not a.get("aria-label"):
            empty_links += 1
    add(
        "media", "Acessibilidade", "Links sem texto descritivo", empty_links,
        "O link fica sem explicação de para onde leva.",
        "Escreva o texto do link ou adicione aria-label.",
        location="Tags <a href>",
    )

    empty_buttons = 0
    for btn in soup.find_all("button"):
        if not btn.get_text(strip=True) and not btn.get("aria-label") and not btn.get("title"):
            empty_buttons += 1
    add(
        "alta", "Acessibilidade", "Botões sem nome", empty_buttons,
        "Ninguém sabe o que o botão faz só de olhar para ele.",
        "Adicione texto visível ou aria-label no botão.",
        location="Tags <button>",
    )

    unlabeled = 0
    for field in soup.find_all("input"):
        if field.get("type") in ("hidden", "submit", "button", "reset", "image"):
            continue
        if not _has_accessible_name(field, soup):
            unlabeled += 1
    for field in soup.find_all(["select", "textarea"]):
        if not _has_accessible_name(field, soup):
            unlabeled += 1
    add(
        "alta", "Acessibilidade", "Campos de formulário sem rótulo", unlabeled,
        "O visitante não sabe o que preencher em cada campo.",
        'Associe um <label for="id"> ao campo ou use aria-label.',
        location="Campos <input>, <select>, <textarea>",
    )

    viewport = soup.find("meta", attrs={"name": "viewport"})
    viewport_content = ""
    if viewport:
        viewport_content = (viewport.get("content") or "").lower().replace(" ", "")
    blocks_zoom = int(
        "user-scalable=no" in viewport_content
        or "maximum-scale=1" in viewport_content
    )
    add(
        "alta", "Acessibilidade", "Zoom bloqueado no celular", blocks_zoom,
        "O visitante não consegue ampliar a página para ler melhor.",
        "Remova user-scalable=no e maximum-scale da meta viewport.",
        location="Meta viewport",
    )

    iframes_no_title = sum(1 for f in soup.find_all("iframe") if not f.get("title"))
    add(
        "media", "Acessibilidade", "Iframes sem título", iframes_no_title,
        "Vídeos e mapas incorporados ficam sem descrição.",
        'Adicione title="descrição" no iframe.',
        location="Tags <iframe>",
    )

    h1_count = len(soup.find_all("h1"))
    add(
        "baixa", "Qualidade", "Página sem título principal (h1)", 1 if h1_count == 0 else 0,
        "O h1 mostra sobre o que é a página, para visitantes e buscadores.",
        "Inclua um único <h1> com o assunto principal.",
        location="Hierarquia de títulos (<h1>)",
    )
    add(
        "baixa", "Qualidade", "Mais de um título principal (h1)", 1 if h1_count > 1 else 0,
        "Vários h1 confundem a estrutura da página.",
        "Mantenha apenas um <h1> por página.",
        location="Hierarquia de títulos (<h1>)",
    )

    levels = [int(h.name[1]) for h in soup.find_all(re.compile(r"^h[1-6]$"))]
    skipped = sum(1 for prev, cur in zip(levels, levels[1:]) if cur - prev > 1)
    add(
        "baixa", "Qualidade", "Títulos pulam níveis (ex.: h2 seguido de h4)", skipped,
        "A hierarquia de títulos fica confusa, para visitantes e para leitores de tela.",
        "Use os níveis em ordem, sem pular de h2 para h4.",
        location="Hierarquia de títulos (h1–h6)",
    )

    for item in issues:
        if not item.get("location"):
            item["location"] = item.get("category") or "Documento HTML"

    score = _compute_score(issues)
    return {"score": score, "issues": issues, "total_issues": len(issues)}


def _has_accessible_name(tag, soup) -> bool:
    if tag.get("aria-label") or tag.get("aria-labelledby") or tag.get("title"):
        return True
    if tag.name == "input" and tag.get("id"):
        if soup.find("label", attrs={"for": tag["id"]}):
            return True
    if tag.find_parent("label"):
        return True
    return False


def _build_result(raw_info: dict, rendered: dict, broken_links: list, checked_links: int) -> dict:
    q = rendered["quality"]
    failed_reqs = rendered.get("failed_requests") or []
    extra = (
        _infrastructure_issues(raw_info)
        + _contrast_issues(rendered["colors"])
        + _js_dependency_issues(raw_info["html"], rendered["html"])
        + _quality_issues(rendered, broken_links)
    )
    result = check_html(rendered["html"], extra)
    result["url"] = raw_info["final_url"]
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
        "total_images": q["totalImages"],
        "broken_images": q["brokenImages"],
        "contrast_elements": len(rendered["colors"]),
        "high_count": sum(1 for i in result["issues"] if i["level"] == "alta"),
        "medium_count": sum(1 for i in result["issues"] if i["level"] == "media"),
        "low_count": sum(1 for i in result["issues"] if i["level"] == "baixa"),
        "infra_count": sum(1 for i in result["issues"] if i["category"] == "Infraestrutura"),
        "a11y_count": sum(1 for i in result["issues"] if i["category"] == "Acessibilidade"),
        "quality_count": sum(1 for i in result["issues"] if i["category"] == "Qualidade"),
    }
    return result


def check_site_steps(raw_url: str):
    """Gera eventos de progresso reais enquanto executa cada etapa da verificação."""
    yield {"type": "progress", "percent": 10, "step": "Validando endereço e segurança da rede..."}
    url = normalize_url(raw_url)

    yield {"type": "progress", "percent": 25, "step": "Consultando resposta inicial, TLS, servidor e cabeçalhos..."}
    raw_info = fetch_raw_page(url)

    yield {"type": "progress", "percent": 55, "step": "Renderizando página no navegador e monitorando rede/assets..."}
    rendered = render_page(raw_info["final_url"])

    yield {"type": "progress", "percent": 80, "step": "Testando links, contraste, SEO técnico e acessibilidade..."}
    broken_links, checked_links = check_links(rendered["quality"]["links"])

    yield {"type": "progress", "percent": 94, "step": "Consolidando pontuação e recomendações..."}
    result = _build_result(raw_info, rendered, broken_links, checked_links)

    yield {"type": "progress", "percent": 100, "step": "Tudo pronto!"}
    yield {"type": "done", "result": result}


def check_site(raw_url: str) -> dict:
    final_result = None
    for event in check_site_steps(raw_url):
        if event["type"] == "done":
            final_result = event["result"]
    if final_result is None:
        raise ValueError("Não foi possível concluir a verificação.")
    return final_result


def check_live_targets(targets=None):
    items = targets if targets is not None else DEFAULT_LIVE_TARGETS
    results = []
    for item in items:
        name = item.get("name") or item.get("url") or "Alvo"
        url = item.get("url") or ""
        start = time.perf_counter()
        ok = False
        status_code = None
        latency_ms = None
        error_msg = None
        try:
            if not url or not _is_safe_url(url):
                raise ValueError("URL inválida ou bloqueada.")
            resp = requests.get(
                url,
                headers={"User-Agent": USER_AGENT},
                timeout=LINK_TIMEOUT,
                allow_redirects=True,
            )
            latency_ms = round((time.perf_counter() - start) * 1000)
            status_code = resp.status_code
            ok = 200 <= resp.status_code < 400
        except Exception as exc:
            latency_ms = round((time.perf_counter() - start) * 1000)
            error_msg = str(exc)[:100]

        checked_at = datetime.now().strftime("%H:%M:%S")
        if ok and (latency_ms is None or latency_ms < 2500):
            status = "online"
            status_label = "ONLINE"
        elif ok:
            status = "degraded"
            status_label = "LENTO"
        else:
            status = "offline"
            status_label = f"OFF ({status_code})" if status_code else "OFFLINE"

        results.append({
            "name": name,
            "url": url,
            "ok": ok,
            "status": status,
            "status_label": status_label,
            "status_code": status_code,
            "latency_ms": latency_ms,
            "checked_at": checked_at,
            "error": error_msg,
        })
    return results