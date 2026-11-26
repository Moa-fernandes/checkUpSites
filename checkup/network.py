"""Camada de rede, segurança SSRF, SSL/TLS, links e monitoramento de alvos."""

from __future__ import annotations

import ipaddress
import os
import socket
import ssl
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from urllib.parse import urlparse

import requests

USER_AGENT = "checkUp/2.0"
REQUEST_TIMEOUT = 12
SSL_TIMEOUT = 5
LINK_TIMEOUT = 5
MAX_LINKS = 40
DNS_CACHE_TTL_S = 120.0

DEFAULT_LIVE_TARGETS = [
    {"name": "Trens RJ", "url": "https://trensrj.com.br/pt"},
    {"name": "Clima – Climatempo Rio de Janeiro", "url": "https://www.climatempo.com.br/previsao-do-tempo/cidade/321/riodejaneiro-rj"},
    {"name": "Aeroportos RJ (Santos Dumont / Galeão)", "url": "https://www.aeroportosantosdumont.net/"},
]

_DNS_CACHE: dict[str, tuple[float, bool, list[str]]] = {}


def is_safe_url(url: str) -> bool:
    """Valida esquema e bloqueia redes privadas/locais (anti-SSRF) com cache de resolução."""
    parsed = urlparse(url or "")
    host = (parsed.hostname or "").strip().lower()
    if parsed.scheme not in ("http", "https") or not host:
        return False

    now = time.monotonic()
    cached = _DNS_CACHE.get(host)
    if cached and (now - cached[0]) < DNS_CACHE_TTL_S:
        return cached[1]

    ips: list[str] = []
    safe = False
    try:
        infos = socket.getaddrinfo(host, None)
        for info in infos:
            addr = info[4][0]
            if addr not in ips:
                ips.append(addr)
        if ips:
            safe = all(
                not (
                    ipaddress.ip_address(addr).is_private
                    or ipaddress.ip_address(addr).is_loopback
                    or ipaddress.ip_address(addr).is_link_local
                    or ipaddress.ip_address(addr).is_reserved
                )
                for addr in ips
            )
    except (socket.gaierror, ValueError):
        safe = False

    _DNS_CACHE[host] = (now, safe, ips)
    return safe


def get_resolved_ips(host: str) -> list[str]:
    """Retorna os IPs resolvidos do cache ou consulta via getaddrinfo."""
    clean_host = (host or "").strip().lower()
    if not clean_host:
        return []
    now = time.monotonic()
    cached = _DNS_CACHE.get(clean_host)
    if cached and (now - cached[0]) < DNS_CACHE_TTL_S:
        return list(cached[2])

    is_safe_url(f"https://{clean_host}")
    cached = _DNS_CACHE.get(clean_host)
    return list(cached[2]) if cached else []


def normalize_url(raw: str) -> str:
    value = (raw or "").strip()
    if not value:
        raise ValueError("Digite o endereço do site.")
    if not value.startswith(("http://", "https://")):
        value = "https://" + value
    if not is_safe_url(value):
        raise ValueError("Este endereço não pode ser verificado.")
    return value


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
            if key in ("organizationName", "commonName"):
                return str(val)
    return None


def inspect_ssl_certificate(url: str) -> dict:
    """Consulta o certificado TLS/SSL da porta 443 e retorna validade, expiração, emissor e protocolo."""
    host = urlparse(url).hostname
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


def detect_server_and_cdn(headers: dict) -> tuple[str, str]:
    server = headers.get("server") or "Não informado"
    via = (headers.get("via") or "").lower()
    cdn = "Direto / Não identificado"

    if "cf-ray" in headers or "cloudflare" in server.lower():
        cdn = "Cloudflare"
    elif "x-amz-cf-id" in headers or "cloudfront" in via:
        cdn = "AWS CloudFront"
    elif "x-vercel-id" in headers:
        cdn = "Vercel"
    elif "x-render-origin-server" in headers:
        cdn = "Render"
    elif "fastly" in via or "x-fastly-request-id" in headers:
        cdn = "Fastly"
    elif "via" in headers:
        cdn = f"Proxy/CDN ({headers['via'][:45]})"

    return server[:60], cdn[:45]


def extract_set_cookies(resp: requests.Response) -> list[str]:
    raw = getattr(resp.raw, "headers", None)
    if raw and hasattr(raw, "getlist"):
        return list(raw.getlist("Set-Cookie"))
    cookie_header = resp.headers.get("Set-Cookie")
    return [cookie_header] if cookie_header else []


def fetch_raw_page(url: str) -> dict:
    """Busca o HTML bruto e coleta métricas de rede, SSL, servidor, CDN e cabeçalhos."""
    start = time.perf_counter()
    resp = requests.get(
        url,
        headers={
            "User-Agent": USER_AGENT,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
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

    server_hdr, cdn_name = detect_server_and_cdn(headers_lower)
    encoding = (headers_lower.get("content-encoding") or "").lower()
    compressed = any(tok in encoding for tok in ("gzip", "br", "zstd", "deflate"))
    raw_bytes = len(resp.content or b"")

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
        "set_cookies": extract_set_cookies(resp),
    }


def safe_probe_url(target_url: str, timeout_s: float = 3.5) -> requests.Response | None:
    if not target_url or not is_safe_url(target_url):
        return None
    try:
        return requests.get(
            target_url,
            headers={"User-Agent": USER_AGENT},
            timeout=timeout_s,
            allow_redirects=True,
        )
    except Exception:
        return None


def _check_one_link(href: str) -> str | None:
    if not is_safe_url(href):
        return None
    try:
        resp = requests.head(
            href,
            headers={"User-Agent": USER_AGENT},
            timeout=LINK_TIMEOUT,
            allow_redirects=True,
        )
        if resp.status_code in (403, 405, 429) or resp.status_code >= 500:
            resp = requests.get(
                href,
                headers={"User-Agent": USER_AGENT, "Range": "bytes=0-2048"},
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


def check_links(urls: list[str]) -> tuple[list[str], int]:
    unique_urls = list(dict.fromkeys(urls or []))[:MAX_LINKS]
    if not unique_urls:
        return [], 0
    workers = 4 if os.environ.get("VERCEL") else 8
    with ThreadPoolExecutor(max_workers=workers) as pool:
        results = list(pool.map(_check_one_link, unique_urls))
    broken = [r for r in results if r]
    return broken, len(unique_urls)


def check_live_targets(targets=None) -> list[dict]:
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
            if not url or not is_safe_url(url):
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
            status, status_label = "online", "ONLINE"
        elif ok:
            status, status_label = "degraded", "LENTO"
        else:
            status, status_label = "offline", (f"OFF ({status_code})" if status_code else "OFFLINE")

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
