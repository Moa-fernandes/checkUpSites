"""Auditoria de HTML, acessibilidade WCAG/ARIA, DOM renderizado e fallback serverless."""

from __future__ import annotations

import os
import re
from urllib.parse import urljoin, urlparse

from bs4 import BeautifulSoup
from playwright.sync_api import Error as PlaywrightError
from playwright.sync_api import sync_playwright

from .network import USER_AGENT, fetch_raw_page, is_safe_url
from .contrast_pixels import measure_contrast_pixels
from .scorer import compute_score

RENDER_TIMEOUT_MS = 20000
SETTLE_MS = 1000

UNIFIED_DOM_JS = r"""
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

  const colors = [];
  const seenColorKeys = new Set();
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
    const snippet = textNodes.map(n => n.textContent.trim()).join(' ').slice(0, 60);
    const dedupKey = `${snippet.toLowerCase()}|${ratio.toFixed(2)}|${cs.fontSize}`;
    if (seenColorKeys.has(dedupKey)) continue;
    seenColorKeys.add(dedupKey);
    colors.push({
      ratio,
      fontSize: parseFloat(cs.fontSize),
      fontWeight: parseInt(cs.fontWeight, 10) || 400,
      text: snippet,
    });
    if (colors.length >= 1500) break;
  }

  const imgs = Array.from(document.images);
  const brokenImgEls = imgs.filter(i => i.complete && i.naturalWidth === 0 && i.getAttribute('src'));
  const seenIds = {};
  let duplicateIds = 0;
  const dupIdNames = [];
  document.querySelectorAll('[id]').forEach(el => {
    if (!el.id) return;
    if (seenIds[el.id]) {
      duplicateIds++;
      if (dupIdNames.length < 4 && !dupIdNames.includes(`#${el.id}`)) dupIdNames.push(`#${el.id}`);
    }
    seenIds[el.id] = true;
  });

  const text = document.body ? document.body.innerText : '';
  const badPattern = /lorem ipsum|undefined|\bNaN\b|\[object Object\]|\bTODO\b|xxx+/i;
  const match = text.match(badPattern);

  const links = Array.from(document.querySelectorAll('a[href]'))
    .map(a => a.href)
    .filter(h => /^https?:\/\//.test(h));

  const scripts = Array.from(document.querySelectorAll('script'));
  const stylesheets = Array.from(document.querySelectorAll('link[rel="stylesheet"]'));
  const blockingHeadScripts = Array.from(new Set(
    Array.from(document.querySelectorAll('head script[src]')).filter(s => {
      const type = (s.getAttribute('type') || '').toLowerCase();
      return !s.defer && !s.async && !s.noModule && type !== 'module';
    }).map(s => s.getAttribute('src')).filter(Boolean)
  )).slice(0, 5);

  const inlineScriptText = scripts
    .filter(s => !s.getAttribute('src'))
    .map(s => s.textContent || '')
    .join('\n');

  const robotsMeta = document.querySelector('meta[name="robots"]');
  const robotsContent = robotsMeta ? (robotsMeta.getAttribute('content') || '').toLowerCase() : '';

  return {
    colors,
    quality: {
      totalImages: imgs.length,
      brokenImages: brokenImgEls.length,
      brokenImageExamples: Array.from(new Set(brokenImgEls.map(i => i.getAttribute('src') || 'imagem sem src'))).slice(0, 4),
      duplicateIds,
      duplicateIdExamples: dupIdNames,
      placeholderText: match ? match[0] : null,
      hasDescription: !!document.querySelector('meta[name="description"]'),
      links: Array.from(new Set(links)),
      scriptCount: scripts.length,
      stylesheetCount: stylesheets.length,
      blockingHeadScripts,
      hasDebugArtifacts: /\b(console\.log|debugger)\b/.test(inlineScriptText),
      hasCanonical: !!document.querySelector('link[rel="canonical"]'),
      hasNoIndex: /\bnoindex\b/.test(robotsContent),
      hasOgTags: !!(document.querySelector('meta[property="og:title"]') && document.querySelector('meta[property="og:description"]')),
      hasMain: !!document.querySelector('main, [role="main"]'),
      hasNav: !!document.querySelector('nav, [role="navigation"]'),
    },
  };
}
"""


def _route_guard(route):
    url = route.request.url
    if urlparse(url).scheme not in ("http", "https") or is_safe_url(url):
        route.continue_()
    else:
        route.abort()


def fallback_render_from_html(html_text: str, base_url: str = "") -> dict:
    """Fallback inteligente em HTML puro (usado na Vercel serverless) extraindo SEO, scripts, IDs e links absolutos."""
    html_str = html_text or ""
    soup = BeautifulSoup(html_str, "html.parser")

    title = soup.title.string.strip() if (soup.title and soup.title.string) else ""
    body_text = soup.get_text(" ", strip=True) if soup.body else soup.get_text(" ", strip=True)
    text_len = len(body_text)
    h1_count = len(soup.find_all("h1"))
    forms = soup.find_all("form")

    raw_links: list[str] = []
    abs_links: list[str] = []
    for a in soup.find_all("a", href=True):
        href = (a.get("href") or "").strip()
        if not href or href.startswith(("#", "mailto:", "tel:", "javascript:")):
            continue
        raw_links.append(href)
        resolved = urljoin(base_url, href) if base_url else href
        if resolved.startswith(("http://", "https://")):
            abs_links.append(resolved)

    images: list[dict] = []
    broken_img_examples: list[str] = []
    for img in soup.find_all("img"):
        src = (img.get("src") or "").strip()
        images.append({"src": src, "alt": (img.get("alt") or "").strip()})
        if not src:
            broken_img_examples.append("<img> sem atributo src")

    seen_ids: set[str] = set()
    dup_ids: list[str] = []
    for el in soup.find_all(attrs={"id": True}):
        el_id = (el.get("id") or "").strip()
        if not el_id:
            continue
        if el_id in seen_ids:
            dup_ids.append(f"#{el_id}")
        seen_ids.add(el_id)

    bad_match = re.search(r"lorem ipsum|undefined|\bNaN\b|\[object Object\]|\bTODO\b|xxx+", body_text, re.I)

    scripts = soup.find_all("script")
    stylesheets = soup.find_all("link", rel=lambda v: v and "stylesheet" in [x.lower() for x in (v if isinstance(v, list) else [v])])
    head = soup.head
    blocking_scripts: list[str] = []
    if head:
        for s in head.find_all("script", src=True):
            stype = (s.get("type") or "").lower()
            if not s.has_attr("defer") and not s.has_attr("async") and not s.has_attr("nomodule") and stype != "module":
                blocking_scripts.append(s["src"])

    inline_js = "\n".join(s.string or "" for s in scripts if not s.get("src"))
    has_debug = bool(re.search(r"\b(console\.log|debugger)\b", inline_js))

    robots_meta = soup.find("meta", attrs={"name": re.compile(r"^robots$", re.I)})
    robots_content = (robots_meta.get("content") or "").lower() if robots_meta else ""

    return {
        "rendered": False,
        "fallback_html": True,
        "title": title,
        "text_length": text_len,
        "h1_count": h1_count,
        "forms_count": len(forms),
        "links": raw_links,
        "images": images,
        "rendered_kb": round(len(html_str.encode("utf-8")) / 1024, 1),
        "colors": [],
        "quality": {
            "totalImages": len(images),
            "brokenImages": len(broken_img_examples),
            "brokenImageExamples": list(dict.fromkeys(broken_img_examples))[:4],
            "duplicateIds": len(dup_ids),
            "duplicateIdExamples": list(dict.fromkeys(dup_ids))[:4],
            "placeholderText": bad_match.group(0) if bad_match else None,
            "hasDescription": bool(soup.find("meta", attrs={"name": re.compile(r"^description$", re.I)})),
            "links": list(dict.fromkeys(abs_links)),
            "scriptCount": len(scripts) if scripts else len(re.findall(r"<script\b", html_str, re.I)),
            "stylesheetCount": len(stylesheets) if stylesheets else len(re.findall(r"rel=[\"\']?stylesheet", html_str, re.I)),
            "blockingHeadScripts": list(dict.fromkeys(blocking_scripts))[:5],
            "hasDebugArtifacts": has_debug,
            "hasCanonical": bool(soup.find("link", rel=lambda v: v and "canonical" in [x.lower() for x in (v if isinstance(v, list) else [v])])),
            "hasNoIndex": bool(re.search(r"\bnoindex\b", robots_content)),
            "hasOgTags": bool(
                soup.find("meta", attrs={"property": "og:title"})
                and soup.find("meta", attrs={"property": "og:description"})
            ),
            "hasMain": bool(soup.find("main") or soup.find(attrs={"role": "main"})),
            "hasNav": bool(soup.find("nav") or soup.find(attrs={"role": "navigation"})),
        },
        "failed_requests": [],
        "console_errors": [],
        "page_errors": [],
        "js_errors": [],
        "mobile_overflow": False,
        "html": html_str,
    }


def render_page(url: str, raw_html: str = "") -> dict:
    """Usa análise HTML otimizada na Vercel e Chromium (single-pass + resize) localmente."""
    if os.environ.get("VERCEL") or os.environ.get("SKIP_PLAYWRIGHT"):
        html_source = raw_html or fetch_raw_page(url).get("html", "")
        return fallback_render_from_html(html_source, base_url=url)

    failed_requests: list[str] = []
    console_errors: list[str] = []
    js_errors: list[str] = []

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

                page.on("console", lambda m: console_errors.append(m.text) if m.type == "error" else None)
                page.on("pageerror", lambda e: js_errors.append(str(e)))
                page.on(
                    "response",
                    lambda r: failed_requests.append(f"{r.status} {r.url[:110]}") if r.status >= 400 else None,
                )
                page.on(
                    "requestfailed",
                    lambda req: failed_requests.append(f"FALHA {req.url[:110]}")
                    if req.failure and "ERR_ABORTED" not in (req.failure or "") else None,
                )

                page.goto(url, wait_until="domcontentloaded", timeout=RENDER_TIMEOUT_MS)
                try:
                    page.wait_for_load_state("networkidle", timeout=6000)
                except PlaywrightError:
                    pass
                page.wait_for_timeout(SETTLE_MS)
                rendered_html = page.content()
                dom_data = page.evaluate(UNIFIED_DOM_JS)
                colors = measure_contrast_pixels(page)

                page.set_viewport_size({"width": 375, "height": 812})
                page.wait_for_timeout(350)
                mobile_overflow = bool(
                    page.evaluate("() => document.documentElement.scrollWidth > window.innerWidth + 2")
                )
            finally:
                browser.close()
    except (PlaywrightError, Exception):
        html_source = raw_html or fetch_raw_page(url).get("html", "")
        return fallback_render_from_html(html_source, base_url=url)

    return {
        "rendered": True,
        "fallback_html": False,
        "html": rendered_html,
        "rendered_kb": round(len(rendered_html.encode("utf-8")) / 1024, 1),
        "colors": colors,
        "quality": dom_data.get("quality") or {},
        "console_errors": list(dict.fromkeys(console_errors)),
        "js_errors": list(dict.fromkeys(js_errors)),
        "failed_requests": list(dict.fromkeys(failed_requests)),
        "mobile_overflow": mobile_overflow,
    }


def _is_large_text(size: float, weight: int) -> bool:
    return size >= 24 or (size >= 18.66 and weight >= 700)


def contrast_issues(color_items: list[dict]) -> list[dict]:
    """Só entra como problema o texto medido por pixels com contraste abaixo do mínimo WCAG."""
    failing = [item for item in (color_items or []) if item.get("status") == "FALHA"]
    if not failing:
        return []
    severe = any(item["ratio"] < 3.0 for item in failing)
    details = [
        {
            "text": item["text"],
            "ratio": item["ratio"],
            "needed": item["needed"],
            "color": item["color"],
            "font_size": item["fontSize"],
            "font_weight": item["fontWeight"],
        }
        for item in failing
    ]
    examples: list[str] = []
    seen: set = set()
    for item in failing:
        sig = (item["text"].strip().lower(), item["ratio"])
        if sig in seen:
            continue
        seen.add(sig)
        examples.append(f'"{item["text"]}": contraste {item["ratio"]:.2f}:1 (mínimo {item["needed"]})')
    return [{
        "id": "wcag-contrast",
        "level": "alta" if severe else "media",
        "category": "Acessibilidade",
        "title": "Contraste de cores insuficiente",
        "count": len(failing),
        "location": "Texto medido pelos pixels visíveis (WCAG AA)",
        "explanation": "Texto com contraste abaixo do mínimo WCAG é difícil de ler. Abaixo de 3:1 o problema é grave.",
        "fix": "Escureça o texto ou clareie o fundo até atingir 4,5:1 (texto normal) ou 3:1 (texto grande).",
        "examples": examples[:40],
        "details": details,
    }]


def _visible_word_count(html: str) -> int:
    soup = BeautifulSoup(html or "", "html.parser")
    for tag in soup(["script", "style", "noscript", "template"]):
        tag.decompose()
    return len(soup.get_text(" ", strip=True).split())


def js_dependency_issues(raw_html: str, rendered_html: str, is_rendered: bool = True) -> list[dict]:
    if not is_rendered:
        return []
    raw_words = _visible_word_count(raw_html)
    rendered_words = _visible_word_count(rendered_html)
    missing = rendered_words - raw_words
    if rendered_words and missing > 50 and (missing / rendered_words) > 0.3:
        return [{
            "id": "js-only-content",
            "level": "media",
            "category": "Qualidade",
            "title": "Parte do conteúdo só aparece com JavaScript",
            "count": 1,
            "location": "HTML inicial vs. DOM renderizado",
            "explanation": f"Cerca de {missing} palavras dependem de execução de JavaScript para aparecer.",
            "fix": "Entregue o conteúdo principal no HTML inicial (SSR/SSG) para SEO e leitores de tela.",
            "examples": [f"Palavras no HTML bruto: {raw_words} · Renderizadas: {rendered_words}"],
        }]
    return []


def quality_issues(rendered: dict, broken_links: list[str]) -> list[dict]:
    q = rendered.get("quality") or {}
    unique_broken_links = list(dict.fromkeys(broken_links or []))
    broken_img_examples = list(dict.fromkeys(q.get("brokenImageExamples") or []))

    # Evita que URLs já apontadas em links/imagens quebrados apareçam dobradas em failed-requests
    already_reported_urls = set()
    for entry in unique_broken_links:
        if " · " in entry:
            already_reported_urls.add(entry.split(" · ", 1)[1].strip())
    for img_src in broken_img_examples:
        already_reported_urls.add(img_src.strip())

    raw_failed_reqs = list(dict.fromkeys(rendered.get("failed_requests") or []))
    failed_reqs = [
        req for req in raw_failed_reqs
        if not any(rep and rep in req for rep in already_reported_urls)
    ]

    blocking_scripts = list(dict.fromkeys(q.get("blockingHeadScripts") or []))
    issues: list[dict] = []

    def add(issue_id, level, category, title, count, explanation, fix, location, examples=None):
        if count > 0:
            issues.append({
                "id": issue_id,
                "level": level,
                "category": category,
                "title": title,
                "count": count,
                "location": location,
                "explanation": explanation,
                "fix": fix,
                "examples": list(dict.fromkeys(examples or []))[:5],
            })

    add("broken-images", "alta", "Qualidade", "Imagens quebradas", q.get("brokenImages", 0),
        "A imagem não carrega para o visitante e deixa espaço vazio ou ícone quebrado.",
        "Confira o caminho/URL da imagem e garanta que o arquivo exista.",
        "Tags <img>", broken_img_examples)

    add("broken-links", "media", "Qualidade", "Links quebrados", len(unique_broken_links),
        "Links que retornam erro degradam a navegação e a confiabilidade do site.",
        "Atualize ou remova os links com falha.",
        "Tags <a href>", unique_broken_links)

    add("failed-requests", "media", "Qualidade", "Requisições de rede falharam no carregamento", len(failed_reqs),
        "Recursos externos ou chamadas da página retornaram erro HTTP (4xx/5xx) ou falha de rede.",
        "Corrija URLs, permissões CORS ou endpoints instáveis.",
        "Requisições HTTP no navegador", failed_reqs)

    add("blocking-scripts", "baixa", "Qualidade", "Scripts bloqueantes no <head>", len(blocking_scripts),
        "Scripts externos no <head> sem defer, async ou type='module' atrasam a renderização inicial.",
        "Adicione defer ou async nos scripts não críticos.",
        "Seção <head> (<script src>)", blocking_scripts)

    placeholder = q.get("placeholderText")
    add("placeholder-text", "alta", "Qualidade", "Texto de teste ou erro visível na página", 1 if placeholder else 0,
        "Textos como 'lorem ipsum', 'undefined' ou 'NaN' indicam conteúdo incompleto ou falha de renderização.",
        "Substitua o texto de teste ou trate valores nulos antes de exibir.",
        "Texto visível em <body>", [f"Encontrado: '{placeholder}'"] if placeholder else [])

    add("debug-artifacts", "baixa", "Qualidade", "Indícios de debug em scripts inline", 1 if q.get("hasDebugArtifacts") else 0,
        "Chamadas como console.log ou debugger ficaram expostas em produção.",
        "Remova logs de depuração no build de produção.",
        "Scripts inline (<script>)")

    add("mobile-overflow", "alta", "Qualidade", "Layout quebra no celular (rolagem lateral)", 1 if rendered.get("mobile_overflow") else 0,
        "Em telas pequenas, parte do conteúdo ultrapassa a largura da tela.",
        "Substitua larguras fixas por layouts responsivos.",
        "Viewport mobile (375×812)")

    unique_js_errors = list(dict.fromkeys((rendered.get("js_errors") or []) + (rendered.get("console_errors") or [])))
    add("js-console-errors", "media", "Qualidade", "Erros de JavaScript no console", len(unique_js_errors),
        "Erros de execução podem quebrar menus, formulários e interações.",
        "Corrija as exceções apontadas no console do navegador.",
        "Console / runtime JavaScript", [e[:160] for e in unique_js_errors])

    add("duplicate-ids", "baixa", "Qualidade", "IDs duplicados no HTML", q.get("duplicateIds", 0),
        "IDs repetidos quebram âncoras, labels de formulário e seletores JavaScript.",
        "Garanta que cada atributo id seja único na página.",
        "Atributos id no DOM", q.get("duplicateIdExamples"))

    add("missing-description", "baixa", "Qualidade", "Descrição da página ausente (meta description)", 0 if q.get("hasDescription") else 1,
        "Sem meta description, os buscadores exibem trechos automáticos nem sempre ideais.",
        'Adicione <meta name="description" content="..."> com 120 a 160 caracteres.',
        "Seção <head> (meta description)")

    add("missing-canonical", "baixa", "Qualidade", "URL canônica ausente (link rel='canonical')", 0 if q.get("hasCanonical", True) else 1,
        "Sem canonical, parâmetros na URL podem gerar duplicidade de indexação.",
        'Adicione <link rel="canonical" href="..."> apontando para a URL principal.',
        "Seção <head> (link canonical)")

    add("noindex-meta", "media", "Qualidade", "Página marcada com noindex", 1 if q.get("hasNoIndex") else 0,
        "A diretiva noindex impede que buscadores indexem esta página.",
        "Remova noindex caso a página deva aparecer nos resultados de busca.",
        "Seção <head> (meta robots)")

    return issues


def audit_a11y_keyboard_and_landmarks(html: str) -> dict:
    """Audita tabindex positivo, controles ocultos com aria-hidden e marcos semânticos HTML5."""
    soup = BeautifulSoup(html or "", "html.parser")
    issues: list[dict] = []

    positive_tabindex = []
    for el in soup.find_all(attrs={"tabindex": True}):
        raw_ti = (el.get("tabindex") or "").strip()
        try:
            if int(raw_ti) > 0:
                positive_tabindex.append(f"<{el.name} tabindex='{raw_ti}'>")
        except ValueError:
            pass

    if positive_tabindex:
        issues.append({
            "id": "a11y-positive-tabindex",
            "level": "media",
            "category": "Acessibilidade",
            "title": "Uso de tabindex positivo altera a ordem natural do teclado",
            "count": len(positive_tabindex),
            "location": "Atributos tabindex no DOM",
            "explanation": "Valores de tabindex maiores que 0 criam saltos imprevisíveis na navegação por teclado.",
            "fix": "Use tabindex='0' ou siga a ordem natural dos elementos no HTML.",
            "examples": list(dict.fromkeys(positive_tabindex))[:5],
        })

    hidden_focusables = []
    for hidden_el in soup.find_all(attrs={"aria-hidden": lambda v: v and v.strip().lower() == "true"}):
        for child in hidden_el.find_all(["a", "button", "input", "select", "textarea"]):
            if child.get("tabindex") != "-1":
                hidden_focusables.append(f"<{child.name}> dentro de aria-hidden='true'")

    if hidden_focusables:
        issues.append({
            "id": "a11y-hidden-focusable",
            "level": "alta",
            "category": "Acessibilidade",
            "title": "Elementos focáveis ocultos com aria-hidden='true'",
            "count": len(hidden_focusables),
            "location": "Árvore de acessibilidade / ARIA",
            "explanation": "Usuários de teclado podem focar elementos ocultos para leitores de tela.",
            "fix": "Aplique tabindex='-1' nos controles internos ou remova aria-hidden='true'.",
            "examples": list(dict.fromkeys(hidden_focusables))[:5],
        })

    has_main = bool(soup.find("main") or soup.find(attrs={"role": "main"}))
    has_header = bool(soup.find("header") or soup.find(attrs={"role": "banner"}))
    has_footer = bool(soup.find("footer") or soup.find(attrs={"role": "contentinfo"}))
    missing_landmarks = [
        name for ok, name in [(has_main, "<main>"), (has_header, "<header>"), (has_footer, "<footer>")] if not ok
    ]
    if missing_landmarks:
        issues.append({
            "id": "a11y-missing-landmarks",
            "level": "baixa",
            "category": "Acessibilidade",
            "title": "Marcos semânticos (landmarks) ausentes na página",
            "count": len(missing_landmarks),
            "location": "Estrutura semântica HTML5",
            "explanation": "Landmarks permitem que leitores de tela saltem diretamente entre cabeçalho, conteúdo e rodapé.",
            "fix": "Estruture a página com <header>, <main> e <footer>.",
            "examples": missing_landmarks,
        })

    return {
        "has_main": has_main,
        "has_header": has_header,
        "has_footer": has_footer,
        "issues": issues,
    }


def audit_html_deep_metrics(html: str, final_url: str) -> dict:
    """Audita formulários inseguros, conteúdo misto HTTP/HTTPS e hierarquia de títulos."""
    soup = BeautifulSoup(html or "", "html.parser")
    is_https_page = urlparse(final_url).scheme == "https"

    forms = soup.find_all("form")
    insecure_forms = sum(
        1 for f in forms if is_https_page and (f.get("action") or "").strip().lower().startswith("http://")
    )

    mixed_assets: list[str] = []
    if is_https_page:
        for tag_name, attr_name in [("script", "src"), ("img", "src"), ("link", "href"), ("iframe", "src")]:
            for el in soup.find_all(tag_name):
                val = (el.get(attr_name) or "").strip()
                if val.lower().startswith("http://"):
                    mixed_assets.append(f"{tag_name}[{attr_name}]: {val[:110]}")

    imgs = soup.find_all("img")
    imgs_empty_src = sum(1 for i in imgs if not (i.get("src") or "").strip())
    h1_tags = [h.get_text(" ", strip=True) for h in soup.find_all("h1") if h.get_text(" ", strip=True)]

    return {
        "forms_count": len(forms),
        "insecure_forms": insecure_forms,
        "mixed_assets": list(dict.fromkeys(mixed_assets))[:8],
        "imgs_empty_src": imgs_empty_src,
        "h1_texts": h1_tags[:4],
        "h2_count": len(soup.find_all("h2")),
        "h3_count": len(soup.find_all("h3")),
    }


def _is_hidden_control(tag) -> bool:
    """Honeypots, campos ocultos e campos fora da árvore de acessibilidade não são avaliados."""
    if (tag.get("aria-hidden") or "").strip().lower() == "true":
        return True
    if (tag.get("tabindex") or "").strip() == "-1":
        return True
    if "hidden" in (tag.get("class") or []):
        return True
    return bool(tag.find_parent(attrs={"hidden": True}) or tag.find_parent(attrs={"aria-hidden": "true"}))


def _has_accessible_name(tag, soup) -> bool:
    if tag.get("aria-label") or tag.get("aria-labelledby") or tag.get("title"):
        return True
    if tag.name == "input" and tag.get("id"):
        if soup.find("label", attrs={"for": tag["id"]}):
            return True
    return bool(tag.find_parent("label"))


_LEVEL_RANK = {"alta": 3, "media": 2, "baixa": 1}


def _merge_and_dedupe_issues(issues: list[dict]) -> list[dict]:
    """Deduplica apontamentos por ID e também por título normalizado na mesma categoria."""
    merged: list[dict] = []
    by_id: dict[str, dict] = {}
    by_norm_title: dict[tuple[str, str], dict] = {}

    for raw_item in issues:
        if not isinstance(raw_item, dict):
            continue
        item = dict(raw_item)
        item["examples"] = list(dict.fromkeys(item.get("examples") or []))[:5]
        if not item.get("location"):
            item["location"] = item.get("category") or "Documento HTML"

        iid = (item.get("id") or "").strip()
        cat = (item.get("category") or "Qualidade").strip()
        norm_title = re.sub(r"\s+", " ", (item.get("title") or "").strip().lower())
        title_key = (cat, norm_title)

        existing = by_id.get(iid) if iid else None
        if existing is None and norm_title:
            existing = by_norm_title.get(title_key)

        if existing is not None:
            # Mescla exemplos únicos sem dobrar o card
            combined_examples = list(dict.fromkeys((existing.get("examples") or []) + item["examples"]))
            existing["examples"] = combined_examples[:5]
            if combined_examples:
                existing["count"] = max(int(existing.get("count") or 1), int(item.get("count") or 1), len(combined_examples))
            else:
                existing["count"] = max(int(existing.get("count") or 1), int(item.get("count") or 1))
            if _LEVEL_RANK.get(item.get("level", "baixa"), 1) > _LEVEL_RANK.get(existing.get("level", "baixa"), 1):
                existing["level"] = item["level"]
            continue

        merged.append(item)
        if iid:
            by_id[iid] = item
        if norm_title:
            by_norm_title[title_key] = item

    return merged


def check_html(html: str, extra_issues=None) -> dict:
    soup = BeautifulSoup(html or "", "html.parser")
    issues = list(extra_issues or [])

    def add(issue_id, level, category, title, count, explanation, fix, location="Documento HTML"):
        if count > 0:
            issues.append({
                "id": issue_id,
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
    add("html-lang", "alta", "Acessibilidade", "Idioma da página não definido",
        0 if (html_tag and html_tag.get("lang")) else 1,
        "Leitores de tela e tradutores precisam do atributo lang para pronunciar e traduzir corretamente.",
        'Adicione lang="pt-BR" na tag <html>.', "Tag <html>")

    title = soup.find("title")
    add("html-title", "media", "Acessibilidade", "Título da página ausente",
        0 if (title and title.get_text(strip=True)) else 1,
        "O título identifica a página na aba do navegador e nos resultados de busca.",
        "Adicione um <title> descritivo dentro do <head>.", "Seção <head> (<title>)")

    imgs_no_alt = [img for img in soup.find_all("img") if img.get("alt") is None]
    add("img-alt", "alta", "Acessibilidade", "Imagens sem texto alternativo", len(imgs_no_alt),
        "Imagens sem alt ficam invisíveis para leitores de tela e mecanismos de busca.",
        'Adicione alt="descrição" ou alt="" se for decorativa.', "Tags <img>")

    empty_links = 0
    for a in soup.find_all("a"):
        text = a.get_text(strip=True)
        has_img_alt = any(img.get("alt") for img in a.find_all("img"))
        if not text and not has_img_alt and not a.get("aria-label"):
            empty_links += 1
    add("empty-links", "media", "Acessibilidade", "Links sem texto descritivo", empty_links,
        "Links vazios deixam o usuário sem saber para onde será levado.",
        "Adicione texto visível ou aria-label no link.", "Tags <a href>")

    empty_buttons = sum(
        1 for btn in soup.find_all("button")
        if not btn.get_text(strip=True) and not btn.get("aria-label") and not btn.get("title")
    )
    add("empty-buttons", "alta", "Acessibilidade", "Botões sem nome", empty_buttons,
        "Botões sem texto ou aria-label são anunciados sem função pelos leitores de tela.",
        "Adicione texto visível ou aria-label no botão.", "Tags <button>")

    unlabeled = 0
    for field in soup.find_all("input"):
        if field.get("type") in ("hidden", "submit", "button", "reset", "image"):
            continue
        if _is_hidden_control(field) or _has_accessible_name(field, soup):
            continue
        unlabeled += 1
    for field in soup.find_all(["select", "textarea"]):
        if _is_hidden_control(field) or _has_accessible_name(field, soup):
            continue
        unlabeled += 1
    add("unlabeled-inputs", "alta", "Acessibilidade", "Campos de formulário sem rótulo", unlabeled,
        "Campos sem label dificultam o preenchimento por leitores de tela e usuários em geral.",
        'Associe um <label for="id"> ao campo ou use aria-label.', "Campos de formulário")

    viewport = soup.find("meta", attrs={"name": "viewport"})
    vp_content = (viewport.get("content") or "").lower().replace(" ", "") if viewport else ""
    blocks_zoom = int("user-scalable=no" in vp_content or "maximum-scale=1" in vp_content)
    add("viewport-zoom", "alta", "Acessibilidade", "Zoom bloqueado no celular", blocks_zoom,
        "Bloquear o zoom impede pessoas com baixa visão de ampliar o conteúdo.",
        "Remova user-scalable=no e maximum-scale=1 da meta viewport.", "Meta viewport")

    iframes_no_title = sum(1 for f in soup.find_all("iframe") if not f.get("title"))
    add("iframe-title", "media", "Acessibilidade", "Iframes sem título", iframes_no_title,
        "Conteúdos incorporados sem title ficam sem contexto para leitores de tela.",
        'Adicione title="descrição" no iframe.', "Tags <iframe>")

    h1_count = len(soup.find_all("h1"))
    add("missing-h1", "baixa", "Qualidade", "Página sem título principal (h1)", 1 if h1_count == 0 else 0,
        "O <h1> define o tema principal da página para visitantes e buscadores.",
        "Inclua um único <h1> principal.", "Hierarquia de títulos (<h1>)")
    add("multiple-h1", "baixa", "Qualidade", "Mais de um título principal (h1)", 1 if h1_count > 1 else 0,
        "Múltiplos <h1> diluem a hierarquia semântica principal.",
        "Mantenha apenas um <h1> por página.", "Hierarquia de títulos (<h1>)")

    levels = [int(h.name[1]) for h in soup.find_all(re.compile(r"^h[1-6]$"))]
    skipped = sum(1 for prev, cur in zip(levels, levels[1:]) if cur - prev > 1)
    add("skipped-headings", "baixa", "Qualidade", "Títulos pulam níveis (ex.: h2 seguido de h4)", skipped,
        "Saltos na hierarquia de títulos prejudicam a navegação estruturada.",
        "Use os níveis de título em sequência (h1 -> h2 -> h3).", "Hierarquia de títulos (h1–h6)")

    deduped = _merge_and_dedupe_issues(issues)

    scoring = compute_score(deduped)
    return {
        "score": scoring["score"],
        "score_breakdown": scoring["breakdown"],
        "issues": deduped,
        "total_issues": len(deduped),
    }
