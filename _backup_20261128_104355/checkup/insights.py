"""Verificações complementares: SEO técnico, peso da página, terceiros, redirecionamentos e cache."""

from __future__ import annotations

import re
from urllib.parse import urlparse

from bs4 import BeautifulSoup

MAX_HTML_KB = 1024
MAX_THIRD_PARTY_HOSTS = 10
MAX_REDIRECTS = 2


def _issue(issue_id, level, category, title, count, location, explanation, fix, examples=None):
    return {
        "id": issue_id,
        "level": level,
        "category": category,
        "title": title,
        "count": max(1, int(count)),
        "location": location,
        "explanation": explanation,
        "fix": fix,
        "examples": [str(e)[:140] for e in (examples or [])][:5],
    }


def _third_party_hosts(soup: BeautifulSoup, own_host: str) -> list[str]:
    hosts: set[str] = set()
    for tag in soup.find_all(["script", "link", "img", "iframe"]):
        attr = "href" if tag.name == "link" else "src"
        value = (tag.get(attr) or "").strip()
        if not value:
            continue
        host = (urlparse(value).hostname or "").lower()
        if host and host != own_host and not host.endswith("." + own_host):
            hosts.add(host)
    return sorted(hosts)


def _has_icon(soup: BeautifulSoup) -> bool:
    for link in soup.find_all("link", rel=True):
        rels = link.get("rel") or []
        if isinstance(rels, str):
            rels = rels.split()
        if any("icon" in r.lower() for r in rels):
            return True
    return False


def audit_insights(raw_info: dict, final_html: str) -> list[dict]:
    """Retorna apontamentos complementares no mesmo formato usado pelo scorer."""
    soup = BeautifulSoup(final_html or "", "html.parser")
    issues: list[dict] = []
    headers = raw_info.get("headers") or {}
    final_url = raw_info.get("final_url") or ""
    own_host = (urlparse(final_url).hostname or "").lower()
    raw_kb = float(raw_info.get("raw_kb") or 0)
    redirects = int(raw_info.get("redirects") or 0)

    title_text = soup.title.get_text(strip=True) if soup.title else ""
    if title_text and not 10 <= len(title_text) <= 70:
        issues.append(_issue(
            "title-length", "baixa", "Qualidade",
            "Título com tamanho fora do ideal (10 a 70 caracteres)", 1,
            "Seção <head> (<title>)",
            f"O título tem {len(title_text)} caracteres. Títulos curtos demais descrevem pouco a página e os longos são cortados nos resultados de busca.",
            "Reescreva o <title> de forma descritiva, entre 10 e 70 caracteres.",
            [title_text],
        ))

    description = soup.find("meta", attrs={"name": "description"})
    desc_text = (description.get("content") or "").strip() if description else ""
    if desc_text and not 50 <= len(desc_text) <= 160:
        issues.append(_issue(
            "description-length", "baixa", "Qualidade",
            "Meta description com tamanho fora do ideal (50 a 160 caracteres)", 1,
            'Meta tag name="description"',
            f"A descrição tem {len(desc_text)} caracteres. Fora dessa faixa os buscadores a truncam ou a reescrevem.",
            "Ajuste a meta description para um resumo claro entre 50 e 160 caracteres.",
            [desc_text],
        ))

    if raw_kb > MAX_HTML_KB:
        issues.append(_issue(
            "html-heavy", "media", "Infraestrutura",
            "HTML inicial muito pesado", 1, "Resposta HTML bruta",
            f"O HTML inicial pesa {raw_kb:.0f} KB. Documentos grandes atrasam a renderização, sobretudo em redes móveis.",
            "Reduza marcação e dados embutidos, carregue JSON grande sob demanda e confirme a compressão gzip/br.",
            [f"{raw_kb:.0f} KB"],
        ))

    if redirects > MAX_REDIRECTS:
        issues.append(_issue(
            "redirect-chain", "media", "Infraestrutura",
            "Cadeia de redirecionamentos longa", redirects, "Resolução da URL",
            f"O endereço passou por {redirects} redirecionamento(s) até a página final, somando latência a cada salto.",
            "Aponte os links de entrada diretamente para a URL final canônica.",
            [final_url],
        ))

    hosts = _third_party_hosts(soup, own_host)
    if len(hosts) > MAX_THIRD_PARTY_HOSTS:
        issues.append(_issue(
            "third-party-overload", "media", "Infraestrutura",
            "Excesso de domínios de terceiros", len(hosts), "Scripts, folhas de estilo, imagens e iframes",
            f"A página depende de {len(hosts)} domínio(s) externos. Cada conexão extra aumenta o tempo de carregamento e a superfície de risco.",
            "Revise scripts de terceiros, remova os que não são usados e use preconnect apenas para os essenciais.",
            hosts,
        ))

    imgs = soup.find_all("img")
    below_fold = [img for img in imgs[3:] if (img.get("loading") or "").lower() != "lazy"]
    if below_fold:
        issues.append(_issue(
            "img-no-lazy", "baixa", "Infraestrutura",
            'Imagens fora da primeira dobra sem loading="lazy"', len(below_fold), "Tags <img>",
            "Imagens que ficam abaixo da dobra são baixadas antes de o visitante precisar delas.",
            'Adicione loading="lazy" às imagens que não aparecem no carregamento inicial.',
            [(img.get("src") or "<img sem src>") for img in below_fold],
        ))

    no_dims = [
        img for img in imgs
        if not (img.get("width") and img.get("height"))
        and not (img.get("src") or "").lower().endswith(".svg")
    ]
    if len(no_dims) >= 3:
        issues.append(_issue(
            "img-no-dimensions", "baixa", "Qualidade",
            "Imagens sem width/height reservados (deslocamento de layout)", len(no_dims), "Tags <img>",
            "Sem dimensões declaradas, o navegador só sabe o tamanho da imagem após baixá-la, e o conteúdo salta na tela.",
            "Declare width e height nas imagens ou reserve a proporção com CSS aspect-ratio.",
            [(img.get("src") or "<img sem src>") for img in no_dims],
        ))

    if soup.find("meta", attrs={"http-equiv": re.compile(r"^refresh$", re.I)}):
        issues.append(_issue(
            "meta-refresh", "media", "Infraestrutura",
            "Redirecionamento ou recarga por meta refresh", 1, "Seção <head> (<meta http-equiv>)",
            "Meta refresh força o navegador a recarregar a página, prejudica o botão Voltar e é tratado como sinal fraco pelos buscadores.",
            "Substitua por redirecionamento HTTP 301/308 feito no servidor.",
            [],
        ))

    if not _has_icon(soup):
        issues.append(_issue(
            "favicon-missing", "baixa", "Qualidade",
            "Favicon não declarado na página", 1, "Seção <head> (<link rel=\"icon\">)",
            "Sem ícone declarado, abas e favoritos ficam sem identidade visual e o navegador faz requisições extras ao acaso.",
            'Declare <link rel="icon" href="..."> apontando para um favicon válido.',
            [],
        ))

    if "cache-control" not in headers:
        issues.append(_issue(
            "cache-control-missing", "baixa", "Infraestrutura",
            "Cabeçalho Cache-Control ausente na resposta HTML", 1, "Cabeçalhos HTTP",
            "Sem Cache-Control, CDNs e navegadores não sabem quanto tempo podem reutilizar a página.",
            "Defina Cache-Control apropriado para o HTML, por exemplo com max-age curto e stale-while-revalidate.",
            [],
        ))

    return issues