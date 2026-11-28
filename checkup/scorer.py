"""Motor de pontuação ponderada, sub-scores por pilar e síntese técnica consolidada."""

from __future__ import annotations

import math

WEIGHTS = {"alta": 9.0, "media": 4.5, "baixa": 1.8}
CAP_PER_ISSUE = {"alta": 22.0, "media": 12.0, "baixa": 6.0}
CATEGORY_WEIGHTS = {
    "Infraestrutura": 0.40,
    "Acessibilidade": 0.30,
    "Qualidade": 0.30,
}


def _pillar_score(issues: list[dict], category: str) -> int:
    penalty = 0.0
    for issue in issues:
        if issue.get("category") != category:
            continue
        level = issue.get("level", "baixa")
        base_weight = WEIGHTS.get(level, 1.8)
        cap = CAP_PER_ISSUE.get(level, 6.0)
        count = max(1, int(issue.get("count") or 1))
        multiplier = 1.0 + 0.20 * math.log1p(count - 1)
        item_penalty = base_weight * multiplier
        if level == "baixa" and issue.get("id") in ("missing-security-txt", "missing-modern-owasp-headers", "missing-cache-control"):
            item_penalty *= 0.5
        penalty += min(item_penalty, cap)
    return max(0, min(100, round(100.0 - penalty)))
def compute_score(issues: list[dict]) -> dict:
    """Calcula a pontuação geral (0-100) e os sub-scores por pilar sem inflação por duplicidade."""
    infra_score = _pillar_score(issues, "Infraestrutura")
    a11y_score = _pillar_score(issues, "Acessibilidade")
    quality_score = _pillar_score(issues, "Qualidade")

    weighted = (
        infra_score * CATEGORY_WEIGHTS["Infraestrutura"]
        + a11y_score * CATEGORY_WEIGHTS["Acessibilidade"]
        + quality_score * CATEGORY_WEIGHTS["Qualidade"]
    )
    overall = max(0, min(100, round(weighted)))

    return {
        "score": overall,
        "breakdown": {
            "infraestrutura": infra_score,
            "acessibilidade": a11y_score,
            "qualidade": quality_score,
            "weights": CATEGORY_WEIGHTS,
        },
    }


def build_incapacitation_synthesis(url: str, score: int, issues: list[dict], metrics: dict, extras: dict) -> dict:
    """Gera síntese técnica consolidada apontando riscos críticos e ações prioritárias."""
    incapacitating: list[dict] = []

    if not metrics.get("is_https"):
        incapacitating.append({
            "severity": "CRÍTICO",
            "area": "Segurança de Transporte (Ausência de HTTPS)",
            "impact": "O tráfego ocorre sem criptografia TLS, gerando avisos de site não seguro e bloqueando APIs modernas.",
            "action": "Provisionar certificado TLS/SSL válido e impor redirecionamento permanente (301/308) para HTTPS.",
        })

    if metrics.get("ssl_valid") is False and metrics.get("is_https"):
        incapacitating.append({
            "severity": "CRÍTICO",
            "area": "Certificado SSL/TLS Inválido ou Expirado",
            "impact": "Falha de confiança TLS provoca tela de bloqueio no navegador, impedindo o acesso ao site.",
            "action": "Renovar ou corrigir a cadeia de certificação TLS/SSL imediatamente.",
        })
    elif metrics.get("ssl_days_left") is not None and metrics.get("ssl_days_left") <= 14:
        incapacitating.append({
            "severity": "ALTO",
            "area": "Expiração Iminente do Certificado TLS",
            "impact": f"Restam {metrics.get('ssl_days_left')} dia(s) para expiração ({metrics.get('ssl_expires_at')}).",
            "action": "Confirmar renovação automática do certificado TLS.",
        })

    if (metrics.get("failed_requests_count") or 0) > 0:
        incapacitating.append({
            "severity": "ALTO",
            "area": "Falhas em Requisições de Rede",
            "impact": f"{metrics.get('failed_requests_count')} requisição(ões) falharam durante o carregamento.",
            "action": "Corrigir endpoints com erro 4xx/5xx, bloqueios CORS ou assets ausentes.",
        })

    if (metrics.get("broken_links") or 0) > 0 or (metrics.get("broken_images") or 0) > 0:
        incapacitating.append({
            "severity": "ALTO",
            "area": "Integridade de Links e Imagens",
            "impact": f"Detectados {metrics.get('broken_links', 0)} link(s) quebrado(s) e {metrics.get('broken_images', 0)} imagem(ns) falha(s).",
            "action": "Reparar URLs quebradas e restaurar ativos estáticos.",
        })

    if (metrics.get("ttfb_ms") or 0) > 2000:
        incapacitating.append({
            "severity": "ALTO",
            "area": "Latência Elevada de Resposta (TTFB)",
            "impact": f"TTFB de {metrics.get('ttfb_ms')} ms degrada a experiência em redes móveis e eleva abandono.",
            "action": "Otimizar queries/backend, aplicar cache e revisar região do servidor.",
        })

    if extras.get("robots_disallows_all"):
        incapacitating.append({
            "severity": "ALTO",
            "area": "Bloqueio Geral em robots.txt",
            "impact": "A diretiva Disallow: / bloqueia rastreadores na raiz do domínio.",
            "action": "Revisar /robots.txt para liberar as rotas públicas.",
        })

    if extras.get("insecure_forms", 0) > 0 or len(extras.get("mixed_assets") or []) > 0:
        incapacitating.append({
            "severity": "ALTO",
            "area": "Conteúdo Misto / Formulários Inseguros",
            "impact": "Recursos ou formulários em HTTP dentro de páginas HTTPS podem ser bloqueados pelo navegador.",
            "action": "Migrar 100% dos formulários e ativos para HTTPS.",
        })

    if not incapacitating:
        for it in [i for i in issues if i.get("level") == "alta"][:3]:
            incapacitating.append({
                "severity": "ALTO",
                "area": f"{it.get('category', 'Qualidade')} · {it.get('title', '')}",
                "impact": it.get("explanation", ""),
                "action": it.get("fix", ""),
            })

    if score < 50:
        verdict = "CRÍTICO — Risco Alto de Incapacitação ou Degradação Grave"
    elif score < 80 or incapacitating:
        verdict = "ATENÇÃO — Operacional com Gargalos / Requer Correções"
    else:
        verdict = "ESTÁVEL — Sem Bloqueios Críticos Detectados"

    technical_overview = (
        f"Síntese Técnica Consolidada para {url}: Pontuação geral {score}/100 com {len(issues)} apontamento(s) "
        f"(Alta: {metrics.get('high_count', 0)}, Média: {metrics.get('medium_count', 0)}, Baixa: {metrics.get('low_count', 0)}). "
        f"Transporte: {'HTTPS' if metrics.get('is_https') else 'HTTP'} ({metrics.get('tls_version') or 'TLS N/A'}), "
        f"SSL válido: {'Sim' if metrics.get('ssl_valid') else 'Não/N/A'} ({metrics.get('ssl_days_left') if metrics.get('ssl_days_left') is not None else 'N/A'}d). "
        f"Latência inicial (TTFB): {metrics.get('ttfb_ms', 0)} ms; Redirecionamentos: {metrics.get('redirects', 0)}; "
        f"Servidor/CDN: {metrics.get('server', 'N/A')} / {metrics.get('cdn', 'N/A')}; "
        f"Tamanho HTML: {metrics.get('raw_kb', 0)} KB -> {metrics.get('rendered_kb', 0)} KB ({metrics.get('encoding', 'nenhuma')}). "
        f"Verificação de links: {metrics.get('broken_links', 0)}/{metrics.get('checked_links', 0)} quebrados; "
        f"Imagens com falha: {metrics.get('broken_images', 0)}/{metrics.get('total_images', 0)}."
    )

    return {
        "verdict": verdict,
        "technical_overview": technical_overview,
        "summary": technical_overview,
        "factors": incapacitating,
        "total_incapacitating_factors": len(incapacitating),
    }
