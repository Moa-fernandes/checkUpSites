import checker
import pytest


def test_normalize_url_adds_https_and_rejects_loopback():
    assert checker.normalize_url("example.com") == "https://example.com"
    with pytest.raises(ValueError):
        checker.normalize_url("http://127.0.0.1")
    with pytest.raises(ValueError):
        checker.normalize_url("   ")


def test_check_html_clean_page_has_high_score():
    html = """
    <html lang="pt-BR">
      <head>
        <title>Página Exemplo</title>
        <meta name="description" content="Descrição adequada para mecanismos de busca.">
        <link rel="canonical" href="https://example.com/">
      </head>
      <body>
        <h1>Título principal</h1>
        <h2>Subtítulo</h2>
        <img src="logo.png" alt="Logo da empresa" width="120" height="40">
        <a href="https://example.com">Saiba mais</a>
        <button type="button">Enviar</button>
        <label for="nome">Nome</label>
        <input id="nome" type="text">
      </body>
    </html>
    """
    res = checker.check_html(html)
    assert res["score"] == 100
    assert res["total_issues"] == 0


def test_check_html_includes_location_and_fix_details():
    html = """
    <html>
      <body>
        <h2>Começa em h2</h2>
        <h4>Pula para h4</h4>
        <img src="sem-alt.png">
        <button></button>
      </body>
    </html>
    """
    res = checker.check_html(html)
    titles = {i["title"] for i in res["issues"]}
    assert "Idioma da página não definido" in titles
    assert "Imagens sem texto alternativo" in titles
    assert "Botões sem nome" in titles
    assert "Títulos pulam níveis (ex.: h2 seguido de h4)" in titles
    for issue in res["issues"]:
        assert issue.get("location")
        assert issue.get("fix")
    assert res["score"] < 100


def test_infrastructure_issues_flags_expiring_ssl_and_slow_ttfb():
    raw_info = {
        "final_url": "https://site.example.com",
        "is_https": True,
        "http_redirects_to_https": False,
        "redirects": 3,
        "ttfb_ms": 2200,
        "ssl": {"checked": True, "valid": True, "days_left": 12, "expires_at": "06/12/2026"},
        "headers": {},
    }
    issues = checker._infrastructure_issues(raw_info)
    titles = {i["title"] for i in issues}
    assert "Certificado SSL/TLS próximo de vencer" in titles
    assert "Cadeia longa de redirecionamentos" in titles
    assert "Tempo de resposta inicial do servidor alto" in titles
    assert "Cabeçalhos de segurança HTTP ausentes" in titles
    assert "Acesso HTTP não redireciona automaticamente para HTTPS" in titles


def test_default_live_targets_has_three_open_targets():
    assert len(checker.DEFAULT_LIVE_TARGETS) == 3