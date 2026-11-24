# checkUp — Diagnóstico de Qualidade, Acessibilidade e Infraestrutura Web

O **checkUp** é uma aplicação web construída em **Python + Flask**, **Playwright (Chromium)**, **BeautifulSoup** e **Tailwind CSS** para auditar sites em tempo real e entregar métricas objetivas, pontuação consolidada, histórico comparativo, laudo técnico para PDF/impressão e exportação estruturada em JSON.

---

## Como eu pensei o projeto

A ideia central do **checkUp** nasceu da necessidade de ter uma ferramenta rápida, didática e técnica ao mesmo tempo: alguém que publica ou mantém um site não quer apenas saber se ele "abriu", mas quer enxergar **o que está falhando, onde está falhando, qual o impacto real e como corrigir**.

Em vez de ficar só em verificações estáticas superficiais ou em métricas difíceis de interpretar, o projeto foi pensado em torno de alguns pilares:

1. **Diagnóstico em camadas (HTTP bruto + navegador real):**
   Primeiro inspecionamos a resposta inicial do servidor (tempo de resposta/TTFB, redirecionamentos, protocolo, certificado SSL/TLS e cabeçalhos). Depois abrimos a página em um navegador real (Chromium via Playwright) tanto em resolução desktop quanto mobile para avaliar contraste de cores, overflow horizontal, erros de console/JS, requisições falhadas e elementos renderizados.
2. **Priorização clara e ação imediata:**
   Os apontamentos são classificados por prioridade (**alta**, **média** e **baixa**) e categoria (**Infraestrutura**, **Acessibilidade** e **Qualidade**), com explicação do problema, localização, exemplos/evidências e orientação prática de correção.
3. **Acompanhamento de evolução ao longo do tempo:**
   A cada nova análise da mesma URL, o sistema registra o histórico e compara nota, quantidade de problemas, tempo de resposta (TTFB) e dias restantes de SSL com a verificação anterior.
4. **Saída técnica para documentação e compartilhamento:**
   Além da visualização interativa na tela com filtros, o relatório pode ser exportado em **JSON** ou impresso/salvo em **PDF** no formato de laudo técnico sequencial por prioridade.

---

## Como eu fiz (Arquitetura e cada peça do projeto)

O projeto foi organizado de forma modular para separar coleta/auditoria, persistência, rotas web e apresentação:

### 1. Motor de verificação (`checker.py`)
É o coração da análise técnica. Ele reúne as etapas de validação e cálculo:
* **Validação e segurança de URL (`normalize_url`, `_is_safe_url`):** normaliza endereços sem esquema para `https://` e bloqueia alvos internos/privados/loopback/reservados para evitar SSRF.
* **Análise HTTP e SSL/TLS (`fetch_raw_page`, `inspect_ssl_certificate`, `_detect_server_and_cdn`):** mede TTFB, conta redirecionamentos, verifica compressão HTTP, lê cookies (`Set-Cookie`), identifica servidor/CDN e consulta o certificado TLS/SSL na porta 443 (validade, data de expiração, dias restantes, emissor e versão do protocolo).
* **Renderização em navegador (`render_page`, `CONTRAST_JS`, `QUALITY_JS`, `OVERFLOW_JS`):** executa no Chromium (desktop `1280x900` e mobile `375x812`) para verificar contraste de texto (WCAG), rolagem lateral no celular, imagens quebradas, scripts bloqueantes no `<head>`, indícios de debug, IDs duplicados, tags de SEO (`meta description`, `canonical`, Open Graph), landmarks semânticos, erros de console/JS e falhas de rede.
* **Verificação de links (`check_links`):** testa links `http/https` em paralelo (`ThreadPoolExecutor`) usando `HEAD` com fallback para `GET` quando necessário.
* **Análise HTML estrutural e pontuação (`check_html`, `_compute_score`):** avalia `lang`, `<title>`, `alt` em imagens, links e botões sem nome, rótulos de formulário, bloqueio de zoom no `viewport`, títulos de `<iframe>` e hierarquia de cabeçalhos (`h1`–`h6`), calculando a nota final de `0` a `100` com pesos e tetos por severidade.
* **Monitoramento de alvos públicos (`DEFAULT_LIVE_TARGETS`, `check_live_targets`):** consulta endpoints públicos abertos de referência e retorna status, latência e horário da checagem.
* **Execução em etapas (`check_site_steps`):** emite eventos de progresso (`progress` e `done`) para alimentar o acompanhamento em tempo real.

### 2. Servidor e rotas Flask (`app.py`)
Responsável por orquestrar a aplicação web:
* `GET /` e `POST /`: registra visualizações/visitantes únicos, renderiza a página inicial e processa verificações tradicionais com tratamento de erros amigável.
* `POST /verificar/stream`: transmite o progresso da análise em `NDJSON` (`application/x-ndjson`) e devolve o HTML renderizado do resultado ao finalizar.
* `GET /status/ao-vivo`: retorna o status dos alvos públicos com cache configurável (`LIVE_TTL_SECONDS`) e suporte a atualização forçada (`?force=1`).
* `POST /avisar`: valida e salva e-mails de interessados em novidades.
* `GET /privacidade` e páginas de erro (`404` / `500`): exibem a política de privacidade (LGPD) e telas de erro padronizadas.

### 3. Persistência e histórico (`storage.py`)
Gerencia contadores anônimos de acessos/visitantes únicos, lista de interessados e o histórico de verificações por URL, gerando o objeto de comparação (`comparison`) entre execuções.

### 4. Camada visual e templates (`templates/` e `static/`)
* `templates/base.html`: estrutura base, tipografia (`Plus Jakarta Sans` e `JetBrains Mono`), alternância de tema claro/escuro, seletor de idioma (`PT`/`EN`), regras de impressão (`@media print`), modal de exportação/pagamento Pix e rodapé com suporte Pix e QR Code.
* `templates/index.html`: formulário principal, overlay circular de progresso em tempo real, painel de alvos ao vivo clicáveis para disparar a análise completa, área de novidades e scripts de interação/filtros.
* `templates/_resultado.html`: exibe a pontuação geral, cards de prioridade clicáveis que filtram a lista de correções, dados do certificado SSL/TLS, métricas técnicas, filtros por categoria e o **laudo técnico dedicado à impressão/PDF** ordenado por prioridade (`alta` → `média` → `baixa`).
* `templates/privacidade.html` e `templates/erro.html`: páginas institucionais e de erro.
* `static/`: ícone da aplicação (`favicon.svg`) e QR Codes Pix (`pix-qrcode.png` e `pix-apoio.png`).

### 5. Testes automatizados (`tests/`)
* `tests/test_checker.py`: cobre normalização/bloqueio de URLs, pontuação de HTML limpo, detalhes de issues (`location`, `fix`), alertas de infraestrutura/SSL/TTFB e alvos ao vivo.
* `tests/test_storage_and_app.py`: cobre histórico/comparação no `Storage` e rotas principais do Flask.

---

## Como executar localmente

```bash
# 1. Crie e ative o ambiente virtual
python -m venv .venv
.venv\Scripts\Activate.ps1

# 2. Instale as dependências
pip install -r requirements.txt
python -m playwright install chromium

# 3. Execute os testes
python -m pytest -v

# 4. Inicie o servidor
python app.py
Acesse http://127.0.0.1:5000 no navegador.

Autor
Desenvolvido por Moacir Fernandes.