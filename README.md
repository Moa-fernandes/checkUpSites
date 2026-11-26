checkUp — Diagnóstico de Qualidade, Acessibilidade, Segurança e Infraestrutura Web

O checkUp é uma aplicação web full-stack desenvolvida em Python + Flask, Playwright (Chromium), BeautifulSoup, Redis e Tailwind CSS para auditar sites em tempo real. A plataforma entrega métricas objetivas, pontuação consolidada (0 a 100), detecção de stack tecnológica, verificação de certificado SSL/TLS, histórico comparativo, internacionalização dinâmica (PT-BR / EN), laudo técnico otimizado para impressão/PDF e exportação estruturada em JSON.

Stack Tecnológica, Infraestrutura & Skills Aplicadas

Backend & Motor de Auditoria

Python 3.12+ & Flask: servidor web, rotas REST/SSR, streaming de progresso em tempo real (NDJSON via stream_with_context) e tratamento de erros.

Playwright (Chromium Headless) & BeautifulSoup4: análise híbrida em camadas (HTML bruto + DOM renderizado em viewport Desktop 1280x900 e Mobile 375x812), com fallback resiliente para ambientes serverless (como Vercel) sem binário de navegador.

Requests & Concorrência (ThreadPoolExecutor): inspeção de rede, medição de TTFB, rastreamento de redirecionamentos e checagem paralela de links quebrados (HEAD com fallback GET).

Criptografia & Rede (ssl, socket, ipaddress, urllib.parse): inspeção direta de certificados SSL/TLS na porta 443 (validade, expiração, dias restantes, emissor e versão TLS) e proteção contra SSRF (bloqueio de IPs privados, loopback e reservados).

Persistência, Cache & Deploy

Redis (redis-py / Redis Cloud via REDIS_URL / rediss://): armazenamento persistente em memória para contagem de visualizações (INCR) e deduplicação de visitantes únicos (SADD/SCARD), com fallback automático e thread-safe (threading.Lock) para sistema de arquivos local (JSON, CSV e TXT).

Vercel (Serverless Deployment): configuração adaptada para execução stateless em nuvem, resolução automática de diretórios graváveis (/tmp) e integração contínua via GitHub.

Frontend, UX & Internacionalização

HTML5 Semântico, Jinja2 & Tailwind CSS: interface responsiva (mobile-first), acessível (landmarks, skip links, foco visível, contraste WCAG) e com suporte a Modo Claro / Modo Escuro (data-theme).

Motor Global de Internacionalização (PT-BR ↔ EN): tradução dinâmica em tempo real de toda a interface, cards de prioridade, filtros, apontamentos técnicos, laudo em PDF e payload JSON exportado.

Laudo Técnico & Exportação (@media print + Modal Responsivo): layout dedicado de impressão em A4 com quebra de página controlada (break-inside: avoid), seleção de idioma do relatório (PDF em PT-BR ou PDF in EN) e integração com fluxo de pagamento via Pix (QR Code + chave copiável).

Qualidade de Software & Boas Práticas

Pytest: suíte de testes automatizados cobrindo validação/segurança de URLs, motor de pontuação, alertas de SSL/infraestrutura, rotas Flask, streaming e persistência.

Engenharia de Resiliência & Segurança: sanitização de entradas, prevenção de SSRF, cabeçalhos de segurança (OWASP), cookies seguros (HttpOnly, Secure, SameSite) e conformidade com LGPD.

Como o Projeto Funciona (Arquitetura)

Diagnóstico em Camadas (checker.py):

Validação e Segurança: normaliza URLs e bloqueia destinos internos (normalize_url, _is_safe_url).

Rede, Cabeçalhos e SSL/TLS: mede TTFB, compressão HTTP, cookies, servidor/CDN e consulta o certificado TLS/SSL (fetch_raw_page, inspect_ssl_certificate).

Fingerprinting de Stack (detect_tech_stack): identifica de forma indicativa linguagens (PHP, Python, JavaScript / Node.js, C# / ASP.NET, Java, Ruby, Go), frameworks/CMS (Next.js, React, Vue.js, Angular, Svelte, Astro, WordPress, WooCommerce, Shopify, Laravel, etc.) e bibliotecas (Tailwind CSS, Bootstrap, jQuery, Three.js, Chart.js, GSAP, Axios, htmx, Vite, etc.).

Renderização, Acessibilidade e Qualidade: executa auditorias de contraste WCAG, overflow horizontal no celular, erros de console/JS, falhas de rede, scripts bloqueantes, SEO (meta description, canonical, noindex), hierarquia de títulos (h1–h6) e atributos ARIA.

Síntese Executiva & Pontuação: calcula a nota de 0 a 100 e gera um diagnóstico consolidado dos fatores que podem comprometer a operação do site.

Rotas & Streaming (app.py):

GET / e POST /: registra métricas de acesso, exibe o painel inicial e processa verificações síncronas.

POST /verificar/stream: transmite o progresso percentual e cada etapa da varredura em tempo real via NDJSON.

GET /status/ao-vivo: monitora endpoints públicos de referência com cache em memória (TTL) e atualização sob demanda.

POST /avisar e GET /privacidade: cadastro na lista de novidades e página de transparência/LGPD.

Camada de Dados (storage.py):

Conecta ao Redis via REDIS_URL para métricas globais persistentes em produção e mantém histórico comparativo por URL (evolução de nota, problemas, TTFB e dias de SSL).

Templates & Interface (templates/ e static/):

templates/base.html: estrutura global, alternância de tema (Bright/Dark), seletor de idioma (PT/EN), motor de tradução completo do relatório/PDF/JSON e modal responsivo de exportação Pix.

templates/index.html: formulário principal, overlay animado de progresso, cards de monitoramento ao vivo clicáveis e filtros interativos.

templates/_resultado.html: dashboard de resultados, cards de prioridade (Alta, Média, Baixa), painel de Certificado SSL / TLS, painel de Linguagens, Frameworks e Bibliotecas e template estruturado do Laudo Técnico em PDF.

Como Executar Localmente

# 1. Crie e ative o ambiente virtual
python -m venv .venv
.venv\Scripts\Activate.ps1

# 2. Instale as dependências
pip install -r requirements.txt
python -m playwright install chromium

# 3. (Opcional) Configure a variável do Redis para métricas persistentes
$env:REDIS_URL="rediss://usuario:senha@host:porta"

# 4. Execute os testes automatizados
python -m pytest -v

# 5. Inicie o servidor local
python app.py


Acesse http://127.0.0.1:5000 no navegador.

Autor

Desenvolvido por Moacir Fernandes.