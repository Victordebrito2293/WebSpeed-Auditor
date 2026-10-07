# WebSpeed Auditor

Auditoria **local**, **offline** e orientada a **privacidade** de performance e
boas práticas de websites. Uma ferramenta em Rust, 100% open source, sem
contas, sem chaves de API, sem telemetria — nada é enviado a terceiros além das
requisições HTTP feitas **para o site que você está auditando**.

```
webspeed-auditor https://example.com
```

## Por quê

Ferramentas de auditoria de performance normalmente enviam seu URL para um
servidor na nuvem, exigem cadastro ou executam código de terceiros no navegador.
O WebSpeed Auditor executa **na sua máquina**, lê apenas o que o próprio site
publica e gera um relatório que responde a cinco perguntas:

1. **O que foi testado e qual foi o resultado?**
2. **Que problemas existem** — com gravidade, evidência, impacto e como corrigir?
3. **O que já está otimizado?**
4. **O que não pôde ser testado neste ambiente** (e por quê)?
5. **Qual é a pontuação geral?**

## Instalação

### Compilar a partir da fonte (recomendado)

Requisitos: [Rust 1.88+](https://rustup.rs) (edição 2024).

```bash
git clone https://github.com/webspeed-auditor/webspeed-auditor.git
cd webspeed-auditor
cargo build --release
./target/release/webspeed-auditor --help
```

### Binários pré-compilados

O workflow de release gera binários assinados por artefato para Linux
(x86_64/aarch64), macOS (x86_64/aarch64) e Windows (x86_64) na página de
releases do GitHub.

## Uso

```bash
# Relatório no terminal (padrão)
webspeed-auditor https://example.com

# JSON para CI/CD
webspeed-auditor https://example.com --format json --output relatorio.json

# HTML autocontido (sem scripts, sem recursos externos)
webspeed-auditor https://example.com --format html --output relatorio.html

# Apenas a página inicial, com mais detalhe
webspeed-auditor https://example.com --no-crawl --verbose

# Modo silencioso (somente o relatório final)
webspeed-auditor https://example.com --quiet --format json
```

Sem URL, a ferramenta exibe um banner e pede a URL interativamente.

### Opções

| Opção | Padrão | Descrição |
|---|---|---|
| `--max-pages <N>` | 5 | Máximo de páginas no crawl (1–50; 1 = só a inicial) |
| `--timeout <S>` | 15 | Timeout por operação de rede, em segundos (1–120) |
| `--concurrency <N>` | 4 | Requisições simultâneas (1–16) |
| `--output <FILE>` | — | Grava o relatório em arquivo (nada é gravado sem isto) |
| `--format <FMT>` | terminal | `terminal`, `json` ou `html` |
| `--no-crawl` | — | Não rastrear links internos |
| `--quiet` | — | Sem logs de progresso (apenas o relatório) |
| `--verbose` | — | Detalha cada etapa e requisição (stderr) |

O relatório vai ao **stdout** e o progresso ao **stderr**, então o uso em
pipeline é seguro:

```bash
webspeed-auditor https://example.com --format json --quiet > relatorio.json
```

### Códigos de saída

| Código | Significado |
|---|---|
| 0 | Auditoria concluída (o relatório é gerado mesmo com falhas parciais) |
| 1 | Falha ao gerar/gravar o relatório |
| 2 | Entrada inválida ou URL recusada por segurança |

## O que é verificado

- **Network**: resolução DNS, endereços IPv4/IPv6, handshake TLS, validade e
  data de expiração do certificado, cadeia de redirects, versão do protocolo
  (HTTP/1.1, HTTP/2), TTFB.
- **Performance**: peso total da página, tamanho do documento, TTFB.
- **HTML**: estrutura, links (interno/externo), iframes, `<meta>` de viewport,
  origens externas distintas, tamanho do documento e compatibilidade de
  conteúdo com o `Content-Type` declarado.
- **CSS**: volume total e inline, folhas duplicadas, CSS inline acima do
  recomendado, recuperação de folhas de estilo com erro.
- **JavaScript**: volume, scripts bloqueantes vs `defer`/`async`/`module`,
  scripts duplicados e tamanho de arquivos individuais.
- **Images**: formatos legados vs modernos (WebP/AVIF), imagens acima do
  limiar de tamanho, `srcset`/`sizes`.
- **Fonts**: volume de fontes externas e inline, preload de fontes externas.
- **Caching**: `Cache-Control`, `ETag`/`Last-Modified`, `immutable` em HTML.
- **Compression**: gzip/brotli/deflate por tipo de recurso, header `Vary`.
- **Best Practices**: headers de segurança (HSTS e `X-Content-Type-Options`),
  cookies (`Set-Cookie` apenas contado — valores nunca coletados),
  Content-Type declarado vs conteúdo real (sniffing), HTTPS, redirects e
  cadeia de redirecionamento.

Toda a tabela de limiares está em [`docs/SCORING.md`](docs/SCORING.md).

## Privacidade

- **Nenhum dado é persistido**: a auditoria inteira vive em memória durante a
  execução e é descartada ao final.
- **Nenhum arquivo é criado sem `--output`**, e nada é gravado automaticamente.
- **Sem telemetria, sem analytics, sem crash reports, sem atualizador
  automático, sem contas, sem chaves de API.**
- O único tráfego externo são as requisições **para o site auditado** (e o
  DNS necessário para resolvê-lo). Nenhum dado é enviado a terceiros.
- O relatório contém apenas dados do site alvo — nunca dados locais do
  operador (caminhos, usuário, ambiente).
- Set-Cookie: apenas a **contagem** é reportada; os valores nunca são lidos,
  guardados ou logados.
- O User-Agent identifica a ferramenta e o projeto, nunca o operador.

Detalhes: [`docs/SECURITY.md`](docs/SECURITY.md) e [`SECURITY.md`](SECURITY.md).

## Segurança

- **SSRF (Server-Side Request Forgery)**: toda URL é validada antes de cada
  requisição — inclusive **a cada salto de redirect** e **em cada resolução de
  DNS feita pelo cliente HTTP** (defesa contra DNS rebinding). Loopback,
  redes privadas, link-local, metadados de cloud (169.254.169.254 etc.),
  CGNAT, endereços reservados e traduções NAT64/6to4/Teredo são bloqueados.
- **Sem flag de CLI para desativar a proteção SSRF.** Ela só pode ser
  desativada por código em testes locais.
- Limites absolutos: 10 MiB por corpo, 60 subrecursos, 10 redirects,
  URL de no máximo 2048 caracteres, concorrência 1–16, timeout 1–120 s.
- Conteúdo remoto é tratado como **nunca confiável**: HTML malformado não
  pode panicar, o relatório HTML escapa todo conteúdo dinâmico e o relatório
  é autocontido (sem `<script>`, sem recursos externos).
- `unsafe` é **proibido** em todo o código (`#![forbid(unsafe_code)]`).

## Como funciona o score

Cada categoria começa em 100. Achados deduzem valores fixos e documentados
(Critical −30, High −15, Medium −8, Low −3, Info 0). A média ponderada é
calculada **apenas sobre as categorias efetivamente medidas** — o que não foi
medido nunca infla a nota. Se nada pôde ser medido, o score é 0 e o relatório
diz explicitamente que ele não avalia o site.

Fórmula completa, pesos e limiares: [`docs/SCORING.md`](docs/SCORING.md).

## Limitações honestas

Esta ferramenta não faz mágica e declara o que **não** mede:

- **Core Web Vitals (LCP/CLS/INP)**: não há navegador real — a medição é
  HTTP estática.
- **HTTP/3 (QUIC)**: não é sondado (evita dependências problemáticas).
- **JavaScript não é executado**: páginas renderizadas só por JS têm análise
  parcial.
- **Registros DNS (CNAME)**: não coletados; apenas resolução e IPs.
- **Acessibilidade**: apenas aspectos ligados a performance (dimensões de
  imagens, lazy loading).
- **Ambiente de medição**: tempos variam com rede, CDN e carga do alvo.

Todas as limitações aparecem na seção "Não testado" de cada relatório.

## Desenvolvimento

```bash
cargo test          # 135+ testes (unidade + integração + SSRF)
cargo fmt --check
cargo clippy --all-targets
```

- Uso completo: [`docs/USAGE.md`](docs/USAGE.md)
- Arquitetura: [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md)
- Contribuindo: [`CONTRIBUTING.md`](CONTRIBUTING.md)
- Build e releases: [`docs/BUILD.md`](docs/BUILD.md)

## Licença

[MIT](LICENSE).
