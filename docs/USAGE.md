# Uso

## Rápido

```bash
webspeed-auditor                      # banner + prompt interativo
webspeed-auditor https://example.com  # relatório no terminal
```

Sem esquema, `https://` é assumido: `webspeed-auditor example.com` equivale a
`webspeed-auditor https://example.com`.

## Formatos de saída

### Terminal (padrão)

Relatório completo com cores ANSI quando o stdout é um TTY (sem cores em
pipeline). Seções: pontuação geral, testes agrupados por status, problemas
com evidência/correção, "já otimizado", "não testado" e detalhes técnicos
(DNS, TLS, tempos, páginas).

```bash
webspeed-auditor https://example.com | less -R
```

### JSON (CI/CD)

Serialização direta do `AuditReport` — estável, sem dados locais, sem ANSI:

```bash
webspeed-auditor https://example.com --format json --quiet > relatorio.json
```

Principais chaves:

```jsonc
{
  "tool": "WebSpeed Auditor",
  "version": "0.1.0",
  "url": "...", "final_url": "...",
  "generated_at_unix": 0, "generated_at_iso8601": "...",
  "duration_ms": 0, "pages_analyzed": 0, "requests_analyzed": 0,
  "scores":   { "score": 0, "categories": [ { "category": "performance", "score": 0, "checks": 0, "passed": 0, "deduction": 0 } ] },
  "tests":    [ { "category": "...", "name": "...", "status": "PASS|WARNING|FAIL|NOT_TESTED|ERROR", "detail": "...", "evidence": "..." } ],
  "findings": [ { "id": "...", "category": "...", "severity": "CRITICAL|HIGH|MEDIUM|LOW|INFO", "title": "...", "problem": "...", "evidence": "...", "impact": "...", "recommendation": "..." } ],
  "optimized": [ /* testes com PASS */ ],
  "not_tested": [ { "area": "...", "reason": "..." } ],
  "dns": {}, "tls": {}, "redirects": {}, "http": {}, "html": {},
  "css": {}, "javascript": {}, "images": {}, "fonts": {},
  "cache": {}, "compression": {},
  "resources": [], "pages": []
}
```

Exemplo de gate em CI:

```bash
webspeed-auditor "$URL" --format json --quiet -o r.json
python3 - <<'PY'
import json, sys
r = json.load(open("r.json"))
criticos = [f for f in r["findings"] if f["severity"] == "CRITICAL"]
if criticos:
    print("problemas críticos:", [f["id"] for f in criticos]); sys.exit(1)
print("score:", r["scores"]["score"])
PY
```

### HTML (autocontido)

Um único arquivo com CSS inline, **sem JavaScript e sem recursos externos**
(abre offline, seguro de compartilhar; todo conteúdo dinâmico é escapado):

```bash
webspeed-auditor https://example.com --format html --output relatorio.html
```

## Opções

| Opção | Padrão | Faixa | Descrição |
|---|---|---|---|
| `--max-pages` | 5 | 1–50 | Páginas no crawl (1 = só a inicial) |
| `--timeout` | 15 | 1–120 | Timeout por operação (s) |
| `--concurrency` | 4 | 1–16 | Requisições simultâneas |
| `--output <FILE>` | — | — | Grava em arquivo (nada é criado sem isto) |
| `--format` | terminal | — | `terminal`, `json`, `html` |
| `--no-crawl` | — | — | Apenas a página inicial |
| `--quiet` | — | — | Sem progresso (stderr silenciado) |
| `--verbose` | — | — | Detalha etapas e requisições (stderr) |

`--quiet` e `--verbose` são mutuamente exclusivos.

## Comportamento de execução

- **Progresso → stderr**, **relatório → stdout** (pipeline seguro).
- O crawl respeita `robots.txt` do alvo (bloqueios são contados e registrados
  em `--verbose`), mesma origem, profundidade máxima 3 e o limite de páginas.
- Falhas parciais não abortam: 404, timeout ou rede indisponível viram testes
  `FAIL`/`ERROR` e limitações — o relatório é sempre gerado.
- Códigos de saída: `0` concluído, `1` falha ao gerar/gravar, `2` entrada ou
  URL recusada.
- Nada é gravado sem `--output`; não há cache, estado ou arquivos temporários.

## Cuidados legítimos

- Sites atrás de login/geo-bloqueio podem ter análise parcial — as limitações
  aparecem no relatório.
- Execute de diferentes redes/locais para comparar tempos (a rede local pesa
  no resultado; é declarado como limitação em todo relatório).
