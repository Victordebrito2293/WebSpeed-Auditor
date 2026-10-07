# Scoring e limiares

Todo valor usado pelas verificações é uma **constante em código**, testada e
documentada aqui. Nenhum modelo externo, IA ou heurística proprietária está
envolvida: o score é uma função determinística dos achados.

## Fórmula do score

1. Cada categoria começa em **100**.
2. Cada *finding* deduz:

   | Severidade | Dedução |
   |---|---:|
   | Critical | −30 |
   | High | −15 |
   | Medium | −8 |
   | Low | −3 |
   | Info | 0 |

   `score_da_categoria = max(0, 100 − Σ deduções)`

3. **Score global** = média ponderada das categorias **efetivamente
   medidas** (com ao menos uma verificação `PASS`/`WARNING`/`FAIL`, ou com
   dedução por finding). Os pesos são renormalizados pela soma dos pesos
   medidos — categorias não medidas nunca inflam a nota.
4. Se **nenhuma** categoria pôde ser avaliada, o score global é **0** e o
   relatório declara que ele não avalia a qualidade do site.

Testes `NOT_TESTED` e `ERROR` **não deduzem**: o que não foi medido não é
punido nem recompensado.

### Pesos por categoria

| Categoria | Peso |
|---|---:|
| Performance | 20 |
| Network | 15 |
| Images | 15 |
| Caching | 10 |
| Compression | 10 |
| JavaScript | 10 |
| HTML | 10 |
| CSS | 5 |
| Best Practices | 5 |

## Limiares

### Network / Performance

| Verificação | Limiar | Ação |
|---|---|---|
| TTFB | > 600 ms | Warning (Medium) |
| TTFB | > 1500 ms | Finding `perf_ttfb_high` (High) |
| Peso total da página | > 3 MiB | Warning (Medium) |
| Cadeia de redirects | > 2 saltos | Finding `redirect_chain_long` (Low) |
| HTTP/1.1 em 2026 | — | Finding `net_no_http2` (Low) |
| Certificado TLS | expirado | Finding `tls_invalid` (Critical) |
| Certificado TLS | expira em < 14 dias | Finding `tls_expiring` (Medium) |

### HTML

| Verificação | Limiar | Ação |
|---|---|---|
| Tamanho do HTML | > 100 KiB | Warning `html_warn` (Low) |
| Tamanho do HTML | > 300 KiB | Finding `html_too_big` (Medium) |
| Origens externas distintas | > 10 | Finding `html_many_origins` (Low) |

### CSS

| Verificação | Limiar | Ação |
|---|---|---|
| Volume total de CSS | > 100 KiB | Warning + Finding `css_too_large` (Medium) |
| Folhas de estilo externas | > 8 | Warning (sem finding) |
| CSS inline no HTML | > 32 KiB | Warning + Finding `css_inline_large` (Low) |
| Folha duplicada | qualquer | Finding `css_duplicate` (Medium) |

### JavaScript

| Verificação | Limiar | Ação |
|---|---|---|
| Volume total de JS | > 300 KiB | Finding `js_too_much` (Medium) |
| Arquivo individual | > 200 KiB | Finding `js_large_files` (Medium) |
| Script bloqueante | qualquer | Finding `js_blocking` (Low) |
| Script duplicado | qualquer | Finding `js_duplicate` (Medium) |

### Images

| Verificação | Limiar | Ação |
|---|---|---|
| Imagem individual | > 300 KiB | Finding `img_oversized` (Medium) |
| Formato legado em arquivo | > 100 KiB | Finding `img_legacy_format` (Low) |
| Sem `width`/`height` | qualquer | Finding `img_no_dimensions` (Medium) |
| Sem `loading="lazy"` (abaixo da dobra) | qualquer | Finding `img_no_lazy` (Low) |
| Content-Type divergente do real | qualquer | Finding `img_content_type_mismatch` (Medium) |

### Fonts

| Verificação | Limiar | Ação |
|---|---|---|
| Volume total de fontes | > 200 KiB | Finding `fonts_too_much` (Low) |
| Fonte externa sem preload | qualquer | Finding `fonts_no_preload` (Low) |

### Caching / Compression / Best Practices

| Verificação | Limiar | Ação |
|---|---|---|
| Recurso estático sem `Cache-Control` | qualquer | Finding `cache_missing` (High) |
| `immutable` em HTML | qualquer | Finding `cache_html_immutable` (Medium) |
| Comprimível sem gzip/brotli (≥ 1 KiB) | qualquer | Finding `compression_missing` (High) |
| `Vary` ausente com `Content-Encoding` | — | Warning (Low) |
| HSTS ausente (HTTPS) | — | Finding `hsts_missing` (Low) |
| `X-Content-Type-Options` ausente | — | Warning (Low) |
| `Set-Cookie` na resposta | > 3 | Warning (Low) |
| Subrecursos com erro (404/5xx) | qualquer | Finding `resource_errors` (Medium) |
| Sem HTTPS | — | Finding `net_no_https` (High) |
| Loop de redirects | — | Finding `redirect_loop` (High) |

## Limites absolutos (não configuráveis)

| Limite | Valor |
|---|---:|
| Corpo por requisição | 10 MiB |
| Subrecursos por página | 60 |
| Redirects por cadeia | 10 |
| Tamanho de URL | 2048 caracteres |
| Concorrência | 1–16 |
| Timeout | 1–120 s |
| Páginas no crawl | 1–50 |

## Transparência

- Cada `TestItem` traz o valor observado no campo `detail`.
- Cada `Finding` traz problema, evidência, impacto e correção.
- `CategoryScore` expõe `checks`, `passed` e `deduction` no JSON, para que
  qualquer pessoa refaça o cálculo manualmente.
