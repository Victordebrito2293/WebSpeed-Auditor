# Arquitetura

## Visão geral

```
CLI (clap) ──► audit::run(url, Config)
                   │
                   ├── utils::ssrf      validação de forma + IPs (duas camadas)
                   ├── scanner::dns     resolução DNS (informativa)
                   ├── scanner::tls     probe TLS (spawn_blocking + complete_io)
                   ├── scanner::http    AuditClient: fetch manual com revalidação
                   │                     SSRF por salto e SafeResolver (anti-rebinding)
                   ├── scanner::html    parsing tolerante → HtmlInfo + recursos
                   ├── scanner::resources  fetch concorrente de subrecursos
                   ├── scanner::crawling   BFS same-origin com robots.txt
                   │
                   ├── scanner::{css,javascript,images,fonts,
                   │            cache,compression,security_headers}
                   │        cada um → (Info, Section)
                   │
                   ├── analysis::recommendations  achados gerais + limitações
                   ├── analysis::scoring          score transparente
                   │
                   └── AuditReport (models) ──► report::{terminal,json,html}
```

## Princípios de projeto

1. **Falha parcial é sucesso.** `audit::run` só retorna `Err` para entrada
   inválida ou URL recusada por segurança. Falha de rede, 404, timeout ou
   HTML malformado viram testes `ERROR`/`FAIL` e limitações no relatório.
2. **Cada scanner é independente.** Recebem o que precisam (HTML já parseado,
   `HttpInfo`, recursos coletados) e devolvem `(Info, Section)`. Nenhum
   scanner faz rede por conta própria, exceto `http`, `dns`, `tls`,
   `resources` e `crawling`.
3. **`Section` é o contrato.** `tests` (o que foi medido), `findings`
   (problemas com evidência) e `limitations` (o que não pôde ser medido).
4. **Score só a partir de achados.** Testes `NOT_TESTED`/`ERROR` não deduzem;
   categorias não medidas não entram na média (renormalização dos pesos).
5. **Nada em disco sem `--output`.** Logs em stderr, relatório em stdout.

## Segurança no fluxo

- `AuditClient::fetch` aplica `validate_url_shape` em cada URL, segue
  redirects manualmente (`Policy::none()`) com limite de saltos e revalida a
  política SSRF **a cada salto** (detecta loops explicitamente).
- `SafeResolver` implementa `reqwest::dns::Resolve`: cada resolução feita
  durante o handshake da conexão passa por `check_ips`. Um DNS rebinding
  entre a validação inicial e a conexão é bloqueado na própria conexão.
- Corpos são lidos em streaming e cortados em `MAX_BODY_BYTES`; o
  decompressor tem limite próprio (anti zip bomb).
- O TLS probe roda em `spawn_blocking` com `connect_timeout`; a falha de
  verificação padrão é reportada, nunca ignorada (o fallback `AcceptAllVerifier`
  existe apenas para ler o certificado e continuar reportando a falha).

## Limites absolutos (`src/config.rs`)

| Constante | Valor |
|---|---|
| `MAX_BODY_BYTES` | 10 MiB |
| `MAX_RESOURCES` | 60 |
| `MAX_REDIRECTS` | 10 |
| `MAX_URL_LENGTH` | 2048 |
| concorrência | 1..=16 (padrão 4) |
| timeout | 1..=120 s (padrão 15) |
| `max_pages` | 1..=50 (padrão 5) |
| `max_depth` | 3 |

## Concorrência

Tokio multi-thread. Subrecursos são buscados com um `Semaphore` de
`cfg.concurrency` dentro de `resources::fetch_resources`. O probe TLS usa
`spawn_blocking` (I/O bloqueante do `rustls` sobre `TcpStream`).
