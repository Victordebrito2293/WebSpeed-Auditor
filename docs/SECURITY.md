# Segurança em detalhes

Companion técnico de [`../SECURITY.md`](../SECURITY.md) (processo de
divulgação e garantias). Este documento descreve **como** as garantias são
implementadas.

## Modelo de ameaças

| Ameaça | Mitigação |
|---|---|
| Auditoria acionada por URL hostil aponta para rede interna | SSRF: validação de forma + validação de IPs em **todas** as camadas |
| DNS rebinding (IP público na validação, privado na conexão) | `SafeResolver` revalida **cada resolução** feita pelo reqwest |
| Redirect para `http://169.254.169.254/` (metadata cloud) | Revalidação da política **a cada salto** de redirect |
| Redirect em loop / cadeia infinita | Limite de 10 saltos + detecção de loop (`loop_detected`) |
| Zip bomb / resposta enorme | Corte em streaming (10 MiB) + limite no decompressor |
| HTML malformado causa pânico | Parser tolerante; `panic = "abort"` no release; testes de fuzzing básico (`malformed_html_does_not_panic`, `huge_html_is_parsed...`) |
| Injeção no relatório HTML (XSS ao abrir o arquivo) | Todo conteúdo dinâmico passa por `html_escape` (inclui `&<>"'`); relatório sem `<script>` e sem recursos externos |
| Vazamento de dados locais no relatório compartilhado | Relatório contém apenas dados do alvo; teste `audit_report_has_no_operator_data` |
| Vazamento de cookies/sessão | `Set-Cookie` apenas contado; valores nunca persistidos |
| Vazamento por logs | Logs apenas em stderr, sem corpo de resposta; sem arquivo de log |
| Dependência comprometida | Dependências mínimas, `cargo audit` no CI, `Cargo.lock` versionado |

## As duas camadas do SSRF

### Camada 1 — forma (`validate_url_shape`, sem rede)

- Esquema deve ser `http`/`https`.
- Sem credenciais na URL (`user:pass@`).
- URL ≤ 2048 caracteres.
- Hostnames proibidos: `localhost`, `*.localhost`, `metadata`,
  `metadata.google.internal`, `instance-data`.

Executada em `audit::normalize_url_input` **antes de qualquer requisição** e
novamente em cada requisição/redirect.

### Camada 2 — endereços (`ip_is_blocked` / `check_ips`)

Bloqueados (IPv4 e IPv6, incluindo mapeamentos `::ffff:`):

- loopback, privadas (10/8, 172.16/12, 192.168/16), link-local 169.254/16
  (metadata AWS/GCP/Azure), unspecified, broadcast, multicast, documentação;
- `0.0.0.0/8`, CGNAT `100.64/10` (inclui metadados Alibaba),
  `192.0.0/24` (metadados Oracle), benchmark `198.18/15`, `240/4`;
- IPv6: unique-local `fc00::/7`, link-local `fe80::/10`, documentação
  `2001:db8::/32`, NAT64 `64:ff9b::/48`, Teredo `2001::/32`, 6to4 `2002::/16`;
- Azure wire server `168.63.129.16`.

A política só pode ser desativada por código (`Config::for_local_tests()`);
**não existe flag de CLI**.

## Revalidação contínua

1. `audit::run` valida a forma da URL de entrada.
2. `AuditClient::fetch` valida a forma de cada URL e de cada salto de
   redirect (com limite de 10 saltos e detecção de loop).
3. `SafeResolver` (injetado via `dns_resolver`) aplica `check_ips` em **cada**
   resolução usada pelas conexões do reqwest — cobre a janela entre a
   validação inicial e a abertura do socket (DNS rebinding).
4. O probe TLS conecta somente aos endereços já resolvidos e validados.

## Limites rígidos

Definidos em `src/config.rs`, aplicados mesmo que a CLI peça valores maiores:

`MAX_BODY_BYTES` 10 MiB · `MAX_RESOURCES` 60 · `MAX_REDIRECTS` 10 ·
`MAX_URL_LENGTH` 2048 · concorrência 1–16 · timeout 1–120 s ·
páginas 1–50.

## Superfície de entrada

- URL do usuário (validada como acima).
- Respostas HTTP de terceiros: tratadas como **não confiáveis** — nunca
  executadas, nunca inseridas sem escape, limitadas em tamanho e profundidade.
- `robots.txt` e `Content-Type`: parsers tolerantes, sem panic.
- Nenhum servidor local é aberto pela aplicação (o `testserver` só existe
  para testes e nunca é iniciado pela CLI).
