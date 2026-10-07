# Contribuindo

Obrigado por ajudar! O projeto é pequeno por design: prefiro mudanças
pequenas, verificáveis e alinhadas aos princípios abaixo.

## Princípios inegociáveis

1. **Privacidade**: nada persistido, nada enviado a terceiros, nenhum dado do
   operador no relatório.
2. **Segurança**: nenhuma mudança pode enfraquecer a validação SSRF, os
   limites absolutos ou a proibição de `unsafe`.
3. **Honestidade**: toda métrica indisponível é reportada como indisponível.
   Nenhum número inventado, nenhum "score" sem base mensurável.
4. **Sem dependências pesadas sem necessidade**: cada nova dependência deve
   ser justificada (manutenção, superfície de ataque, binário estático).

## Ambiente

```bash
rustup update          # Rust 1.88+ (edição 2024)
cargo test             # todos os testes (unidade + integração)
cargo fmt --check
cargo clippy --all-targets
```

Os testes usam um servidor HTTP local (`src/testserver.rs`) — nenhum teste
depende de internet.

## Estrutura

| Caminho | Papel |
|---|---|
| `src/audit.rs` | Orquestração ponta a ponta (falhas parciais não abortam) |
| `src/scanner/` | Coleta e análise por categoria (redes, HTML, recursos...) |
| `src/analysis/` | `Section` (testes/findings/limitações), scoring, recomendações |
| `src/models/` | Tipos serializáveis compartilhados |
| `src/utils/` | SSRF, robots.txt, decodificação, logs, tempo |
| `src/report/` | Terminal (ANSI), JSON, HTML |
| `src/testserver.rs` | Servidor HTTP local para testes |
| `tests/` | Testes de integração (E2E + suite SSRF) |

## Checklist para um PR

- [ ] `cargo fmt --check`, `cargo clippy --all-targets` e `cargo test` limpos.
- [ ] Mudanças de comportamento documentadas (README/docs).
- [ ] Novos limiares adicionados a `docs/SCORING.md`.
- [ ] Nenhum dado do operador pode aparecer em relatório/log.
- [ ] Nenhuma URL de teste real de terceiros em testes (usar o testserver).

## Commits

Mensagens curtas em inglês ou português, no formato
`tipo: descrição` (ex.: `fix: revalida SSRF a cada salto de redirect`).
