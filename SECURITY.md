# Segurança

## Escopo

O WebSpeed Auditor é uma ferramenta de auditoria local. Este documento descreve
as garantias de segurança do projeto e como reportar vulnerabilidades.

### Garantias

- **Proteção SSRF obrigatória e não desativável por CLI.** Toda URL é
  validada duas vezes — formato e endereços resolvidos — antes de cada
  requisição, inclusive a cada salto de redirect e em cada resolução feita
  pelo resolvedor do cliente HTTP (defesa contra DNS rebinding).
- Bloqueio de: loopback, redes privadas, link-local (incluindo metadados de
  cloud 169.254.169.254), CGNAT, endereços reservados, IPv6 unique-local,
  NAT64/6to4/Teredo, `localhost`/`*.localhost`/`metadata.google.internal`,
  URLs com credenciais (`user:pass@`) e esquemas diferentes de http/https.
- **Limites absolutos independentes de CLI**: 10 MiB por corpo de resposta,
  60 subrecursos por página, 10 redirects por cadeia, URLs de até 2048
  caracteres, concorrência de 1 a 16, timeout de 1 a 120 segundos.
- **Nenhum arquivo é criado sem `--output`.** Nada é persistido
  automaticamente; não há cache, banco ou diretório de estado.
- **Nenhum dado do operador no relatório.** O relatório contém apenas dados
  do site auditado (URLs, headers, tempos). Sem caminhos locais, usuário ou
  ambiente.
- **Set-Cookie**: apenas a contagem é reportada. Valores nunca são lidos,
  armazenados ou logados.
- **Conteúdo remoto é não confiável**: HTML malformado não pode causar pânico
  (parsers tolerantes e limites de tamanho); o relatório HTML escapa todo
  conteúdo dinâmico e é autocontido (sem `<script>`, sem recursos externos).
- **`unsafe` proibido** em todo o código-fonte (`unsafe_code = "forbid"`).
- **Sem telemetria**: sem analytics, crash reports, atualizador automático,
  contas ou chaves de API. O único tráfego é para o site auditado.
- Decompressão com limite (proteção contra zip bomb) e corte de streaming de
  corpos grandes.

### O que esta ferramenta NÃO é

- Não é um scanner de vulnerabilidades (não explora, não fuzzing, não envia
  payloads).
- Não executa JavaScript; portanto não detecta problemas que só aparecem em
  runtime.
- Não é um WAF e não protege sites — apenas relata observações.

## Reportando vulnerabilidades

Por favor **não** abra uma issue pública para vulnerabilidades.

Envie um e-mail ou use o formulário de segurança privado do GitHub
(Security → Report a vulnerability) com:

1. Descrição do problema e impacto.
2. Passos para reproduzir (URL de teste, versão, sistema operacional).
3. Vetor (SSRF, vazamento de dados, injeção no relatório HTML, dependência...).

Expectativa de resposta: confirmação em até 72 horas; correção coordenada
antes da divulgação pública (CVE quando aplicável).

## Uso responsável

A ferramenta só deve ser usada em sites que você tem permissão para auditar.
As proteções SSRF existem para evitar que um URL malicioso transforme a
ferramenta em um vetor de acesso a redes internas — mantenha-as sempre ativas.
