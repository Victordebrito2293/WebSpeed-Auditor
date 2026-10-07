# Build e releases

## Requisitos

- Rust **1.88+** (edição 2024) — [rustup](https://rustup.rs)
- Sem dependências de sistema: TLS via `rustls` (ring), **sem OpenSSL**;
  binários estáticos em termos de bibliotecas dinâmicas além da libc padrão.

## Comandos

```bash
cargo build --release      # binário em target/release/webspeed-auditor
cargo test                 # 135+ testes (unidade, integração, SSRF)
cargo fmt --check          # formatação
cargo clippy --all-targets # lints (zero warnings; unsafe proibido)
cargo audit                # auditoria de dependências (CI)
```

O `release` profile usa `lto = "thin"`, `codegen-units = 1`, `strip = true`
e `panic = "abort"` para binários menores e sem símbolos.

## CI (`.github/workflows/ci.yml`)

Em cada push/PR:

1. `cargo fmt --check`
2. `cargo clippy --all-targets -- -D warnings`
3. `cargo test --locked`
4. `cargo audit` (auditoria de vulnerabilidades conhecidas nas dependências)

## Releases (`.github/workflows/release.yml`)

Em tag `v*`:

1. Build de binários para **linux** (x86_64, aarch64), **macos** (x86_64,
   aarch64) e **windows** (x86_64) — GNU para Linux, MSVC para Windows.
2. Empacotamento `.tar.gz` (ou `.zip` no Windows) com binário + `README.md` +
   `LICENSE`.
3. SHA-256 de cada artefato publicado junto do release.
4. Publicação via `softprops/action-gh-release` — **nenhum segredo é
   necessário** (token padrão do GitHub).

Nenhum workflow envia dados a serviços externos além do registro do GitHub.

## Versionamento

Semver a partir de `0.1.0`. A versão em `Cargo.toml` alimenta `--version` e o
campo `version` do relatório JSON.
