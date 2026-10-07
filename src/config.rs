//! Configuração da execução. Sem arquivos de configuração persistentes:
//! tudo vem da linha de comando e existe apenas durante o processo.

use std::time::Duration;

/// Limite absoluto de concorrência imposto pelo programa (o usuário não
/// pode configurar valores maiores que isto).
pub const ABSOLUTE_MAX_CONCURRENCY: usize = 16;
/// Limite absoluto de páginas por auditoria.
pub const ABSOLUTE_MAX_PAGES: usize = 50;
/// Limite absoluto de timeout (segundos).
pub const ABSOLUTE_MAX_TIMEOUT_SECS: u64 = 120;
/// Tamanho máximo de corpo baixado por recurso, em bytes (10 MiB).
pub const MAX_BODY_BYTES: u64 = 10 * 1024 * 1024;
/// Limite de recursos (subrequests) analisados por auditoria.
pub const MAX_RESOURCES: usize = 60;
/// Limite máximo de redirects seguidos.
pub const MAX_REDIRECTS: usize = 10;
/// Tamanho máximo aceito para a URL de entrada.
pub const MAX_URL_LENGTH: usize = 2048;

#[derive(Debug, Clone)]
pub struct Config {
    /// Número máximo de páginas no crawl (1 = sem crawl multi-página).
    pub max_pages: usize,
    /// Profundidade máxima do crawl.
    pub max_depth: usize,
    /// Timeout por operação de rede.
    pub timeout: Duration,
    /// Requisições simultâneas (1..=16).
    pub concurrency: usize,
    /// Rastrear links internos (desativável com `--no-crawl`).
    pub crawl: bool,
    /// Nível de verbosidade dos logs em execução.
    pub log_level: LogLevel,
    /// User-Agent enviado — identifica a ferramanta e o projeto.
    pub user_agent: String,
    /// Proteção SSRF. `true` em todos os cenários de produção; só pode ser
    /// desativada por código (testes com servidor local). **Não existe flag
    /// de CLI para desativar isto.**
    pub ssrf_protection: bool,
    /// Tamanho máximo de corpo por recurso.
    pub max_body_bytes: u64,
    /// Máximo de recursos subrequest.
    pub max_resources: usize,
    /// Máximo de redirects.
    pub max_redirects: usize,
    pub browser: bool,
    pub browser_path: Option<String>,
    pub profile: String,
    pub runs: u32,
    pub cold_cache: bool,
    pub warm_cache: bool,
    pub network_condition: Option<String>,
    pub cpu_throttling: Option<f64>,
    pub viewport_width: Option<u32>,
    pub viewport_height: Option<u32>,
    pub device_scale_factor: Option<f64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogLevel {
    Quiet,
    Normal,
    Verbose,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            max_pages: 5,
            max_depth: 3,
            timeout: Duration::from_secs(15),
            concurrency: 4,
            crawl: true,
            log_level: LogLevel::Normal,
            user_agent: format!(
                "WebSpeed-Auditor/{} (+https://github.com/webspeed-auditor/webspeed-auditor)",
                env!("CARGO_PKG_VERSION")
            ),
            ssrf_protection: true,
            max_body_bytes: MAX_BODY_BYTES,
            max_resources: MAX_RESOURCES,
            max_redirects: MAX_REDIRECTS,
            browser: false,
            browser_path: None,
            profile: "desktop".into(),
            runs: 1,
            cold_cache: false,
            warm_cache: false,
            network_condition: None,
            cpu_throttling: None,
            viewport_width: None,
            viewport_height: None,
            device_scale_factor: None,
        }
    }
}

impl Config {
    /// Ajusta valores fora dos limites em vez de rejeitar o usuário.
    pub fn clamped(mut self) -> Self {
        self.max_pages = self.max_pages.clamp(1, ABSOLUTE_MAX_PAGES);
        self.max_depth = self.max_depth.clamp(1, 10);
        self.concurrency = self.concurrency.clamp(1, ABSOLUTE_MAX_CONCURRENCY);
        let secs = self.timeout.as_secs().clamp(1, ABSOLUTE_MAX_TIMEOUT_SECS);
        self.timeout = Duration::from_secs(secs);
        self.max_redirects = self.max_redirects.clamp(1, MAX_REDIRECTS);
        self.max_body_bytes = self.max_body_bytes.clamp(1024, MAX_BODY_BYTES);
        self.max_resources = self.max_resources.clamp(1, 500);
        self
    }

    /// Modo exclusivamente para testes de integração com servidor local.
    /// Nunca é exposto na interface de linha de comando.
    #[doc(hidden)]
    pub fn for_local_tests() -> Self {
        Self {
            ssrf_protection: false,
            max_pages: 3,
            timeout: Duration::from_secs(5),
            concurrency: 2,
            crawl: true,
            ..Self::default()
        }
    }
}

#[allow(dead_code)]
fn default_profile() -> String {
    "desktop".into()
}
#[allow(dead_code)]
fn default_runs() -> u32 {
    1
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_is_conservative() {
        let c = Config::default();
        assert!(c.ssrf_protection);
        assert!(c.concurrency <= ABSOLUTE_MAX_CONCURRENCY);
        assert!(c.max_pages <= ABSOLUTE_MAX_PAGES);
        assert_eq!(c.log_level, LogLevel::Normal);
    }

    #[test]
    fn clamping_limits_absurd_values() {
        let c = Config {
            max_pages: 10_000,
            concurrency: 9_999,
            timeout: Duration::from_secs(99_999),
            ..Config::default()
        }
        .clamped();
        assert_eq!(c.max_pages, ABSOLUTE_MAX_PAGES);
        assert_eq!(c.concurrency, ABSOLUTE_MAX_CONCURRENCY);
        assert_eq!(c.timeout.as_secs(), ABSOLUTE_MAX_TIMEOUT_SECS);
    }

    #[test]
    fn clamping_limits_tiny_values() {
        let c = Config {
            max_pages: 0,
            concurrency: 0,
            timeout: Duration::from_secs(0),
            ..Config::default()
        }
        .clamped();
        assert_eq!(c.max_pages, 1);
        assert_eq!(c.concurrency, 1);
        assert_eq!(c.timeout.as_secs(), 1);
    }
}
