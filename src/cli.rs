//! Interface de linha de comando.

use crate::config::{Config, LogLevel};
use clap::{Parser, ValueEnum};
use std::io::{self, BufRead, Write};
use std::time::Duration;

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum OutputFormat {
    /// Relatório no terminal (padrão).
    Terminal,
    /// JSON estruturado, para CI/CD.
    Json,
    /// Relatório HTML autocontido.
    Html,
}

/// WebSpeed Auditor — auditoria local de performance web.
///
/// Exemplos:
///   webspeed-auditor
///   webspeed-auditor https://example.com
///   webspeed-auditor https://example.com --format json --output report.json
#[derive(Debug, Parser)]
#[command(
    name = "webspeed-auditor",
    version,
    about = "Auditoria local, offline e orientada a privacidade de performance de websites",
    long_about = None,
    arg_required_else_help = false
)]
pub struct Cli {
    /// URL do website a analisar. Se omitida, a ferramenta pede interativamente.
    #[arg(value_name = "URL")]
    pub url: Option<String>,

    /// Número máximo de páginas no crawl (1 = apenas a página inicial).
    #[arg(long, default_value_t = 5)]
    pub max_pages: usize,

    /// Timeout por operação de rede, em segundos (1-120).
    #[arg(long, default_value_t = 15)]
    pub timeout: u64,

    /// Requisições simultâneas (1-16).
    #[arg(long, default_value_t = 4)]
    pub concurrency: usize,

    /// Caminho do arquivo de relatório. Sem esta opção o relatório vai ao stdout.
    /// Nenhum arquivo é criado automaticamente.
    #[arg(long, value_name = "FILE")]
    pub output: Option<String>,

    /// Formato do relatório.
    #[arg(long, value_enum, default_value_t = OutputFormat::Terminal)]
    pub format: OutputFormat,

    /// Não rastrear links internos (analisa somente a página inicial).
    #[arg(long)]
    pub no_crawl: bool,

    /// Apenas o resultado final (sem progresso).
    #[arg(long, conflicts_with = "verbose")]
    pub quiet: bool,

    /// Detalhar o progresso e cada requisição.
    #[arg(long)]
    pub verbose: bool,

    // --- Extensões ---
    /// Usar navegador real (Chromium headless) para métricas reais (requer feature 'browser').
    #[arg(long)]
    pub browser: bool,
    /// Caminho customizado para binário Chrome/Chromium.
    #[arg(long)]
    pub browser_path: Option<String>,
    /// Perfil de ambiente: desktop, mobile, mobile-throttled, fast, slow-network.
    #[arg(long)]
    pub profile: Option<String>,
    /// Número de execuções para benchmark (padrão 1).
    #[arg(long)]
    pub runs: Option<u32>,
    /// Cache frio a cada execução (benchmark).
    #[arg(long)]
    pub cold_cache: bool,
    /// Cache quente (reutilizar conexões).
    #[arg(long)]
    pub warm_cache: bool,
    /// Condição de rede: slow-3g, fast-3g, offline.
    #[arg(long)]
    pub network_condition: Option<String>,
    /// Fator de CPU throttling (ex: 4 para 4x lento).
    #[arg(long)]
    pub cpu_throttling: Option<f64>,
    /// Viewport width.
    #[arg(long)]
    pub viewport_width: Option<u32>,
    /// Viewport height.
    #[arg(long)]
    pub viewport_height: Option<u32>,
    /// Device scale factor.
    #[arg(long)]
    pub device_scale_factor: Option<f64>,
}

impl Cli {
    /// Converte para a configuração interna, aplicando limites absolutos.
    pub fn to_config(&self) -> Config {
        let log_level = if self.quiet {
            LogLevel::Quiet
        } else if self.verbose {
            LogLevel::Verbose
        } else {
            LogLevel::Normal
        };
        Config {
            max_pages: self.max_pages,
            timeout: Duration::from_secs(self.timeout),
            concurrency: self.concurrency,
            crawl: !self.no_crawl,
            log_level,
            browser: self.browser,
            browser_path: self.browser_path.clone(),
            profile: self.profile.clone().unwrap_or_else(|| "desktop".into()),
            runs: self.runs.unwrap_or(1),
            cold_cache: self.cold_cache,
            warm_cache: self.warm_cache,
            network_condition: self.network_condition.clone(),
            cpu_throttling: self.cpu_throttling,
            viewport_width: self.viewport_width,
            viewport_height: self.viewport_height,
            device_scale_factor: self.device_scale_factor,
            ..Config::default()
        }
        .clamped()
    }

    /// Obtém a URL: argumento posicional ou prompt interativo.
    /// Retorna `None` se o usuário fornecer entrada vazia ou interromper.
    pub fn resolve_url(&self) -> Option<String> {
        if let Some(u) = &self.url {
            let trimmed = u.trim();
            if !trimmed.is_empty() {
                return Some(trimmed.to_string());
            }
            return None;
        }
        prompt_url()
    }
}

/// Banner + prompt interativo no estilo especificado.
fn prompt_url() -> Option<String> {
    let stdout = io::stdout();
    let mut out = stdout.lock();
    let _ = writeln!(out, "========================================");
    let _ = writeln!(out, "        WebSpeed Auditor");
    let _ = writeln!(out, "========================================");
    let _ = writeln!(out);
    let _ = writeln!(out, "Auditoria local de performance web");
    let _ = writeln!(out);
    let _ = write!(out, "URL do website:\n> ");
    let _ = out.flush();

    let stdin = io::stdin();
    let mut line = String::new();
    match stdin.lock().read_line(&mut line) {
        Ok(0) => None,
        Ok(_) => {
            let t = line.trim();
            if t.is_empty() {
                None
            } else {
                Some(t.to_string())
            }
        }
        Err(_) => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_no_args() {
        let cli = Cli::try_parse_from(["webspeed-auditor"]).expect("sem argumentos deve aceitar");
        assert!(cli.url.is_none());
        assert!(!cli.no_crawl);
        assert_eq!(cli.format, OutputFormat::Terminal);
    }

    #[test]
    fn parses_url_and_flags() {
        let cli = Cli::try_parse_from([
            "webspeed-auditor",
            "https://example.com",
            "--max-pages",
            "3",
            "--timeout",
            "30",
            "--concurrency",
            "2",
            "--no-crawl",
            "--format",
            "json",
            "--output",
            "r.json",
        ])
        .expect("parse");
        assert_eq!(cli.url.as_deref(), Some("https://example.com"));
        assert_eq!(cli.max_pages, 3);
        assert_eq!(cli.timeout, 30);
        assert_eq!(cli.concurrency, 2);
        assert!(cli.no_crawl);
        assert_eq!(cli.format, OutputFormat::Json);
        assert_eq!(cli.output.as_deref(), Some("r.json"));
    }

    #[test]
    fn help_and_version_work() {
        let help = Cli::try_parse_from(["webspeed-auditor", "--help"]).unwrap_err();
        assert_eq!(help.kind(), clap::error::ErrorKind::DisplayHelp);
        let version = Cli::try_parse_from(["webspeed-auditor", "--version"]).unwrap_err();
        assert_eq!(version.kind(), clap::error::ErrorKind::DisplayVersion);
    }

    #[test]
    fn config_applies_absolute_limits() {
        let cli = Cli::try_parse_from([
            "webspeed-auditor",
            "https://example.com",
            "--concurrency",
            "9999",
            "--max-pages",
            "9999",
            "--timeout",
            "99999",
        ])
        .expect("parse");
        let cfg = cli.to_config();
        assert!(cfg.concurrency <= 16);
        assert!(cfg.max_pages <= 50);
        assert!(cfg.timeout.as_secs() <= 120);
    }

    #[test]
    fn quiet_and_verbose_conflict() {
        assert!(Cli::try_parse_from(["webspeed-auditor", "--quiet", "--verbose"]).is_err());
    }
}
