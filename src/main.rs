//! Ponto de entrada do WebSpeed Auditor.
//!
//! Nenhum arquivo é criado sem `--output`; o relatório padrão vai ao stdout
//! e os logs de progresso ao stderr.

use clap::Parser;
use webspeed_auditor::cli::Cli;
use webspeed_auditor::utils::log;
use webspeed_auditor::{audit, report};

fn main() {
    let cli = Cli::parse();

    let Some(url) = cli.resolve_url() else {
        if cli.url.is_some() {
            log::error("URL vazia.");
        } else {
            log::error("Nenhuma URL informada.");
        }
        std::process::exit(2);
    };

    let cfg = cli.to_config();

    let rt = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            log::error(&format!("falha ao iniciar o runtime: {e}"));
            std::process::exit(1);
        }
    };

    let result = rt.block_on(async { audit::run(&url, cfg).await });

    let report_data = match result {
        Ok(r) => r,
        Err(e) => {
            log::error(&e.to_string());
            std::process::exit(2);
        }
    };

    match report::render(&report_data, cli.format)
        .and_then(|content| report::write_output(&content, cli.output.as_deref()))
    {
        Ok(()) => {}
        Err(e) => {
            log::error(&e.to_string());
            std::process::exit(1);
        }
    }
}
