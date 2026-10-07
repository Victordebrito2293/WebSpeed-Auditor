//! Relatórios de saída. O JSON e o HTML nunca contêm dados locais do
//! operador — apenas informações da URL alvo já presentes no relatório.

pub mod html;
pub mod json;
pub mod terminal;

use crate::cli::OutputFormat;
use crate::models::AuditReport;

#[derive(Debug)]
pub enum ReportError {
    Serialize(String),
    Io(String),
}

impl std::fmt::Display for ReportError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ReportError::Serialize(e) => write!(f, "falha ao serializar o relatório: {e}"),
            ReportError::Io(e) => write!(f, "falha ao gravar o relatório: {e}"),
        }
    }
}

impl std::error::Error for ReportError {}

/// Renderiza o relatório no formato solicitado.
pub fn render(report: &AuditReport, format: OutputFormat) -> Result<String, ReportError> {
    match format {
        OutputFormat::Terminal => Ok(terminal::render(report)),
        OutputFormat::Json => json::render(report),
        OutputFormat::Html => Ok(html::render(report)),
    }
}

/// Escreve o relatório. `None` em `output` significa stdout (nada é gravado
/// em disco sem que o usuário solicite explicitamente).
pub fn write_output(content: &str, output: Option<&str>) -> Result<(), ReportError> {
    match output {
        None => {
            use std::io::Write;
            let stdout = std::io::stdout();
            let mut lock = stdout.lock();
            lock.write_all(content.as_bytes())
                .and_then(|_| {
                    if !content.ends_with('\n') {
                        lock.write_all(b"\n")
                    } else {
                        Ok(())
                    }
                })
                .map_err(|e| ReportError::Io(e.to_string()))?;
            lock.flush().map_err(|e| ReportError::Io(e.to_string()))?;
            Ok(())
        }
        Some(path) => {
            std::fs::write(path, content).map_err(|e| ReportError::Io(format!("{path}: {e}")))?;
            crate::utils::log::progress(&format!("Relatório gravado em {path}"));
            Ok(())
        }
    }
}

#[cfg(test)]
pub(crate) mod fixtures {
    use crate::models::*;

    pub fn sample_report() -> AuditReport {
        AuditReport {
            tool: "WebSpeed Auditor".into(),
            version: "0.1.0".into(),
            url: "https://example.com/".into(),
            final_url: "https://example.com/".into(),
            generated_at_unix: 1_700_000_000,
            generated_at_iso8601: "2023-11-14T22:13:20Z".into(),
            duration_ms: 1234,
            pages_analyzed: 1,
            requests_analyzed: 3,
            scores: OverallScore {
                score: 87,
                categories: vec![CategoryScore {
                    category: Category::Performance,
                    score: 80,
                    checks: 2,
                    passed: 1,
                    deduction: 10,
                }],
            },
            tests: vec![TestItem::new(
                Category::Performance,
                "Documento principal",
                TestStatus::Pass,
                "HTTP 200",
            )],
            findings: vec![Finding {
                id: "test_finding".into(),
                category: Category::Performance,
                severity: Severity::High,
                title: "Título <script>alert(1)</script>".into(),
                problem: "Problema.".into(),
                evidence: "evidência".into(),
                impact: "Impacto não quantificado neste ambiente.".into(),
                recommendation: "Corrigir.".into(),
            }],
            optimized: vec![TestItem::new(
                Category::Performance,
                "Documento principal",
                TestStatus::Pass,
                "HTTP 200",
            )],
            not_tested: vec![Limitation {
                area: "Core Web Vitals".into(),
                reason: "Não disponível neste ambiente.".into(),
            }],
            dns: DnsInfo {
                status: TestStatus::Pass,
                detail: "ok".into(),
                ipv4: vec!["93.184.216.34".into()],
                ipv6: vec![],
                resolution_ms: Some(10),
            },
            tls: None,
            redirects: RedirectChain {
                status: TestStatus::Pass,
                detail: "sem redirects".into(),
                hops: vec![],
                final_url: "https://example.com/".into(),
                loop_detected: false,
            },
            http: None,
            html: None,
            css: CssInfo::default(),
            javascript: JsInfo::default(),
            images: ImagesInfo::default(),
            fonts: FontsInfo::default(),
            cache: CacheInfo::default(),
            compression: CompressionInfo::default(),
            resources: vec![],
            pages: vec!["https://example.com/".into()],
        }
    }
}
