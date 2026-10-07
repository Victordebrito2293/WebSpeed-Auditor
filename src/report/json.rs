//! Relatório JSON estruturado para CI/CD. O objeto serializado é exatamente
//! o `AuditReport` — sem metadados locais, caminhos ou dados do operador.

use super::ReportError;
use crate::models::AuditReport;

pub fn render(report: &AuditReport) -> Result<String, ReportError> {
    serde_json::to_string_pretty(report).map_err(|e| ReportError::Serialize(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::report::fixtures::sample_report;

    #[test]
    fn json_is_valid_and_round_trips() {
        let r = sample_report();
        let out = render(&r).expect("render");
        let parsed: AuditReport = serde_json::from_str(&out).expect("JSON válido e tipado");
        assert_eq!(parsed.tool, "WebSpeed Auditor");
        assert_eq!(parsed.scores.score, 87);
        assert_eq!(parsed.findings.len(), 1);
        assert_eq!(parsed.findings[0].id, "test_finding");
        assert_eq!(parsed.not_tested.len(), 1);
        assert_eq!(parsed.optimized.len(), 1);
    }

    #[test]
    fn json_contains_no_ansi_or_local_paths() {
        let r = sample_report();
        let out = render(&r).expect("render");
        assert!(!out.contains("\x1b["));
        // O JSON só pode conter a URL alvo, não dados do operador.
        assert!(!out.contains("/Users/"));
        assert!(out.contains("https://example.com/"));
    }

    #[test]
    fn json_keeps_html_unescaped_in_data() {
        // JSON é dado bruto (não HTML): o título deve estar como string JSON válida.
        let r = sample_report();
        let out = render(&r).expect("render");
        assert!(out.contains("alert(1)"));
    }
}
