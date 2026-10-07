//! Análise de CSS: quantidade, tamanho, duplicação e bloqueio de renderização.

use crate::analysis::Section;
use crate::models::{Category, CssInfo, Finding, Severity, TestItem, TestStatus};
use crate::scanner::html::HtmlAnalysis;
use crate::scanner::resources::FetchedResource;
use crate::utils::timex::fmt_bytes;

/// Limiares documentados (ver docs/SCORING.md).
pub const CSS_TOTAL_WARN_BYTES: u64 = 100 * 1024;
pub const CSS_FILES_WARN: usize = 8;
pub const INLINE_CSS_WARN_BYTES: u64 = 32 * 1024;

pub fn analyze(html: &HtmlAnalysis, fetched: &[FetchedResource]) -> (CssInfo, Section) {
    let mut section = Section::default();
    let mut info = CssInfo {
        external_urls: html
            .resources
            .iter()
            .filter(|r| r.kind == crate::models::ResourceKind::Css)
            .map(|r| r.url.clone())
            .collect(),
        inline_bytes: html.info.inline_style_bytes as u64,
        ..CssInfo::default()
    };

    // Folhas externas coletadas com sucesso.
    let mut css_records: Vec<&FetchedResource> = Vec::new();
    for f in fetched
        .iter()
        .filter(|f| f.record.kind == crate::models::ResourceKind::Css)
    {
        css_records.push(f);
        if let Some(size) = f.record.decoded_size.or(f.record.transfer_size) {
            info.total_bytes += size;
        }
    }
    info.file_count = info.external_urls.len();

    // Duplicatas (mesma URL referenciada mais de uma vez no HTML).
    info.duplicate_urls = html
        .info
        .duplicate_resources
        .iter()
        .filter(|u| {
            html.resources
                .iter()
                .any(|r| r.url.as_str() == u.as_str() && r.kind == crate::models::ResourceKind::Css)
        })
        .cloned()
        .collect();

    // --- Testes ---

    section.tests.push(TestItem::new(
        Category::Css,
        "Folhas de estilo externas",
        if info.file_count > CSS_FILES_WARN {
            TestStatus::Warning
        } else {
            TestStatus::Pass
        },
        format!("{} folha(s) externa(s)", info.file_count),
    ));

    section.tests.push(TestItem::new(
        Category::Css,
        "Volume total de CSS",
        if info.total_bytes > CSS_TOTAL_WARN_BYTES {
            TestStatus::Warning
        } else if info.total_bytes == 0 && info.file_count == 0 && info.inline_bytes == 0 {
            TestStatus::NotTested
        } else {
            TestStatus::Pass
        },
        format!(
            "{} externo + {} inline",
            fmt_bytes(info.total_bytes),
            fmt_bytes(info.inline_bytes)
        ),
    ));

    if info.duplicate_urls.is_empty() {
        section.tests.push(TestItem::new(
            Category::Css,
            "CSS duplicado",
            TestStatus::Pass,
            "nenhuma folha referenciada mais de uma vez".to_string(),
        ));
    } else {
        section.tests.push(
            TestItem::new(
                Category::Css,
                "CSS duplicado",
                TestStatus::Warning,
                format!("{} URL(s) duplicada(s)", info.duplicate_urls.len()),
            )
            .with_evidence(info.duplicate_urls.join(", ")),
        );
        section.findings.push(Finding {
            id: "css_duplicate".into(),
            category: Category::Css,
            severity: Severity::Medium,
            title: "Folhas de estilo duplicadas".into(),
            problem: "A mesma folha de estilo é referenciada mais de uma vez na página, causando downloads e parsing redundantes.".into(),
            evidence: format!("URLs duplicadas: {}", info.duplicate_urls.join(", ")),
            impact: "Impacto não quantificado neste ambiente.".into(),
            recommendation: "Remover referências duplicadas ou unificar as folhas em um único arquivo.".into(),
        });
    }

    // CSS inline relevante bloqueia o first paint até ser parseado.
    if info.inline_bytes > INLINE_CSS_WARN_BYTES {
        section.tests.push(
            TestItem::new(
                Category::Css,
                "CSS inline no HTML",
                TestStatus::Warning,
                format!(
                    "{} de CSS inline acima do limiar de {}",
                    fmt_bytes(info.inline_bytes),
                    fmt_bytes(INLINE_CSS_WARN_BYTES)
                ),
            )
            .with_evidence("Blocos <style> somados no <head>"),
        );
        section.findings.push(Finding {
            id: "css_inline_large".into(),
            category: Category::Css,
            severity: Severity::Low,
            title: "CSS inline acima do recomendado".into(),
            problem: "Grande volume de CSS embutido no HTML aumenta o tamanho do documento e atrasa o início do render.".into(),
            evidence: format!("{} de CSS inline", fmt_bytes(info.inline_bytes)),
            impact: "Impacto não quantificado neste ambiente.".into(),
            recommendation: "Mover parte do CSS inline para arquivos externos com cache, mantendo apenas o CSS crítico inline.".into(),
        });
    }

    if info.total_bytes > CSS_TOTAL_WARN_BYTES {
        section.findings.push(Finding {
            id: "css_too_large".into(),
            category: Category::Css,
            severity: Severity::Medium,
            title: "Volume elevado de CSS".into(),
            problem: "O CSS total excede o limiar documentado de auditoria.".into(),
            evidence: format!(
                "{} de CSS externo em {} arquivo(s); limiar: {}",
                fmt_bytes(info.total_bytes),
                info.file_count,
                fmt_bytes(CSS_TOTAL_WARN_BYTES)
            ),
            impact: "Impacto não quantificado neste ambiente.".into(),
            recommendation: "Remover regras não utilizadas (purge CSS), dividir CSS por rota e servir somente o necessário para a página inicial.".into(),
        });
    }

    // Falhas de fetch das folhas.
    let failed_records: Vec<String> = css_records
        .iter()
        .filter(|f| matches!(f.record.status, TestStatus::Fail | TestStatus::Error))
        .map(|f| {
            format!(
                "{} ({})",
                f.record.url,
                f.record
                    .error
                    .clone()
                    .unwrap_or_else(|| format!("HTTP {}", f.record.status_code.unwrap_or(0)))
            )
        })
        .collect();
    if !failed_records.is_empty() {
        section.tests.push(
            TestItem::new(
                Category::Css,
                "Recuperação de folhas de estilo",
                TestStatus::Fail,
                format!("{} falha(s)", failed_records.len()),
            )
            .with_evidence(failed_records.join("; ")),
        );
    }

    (info, section)
}
