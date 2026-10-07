//! Análise de fontes web: quantidade, formatos, preload e volume.

use crate::analysis::Section;
use crate::models::{Category, Finding, FontsInfo, ResourceKind, Severity, TestItem, TestStatus};
use crate::scanner::html::HtmlAnalysis;
use crate::scanner::resources::FetchedResource;
use crate::utils::timex::fmt_bytes;

/// Limiares documentados (ver docs/SCORING.md).
pub const FONTS_TOTAL_WARN_BYTES: u64 = 200 * 1024;

pub fn analyze(html: &HtmlAnalysis, fetched: &[FetchedResource]) -> (FontsInfo, Section) {
    let mut section = Section::default();

    let font_refs: Vec<_> = html
        .resources
        .iter()
        .filter(|r| r.kind == ResourceKind::Font)
        .collect();

    let mut info = FontsInfo {
        count: font_refs.len(),
        external_count: font_refs.iter().filter(|r| r.external).count(),
        preloaded: font_refs.iter().filter(|r| r.preloaded).count(),
        ..FontsInfo::default()
    };

    for f in fetched
        .iter()
        .filter(|f| f.record.kind == ResourceKind::Font)
    {
        info.total_bytes += f
            .record
            .decoded_size
            .or(f.record.transfer_size)
            .unwrap_or(0);
        if let Some(ct) = &f.record.content_type {
            let fmt = ct.split(';').next().unwrap_or("").trim().to_string();
            if !info.formats.contains(&fmt) {
                info.formats.push(fmt);
            }
        }
        if let Some(name) = font_family_hint(&f.record.url)
            && !info.families.contains(&name)
        {
            info.families.push(name);
        }
    }

    if info.count == 0 {
        section.tests.push(TestItem::new(
            Category::BestPractices,
            "Fontes web",
            TestStatus::NotTested,
            "nenhuma fonte referenciada no HTML (fontes embutidas em CSS não são detectadas)"
                .to_string(),
        ));
        return (info, section);
    }

    section.tests.push(TestItem::new(
        Category::BestPractices,
        "Fontes carregadas",
        TestStatus::Pass,
        format!(
            "{} fonte(s), {} externa(s), {} pré-carregada(s), {}",
            info.count,
            info.external_count,
            info.preloaded,
            fmt_bytes(info.total_bytes)
        ),
    ));

    if info.total_bytes > FONTS_TOTAL_WARN_BYTES {
        section.tests.push(
            TestItem::new(
                Category::BestPractices,
                "Volume de fontes",
                TestStatus::Warning,
                format!(
                    "{} acima de {}",
                    fmt_bytes(info.total_bytes),
                    fmt_bytes(FONTS_TOTAL_WARN_BYTES)
                ),
            )
            .with_evidence(format!("{} arquivo(s) de fonte", info.count)),
        );
        section.findings.push(Finding {
            id: "fonts_too_much".into(),
            category: Category::BestPractices,
            severity: Severity::Low,
            title: "Volume elevado de fontes".into(),
            problem: "O conjunto de fontes ultrapassa o limiar documentado de auditoria.".into(),
            evidence: format!("{} em {} arquivo(s)", fmt_bytes(info.total_bytes), info.count),
            impact: "Impacto não quantificado neste ambiente.".into(),
            recommendation: "Limitar famílias e pesos, subsetar as fontes e avaliar o uso de system-ui para textos não críticos.".into(),
        });
    }

    if info.external_count > 0 && info.preloaded == 0 {
        section.tests.push(TestItem::new(
            Category::BestPractices,
            "Preload de fontes externas",
            TestStatus::Warning,
            format!(
                "{} fonte(s) externa(s) sem <link rel=preload>",
                info.external_count
            ),
        ));
        section.findings.push(Finding {
            id: "fonts_no_preload".into(),
            category: Category::BestPractices,
            severity: Severity::Low,
            title: "Fontes externas sem preload".into(),
            problem: "Fontes só são descobertas após o parse do CSS, atrasando o texto renderizado (FOIT/FOUT).".into(),
            evidence: format!("{} fonte(s) externa(s) e 0 preloads", info.external_count),
            impact: "Impacto não quantificado neste ambiente.".into(),
            recommendation: "Adicionar <link rel=preload as=font type=font/woff2 crossorigin> para a fonte crítica (apenas a necessária ao first paint).".into(),
        });
    }

    (info, section)
}

/// Heurística simples de nome de família a partir do filename.
fn font_family_hint(url: &str) -> Option<String> {
    let name = url.rsplit('/').next()?;
    let stem = name.split('.').next()?;
    if stem.is_empty() {
        return None;
    }
    Some(stem.replace(['-', '_'], " "))
}
