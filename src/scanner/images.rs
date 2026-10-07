//! Análise de imagens: formato, dimensões declaradas, lazy loading,
//! srcset e tamanho dos arquivos coletados (magic bytes, sem executar nada).

use crate::analysis::Section;
use crate::models::{Category, Finding, ImagesInfo, ResourceKind, Severity, TestItem, TestStatus};
use crate::scanner::html::HtmlAnalysis;
use crate::scanner::resources::FetchedResource;
use crate::utils::sniff;
use crate::utils::timex::fmt_bytes;

/// Limiares documentados (ver docs/SCORING.md).
pub const IMAGE_OVERSIZE_BYTES: u64 = 300 * 1024;
pub const IMAGE_MODERNIZE_BYTES: u64 = 100 * 1024;

pub fn analyze(html: &HtmlAnalysis, fetched: &[FetchedResource]) -> (ImagesInfo, Section) {
    let mut section = Section::default();

    let img_refs: Vec<_> = html
        .resources
        .iter()
        .filter(|r| r.kind == ResourceKind::Image)
        .collect();

    let mut info = ImagesInfo {
        count: img_refs.len(),
        without_dimensions: img_refs.iter().filter(|r| !r.has_dimensions).count(),
        without_lazy: img_refs.iter().filter(|r| !r.lazy).count(),
        with_srcset: img_refs.iter().filter(|r| r.srcset).count(),
        ..ImagesInfo::default()
    };

    let img_records: Vec<&FetchedResource> = fetched
        .iter()
        .filter(|f| f.record.kind == ResourceKind::Image)
        .collect();

    for f in &img_records {
        let size = f
            .record
            .decoded_size
            .or(f.record.transfer_size)
            .unwrap_or(0);
        info.total_bytes += size;

        if let Some(fmt) = &f.record.sniffed_format {
            if sniff::is_modern_image_format(fmt) {
                info.modern_format += 1;
            } else if sniff::is_legacy_image_format(fmt) {
                info.legacy_format += 1;
            }
            // Content-Type declarado x formato real.
            if f.record.status == TestStatus::Pass
                && sniff::content_type_match_status(f.record.content_type.as_deref(), fmt)
                    == TestStatus::Fail
            {
                info.format_mismatch.push(format!(
                    "{} (declarado: {}, real: {})",
                    f.record.url,
                    f.record.content_type.as_deref().unwrap_or("?"),
                    fmt
                ));
            }
        }
        if size > IMAGE_OVERSIZE_BYTES {
            info.oversized
                .push(format!("{} ({})", f.record.url, fmt_bytes(size)));
        }
    }

    // --- Testes ---

    if info.count == 0 {
        section.tests.push(TestItem::new(
            Category::Images,
            "Imagens na página",
            TestStatus::NotTested,
            "nenhuma imagem referenciada no HTML".to_string(),
        ));
        return (info, section);
    }

    section.tests.push(TestItem::new(
        Category::Images,
        "Dimensões declaradas (width/height)",
        if info.without_dimensions > 0 {
            TestStatus::Warning
        } else {
            TestStatus::Pass
        },
        format!(
            "{} de {} sem width/height",
            info.without_dimensions, info.count
        ),
    ));

    section.tests.push(TestItem::new(
        Category::Images,
        "Lazy loading",
        if info.without_lazy > 0 {
            TestStatus::Warning
        } else {
            TestStatus::Pass
        },
        format!(
            "{} de {} sem loading=\"lazy\"",
            info.without_lazy, info.count
        ),
    ));

    section.tests.push(TestItem::new(
        Category::Images,
        "Imagens responsivas (srcset)",
        if info.with_srcset == 0 && info.count > 1 {
            TestStatus::Warning
        } else {
            TestStatus::Pass
        },
        format!("{}/{} com srcset", info.with_srcset, info.count),
    ));

    if info.without_dimensions > 0 {
        section.findings.push(Finding {
            id: "img_no_dimensions".into(),
            category: Category::Images,
            severity: Severity::Medium,
            title: "Imagens sem dimensões declaradas".into(),
            problem: "Imagens sem atributos width/height causam deslocamento do layout (CLS) durante o carregamento.".into(),
            evidence: format!("{} imagem(ns) sem width/height no HTML", info.without_dimensions),
            impact: "Impacto não quantificado neste ambiente.".into(),
            recommendation: "Declarar width e height em todas as imagens (mesmo com CSS responsivo via aspect-ratio).".into(),
        });
    }

    if !info.oversized.is_empty() {
        section.tests.push(
            TestItem::new(
                Category::Images,
                "Imagens com peso elevado",
                TestStatus::Warning,
                format!(
                    "{} acima de {}",
                    info.oversized.len(),
                    fmt_bytes(IMAGE_OVERSIZE_BYTES)
                ),
            )
            .with_evidence(info.oversized.join(", ")),
        );
        section.findings.push(Finding {
            id: "img_oversized".into(),
            category: Category::Images,
            severity: Severity::Medium,
            title: "Imagens muito pesadas".into(),
            problem: "Arquivos de imagem acima do limiar aumentam o tempo de download e o uso de memória.".into(),
            evidence: info.oversized.join(", "),
            impact: "Impacto não quantificado neste ambiente.".into(),
            recommendation: "Reduzir dimensões ao tamanho real de exibição, comprimir e servir em formato moderno (WebP/AVIF).".into(),
        });
    }

    // Só sugerimos conversão de formato quando o arquivo é grande o suficiente
    // para justificar a troca (contexto, não regra cega).
    if info.legacy_format > 0 {
        let legacy_big: Vec<String> = img_records
            .iter()
            .filter(|f| {
                f.record
                    .sniffed_format
                    .as_deref()
                    .is_some_and(sniff::is_legacy_image_format)
                    && f.record
                        .decoded_size
                        .or(f.record.transfer_size)
                        .unwrap_or(0)
                        > IMAGE_MODERNIZE_BYTES
            })
            .map(|f| f.record.url.clone())
            .collect();
        if !legacy_big.is_empty() {
            section.tests.push(
                TestItem::new(
                    Category::Images,
                    "Formato de imagem moderno",
                    TestStatus::Warning,
                    format!(
                        "{} imagem(ns) grande(s) em formato legado",
                        legacy_big.len()
                    ),
                )
                .with_evidence(legacy_big.join(", ")),
            );
            section.findings.push(Finding {
                id: "img_legacy_format".into(),
                category: Category::Images,
                severity: Severity::Low,
                title: "Formatos de imagem legados em arquivos grandes".into(),
                problem: "Imagens grandes em formatos antigos ocupam mais bytes do que formatos modernos equivalentes.".into(),
                evidence: legacy_big.join(", "),
                impact: "Impacto não quantificado neste ambiente.".into(),
                recommendation: "Converter para WebP ou AVIF com fallback; manter JPEG/PNG apenas quando o ganho for insignificante.".into(),
            });
        }
    }

    if !info.format_mismatch.is_empty() {
        section.tests.push(
            TestItem::new(
                Category::Images,
                "Content-Type x conteúdo real",
                TestStatus::Fail,
                format!("{} divergência(s)", info.format_mismatch.len()),
            )
            .with_evidence(info.format_mismatch.join("; ")),
        );
        section.findings.push(Finding {
            id: "img_content_type_mismatch".into(),
            category: Category::Images,
            severity: Severity::Medium,
            title: "Content-Type divergente do conteúdo real".into(),
            problem: "O Content-Type declarado não corresponde aos bytes servidos, o que pode causar fallback de parse ou bloqueio.".into(),
            evidence: info.format_mismatch.join("; "),
            impact: "Impacto não quantificado neste ambiente.".into(),
            recommendation: "Corrigir o Content-Type no servidor/CDN para corresponder ao formato real do arquivo.".into(),
        });
    }

    if info.without_lazy > 0 {
        section.findings.push(Finding {
            id: "img_no_lazy".into(),
            category: Category::Images,
            severity: Severity::Low,
            title: "Imagens sem lazy loading".into(),
            problem: "Imagens abaixo da dobra carregam junto com as visíveis, competindo por banda.".into(),
            evidence: format!("{} imagem(ns) sem loading=\"lazy\"", info.without_lazy),
            impact: "Impacto não quantificado neste ambiente.".into(),
            recommendation: "Adicionar loading=\"lazy\" em imagens que não estão acima da dobra (as imagens principais/devem continuar eager).".into(),
        });
    }

    (info, section)
}
