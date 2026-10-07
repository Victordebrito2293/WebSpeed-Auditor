//! Análise de compressão: gzip/Brotli sobre conteúdo textual.

use crate::analysis::Section;
use crate::models::{
    Category, CompressionInfo, Finding, HttpInfo, ResourceKind, Severity, TestItem, TestStatus,
};

/// Tamanho mínimo para que compressão seja esperada.
pub const COMPRESS_MIN_BYTES: u64 = 1024;

fn is_static_text(kind: ResourceKind) -> bool {
    matches!(
        kind,
        ResourceKind::Css | ResourceKind::JavaScript | ResourceKind::Html
    )
}

pub fn analyze(
    http: Option<&HttpInfo>,
    resources: &[crate::models::ResourceRecord],
) -> (CompressionInfo, Section) {
    let mut section = Section::default();
    let mut info = CompressionInfo::default();

    // Documento principal.
    if let Some(h) = http {
        if let Some(enc) = &h.content_encoding
            && enc != "identity"
            && !info.used_encodings.contains(enc)
        {
            info.used_encodings.push(enc.clone());
        }
        let ct = h.content_type.as_deref();
        let size = h.decoded_size.or(h.transfer_size).unwrap_or(0);
        if crate::utils::sniff::is_compressible_content_type(ct) && size >= COMPRESS_MIN_BYTES {
            info.compressible_total += 1;
            if h.content_encoding
                .as_deref()
                .is_some_and(|e| e != "identity")
            {
                info.compressed += 1;
            } else {
                info.uncompressed
                    .push(format!("{} (documento)", h.final_doc_label()));
            }
        }
    }

    // Recursos.
    for r in resources {
        if r.status != TestStatus::Pass {
            continue;
        }
        let size = r.decoded_size.or(r.transfer_size).unwrap_or(0);
        let compressible = if is_static_text(r.kind) {
            true
        } else {
            crate::utils::sniff::is_compressible_content_type(r.content_type.as_deref())
        };
        if compressible && size >= COMPRESS_MIN_BYTES {
            info.compressible_total += 1;
            match r.content_encoding.as_deref() {
                Some(e) if e != "identity" => {
                    info.compressed += 1;
                    if !info.used_encodings.contains(&e.to_string()) {
                        info.used_encodings.push(e.to_string());
                    }
                }
                _ => info.uncompressed.push(r.url.clone()),
            }
        }
    }

    if info.compressible_total == 0 {
        section.tests.push(TestItem::new(
            Category::Compression,
            "Compressão de resposta (gzip/brotli)",
            TestStatus::NotTested,
            "nenhum recurso comprimível com tamanho relevante coletado".to_string(),
        ));
        return (info, section);
    }

    section.tests.push(TestItem::new(
        Category::Compression,
        "Compressão de resposta (gzip/brotli)",
        if info.uncompressed.is_empty() {
            TestStatus::Pass
        } else {
            TestStatus::Warning
        },
        format!(
            "{} de {} recurso(s) comprimível(is) comprimido(s); encodings usados: {}",
            info.compressed,
            info.compressible_total,
            if info.used_encodings.is_empty() {
                "nenhum".to_string()
            } else {
                info.used_encodings.join(", ")
            }
        ),
    ));

    if !info.uncompressed.is_empty() {
        section.findings.push(Finding {
            id: "compression_missing".into(),
            category: Category::Compression,
            severity: Severity::High,
            title: "Conteúdo textual sem compressão".into(),
            problem: "Recursos textuais servidos sem Content-Encoding (gzip/brotli) transferem mais bytes do que o necessário.".into(),
            evidence: format!(
                "Sem Content-Encoding: {}",
                info.uncompressed.join(", ")
            ),
            impact: "Impacto não quantificado neste ambiente.".into(),
            recommendation: "Habilitar compressão gzip ou Brotli no servidor/CDN para HTML, CSS, JS e SVG (não para JPEG/PNG/MP4 já comprimidos).".into(),
        });
    }

    (info, section)
}

/// Helper para rotular o documento no relatório.
trait DocLabel {
    fn final_doc_label(&self) -> String;
}

impl DocLabel for HttpInfo {
    fn final_doc_label(&self) -> String {
        match self.status_code {
            Some(c) => format!("HTTP {c}"),
            None => "documento".to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::ResourceRecord;

    fn rec(url: &str, kind: ResourceKind, enc: Option<&str>, size: u64) -> ResourceRecord {
        ResourceRecord {
            url: url.into(),
            kind,
            status: TestStatus::Pass,
            status_code: Some(200),
            content_type: Some(match kind {
                ResourceKind::Css => "text/css".into(),
                ResourceKind::JavaScript => "application/javascript".into(),
                ResourceKind::Html => "text/html".into(),
                _ => "image/png".into(),
            }),
            content_encoding: enc.map(|s| s.to_string()),
            transfer_size: Some(size),
            decoded_size: Some(size),
            cache_control: None,
            etag: false,
            last_modified: false,
            timing_ms: None,
            error: None,
            sniffed_format: None,
        }
    }

    #[test]
    fn uncompressed_text_is_flagged() {
        let (_, section) = analyze(None, &[rec("/a.css", ResourceKind::Css, None, 5000)]);
        assert!(
            section
                .findings
                .iter()
                .any(|f| f.id == "compression_missing")
        );
        assert!(
            section
                .tests
                .iter()
                .any(|t| t.status == TestStatus::Warning)
        );
    }

    #[test]
    fn compressed_text_passes() {
        let (info, section) = analyze(None, &[rec("/a.css", ResourceKind::Css, Some("br"), 5000)]);
        assert_eq!(info.compressed, 1);
        assert!(info.uncompressed.is_empty());
        assert!(section.tests.iter().any(|t| t.status == TestStatus::Pass));
    }

    #[test]
    fn small_text_not_flagged() {
        let (_, section) = analyze(None, &[rec("/tiny.css", ResourceKind::Css, None, 200)]);
        assert!(section.findings.is_empty());
        assert_eq!(section.tests[0].status, TestStatus::NotTested);
    }

    #[test]
    fn images_are_not_expected_to_compress() {
        let (_, section) = analyze(None, &[rec("/a.png", ResourceKind::Image, None, 500_000)]);
        assert!(section.findings.is_empty());
        assert_eq!(section.tests[0].status, TestStatus::NotTested);
    }

    #[test]
    fn gzipped_document_counts() {
        let http = HttpInfo {
            status: TestStatus::Pass,
            status_code: Some(200),
            http_version: None,
            content_type: Some("text/html".into()),
            content_encoding: Some("gzip".into()),
            transfer_size: Some(2000),
            decoded_size: Some(20_000),
            cache_control: None,
            etag: false,
            last_modified: None,
            set_cookie_count: 0,
            server: None,
            vary: None,
            age: None,
            hsts: false,
            x_content_type_options: false,
            timings: Default::default(),
            body_truncated: false,
        };
        let (info, _) = analyze(Some(&http), &[]);
        assert_eq!(info.compressed, 1);
        assert!(info.uncompressed.is_empty());
    }
}
