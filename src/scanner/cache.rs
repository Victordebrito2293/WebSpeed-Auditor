//! Análise de headers de cache sobre o documento e recursos coletados.

use crate::analysis::Section;
use crate::models::{
    CacheInfo, Category, Finding, HttpInfo, ResourceKind, Severity, TestItem, TestStatus,
};

/// Recursos estáticos considerados "cacheáveis com política longa".
const STATIC_KINDS: [ResourceKind; 4] = [
    ResourceKind::Css,
    ResourceKind::JavaScript,
    ResourceKind::Image,
    ResourceKind::Font,
];

pub fn analyze(
    http: Option<&HttpInfo>,
    resources: &[crate::models::ResourceRecord],
) -> (CacheInfo, Section) {
    let mut section = Section::default();
    let mut info = CacheInfo::default();

    for r in resources {
        if !STATIC_KINDS.contains(&r.kind) {
            continue;
        }
        if r.status != TestStatus::Pass {
            continue;
        }
        info.static_total += 1;
        let cc = r.cache_control.as_deref().unwrap_or("");
        if cc.is_empty() {
            info.static_without_policy += 1;
        }
        let max_age = parse_max_age(cc);
        if max_age.is_some_and(|m| m >= 86_400) && (r.etag || r.last_modified) {
            info.immutable_candidates += 1;
        }
        if cc.contains("immutable") && r.kind == ResourceKind::Html {
            info.html_with_immutable = true;
        }
    }

    // HTML principal.
    if let Some(h) = http
        && let Some(cc) = &h.cache_control
        && cc.contains("immutable")
    {
        info.html_with_immutable = true;
    }

    if info.static_total == 0 {
        section.tests.push(TestItem::new(
            Category::Caching,
            "Política de cache de recursos estáticos",
            TestStatus::NotTested,
            "nenhum recurso estático coletado".to_string(),
        ));
    } else {
        section.tests.push(TestItem::new(
            Category::Caching,
            "Política de cache de recursos estáticos",
            if info.static_without_policy > 0 {
                TestStatus::Warning
            } else {
                TestStatus::Pass
            },
            format!(
                "{} de {} recurso(s) estático(s) sem Cache-Control",
                info.static_without_policy, info.static_total
            ),
        ));
    }

    if info.static_without_policy > 0 && info.static_total > 0 {
        let urls: Vec<&str> = resources
            .iter()
            .filter(|r| STATIC_KINDS.contains(&r.kind))
            .filter(|r| r.status == TestStatus::Pass)
            .filter(|r| r.cache_control.as_deref().unwrap_or("").is_empty())
            .map(|r| r.url.as_str())
            .collect();
        section.findings.push(Finding {
            id: "cache_missing".into(),
            category: Category::Caching,
            severity: Severity::High,
            title: "Recursos estáticos sem política de cache".into(),
            problem: "Arquivos estáticos são servidos sem Cache-Control, forçando novos downloads em visitas futuras.".into(),
            evidence: format!(
                "Cache-Control ausente em {}/{} recurso(s): {}",
                info.static_without_policy,
                info.static_total,
                urls.join(", ")
            ),
            impact: "Recursos podem ser baixados novamente em visitas futuras. Impacto não quantificado neste ambiente.".into(),
            recommendation: "Configurar política de cache apropriada para assets versionados (ex.: public, max-age=31536000, immutable).".into(),
        });
    }

    if info.html_with_immutable {
        section.tests.push(TestItem::new(
            Category::Caching,
            "Cache do documento HTML",
            TestStatus::Warning,
            "HTML servido com immutable/longo prazo — o navegador pode não ver atualizações"
                .to_string(),
        ));
        section.findings.push(Finding {
            id: "cache_html_immutable".into(),
            category: Category::Caching,
            severity: Severity::Medium,
            title: "HTML com cache demasiado longo".into(),
            problem: "Documentos HTML com política immutable/longa impedem que o navegador veja novas versões.".into(),
            evidence: "Cache-Control contém immutable (ou max-age muito alto) no documento HTML".into(),
            impact: "Impacto não quantificado neste ambiente.".into(),
            recommendation: "Servir HTML com no-cache (ou revalidação via ETag) e aplicar cache longo somente a assets versionados.".into(),
        });
    }

    (info, section)
}

fn parse_max_age(cc: &str) -> Option<u64> {
    for part in cc.split(',') {
        let part = part.trim();
        if let Some(v) = part.strip_prefix("max-age=") {
            return v.trim().parse().ok();
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::ResourceRecord;

    fn rec(kind: ResourceKind, cc: Option<&str>) -> ResourceRecord {
        ResourceRecord {
            url: "https://example.com/a.css".into(),
            kind,
            status: TestStatus::Pass,
            status_code: Some(200),
            content_type: Some("text/css".into()),
            content_encoding: None,
            transfer_size: Some(100),
            decoded_size: Some(100),
            cache_control: cc.map(|s| s.to_string()),
            etag: false,
            last_modified: false,
            timing_ms: None,
            error: None,
            sniffed_format: None,
        }
    }

    #[test]
    fn static_without_cache_is_warning() {
        let (info, section) = analyze(None, &[rec(ResourceKind::Css, None)]);
        assert_eq!(info.static_without_policy, 1);
        assert!(
            section
                .tests
                .iter()
                .any(|t| t.status == TestStatus::Warning)
        );
        assert!(section.findings.iter().any(|f| f.id == "cache_missing"));
    }

    #[test]
    fn static_with_cache_passes() {
        let (info, section) = analyze(None, &[rec(ResourceKind::Css, Some("public, max-age=60"))]);
        assert_eq!(info.static_without_policy, 0);
        assert!(section.tests.iter().any(|t| t.status == TestStatus::Pass));
        assert!(section.findings.is_empty());
    }

    #[test]
    fn html_not_counted_as_static() {
        let (info, section) = analyze(None, &[rec(ResourceKind::Html, None)]);
        assert_eq!(info.static_total, 0);
        assert_eq!(section.tests[0].status, TestStatus::NotTested);
    }

    #[test]
    fn immutable_html_is_flagged() {
        // HTML não é tratado como "recurso estático"; o flag vem do documento.
        let http = HttpInfo {
            status: TestStatus::Pass,
            status_code: Some(200),
            http_version: None,
            content_type: None,
            content_encoding: None,
            transfer_size: None,
            decoded_size: None,
            cache_control: Some("public, max-age=31536000, immutable".into()),
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
        let (info2, section2) = analyze(Some(&http), &[]);
        assert!(info2.html_with_immutable);
        assert!(
            section2
                .findings
                .iter()
                .any(|f| f.id == "cache_html_immutable")
        );
    }

    #[test]
    fn max_age_parsed() {
        assert_eq!(parse_max_age("public, max-age=86400"), Some(86400));
        assert_eq!(parse_max_age("no-store"), None);
        assert_eq!(parse_max_age(""), None);
    }
}
