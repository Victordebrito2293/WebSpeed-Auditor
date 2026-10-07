//! Verificação de headers relevantes para boas práticas e segurança básica
//! relacionada a performance (sem prometer "site seguro").

use crate::analysis::Section;
use crate::models::{Category, Finding, HttpInfo, Severity, TestItem, TestStatus};

pub fn analyze(http: &HttpInfo, final_url_is_https: bool) -> Section {
    let mut section = Section::default();

    // Número de Set-Cookie (apenas contagem — valores nunca são persistidos).
    section.tests.push(TestItem::new(
        Category::BestPractices,
        "Cookies na resposta",
        if http.set_cookie_count > 3 {
            TestStatus::Warning
        } else {
            TestStatus::Pass
        },
        format!(
            "{} cabeçalho(s) Set-Cookie (valores não coletados)",
            http.set_cookie_count
        ),
    ));

    // HSTS: só faz sentido em HTTPS.
    if final_url_is_https {
        // Header name literal para não depender de crates de header well-known.
        let has_hsts = http.hsts;
        section.tests.push(TestItem::new(
            Category::BestPractices,
            "Strict-Transport-Security",
            if has_hsts {
                TestStatus::Pass
            } else {
                TestStatus::Warning
            },
            if has_hsts {
                "presente".to_string()
            } else {
                "ausente em resposta HTTPS".to_string()
            },
        ));
        if !has_hsts {
            section.findings.push(Finding {
                id: "hsts_missing".into(),
                category: Category::BestPractices,
                severity: Severity::Low,
                title: "HSTS ausente".into(),
                problem: "Sem Strict-Transport-Security, o primeiro acesso pode ocorrer por HTTP antes do redirect.".into(),
                evidence: "Header Strict-Transport-Security não presente na resposta HTTPS".into(),
                impact: "Impacto não quantificado neste ambiente.".into(),
                recommendation: "Adicionar Strict-Transport-Security: max-age=31536000; includeSubDomains (com cautela em ambientes de teste).".into(),
            });
        }
    } else {
        section.tests.push(TestItem::new(
            Category::BestPractices,
            "Strict-Transport-Security",
            TestStatus::NotTested,
            "site servido apenas por HTTP — HSTS não aplicável".to_string(),
        ));
    }

    // X-Content-Type-Options: evita MIME sniffing (relevante para assets).
    let has_xcto = http.x_content_type_options;
    section.tests.push(TestItem::new(
        Category::BestPractices,
        "X-Content-Type-Options",
        if has_xcto {
            TestStatus::Pass
        } else {
            TestStatus::Warning
        },
        if has_xcto {
            "nosniff presente"
        } else {
            "ausente"
        },
    ));

    // Vary: relevante quando há compressão/CDN.
    if http.content_encoding.is_some() && http.vary.is_none() {
        section.tests.push(TestItem::new(
            Category::Compression,
            "Vary em resposta comprimida",
            TestStatus::Warning,
            "Content-Encoding presente sem header Vary — proxies podem servir a variante errada",
        ));
    }

    section
}
