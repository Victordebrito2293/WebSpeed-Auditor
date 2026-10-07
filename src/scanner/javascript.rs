//! Análise de JavaScript: quantidade, tamanho, bloqueio e duplicação.
//! O JS nunca é executado — apenas bytes e atributos são inspecionados.

use crate::analysis::Section;
use crate::models::{Category, Finding, JsInfo, ResourceKind, Severity, TestItem, TestStatus};
use crate::scanner::html::HtmlAnalysis;
use crate::scanner::resources::FetchedResource;
use crate::utils::timex::fmt_bytes;

/// Limiares documentados (ver docs/SCORING.md).
pub const JS_TOTAL_WARN_BYTES: u64 = 300 * 1024;
pub const JS_LARGE_FILE_BYTES: u64 = 200 * 1024;

pub fn analyze(html: &HtmlAnalysis, fetched: &[FetchedResource]) -> (JsInfo, Section) {
    let mut section = Section::default();
    let mut info = JsInfo {
        inline_count: html.info.scripts_inline,
        inline_bytes: html.info.inline_script_bytes as u64,
        blocking: html.info.scripts_blocking,
        defer: html.info.scripts_defer,
        r#async: html.info.scripts_async,
        module: html.info.scripts_module,
        ..JsInfo::default()
    };

    let js_records: Vec<&FetchedResource> = fetched
        .iter()
        .filter(|f| f.record.kind == ResourceKind::JavaScript)
        .collect();

    info.external_count = html
        .resources
        .iter()
        .filter(|r| r.kind == ResourceKind::JavaScript)
        .count();

    for f in &js_records {
        let size = f
            .record
            .decoded_size
            .or(f.record.transfer_size)
            .unwrap_or(0);
        info.total_external_bytes += size;
        if size > JS_LARGE_FILE_BYTES {
            info.large_files
                .push(format!("{} ({})", f.record.url, fmt_bytes(size)));
        }
    }

    info.duplicate_urls = html
        .info
        .duplicate_resources
        .iter()
        .filter(|u| {
            html.resources
                .iter()
                .any(|r| r.url.as_str() == u.as_str() && r.kind == ResourceKind::JavaScript)
        })
        .cloned()
        .collect();

    // --- Testes ---

    section.tests.push(TestItem::new(
        Category::JavaScript,
        "Scripts bloqueantes",
        if info.blocking > 0 {
            TestStatus::Warning
        } else {
            TestStatus::Pass
        },
        format!(
            "{} bloqueante(s), {} defer, {} async, {} module, {} inline",
            info.blocking, info.defer, info.r#async, info.module, info.inline_count
        ),
    ));

    section.tests.push(TestItem::new(
        Category::JavaScript,
        "Volume total de JavaScript",
        if info.total_external_bytes > JS_TOTAL_WARN_BYTES {
            TestStatus::Warning
        } else if info.total_external_bytes == 0 && info.inline_bytes == 0 {
            TestStatus::NotTested
        } else {
            TestStatus::Pass
        },
        format!(
            "{} externo + {} inline",
            fmt_bytes(info.total_external_bytes),
            fmt_bytes(info.inline_bytes)
        ),
    ));

    if !info.large_files.is_empty() {
        section.tests.push(
            TestItem::new(
                Category::JavaScript,
                "Arquivos JavaScript muito grandes",
                TestStatus::Warning,
                format!(
                    "{} arquivo(s) acima de {}",
                    info.large_files.len(),
                    fmt_bytes(JS_LARGE_FILE_BYTES)
                ),
            )
            .with_evidence(info.large_files.join(", ")),
        );
        section.findings.push(Finding {
            id: "js_large_files".into(),
            category: Category::JavaScript,
            severity: Severity::Medium,
            title: "Arquivos JavaScript muito grandes".into(),
            problem: "Arquivos individuais acima do limiar aumentam o tempo de download e o custo de parse/execução.".into(),
            evidence: info.large_files.join(", "),
            impact: "Impacto não quantificado neste ambiente.".into(),
            recommendation: "Dividir o bundle em chunks carregados sob demanda, remover código morto e avaliar tree-shaking.".into(),
        });
    }

    if info.blocking > 0 {
        section.findings.push(Finding {
            id: "js_blocking".into(),
            category: Category::JavaScript,
            severity: Severity::Low,
            title: "Scripts bloqueantes no carregamento".into(),
            problem: "Scripts sem defer/async/module bloqueiam o parsing do HTML até serem baixados e executados.".into(),
            evidence: format!("{} script(s) bloqueante(s) detectado(s)", info.blocking),
            impact: "Impacto não quantificado neste ambiente.".into(),
            recommendation: "Adicionar defer (ou type=module, que já é deferido por padrão) quando o script não precisa executar imediatamente; async apenas para scripts independentes.".into(),
        });
    }

    if info.total_external_bytes > JS_TOTAL_WARN_BYTES {
        section.findings.push(Finding {
            id: "js_too_much".into(),
            category: Category::JavaScript,
            severity: Severity::Medium,
            title: "Volume elevado de JavaScript".into(),
            problem: "O total de JavaScript excede o limiar documentado de auditoria.".into(),
            evidence: format!(
                "{} em {} arquivo(s) externo(s); limiar: {}",
                fmt_bytes(info.total_external_bytes),
                info.external_count,
                fmt_bytes(JS_TOTAL_WARN_BYTES)
            ),
            impact: "Impacto não quantificado neste ambiente.".into(),
            recommendation: "Reduzir o bundle inicial: code splitting, remoção de dependências pesadas e carregamento sob demanda.".into(),
        });
    }

    if !info.duplicate_urls.is_empty() {
        section.tests.push(
            TestItem::new(
                Category::JavaScript,
                "JavaScript duplicado",
                TestStatus::Warning,
                format!("{} URL(s) duplicada(s)", info.duplicate_urls.len()),
            )
            .with_evidence(info.duplicate_urls.join(", ")),
        );
        section.findings.push(Finding {
            id: "js_duplicate".into(),
            category: Category::JavaScript,
            severity: Severity::Medium,
            title: "Scripts duplicados".into(),
            problem: "O mesmo arquivo JavaScript é carregado mais de uma vez.".into(),
            evidence: info.duplicate_urls.join(", "),
            impact: "Impacto não quantificado neste ambiente.".into(),
            recommendation: "Remover a referência duplicada; verificar se o mesmo código foi incluído por bundles diferentes.".into(),
        });
    }

    (info, section)
}
