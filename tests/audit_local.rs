//! Testes de integração ponta a ponta contra o servidor HTTP local.
//! A proteção SSRF é desativada apenas via `Config::for_local_tests()` —
//! nunca por flag de CLI (que não existe).

use webspeed_auditor::cli::OutputFormat;
use webspeed_auditor::config::Config;
use webspeed_auditor::models::{TestItem, TestStatus};
use webspeed_auditor::{audit, report, testserver};

#[tokio::test]
async fn full_audit_produces_complete_report() {
    let server = testserver::spawn_test_server();
    let cfg = Config::for_local_tests();
    let max_pages = cfg.max_pages;
    let r = audit::run(&server.base, cfg)
        .await
        .expect("auditoria deve concluir");

    assert_eq!(r.tool, "WebSpeed Auditor");
    assert!(!r.version.is_empty());
    assert!(r.generated_at_unix > 0);
    assert!(!r.generated_at_iso8601.is_empty());

    // Documento principal e HTML analisados.
    let http = r.http.as_ref().expect("http principal deve existir");
    assert_eq!(http.status_code, Some(200));
    assert!(r.html.is_some(), "HTML deve ter sido analisado");

    // Testes e scores.
    assert!(!r.tests.is_empty(), "ao menos um teste deve existir");
    assert!(!r.scores.categories.is_empty());
    assert!(r.scores.score <= 100);

    // Recursos coletados a partir do HTML da home.
    assert!(
        !r.resources.is_empty(),
        "recursos da home devem ser coletados"
    );
    assert!(r.requests_analyzed > r.resources.len());

    // Otimizados / não testados estruturados (mesmo que vazios).
    assert!(r.optimized.iter().all(|t| t.status == TestStatus::Pass));

    // DNS do alvo (IP literal) reportado sem dados locais.
    assert!(!r.dns.detail.is_empty());
    assert!(r.url.starts_with("http://127.0.0.1"));

    // Crawl respeitou o limite.
    assert!(r.pages_analyzed <= max_pages);
    assert!(r.pages.contains(&r.final_url) || r.pages.contains(&r.url));
}

#[tokio::test]
async fn audit_respects_no_crawl() {
    let server = testserver::spawn_test_server();
    let cfg = Config {
        crawl: false,
        ..Config::for_local_tests()
    };
    let r = audit::run(&server.base, cfg).await.expect("auditoria");
    assert_eq!(
        r.pages_analyzed, 1,
        "sem crawl deve haver apenas a página inicial"
    );
    assert!(r.pages.len() == 1);
}

#[tokio::test]
async fn audit_respects_max_pages() {
    let server = testserver::spawn_test_server();
    let cfg = Config {
        max_pages: 2,
        ..Config::for_local_tests()
    };
    let r = audit::run(&server.base, cfg).await.expect("auditoria");
    assert!(
        r.pages.len() <= 2,
        "esperava no máximo 2 páginas, veio {}",
        r.pages.len()
    );
}

#[tokio::test]
async fn audit_on_404_reports_failure_but_completes() {
    let server = testserver::spawn_test_server();
    let cfg = Config {
        crawl: false,
        ..Config::for_local_tests()
    };
    // Rota inexistente do servidor de teste.
    let r = audit::run(&format!("{}/does-not-exist", server.base), cfg)
        .await
        .expect("falha HTTP não deve abortar a auditoria");
    let doc_test = r
        .tests
        .iter()
        .find(|t| t.name == "Documento principal")
        .expect("teste do documento");
    assert_eq!(doc_test.status, TestStatus::Fail);
    assert!(doc_test.detail.contains("404"));
    // O relatório continua completo e renderizável.
    assert!(report::render(&r, OutputFormat::Json).is_ok());
}

#[tokio::test]
async fn audit_on_unreachable_port_still_returns_report() {
    let cfg = Config {
        crawl: false,
        timeout: std::time::Duration::from_secs(2),
        ..Config::for_local_tests()
    };
    // Porta fechada em loopback: SSRF desativado (teste local).
    let r = audit::run("http://127.0.0.1:9", cfg)
        .await
        .expect("falha de rede não deve abortar a auditoria");
    assert!(r.http.is_none());
    assert!(
        r.tests
            .iter()
            .any(|t: &TestItem| t.status == TestStatus::Error)
    );
    assert!(
        r.not_tested
            .iter()
            .any(|l| l.area.contains("Documento principal"))
    );
}

#[tokio::test]
async fn all_three_render_formats_work_end_to_end() {
    let server = testserver::spawn_test_server();
    let cfg = Config {
        crawl: false,
        ..Config::for_local_tests()
    };
    let r = audit::run(&server.base, cfg).await.expect("auditoria");

    let json = report::render(&r, OutputFormat::Json).expect("json");
    let parsed: webspeed_auditor::models::AuditReport =
        serde_json::from_str(&json).expect("json válido");
    assert_eq!(parsed.url, r.url);

    let html = report::render(&r, OutputFormat::Html).expect("html");
    assert!(html.starts_with("<!DOCTYPE html>"));
    assert!(!html.contains("<script"));

    let term = report::render(&r, OutputFormat::Terminal).expect("terminal");
    assert!(term.contains("PONTUAÇÃO GERAL"));
    assert!(!term.contains("/Users/"));
}

#[tokio::test]
async fn audit_report_has_no_operator_data() {
    let server = testserver::spawn_test_server();
    let cfg = Config {
        crawl: false,
        ..Config::for_local_tests()
    };
    let r = audit::run(&server.base, cfg).await.expect("auditoria");
    let json = report::render(&r, OutputFormat::Json).expect("json");
    assert!(!json.contains("/Users/"));
    assert!(!json.contains("\x1b["));
    assert!(!json.to_lowercase().contains("password"));
    assert!(!json.to_lowercase().contains("authorization:"));
}
