//! Suite de segurança SSRF: nenhuma URL hostil deve ser acessada e as
//! falhas devem ser explícitas no relatório (nunca silenciosas).

use std::time::Duration;
use url::Url;
use webspeed_auditor::config::Config;
use webspeed_auditor::models::TestStatus;
use webspeed_auditor::utils::ssrf;
use webspeed_auditor::{audit, testserver};

fn prod_cfg() -> Config {
    Config {
        crawl: false,
        timeout: Duration::from_secs(3),
        ssrf_protection: true,
        ..Config::default()
    }
}

#[test]
fn shape_blocks_non_http_schemes() {
    for bad in [
        "ftp://example.com/a",
        "file:///etc/passwd",
        "gopher://example.com",
        "javascript:alert(1)",
        "data:text/html,<script>x</script>",
        "ws://example.com",
    ] {
        let url = Url::parse(bad).expect("parse");
        assert!(
            ssrf::validate_url_shape(&url).is_err(),
            "esquema de {bad} deve ser bloqueado"
        );
    }
}

#[test]
fn shape_blocks_userinfo_and_localhost() {
    for bad in [
        "http://user:pass@example.com/",
        "http://admin@example.com/",
        "http://localhost/",
        "http://LOCALHOST./",
        "http://foo.localhost/",
        "https://metadata.google.internal/computeMetadata/v1/",
        "http://metadata/",
        "http://instance-data/",
    ] {
        let url = Url::parse(bad).expect("parse");
        assert!(
            ssrf::validate_url_shape(&url).is_err(),
            "{bad} deve ser bloqueado"
        );
    }
}

#[test]
fn shape_blocks_oversized_urls() {
    let long = format!("https://example.com/{}", "a".repeat(3000));
    let url = Url::parse(&long).expect("parse");
    assert!(matches!(
        ssrf::validate_url_shape(&url),
        Err(ssrf::SsrfError::UrlTooLong)
    ));
}

#[test]
fn ip_policy_blocks_everything_not_public() {
    use std::net::IpAddr;
    let blocked = [
        "127.0.0.1",
        "127.8.9.10",
        "10.0.0.1",
        "172.16.5.5",
        "192.168.1.1",
        "169.254.169.254", // metadata AWS/GCP/Azure
        "100.100.100.200", // metadata Alibaba (CGNAT)
        "168.63.129.16",   // Azure wire server
        "0.0.0.0",
        "255.255.255.255",
        "192.0.0.192", // Oracle cloud metadata (192.0.0.0/24)
        "198.18.0.1",
        "240.0.0.1",
        "::1",
        "fe80::1",
        "fc00::1",
        "fd12:3456::1",
        "2001:db8::1",
        "64:ff9b::a00:1",
        "::ffff:127.0.0.1",
        "::ffff:10.0.0.1",
    ];
    for s in blocked {
        let ip: IpAddr = s.parse().expect("ip");
        assert!(ssrf::ip_is_blocked(ip), "{s} deve ser bloqueado");
    }
    // Endereços públicos continuam permitidos.
    for s in ["93.184.216.34", "1.1.1.1", "2606:4700:4700::1111"] {
        let ip: IpAddr = s.parse().expect("ip");
        assert!(!ssrf::ip_is_blocked(ip), "{s} não deve ser bloqueado");
    }
}

#[tokio::test]
async fn audit_refuses_loopback_when_protection_enabled() {
    let server = testserver::spawn_test_server();
    let r = audit::run(&server.base, prod_cfg())
        .await
        .expect("auditoria não aborta — apenas recusa a URL");
    // Nada deve ter sido baixado: o documento principal não existe no relatório.
    assert!(
        r.http.is_none(),
        "loopback não pode ser baixado com proteção ativa"
    );
    assert!(r.html.is_none());
    assert!(r.resources.is_empty());
    assert!(
        r.tests.iter().any(|t| t.status == TestStatus::Error),
        "a recusa deve aparecer explicitamente como teste ERROR"
    );
    let err_detail = r
        .tests
        .iter()
        .filter(|t| t.status == TestStatus::Error)
        .map(|t| t.detail.clone())
        .collect::<Vec<_>>()
        .join(" ");
    assert!(
        err_detail.to_lowercase().contains("bloquead")
            || err_detail.to_lowercase().contains("não público")
            || err_detail.to_lowercase().contains("bloqueado"),
        "detalhe do erro deve indicar o bloqueio, veio: {err_detail}"
    );
}

#[tokio::test]
async fn audit_refuses_hostname_localhost_before_any_request() {
    let err = audit::run("http://localhost:1/", prod_cfg())
        .await
        .expect_err("localhost deve ser recusado antes de qualquer requisição");
    assert!(
        err.to_string().contains("bloquead"),
        "erro de hostname bloqueado esperado, veio: {err}"
    );
}

#[tokio::test]
async fn audit_refuses_credentials_in_url() {
    let err = audit::run("http://user:secret@example.com/", prod_cfg())
        .await
        .expect_err("credenciais na URL devem ser recusadas antes de qualquer requisição");
    assert!(err.to_string().contains("credenciais"), "erro: {err}");
}

#[test]
fn normalize_rejects_bad_input() {
    assert!(audit::normalize_url_input("").is_err());
    assert!(audit::normalize_url_input("   ").is_err());
    assert!(audit::normalize_url_input("ftp://x.com").is_err());
    assert!(audit::normalize_url_input("javascript:alert(1)").is_err());
    assert!(audit::normalize_url_input("http://localhost/").is_err());
    assert!(audit::normalize_url_input(&format!("https://e.com/{}", "a".repeat(3000))).is_err());
    // Sem esquema assume https.
    let ok = audit::normalize_url_input("example.com").expect("deve aceitar");
    assert_eq!(ok.scheme(), "https");
    assert_eq!(ok.host_str(), Some("example.com"));
}

#[tokio::test]
async fn manual_redirects_revalidate_each_hop() {
    // Servidor local com SSRF desativado: valida a mecânica de cadeia
    // (o revalidação por salto está no SafeResolver/exclusão por política).
    let server = testserver::spawn_test_server();
    let cfg = Config {
        crawl: false,
        timeout: Duration::from_secs(3),
        ..Config::for_local_tests()
    };
    let r = audit::run(&format!("{}/redirect-chain", server.base), cfg)
        .await
        .expect("auditoria");
    assert!(
        r.redirects.hops.len() >= 2,
        "cadeia deve ter saltos: {:?}",
        r.redirects
    );
    assert!(!r.redirects.loop_detected);
    assert_eq!(r.http.expect("final").status_code, Some(200));
}

#[tokio::test]
async fn redirect_loop_is_detected_not_hung() {
    let server = testserver::spawn_test_server();
    let cfg = Config {
        crawl: false,
        timeout: Duration::from_secs(3),
        ..Config::for_local_tests()
    };
    let start = std::time::Instant::now();
    let r = audit::run(&format!("{}/loop", server.base), cfg)
        .await
        .expect("auditoria não pode travar");
    assert!(
        start.elapsed() < Duration::from_secs(20),
        "não pode travar em loop"
    );
    assert!(r.http.is_none() || r.redirects.loop_detected);
}
