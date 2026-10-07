//! Regras de recomendação sobre os resultados agregados da auditoria.
//!
//! Cada finding carrega: problema, evidência, impacto, como corrigir e
//! prioridade. Quando um ganho não pode ser quantificado com honestidade,
//! o impacto é registrado como "Impacto não quantificado neste ambiente.".

use crate::analysis::Section;
use crate::models::{
    Category, DnsInfo, Finding, HtmlInfo, HttpInfo, RedirectChain, Severity, TestItem, TestStatus,
    TlsInfo,
};
use crate::utils::timex::fmt_bytes;

/// Limiares documentados (docs/SCORING.md).
pub const TTFB_WARN_MS: u64 = 600;
pub const TTFB_BAD_MS: u64 = 1500;
pub const PAGE_WEIGHT_WARN: u64 = 3 * 1024 * 1024;
pub const HTML_WARN_BYTES: u64 = 100 * 1024;
pub const HTML_BAD_BYTES: u64 = 300 * 1024;
pub const EXTERNAL_ORIGINS_WARN: usize = 10;
pub const REDIRECT_CHAIN_WARN: usize = 2;

pub struct Inputs<'a> {
    pub start_url: &'a str,
    pub final_url: &'a str,
    pub http: Option<&'a HttpInfo>,
    pub redirects: &'a RedirectChain,
    pub dns: &'a DnsInfo,
    pub tls: Option<&'a TlsInfo>,
    pub html: Option<&'a HtmlInfo>,
    pub pages_ok: usize,
    pub pages_failed: usize,
    /// Peso total transferido da página (documento + recursos), em bytes.
    pub page_weight: u64,
}

pub fn analyze(i: &Inputs<'_>) -> Section {
    let mut s = Section::default();
    let start_is_https = i.start_url.starts_with("https://");
    let final_is_https = i.final_url.starts_with("https://");

    // ---------------- Performance ----------------
    match i.http.and_then(|h| h.timings.ttfb_ms) {
        Some(ms) if ms > TTFB_BAD_MS => {
            s.tests.push(TestItem::new(
                Category::Performance,
                "Tempo até a primeira resposta (TTFB)",
                TestStatus::Fail,
                format!("{ms} ms (limiar: {TTFB_BAD_MS} ms)"),
            ));
            s.findings.push(Finding {
                id: "perf_ttfb_high".into(),
                category: Category::Performance,
                severity: Severity::High,
                title: "Tempo de resposta do servidor elevado".into(),
                problem: "O servidor demorou mais que o limiar documentado para entregar os primeiros bytes.".into(),
                evidence: format!("TTFB medido: {ms} ms; limiar: {TTFB_BAD_MS} ms"),
                impact: "Impacto não quantificado neste ambiente (varia com distância e carga).".into(),
                recommendation: "Investigar tempo de processamento no servidor, cache de página e latência até o usuário (CDN).".into(),
            });
        }
        Some(ms) if ms > TTFB_WARN_MS => {
            s.tests.push(TestItem::new(
                Category::Performance,
                "Tempo até a primeira resposta (TTFB)",
                TestStatus::Warning,
                format!("{ms} ms (limiar: {TTFB_WARN_MS} ms)"),
            ));
            s.findings.push(Finding {
                id: "perf_ttfb_warn".into(),
                category: Category::Performance,
                severity: Severity::Medium,
                title: "Tempo de resposta do servidor moderado".into(),
                problem: "O TTFB superou o limiar de atenção da auditoria.".into(),
                evidence: format!("TTFB medido: {ms} ms; limiar: {TTFB_WARN_MS} ms"),
                impact: "Impacto não quantificado neste ambiente.".into(),
                recommendation:
                    "Avaliar cache no servidor/CDN e reduzir trabalho síncrono antes da resposta."
                        .into(),
            });
        }
        Some(ms) => {
            s.tests.push(TestItem::new(
                Category::Performance,
                "Tempo até a primeira resposta (TTFB)",
                TestStatus::Pass,
                format!("{ms} ms (limiar: {TTFB_WARN_MS} ms)"),
            ));
        }
        None => {
            s.tests.push(TestItem::new(
                Category::Performance,
                "Tempo até a primeira resposta (TTFB)",
                TestStatus::NotTested,
                "Não disponível neste ambiente.".to_string(),
            ));
        }
    }

    // ---------------- Network ----------------
    if let Some(h) = i.http {
        let version = h.http_version.as_deref().unwrap_or("desconhecido");
        match version {
            "HTTP/2" | "HTTP/3" => {
                s.tests.push(TestItem::new(
                    Category::Network,
                    "Versão do protocolo HTTP",
                    TestStatus::Pass,
                    format!("negociado {version}"),
                ));
            }
            "HTTP/1.1" => {
                s.tests.push(TestItem::new(
                    Category::Network,
                    "Versão do protocolo HTTP",
                    TestStatus::Warning,
                    "negociado HTTP/1.1 (HTTP/2 não utilizado)".to_string(),
                ));
                s.findings.push(Finding {
                    id: "net_no_http2".into(),
                    category: Category::Network,
                    severity: Severity::Low,
                    title: "HTTP/2 não utilizado".into(),
                    problem:
                        "A conexão negociou HTTP/1.1, que não permite multiplexação de requisições."
                            .into(),
                    evidence: format!("protocolo negociado: {version}"),
                    impact: "Impacto não quantificado neste ambiente.".into(),
                    recommendation:
                        "Habilitar HTTP/2 (ou HTTP/3) no servidor/CDN; normalmente requer TLS."
                            .into(),
                });
            }
            other => {
                s.tests.push(TestItem::new(
                    Category::Network,
                    "Versão do protocolo HTTP",
                    TestStatus::NotTested,
                    format!("versão não reconhecida: {other}"),
                ));
            }
        }
    }

    // HTTP -> HTTPS.
    if start_is_https {
        s.tests.push(TestItem::new(
            Category::Network,
            "Uso de HTTPS",
            TestStatus::Pass,
            "URL inicial já é HTTPS".to_string(),
        ));
    } else if final_is_https {
        s.tests.push(TestItem::new(
            Category::Network,
            "Uso de HTTPS",
            TestStatus::Pass,
            "redirect HTTP -> HTTPS presente".to_string(),
        ));
    } else {
        s.tests.push(TestItem::new(
            Category::Network,
            "Uso de HTTPS",
            TestStatus::Fail,
            "site responde somente por HTTP".to_string(),
        ));
        s.findings.push(Finding {
            id: "net_no_https".into(),
            category: Category::Network,
            severity: Severity::High,
            title: "Site sem HTTPS".into(),
            problem: "O site final não está disponível por HTTPS, expondo tráfego a interceptação e impedindo HSTS/HTTP2 amplamente.".into(),
            evidence: format!("URL final: {}", i.final_url),
            impact: "Impacto não quantificado neste ambiente.".into(),
            recommendation: "Emitir certificado válido e redirecionar todo HTTP para HTTPS (mantendo o redirect mínimo — idealmente um salto).".into(),
        });
    }

    // DNS.
    match i.dns.status {
        TestStatus::Pass => {
            s.tests.push(TestItem::new(
                Category::Network,
                "Resolução DNS",
                TestStatus::Pass,
                i.dns.detail.clone(),
            ));
            if !i.dns.ipv6.is_empty() {
                s.tests.push(TestItem::new(
                    Category::Network,
                    "IPv6 disponível",
                    TestStatus::Pass,
                    format!("{} endereço(s) IPv6", i.dns.ipv6.len()),
                ));
            }
        }
        _ => {
            s.tests.push(TestItem::new(
                Category::Network,
                "Resolução DNS",
                TestStatus::Error,
                i.dns.detail.clone(),
            ));
        }
    }

    // Redirects.
    if i.redirects.loop_detected {
        s.tests.push(TestItem::new(
            Category::Network,
            "Cadeia de redirects",
            TestStatus::Fail,
            "loop de redirects detectado".to_string(),
        ));
        s.findings.push(Finding {
            id: "redirect_loop".into(),
            category: Category::Network,
            severity: Severity::High,
            title: "Loop de redirects".into(),
            problem: "A cadeia de redirects repete URLs, gastando requisições sem chegar a um destino estável.".into(),
            evidence: format!(
                "hops: {}",
                i.redirects
                    .hops
                    .iter()
                    .map(|h| format!("{} -> {} ({})", h.from, h.to, h.status))
                    .collect::<Vec<_>>()
                    .join(" | ")
            ),
            impact: "Impacto não quantificado neste ambiente.".into(),
            recommendation: "Corrigir a regra de redirect para apontar diretamente ao destino final.".into(),
        });
    } else {
        let hops = i.redirects.hops.len();
        if hops > REDIRECT_CHAIN_WARN {
            s.tests.push(TestItem::new(
                Category::Network,
                "Cadeia de redirects",
                TestStatus::Warning,
                format!("{hops} salto(s) (limiar: {REDIRECT_CHAIN_WARN})"),
            ));
            s.findings.push(Finding {
                id: "redirect_chain_long".into(),
                category: Category::Network,
                severity: Severity::Low,
                title: "Cadeia de redirects longa".into(),
                problem: "Vários saltos de redirect atrasam o carregamento do documento.".into(),
                evidence: i.redirects
                    .hops
                    .iter()
                    .map(|h| format!("{} -> {} ({})", h.from, h.to, h.status))
                    .collect::<Vec<_>>()
                    .join(" | "),
                impact: "Impacto não quantificado neste ambiente.".into(),
                recommendation: "Apontar a URL inicial diretamente ao destino final (um único redirect quando necessário).".into(),
            });
        } else {
            s.tests.push(TestItem::new(
                Category::Network,
                "Cadeia de redirects",
                TestStatus::Pass,
                format!("{hops} salto(s)"),
            ));
        }
    }

    // TLS.
    match i.tls {
        Some(t) if t.status == TestStatus::Pass => {
            s.tests.push(TestItem::new(
                Category::Network,
                "TLS / certificado",
                TestStatus::Pass,
                t.detail.clone(),
            ));
        }
        Some(t) if t.status == TestStatus::Warning => {
            s.tests.push(TestItem::new(
                Category::Network,
                "TLS / certificado",
                TestStatus::Warning,
                t.detail.clone(),
            ));
            if let Some(days) = t.days_until_expiry
                && days >= 0
            {
                s.findings.push(Finding {
                    id: "tls_expiring".into(),
                    category: Category::Network,
                    severity: Severity::Medium,
                    title: "Certificado próximo do vencimento".into(),
                    problem: "O certificado TLS expira em breve; sem renovação o site passará a falhar.".into(),
                    evidence: format!("expiração em {days} dia(s); validade: {}", t.not_after.clone().unwrap_or_default()),
                    impact: "Impacto não quantificado neste ambiente.".into(),
                    recommendation: "Renovar o certificado (automatizar com ACME/Let's Encrypt) e monitorar a expiração.".into(),
                });
            }
        }
        Some(t) if t.status == TestStatus::Fail => {
            s.tests.push(TestItem::new(
                Category::Network,
                "TLS / certificado",
                TestStatus::Fail,
                t.detail.clone(),
            ));
            s.findings.push(Finding {
                id: "tls_invalid".into(),
                category: Category::Network,
                severity: Severity::Critical,
                title: "Certificado TLS inválido ou expirado".into(),
                problem: "A verificação do certificado falhou — navegadores exibirão aviso de segurança.".into(),
                evidence: t.detail.clone(),
                impact: "Impacto não quantificado neste ambiente.".into(),
                recommendation: "Emitir/renovar certificado confiável, corrigir a cadeia de intermediários e o nome do servidor (SNI).".into(),
            });
        }
        Some(t) => {
            s.tests.push(TestItem::new(
                Category::Network,
                "TLS / certificado",
                TestStatus::Error,
                t.detail.clone(),
            ));
        }
        None if start_is_https || final_is_https => {
            s.tests.push(TestItem::new(
                Category::Network,
                "TLS / certificado",
                TestStatus::NotTested,
                "Não disponível neste ambiente.".to_string(),
            ));
        }
        None => {
            s.tests.push(TestItem::new(
                Category::Network,
                "TLS / certificado",
                TestStatus::NotTested,
                "site sem HTTPS — TLS não aplicável".to_string(),
            ));
        }
    }

    // ---------------- HTML ----------------
    if let Some(h) = i.html {
        if h.bytes > HTML_BAD_BYTES {
            s.tests.push(TestItem::new(
                Category::Html,
                "Tamanho do HTML",
                TestStatus::Fail,
                format!(
                    "{} (limiar: {})",
                    fmt_bytes(h.bytes),
                    fmt_bytes(HTML_BAD_BYTES)
                ),
            ));
            s.findings.push(Finding {
                id: "html_too_big".into(),
                category: Category::Html,
                severity: Severity::Medium,
                title: "HTML excessivamente grande".into(),
                problem: "O documento excede o limiar de tamanho, aumentando transferência e parse.".into(),
                evidence: format!("{} de HTML (limiar: {})", fmt_bytes(h.bytes), fmt_bytes(HTML_BAD_BYTES)),
                impact: "Impacto não quantificado neste ambiente.".into(),
                recommendation: "Reduzir markup (templates mais enxutos), paginar conteúdo e garantir compressão gzip/brotli.".into(),
            });
        } else if h.bytes > HTML_WARN_BYTES {
            s.tests.push(TestItem::new(
                Category::Html,
                "Tamanho do HTML",
                TestStatus::Warning,
                format!(
                    "{} (limiar: {})",
                    fmt_bytes(h.bytes),
                    fmt_bytes(HTML_WARN_BYTES)
                ),
            ));
            s.findings.push(Finding {
                id: "html_warn".into(),
                category: Category::Html,
                severity: Severity::Low,
                title: "HTML acima do limiar de atenção".into(),
                problem: "O documento é maior que o limiar de atenção da auditoria.".into(),
                evidence: format!("{} de HTML (limiar: {})", fmt_bytes(h.bytes), fmt_bytes(HTML_WARN_BYTES)),
                impact: "Impacto não quantificado neste ambiente.".into(),
                recommendation: "Revisar markup gerado, remover comentários/DOM desnecessário e paginar quando fizer sentido.".into(),
            });
        } else {
            s.tests.push(TestItem::new(
                Category::Html,
                "Tamanho do HTML",
                TestStatus::Pass,
                fmt_bytes(h.bytes).to_string(),
            ));
        }

        if h.external_origins.len() > EXTERNAL_ORIGINS_WARN {
            s.tests.push(TestItem::new(
                Category::Html,
                "Origens externas",
                TestStatus::Warning,
                format!("{} origem(ns) distinta(s)", h.external_origins.len()),
            ));
            s.findings.push(Finding {
                id: "html_many_origins".into(),
                category: Category::Html,
                severity: Severity::Low,
                title: "Excesso de origens externas".into(),
                problem: "Muitos domínios distintos servem recursos, aumentando DNS/TLS e risco de disponibilidade.".into(),
                evidence: h.external_origins.join(", "),
                impact: "Impacto não quantificado neste ambiente.".into(),
                recommendation: "Consolidar assets em menos domínios ou usar same-origin/CDN única; avaliar preconnect quando realmente necessário.".into(),
            });
        } else {
            s.tests.push(TestItem::new(
                Category::Html,
                "Origens externas",
                TestStatus::Pass,
                format!("{} origem(ns) distinta(s)", h.external_origins.len()),
            ));
        }
    }

    // ---------------- Crawl ----------------
    if i.pages_ok + i.pages_failed > 0 {
        if i.pages_failed == 0 {
            s.tests.push(TestItem::new(
                Category::Performance,
                "Páginas rastreadas",
                TestStatus::Pass,
                format!("{} página(s) acessada(s) com sucesso", i.pages_ok),
            ));
        } else {
            s.tests.push(TestItem::new(
                Category::Performance,
                "Páginas rastreadas",
                TestStatus::Warning,
                format!("{} sucesso, {} falha(s)", i.pages_ok, i.pages_failed),
            ));
        }
    }

    // ---------------- Limitações declaradas ----------------
    s.limitations.push(crate::models::Limitation {
        area: "Métricas de navegador (Core Web Vitals)".into(),
        reason: "Não há navegador real neste modo: LCP/CLS/INP não foram medidos. A medição é HTTP estática.".into(),
    });
    s.limitations.push(crate::models::Limitation {
        area: "HTTP/3 (QUIC)".into(),
        reason:
            "Não sondado: depende de suporte da plataforma e evitaria dependências problemáticas."
                .into(),
    });
    s.limitations.push(crate::models::Limitation {
        area: "Registros DNS (CNAME)".into(),
        reason:
            "Não coletados: exigiria resolvedor DNS completo; apenas resolução e IPs foram medidos."
                .into(),
    });
    s.limitations.push(crate::models::Limitation {
        area: "Execução de JavaScript".into(),
        reason: "O JS não é executado; páginas que renderizam conteúdo apenas via JS têm análise parcial.".into(),
    });
    s.limitations.push(crate::models::Limitation {
        area: "Acessibilidade completa".into(),
        reason: "Somente aspectos de acessibilidade ligados a performance (dimensões de imagens, lazy loading) foram verificados.".into(),
    });
    if i.html.is_none() {
        s.limitations.push(crate::models::Limitation {
            area: "Análise de HTML/CSS/JS/imagens".into(),
            reason: "O documento principal não pôde ser obtido ou parseado.".into(),
        });
    }
    s.limitations.push(crate::models::Limitation {
        area: "Ambiente de medição".into(),
        reason: "Tempos variam com rede, distância, CDN e carga do alvo; execute de vários locais para comparar.".into(),
    });

    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::HttpTimings;

    fn base_http(ttfb: Option<u64>, version: &str) -> HttpInfo {
        HttpInfo {
            status: TestStatus::Pass,
            status_code: Some(200),
            http_version: Some(version.into()),
            content_type: Some("text/html".into()),
            content_encoding: Some("gzip".into()),
            transfer_size: Some(1000),
            decoded_size: Some(5000),
            cache_control: Some("no-cache".into()),
            etag: true,
            last_modified: None,
            set_cookie_count: 1,
            server: Some("test".into()),
            vary: Some("Accept-Encoding".into()),
            age: None,
            hsts: true,
            x_content_type_options: true,
            timings: HttpTimings {
                ttfb_ms: ttfb,
                ..HttpTimings::default()
            },
            body_truncated: false,
        }
    }

    fn dns_ok() -> DnsInfo {
        DnsInfo {
            status: TestStatus::Pass,
            detail: "2 endereço(s)".into(),
            ipv4: vec!["93.184.216.34".into()],
            ipv6: vec![],
            resolution_ms: Some(10),
        }
    }

    fn redirects_ok() -> RedirectChain {
        RedirectChain {
            status: TestStatus::Pass,
            detail: "0 hops".into(),
            hops: vec![],
            final_url: "https://example.com".into(),
            loop_detected: false,
        }
    }

    fn html_ok() -> HtmlInfo {
        HtmlInfo {
            bytes: 2048,
            ..HtmlInfo::default()
        }
    }

    #[test]
    fn high_ttfb_produces_high_finding() {
        let http = base_http(Some(2000), "HTTP/2");
        let s = analyze(&Inputs {
            start_url: "https://example.com",
            final_url: "https://example.com",
            http: Some(&http),
            redirects: &redirects_ok(),
            dns: &dns_ok(),
            tls: None,
            html: Some(&html_ok()),
            pages_ok: 0,
            pages_failed: 0,
            page_weight: 0,
        });
        assert!(s.findings.iter().any(|f| f.id == "perf_ttfb_high"));
        let t = s.tests.iter().find(|t| t.name.contains("TTFB")).expect("t");
        assert_eq!(t.status, TestStatus::Fail);
    }

    #[test]
    fn low_ttfb_passes() {
        let http = base_http(Some(120), "HTTP/2");
        let s = analyze(&Inputs {
            start_url: "https://example.com",
            final_url: "https://example.com",
            http: Some(&http),
            redirects: &redirects_ok(),
            dns: &dns_ok(),
            tls: None,
            html: Some(&html_ok()),
            pages_ok: 0,
            pages_failed: 0,
            page_weight: 0,
        });
        assert!(s.findings.iter().all(|f| f.id != "perf_ttfb_high"));
        let t = s.tests.iter().find(|t| t.name.contains("TTFB")).expect("t");
        assert_eq!(t.status, TestStatus::Pass);
    }

    #[test]
    fn http11_gets_low_finding() {
        let http = base_http(Some(100), "HTTP/1.1");
        let s = analyze(&Inputs {
            start_url: "https://example.com",
            final_url: "https://example.com",
            http: Some(&http),
            redirects: &redirects_ok(),
            dns: &dns_ok(),
            tls: None,
            html: Some(&html_ok()),
            pages_ok: 0,
            pages_failed: 0,
            page_weight: 0,
        });
        assert!(s.findings.iter().any(|f| f.id == "net_no_http2"));
    }

    #[test]
    fn no_https_is_high() {
        let http = base_http(Some(100), "HTTP/1.1");
        let s = analyze(&Inputs {
            start_url: "http://example.com",
            final_url: "http://example.com",
            http: Some(&http),
            redirects: &redirects_ok(),
            dns: &dns_ok(),
            tls: None,
            html: Some(&html_ok()),
            pages_ok: 0,
            pages_failed: 0,
            page_weight: 0,
        });
        assert!(s.findings.iter().any(|f| f.id == "net_no_https"));
    }

    #[test]
    fn http_to_https_redirect_passes() {
        let http = base_http(Some(100), "HTTP/2");
        let s = analyze(&Inputs {
            start_url: "http://example.com",
            final_url: "https://example.com",
            http: Some(&http),
            redirects: &redirects_ok(),
            dns: &dns_ok(),
            tls: None,
            html: Some(&html_ok()),
            pages_ok: 0,
            pages_failed: 0,
            page_weight: 0,
        });
        assert!(s.findings.iter().all(|f| f.id != "net_no_https"));
        assert!(
            s.tests
                .iter()
                .any(|t| t.name == "Uso de HTTPS" && t.status == TestStatus::Pass)
        );
    }

    #[test]
    fn redirect_loop_is_high() {
        let http = base_http(Some(100), "HTTP/2");
        let chain = RedirectChain {
            status: TestStatus::Fail,
            detail: "loop".into(),
            hops: vec![],
            final_url: "https://example.com/loop".into(),
            loop_detected: true,
        };
        let s = analyze(&Inputs {
            start_url: "https://example.com",
            final_url: "https://example.com/loop",
            http: Some(&http),
            redirects: &chain,
            dns: &dns_ok(),
            tls: None,
            html: Some(&html_ok()),
            pages_ok: 0,
            pages_failed: 0,
            page_weight: 0,
        });
        assert!(
            s.findings
                .iter()
                .any(|f| f.id == "redirect_loop" && f.severity == Severity::High)
        );
    }

    #[test]
    fn invalid_tls_is_critical() {
        let http = base_http(Some(100), "HTTP/2");
        let tls = TlsInfo {
            status: TestStatus::Fail,
            detail: "certificado expirado".into(),
            protocol: Some("TLSv1.3".into()),
            cipher: None,
            subject: None,
            issuer: None,
            not_before: None,
            not_after: None,
            days_until_expiry: Some(-1),
            sans: vec![],
        };
        let s = analyze(&Inputs {
            start_url: "https://example.com",
            final_url: "https://example.com",
            http: Some(&http),
            redirects: &redirects_ok(),
            dns: &dns_ok(),
            tls: Some(&tls),
            html: Some(&html_ok()),
            pages_ok: 0,
            pages_failed: 0,
            page_weight: 0,
        });
        assert!(
            s.findings
                .iter()
                .any(|f| f.id == "tls_invalid" && f.severity == Severity::Critical)
        );
    }

    #[test]
    fn limitations_always_documented() {
        let http = base_http(Some(100), "HTTP/2");
        let s = analyze(&Inputs {
            start_url: "https://example.com",
            final_url: "https://example.com",
            http: Some(&http),
            redirects: &redirects_ok(),
            dns: &dns_ok(),
            tls: None,
            html: Some(&html_ok()),
            pages_ok: 0,
            pages_failed: 0,
            page_weight: 0,
        });
        assert!(s.limitations.len() >= 5);
        assert!(
            s.limitations
                .iter()
                .any(|l| l.area.contains("Core Web Vitals"))
        );
        assert!(s.limitations.iter().any(|l| l.area.contains("HTTP/3")));
        assert!(s.limitations.iter().any(|l| l.reason.contains("JS")));
    }

    #[test]
    fn big_html_flagged() {
        let http = base_http(Some(100), "HTTP/2");
        let html = HtmlInfo {
            bytes: 400 * 1024,
            ..HtmlInfo::default()
        };
        let s = analyze(&Inputs {
            start_url: "https://example.com",
            final_url: "https://example.com",
            http: Some(&http),
            redirects: &redirects_ok(),
            dns: &dns_ok(),
            tls: None,
            html: Some(&html),
            pages_ok: 0,
            pages_failed: 0,
            page_weight: 0,
        });
        assert!(s.findings.iter().any(|f| f.id == "html_too_big"));
    }

    #[test]
    fn ttfb_unavailable_is_not_tested() {
        let http = base_http(None, "HTTP/2");
        let s = analyze(&Inputs {
            start_url: "https://example.com",
            final_url: "https://example.com",
            http: Some(&http),
            redirects: &redirects_ok(),
            dns: &dns_ok(),
            tls: None,
            html: Some(&html_ok()),
            pages_ok: 0,
            pages_failed: 0,
            page_weight: 0,
        });
        let t = s.tests.iter().find(|t| t.name.contains("TTFB")).expect("t");
        assert_eq!(t.status, TestStatus::NotTested);
        assert!(t.detail.contains("Não disponível"));
    }
}
