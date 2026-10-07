//! Orquestração da auditoria ponta a ponta.
//!
//! Cada etapa é isolada: a falha de uma analise não interrompe as demais.
//! Todos os dados permanecem em memória até o relatório ser (ou não)
//! exportado pelo usuário.

use crate::analysis::{self, Section, recommendations, scoring};
use crate::config::{Config, LogLevel};
use crate::models::*;
use crate::scanner::{
    cache, compression, crawling, css, dns, fonts, html, http, images, javascript, resources,
    security_headers, tls,
};
use crate::utils::decode;
use crate::utils::log;
use crate::utils::timex;
use reqwest::header::{CONTENT_ENCODING, CONTENT_TYPE, ETAG, LAST_MODIFIED};
use std::time::Instant;
use url::Url;

#[derive(Debug)]
pub enum AuditError {
    InvalidUrl(String),
    Blocked(String),
    Internal(String),
}

impl std::fmt::Display for AuditError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AuditError::InvalidUrl(e) => write!(f, "URL inválida: {e}"),
            AuditError::Blocked(e) => write!(f, "URL bloqueada por segurança: {e}"),
            AuditError::Internal(e) => write!(f, "erro interno: {e}"),
        }
    }
}

impl std::error::Error for AuditError {}

/// Normaliza a entrada do usuário: aceita `example.com` (assume https).
pub fn normalize_url_input(input: &str) -> Result<Url, AuditError> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return Err(AuditError::InvalidUrl("entrada vazia".into()));
    }
    if trimmed.len() > crate::config::MAX_URL_LENGTH {
        return Err(AuditError::InvalidUrl("URL excede o tamanho máximo".into()));
    }
    // Preserva o esquema quando explícito (inclusive os que serão rejeitados
    // pela validação de forma); assume https apenas quando ausente.
    let has_scheme = trimmed.contains("://")
        || trimmed.starts_with("javascript:")
        || trimmed.starts_with("data:");
    let candidate = if has_scheme {
        trimmed.to_string()
    } else {
        format!("https://{trimmed}")
    };
    let url = Url::parse(&candidate).map_err(|e| AuditError::InvalidUrl(e.to_string()))?;
    crate::utils::ssrf::validate_url_shape(&url).map_err(|e| AuditError::Blocked(e.to_string()))?;
    Ok(url)
}

/// Executa a auditoria completa. Retorna o relatório em memória.
pub async fn run(url_input: &str, cfg: Config) -> Result<AuditReport, AuditError> {
    let cfg = cfg.clamped();
    log::set_level(cfg.log_level);

    let url = normalize_url_input(url_input)?;
    let started = Instant::now();
    log::progress("Validando URL...");
    log::progress("Verificando conectividade...");
    log::progress("Iniciando análise...");

    let client = http::AuditClient::new(std::sync::Arc::new(cfg.clone()))
        .map_err(|e| AuditError::Internal(e.to_string()))?;

    let host = url.host_str().unwrap_or("").to_string();
    let is_https = url.scheme() == "https";
    let port = url
        .port_or_known_default()
        .unwrap_or(if is_https { 443 } else { 80 });

    // --- DNS ---
    let dns_info = dns::analyze(&host).await;
    if dns_info.status == TestStatus::Error {
        log::warn(&format!("DNS: FAILED — {}", dns_info.detail));
    }

    // --- TLS (apenas HTTPS, com endereços já resolvidos) ---
    let mut tls_result: Option<tls::TlsProbeResult> = None;
    if is_https && dns_info.status == TestStatus::Pass {
        let ips: Vec<std::net::IpAddr> = dns_info
            .ipv4
            .iter()
            .chain(dns_info.ipv6.iter())
            .filter_map(|s| s.parse().ok())
            .collect();
        if !ips.is_empty() {
            log::progress("Verificando TLS...");
            let probe = tls::probe(host.clone(), port, ips, cfg.timeout).await;
            tls_result = Some(probe);
        }
    }

    // --- Documento principal ---
    log::progress("Baixando documento principal...");
    let mut section = Section::default();
    let main_fetch = match client.fetch(&url).await {
        Ok(f) => Some(f),
        Err(e) => {
            log::error(&format!("Falha ao obter o documento principal: {e}"));
            section.merge(analysis::failed_step(
                Category::Performance,
                "Documento principal",
                &e.to_string(),
            ));
            None
        }
    };

    // --- Redirects ---
    let mut redirects = RedirectChain {
        status: TestStatus::NotTested,
        detail: "documento não obtido".into(),
        hops: vec![],
        final_url: url.to_string(),
        loop_detected: false,
    };

    // --- HTTP / HTML / recursos ---
    let mut http_info: Option<HttpInfo> = None;
    let mut html_info: Option<HtmlInfo> = None;
    let mut html_analysis: Option<html::HtmlAnalysis> = None;
    let mut fetched: Vec<resources::FetchedResource> = Vec::new();
    let mut page_weight: u64 = 0;

    if let Some(fr) = &main_fetch {
        // Cadeia de redirects.
        redirects.hops = fr
            .hops
            .iter()
            .map(|(from, status, to, latency)| RedirectHop {
                from: from.clone(),
                status: *status,
                to: to.clone(),
                latency_ms: *latency,
            })
            .collect();
        redirects.final_url = fr.final_url.to_string();
        redirects.loop_detected = fr.loop_detected;
        redirects.status = if fr.loop_detected {
            TestStatus::Fail
        } else {
            TestStatus::Pass
        };
        redirects.detail = if redirects.hops.is_empty() {
            "sem redirects".into()
        } else {
            format!("{} salto(s)", redirects.hops.len())
        };

        // HttpInfo.
        let content_type = fr.header_str(CONTENT_TYPE);
        let content_encoding = fr.header_str(CONTENT_ENCODING);
        let (decoded, decoded_ok) = match decode::decompress(
            content_encoding.as_deref(),
            &fr.body,
            cfg.max_body_bytes.min(32 * 1024 * 1024),
        ) {
            Ok((b, done)) => (b, done),
            Err(e) => {
                section.tests.push(TestItem::new(
                    Category::Compression,
                    "Descompressão do documento",
                    TestStatus::Warning,
                    format!("não foi possível descomprimir: {e}"),
                ));
                (fr.body.clone(), false)
            }
        };
        let _ = decoded_ok;

        let mut timings = HttpTimings {
            dns_ms: fr.dns_ms,
            connect_ms: tls_result.as_ref().and_then(|t| t.connect_ms),
            tls_ms: tls_result.as_ref().and_then(|t| t.tls_ms),
            ttfb_ms: fr.ttfb_ms,
            download_ms: fr.download_ms,
            total_ms: fr.total_ms,
        };
        if !is_https {
            timings.tls_ms = None;
        }

        http_info = Some(HttpInfo {
            status: TestStatus::Pass,
            status_code: Some(fr.status_code),
            http_version: Some(fr.http_version.clone()),
            content_type: content_type.clone(),
            content_encoding,
            transfer_size: Some(fr.body.len() as u64),
            decoded_size: Some(decoded.len() as u64),
            cache_control: fr.header_str(reqwest::header::CACHE_CONTROL),
            etag: fr.headers.contains_key(ETAG),
            last_modified: fr.header_str(LAST_MODIFIED),
            set_cookie_count: fr
                .headers
                .get_all(reqwest::header::SET_COOKIE)
                .iter()
                .count(),
            server: fr.header_str(reqwest::header::SERVER),
            vary: fr.header_str(reqwest::header::VARY),
            age: fr.header_str(reqwest::header::AGE),
            hsts: fr
                .headers
                .contains_key(reqwest::header::STRICT_TRANSPORT_SECURITY),
            x_content_type_options: fr
                .headers
                .contains_key(reqwest::header::X_CONTENT_TYPE_OPTIONS),
            timings,
            body_truncated: fr.body_truncated,
        });
        page_weight += fr.body.len() as u64;

        // Teste do documento.
        let code = fr.status_code;
        section.tests.push(TestItem::new(
            Category::Performance,
            "Documento principal",
            if (200..300).contains(&code) {
                TestStatus::Pass
            } else {
                TestStatus::Fail
            },
            format!("HTTP {code} em {}", fr.final_url),
        ));

        if fr.body_truncated {
            section.tests.push(TestItem::new(
                Category::Performance,
                "Tamanho do corpo do documento",
                TestStatus::Warning,
                format!(
                    "corpo truncado no limite de {}",
                    timex::fmt_bytes(cfg.max_body_bytes)
                ),
            ));
            section.limitations.push(crate::models::Limitation {
                area: "Corpo do documento".into(),
                reason: "excede o limite de tamanho por requisição; análise parcial".into(),
            });
        }

        // HTML?
        let is_html = content_type
            .as_deref()
            .unwrap_or("")
            .starts_with("text/html");
        if is_html {
            let (text, _) = decode::decode_text(content_type.as_deref(), &decoded);
            let analysis = html::analyze(&text, &fr.final_url);
            html_info = Some(analysis.info.clone());
            html_analysis = Some(analysis);
            log::verbose("HTML analisado");
        } else {
            section.tests.push(TestItem::new(
                Category::Html,
                "Análise de HTML",
                TestStatus::NotTested,
                format!(
                    "Content-Type do documento é '{}' — análise de HTML pulada",
                    content_type.as_deref().unwrap_or("desconhecido")
                ),
            ));
            section.limitations.push(crate::models::Limitation {
                area: "Análise de HTML".into(),
                reason: "o documento não é text/html".into(),
            });
        }

        // Subrecursos.
        if let Some(analysis) = &html_analysis
            && !fr.body_truncated
            && cfg.max_resources > 0
        {
            fetched = resources::fetch_resources(&client, &analysis.resources).await;
            page_weight += fetched
                .iter()
                .map(|f| f.record.transfer_size.unwrap_or(0))
                .sum::<u64>();
        }
    }

    // --- Crawl multi-página ---
    let mut crawl_result = crawling::CrawlResult::default();
    if cfg.crawl
        && cfg.max_pages > 1
        && html_analysis.is_some()
        && let Some(fr) = main_fetch.as_ref()
    {
        let links = html_analysis
            .as_ref()
            .map(|a| a.links.clone())
            .unwrap_or_default();
        log::progress("Rastreando páginas...");
        crawl_result = crawling::crawl(
            client.clone(),
            std::sync::Arc::new(cfg.clone()),
            &fr.final_url,
            links,
        )
        .await;
        if let Some(err) = &crawl_result.robots_error {
            log::verbose(&format!("robots.txt: {err}"));
        }
    }

    // --- Análises por categoria (executadas uma única vez) ---
    let mut css_info = CssInfo::default();
    let mut js_info = JsInfo::default();
    let mut images_info = ImagesInfo::default();
    let mut fonts_info = FontsInfo::default();

    if let Some(analysis) = &html_analysis {
        let (info, sec) = css::analyze(analysis, &fetched);
        css_info = info;
        section.merge(sec);
        let (info, sec) = javascript::analyze(analysis, &fetched);
        js_info = info;
        section.merge(sec);
        let (info, sec) = images::analyze(analysis, &fetched);
        images_info = info;
        section.merge(sec);
        let (info, sec) = fonts::analyze(analysis, &fetched);
        fonts_info = info;
        section.merge(sec);
    } else {
        section.merge(Section::default().limitation(
            "Análises de CSS/JavaScript/imagens/fontes",
            "o documento HTML não estava disponível",
        ));
    }

    // Peso da página.
    if page_weight > 0 {
        if page_weight > recommendations::PAGE_WEIGHT_WARN {
            section.tests.push(TestItem::new(
                Category::Performance,
                "Peso total da página",
                TestStatus::Warning,
                format!(
                    "{} (limiar: {})",
                    timex::fmt_bytes(page_weight),
                    timex::fmt_bytes(recommendations::PAGE_WEIGHT_WARN)
                ),
            ));
            section.findings.push(Finding {
                id: "perf_page_weight".into(),
                category: Category::Performance,
                severity: Severity::Medium,
                title: "Peso total da página elevado".into(),
                problem: "A soma de documento e recursos excede o limiar documentado de auditoria.".into(),
                evidence: format!(
                    "{} transferidos (documento + {} recurso(s))",
                    timex::fmt_bytes(page_weight),
                    fetched.len()
                ),
                impact: "Impacto não quantificado neste ambiente.".into(),
                recommendation: "Reduzir a quantidade e o tamanho de recursos, usar formatos modernos, compressão e cache eficaz.".into(),
            });
        } else {
            section.tests.push(TestItem::new(
                Category::Performance,
                "Peso total da página",
                TestStatus::Pass,
                format!(
                    "{} (limiar: {})",
                    timex::fmt_bytes(page_weight),
                    timex::fmt_bytes(recommendations::PAGE_WEIGHT_WARN)
                ),
            ));
        }
    }

    // Recursos com erro.
    let bad_resources: Vec<String> = fetched
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
    if !bad_resources.is_empty() {
        section.tests.push(
            TestItem::new(
                Category::BestPractices,
                "Recuperação de subrecursos",
                TestStatus::Warning,
                format!("{} recurso(s) com falha/erro", bad_resources.len()),
            )
            .with_evidence(bad_resources.join("; ")),
        );
        section.findings.push(Finding {
            id: "resource_errors".into(),
            category: Category::BestPractices,
            severity: Severity::Medium,
            title: "Subrecursos com erro".into(),
            problem: "Alguns recursos referenciados não puderam ser baixados com sucesso (404/5xx/falha).".into(),
            evidence: bad_resources.join("; "),
            impact: "Impacto não quantificado neste ambiente.".into(),
            recommendation: "Corrigir as URLs quebradas ou remover as referências no HTML.".into(),
        });
    }

    // Headers, cache, compressão.
    let records: Vec<crate::models::ResourceRecord> =
        fetched.iter().map(|f| f.record.clone()).collect();
    if let Some(h) = &http_info {
        section.merge(security_headers::analyze(
            h,
            is_https || redirects.final_url.starts_with("https://"),
        ));
    } else {
        section.merge(
            Section::default().limitation("Headers HTTP", "documento principal indisponível"),
        );
    }
    let (cache_info, sec) = cache::analyze(http_info.as_ref(), &records);
    section.merge(sec);
    let (compression_info, sec) = compression::analyze(http_info.as_ref(), &records);
    section.merge(sec);

    // --- Recomendações gerais ---
    let pages_ok = crawl_result
        .pages
        .iter()
        .filter(|p| p.status == TestStatus::Pass)
        .count();
    let pages_failed = crawl_result.pages.len() - pages_ok;

    section.merge(recommendations::analyze(&recommendations::Inputs {
        start_url: url.as_str(),
        final_url: redirects.final_url.as_str(),
        http: http_info.as_ref(),
        redirects: &redirects,
        dns: &dns_info,
        tls: tls_result.as_ref().map(|t| &t.info),
        html: html_info.as_ref(),
        pages_ok,
        pages_failed,
        page_weight,
    }));

    // Resultado do TLS (se houver).
    if let Some(t) = &tls_result {
        if matches!(t.info.status, TestStatus::Pass | TestStatus::Warning) {
            // já coberto pelas recomendações
        } else if t.info.status == TestStatus::Error {
            section.limitations.push(crate::models::Limitation {
                area: "Sondagem TLS".into(),
                reason: t.info.detail.clone(),
            });
        }
    }

    // --- Análises que dependem dos resultados ---
    let mut tests = section.tests;
    let mut findings = section.findings;
    let mut limitations = section.limitations;

    // Regra de honestidade: HTTP/3 nunca é afirmado sem teste.
    limitations.sort_by(|a, b| a.area.cmp(&b.area));
    limitations.dedup_by(|a, b| a.area == b.area && a.reason == b.reason);

    // Ordena findings: severidade desc, depois peso da categoria.
    findings.sort_by(|b, a| {
        a.severity
            .cmp(&b.severity)
            .then_with(|| a.category.weight().cmp(&b.category.weight()))
    });
    // IDs únicos.
    let mut seen_ids: Vec<String> = vec![];
    findings.retain(|f| {
        if seen_ids.contains(&f.id) {
            false
        } else {
            seen_ids.push(f.id.clone());
            true
        }
    });

    // Transparência: se nada pôde ser avaliado, o score não representa o site.
    let evaluated = tests
        .iter()
        .filter(|t| {
            matches!(
                t.status,
                TestStatus::Pass | TestStatus::Warning | TestStatus::Fail
            )
        })
        .count();
    if evaluated == 0 {
        limitations.push(crate::models::Limitation {
            area: "Score geral".into(),
            reason: "nenhuma verificação pôde ser concluída neste ambiente; o score 0 não avalia a qualidade do site".into(),
        });
    }

    let scores = scoring::compute(&tests, &findings);
    let optimized: Vec<TestItem> = tests
        .iter()
        .filter(|t| t.status == TestStatus::Pass)
        .cloned()
        .collect();

    let mut pages: Vec<String> = vec![url.to_string()];
    pages.extend(crawl_result.pages.iter().map(|p| p.url.clone()));

    let requests_analyzed = 1 + fetched.len() + crawl_result.pages.len();

    let generated_at_unix = timex::unix_now();
    let duration_ms = started.elapsed().as_millis() as u64;

    // Nunca registrar nível verboso com dados do alvo fora do relatório.
    if cfg.log_level == LogLevel::Verbose {
        log::verbose(&format!("análise concluída em {duration_ms} ms"));
    }

    Ok(AuditReport {
        tool: "WebSpeed Auditor".into(),
        version: env!("CARGO_PKG_VERSION").into(),
        url: url.to_string(),
        final_url: redirects.final_url.clone(),
        generated_at_unix,
        generated_at_iso8601: timex::unix_to_iso8601(generated_at_unix),
        duration_ms,
        pages_analyzed: pages.len(),
        requests_analyzed,
        scores,
        tests: std::mem::take(&mut tests),
        findings,
        optimized,
        not_tested: limitations,
        dns: dns_info,
        tls: tls_result.map(|t| t.info),
        redirects,
        http: http_info,
        html: html_info,
        css: css_info,
        javascript: js_info,
        images: images_info,
        fonts: fonts_info,
        cache: cache_info,
        compression: compression_info,
        resources: fetched.iter().map(|f| f.record.clone()).collect(),
        pages,
    })
}
