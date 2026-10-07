//! Crawler conservador: mesma origem, limite de páginas/profundidade,
//! robots.txt respeitado e concorrência controlada.

use crate::config::Config;
use crate::models::TestStatus;
use crate::scanner::html;
use crate::scanner::http::AuditClient;
use crate::utils::log;
use crate::utils::robots;
use std::collections::VecDeque;
use std::sync::Arc;
use url::Url;

/// Página visitada durante o crawl.
#[derive(Debug)]
pub struct CrawledPage {
    pub url: String,
    pub status: TestStatus,
    pub status_code: Option<u16>,
    pub error: Option<String>,
    pub html_bytes: Option<u64>,
    pub links: Vec<String>,
    pub robots_blocked: bool,
}

/// Resultado agregado do crawl.
#[derive(Debug, Default)]
pub struct CrawlResult {
    pub pages: Vec<CrawledPage>,
    /// Páginas bloqueadas por robots.txt (não visitadas).
    pub blocked_by_robots: usize,
    pub robots_error: Option<String>,
}

/// Executa o crawl limitado. `seed_links` vem do documento principal.
pub async fn crawl(
    client: AuditClient,
    cfg: Arc<Config>,
    start: &Url,
    seed_links: Vec<String>,
) -> CrawlResult {
    let mut result = CrawlResult::default();
    if !cfg.crawl || cfg.max_pages <= 1 {
        return result;
    }

    // robots.txt da origem (uma única requisição).
    let robots_rules = match fetch_robots(&client, start).await {
        Ok(rules) => rules,
        Err(e) => {
            result.robots_error = Some(e);
            robots::parse("", &cfg.user_agent)
        }
    };

    let mut visited: Vec<String> = vec![start.as_str().to_string()];
    let mut queue: VecDeque<(Url, usize)> = VecDeque::new();
    for l in &seed_links {
        if let Ok(u) = Url::parse(l)
            && same_origin(&u, start)
        {
            queue.push_back((u, 1));
        }
    }

    while result.pages.len() < cfg.max_pages - 1 {
        let Some((url, depth)) = queue.pop_front() else {
            break;
        };
        let key = url.as_str().to_string();
        if visited.contains(&key) {
            continue;
        }
        if depth > cfg.max_depth {
            continue;
        }
        visited.push(key.clone());

        let path = url.path().to_string();
        if !robots_rules.is_allowed(&path) {
            result.blocked_by_robots += 1;
            log::verbose(&format!("robots.txt bloqueia {path}"));
            continue;
        }

        log::progress(&format!(
            "Rastreando página {} de {}...",
            result.pages.len() + 1,
            cfg.max_pages - 1
        ));
        match client.fetch(&url).await {
            Ok(fr) => {
                if !same_origin(&fr.final_url, start) {
                    // Saiu da origem via redirect: não seguimos além.
                    result.pages.push(CrawledPage {
                        url: key,
                        status: TestStatus::Warning,
                        status_code: Some(fr.status_code),
                        error: Some("redirect para outra origem — não rastreada".into()),
                        html_bytes: None,
                        links: vec![],
                        robots_blocked: false,
                    });
                    continue;
                }
                let status = if (200..300).contains(&fr.status_code) {
                    TestStatus::Pass
                } else {
                    TestStatus::Warning
                };
                let mut links = Vec::new();
                let mut html_bytes = None;
                if fr
                    .header_str(reqwest::header::CONTENT_TYPE)
                    .is_some_and(|ct| ct.starts_with("text/html"))
                {
                    let (text, _) = crate::utils::decode::decode_text(
                        fr.header_str(reqwest::header::CONTENT_TYPE).as_deref(),
                        &fr.body,
                    );
                    html_bytes = Some(text.len() as u64);
                    let analysis = html::analyze(&text, &fr.final_url);
                    for l in analysis.links {
                        if let Ok(u) = Url::parse(&l)
                            && same_origin(&u, start)
                            && !visited.contains(&u.as_str().to_string())
                        {
                            queue.push_back((u, depth + 1));
                            links.push(l);
                        }
                    }
                }
                result.pages.push(CrawledPage {
                    url: key,
                    status,
                    status_code: Some(fr.status_code),
                    error: None,
                    html_bytes,
                    links,
                    robots_blocked: false,
                });
            }
            Err(e) => {
                result.pages.push(CrawledPage {
                    url: key,
                    status: TestStatus::Error,
                    status_code: None,
                    error: Some(e.to_string()),
                    html_bytes: None,
                    links: vec![],
                    robots_blocked: false,
                });
            }
        }
    }

    result
}

async fn fetch_robots(client: &AuditClient, start: &Url) -> Result<robots::Robots, String> {
    let robots_url = start.join("/robots.txt").map_err(|e| e.to_string())?;
    match client.fetch(&robots_url).await {
        Ok(fr) if (200..300).contains(&fr.status_code) => {
            let (text, _) = crate::utils::decode::decode_text(
                fr.header_str(reqwest::header::CONTENT_TYPE).as_deref(),
                &fr.body,
            );
            Ok(robots::parse(&text, &client.cfg.user_agent))
        }
        Ok(fr) => Err(format!("robots.txt HTTP {}", fr.status_code)),
        Err(e) => Err(e.to_string()),
    }
}

fn same_origin(a: &Url, b: &Url) -> bool {
    a.host_str() == b.host_str()
        && a.scheme() == b.scheme()
        && a.port_or_known_default() == b.port_or_known_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;

    #[tokio::test]
    async fn crawl_respects_max_pages() {
        let server = crate::testserver::spawn_test_server();
        let cfg = Arc::new(Config {
            max_pages: 2,
            ..Config::for_local_tests()
        });
        let client = AuditClient::new(cfg.clone()).expect("client");
        let start = Url::parse(&server.base).expect("url");
        let result = crawl(client, cfg, &start, vec![format!("{}/page2", server.base)]).await;
        assert!(result.pages.len() <= 1); // max_pages=2 => principal + 1
        if let Some(p) = result.pages.first() {
            assert_eq!(p.status, TestStatus::Pass);
        }
    }

    #[tokio::test]
    async fn crawl_respects_robots_txt() {
        let server = crate::testserver::spawn_test_server();
        let cfg = Arc::new(Config {
            max_pages: 3,
            ..Config::for_local_tests()
        });
        let client = AuditClient::new(cfg.clone()).expect("client");
        let start = Url::parse(&server.base).expect("url");
        // /private/secret está em robots.txt (Disallow).
        let result = crawl(
            client,
            cfg,
            &start,
            vec![format!("{}/private/secret", server.base)],
        )
        .await;
        assert_eq!(result.blocked_by_robots, 1);
        assert!(result.pages.is_empty());
    }

    #[tokio::test]
    async fn disabled_crawl_returns_empty() {
        let server = crate::testserver::spawn_test_server();
        let cfg = Arc::new(Config {
            crawl: false,
            ..Config::for_local_tests()
        });
        let client = AuditClient::new(cfg.clone()).expect("client");
        let start = Url::parse(&server.base).expect("url");
        let result = crawl(client, cfg, &start, vec![]).await;
        assert!(result.pages.is_empty());
        assert!(result.robots_error.is_none());
    }

    #[tokio::test]
    async fn crawl_stays_on_same_origin() {
        let server = crate::testserver::spawn_test_server();
        let cfg = Arc::new(Config {
            max_pages: 3,
            ..Config::for_local_tests()
        });
        let client = AuditClient::new(cfg.clone()).expect("client");
        let start = Url::parse(&server.base).expect("url");
        let result = crawl(
            client,
            cfg,
            &start,
            vec!["https://external.example.org/other".into()],
        )
        .await;
        assert!(result.pages.is_empty());
    }
}
