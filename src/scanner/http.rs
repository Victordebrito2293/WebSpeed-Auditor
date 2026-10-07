//! Cliente HTTP de auditoria: redirects manuais com revalidação SSRF,
//! limites de tamanho/tempo, medição de tempos e resolvedor DNS seguro.

use crate::config::{Config, LogLevel};
use crate::utils::log;
use crate::utils::ssrf::{self, SsrfError};
use reqwest::header::{ACCEPT_ENCODING, HeaderMap, LOCATION, USER_AGENT};
use std::collections::HashSet;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Semaphore;
use url::Url;

/// Erro ao buscar um recurso.
#[derive(Debug)]
pub enum FetchError {
    Ssrf(SsrfError),
    Timeout,
    Http(String),
    TooManyRedirects,
    RedirectLoop,
    InvalidRedirect(String),
    InvalidUrl(String),
    Cancelled,
}

impl std::fmt::Display for FetchError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FetchError::Ssrf(e) => write!(f, "bloqueio de segurança: {e}"),
            FetchError::Timeout => write!(f, "timeout excedido"),
            FetchError::Http(e) => write!(f, "erro HTTP: {e}"),
            FetchError::TooManyRedirects => write!(f, "número máximo de redirects excedido"),
            FetchError::RedirectLoop => write!(f, "loop de redirects detectado"),
            FetchError::InvalidRedirect(e) => write!(f, "redirect inválido: {e}"),
            FetchError::InvalidUrl(e) => write!(f, "URL inválida: {e}"),
            FetchError::Cancelled => write!(f, "cancelado"),
        }
    }
}

impl std::error::Error for FetchError {}

impl From<SsrfError> for FetchError {
    fn from(e: SsrfError) -> Self {
        FetchError::Ssrf(e)
    }
}

/// Resultado de uma busca (somente em memória).
#[derive(Debug)]
pub struct FetchResult {
    pub requested_url: Url,
    pub final_url: Url,
    pub status_code: u16,
    pub headers: HeaderMap,
    pub body: Vec<u8>,
    pub body_truncated: bool,
    pub http_version: String,
    /// Tempo até os cabeçalhos da resposta final (inclui conexão/TLS).
    pub ttfb_ms: Option<u64>,
    /// Download do corpo da resposta final.
    pub download_ms: Option<u64>,
    /// Tempo total (todos os hops).
    pub total_ms: Option<u64>,
    /// Tempo de DNS medido na validação prévia.
    pub dns_ms: Option<u64>,
    /// Cadeia de redirects percorrida.
    pub hops: Vec<(String, u16, String, Option<u64>)>,
    /// Loop de redirects detectado.
    pub loop_detected: bool,
}

impl FetchResult {
    pub fn header_str(&self, name: reqwest::header::HeaderName) -> Option<String> {
        self.headers
            .get(name)
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string())
    }

    pub fn header_opt(&self, name: reqwest::header::HeaderName) -> Option<&str> {
        self.headers.get(name).and_then(|v| v.to_str().ok())
    }
}

/// Resolvedor DNS que aplica a política SSRF em TODA resolução de conexão
/// (defesa contra DNS rebinding em subrequests e redirects).
pub struct SafeResolver {
    pub protection: bool,
}

impl reqwest::dns::Resolve for SafeResolver {
    fn resolve(&self, name: reqwest::dns::Name) -> reqwest::dns::Resolving {
        let protection = self.protection;
        let host = name.as_str().to_string();
        Box::pin(async move {
            let ips = tokio::time::timeout(Duration::from_secs(10), ssrf::resolve_host(&host))
                .await
                .map_err(|_| "timeout na resolução DNS".to_string())?
                .map_err(|e| e.to_string())?;
            if protection {
                ssrf::check_ips(&ips).map_err(|e| e.to_string())?;
            }
            let addrs: Vec<std::net::SocketAddr> = ips
                .iter()
                .map(|ip| std::net::SocketAddr::new(*ip, 0))
                .collect();
            if addrs.is_empty() {
                return Err("nenhum endereço resolvido".into());
            }
            let iter: reqwest::dns::Addrs = Box::new(addrs.into_iter());
            Ok(iter)
        })
    }
}

#[derive(Clone)]
pub struct AuditClient {
    inner: reqwest::Client,
    pub cfg: Arc<Config>,
    gate: Arc<Semaphore>,
}

impl AuditClient {
    pub fn new(cfg: Arc<Config>) -> Result<Self, FetchError> {
        let resolver = SafeResolver {
            protection: cfg.ssrf_protection,
        };
        let inner = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(cfg.timeout)
            .pool_max_idle_per_host(4)
            .tcp_nodelay(true)
            .dns_resolver(Arc::new(resolver))
            .build()
            .map_err(|e| FetchError::Http(e.to_string()))?;
        Ok(Self {
            inner,
            gate: Arc::new(Semaphore::new(cfg.concurrency)),
            cfg,
        })
    }

    /// Valida formato + endereços e mede o tempo de DNS.
    pub async fn preflight(&self, url: &Url) -> Result<Option<u64>, FetchError> {
        let t = Instant::now();
        ssrf::validate_url(&self.cfg, url).await?;
        Ok(Some(t.elapsed().as_millis() as u64))
    }

    /// Busca uma URL seguindo redirects manualmente, revalidando cada salto.
    pub async fn fetch(&self, url: &Url) -> Result<FetchResult, FetchError> {
        let mut current = url.clone();
        let mut seen: HashSet<String> = HashSet::new();
        seen.insert(current.as_str().to_string());

        let total_start = Instant::now();
        let mut hops: Vec<(String, u16, String, Option<u64>)> = Vec::new();
        let mut dns_ms: Option<u64> = None;

        for hop in 0..=self.cfg.max_redirects {
            // Revalidação a cada salto: uma URL pública nunca pode virar interna.
            let dns = self.preflight(&current).await?;
            if dns_ms.is_none() {
                dns_ms = dns;
            }

            let (status, headers, version, body, truncated, ttfb, download) =
                self.request_once(&current).await?;

            if (300..400).contains(&status) {
                let location = headers
                    .get(LOCATION)
                    .and_then(|v| v.to_str().ok())
                    .map(|s| s.to_string());
                let Some(location) = location else {
                    // Redirect sem Location: tratamos como resposta final.
                    return Ok(FetchResult {
                        requested_url: url.clone(),
                        final_url: current,
                        status_code: status,
                        headers,
                        body,
                        body_truncated: truncated,
                        http_version: version,
                        ttfb_ms: Some(ttfb),
                        download_ms: Some(download),
                        total_ms: Some(total_start.elapsed().as_millis() as u64),
                        dns_ms,
                        hops,
                        loop_detected: false,
                    });
                };
                let next = current
                    .join(&location)
                    .map_err(|e| FetchError::InvalidRedirect(format!("{location}: {e}")))?;
                // Validar esquema/destino imediatamente.
                ssrf::validate_url_shape(&next).map_err(FetchError::Ssrf)?;
                let hop_no = hop + 1;
                if !seen.insert(next.as_str().to_string()) {
                    hops.push((current.to_string(), status, next.to_string(), Some(ttfb)));
                    return Ok(FetchResult {
                        requested_url: url.clone(),
                        final_url: next,
                        status_code: status,
                        headers,
                        body,
                        body_truncated: truncated,
                        http_version: version,
                        ttfb_ms: Some(ttfb),
                        download_ms: Some(download),
                        total_ms: Some(total_start.elapsed().as_millis() as u64),
                        dns_ms,
                        hops,
                        loop_detected: true,
                    });
                }
                log::verbose(&format!(
                    "redirect {hop_no}: {current} -> {next} ({status})"
                ));
                hops.push((current.to_string(), status, next.to_string(), Some(ttfb)));
                current = next;
                continue;
            }

            return Ok(FetchResult {
                requested_url: url.clone(),
                final_url: current,
                status_code: status,
                headers,
                body,
                body_truncated: truncated,
                http_version: version,
                ttfb_ms: Some(ttfb),
                download_ms: Some(download),
                total_ms: Some(total_start.elapsed().as_millis() as u64),
                dns_ms,
                hops,
                loop_detected: false,
            });
        }
        Err(FetchError::TooManyRedirects)
    }

    /// Uma requisição única: headers + corpo limitado.
    async fn request_once(
        &self,
        url: &Url,
    ) -> Result<(u16, HeaderMap, String, Vec<u8>, bool, u64, u64), FetchError> {
        let _permit = self
            .gate
            .acquire()
            .await
            .map_err(|_| FetchError::Cancelled)?;

        let req = self
            .inner
            .get(url.clone())
            .header(USER_AGENT, self.cfg.user_agent.clone())
            .header(ACCEPT_ENCODING, "gzip, deflate, br");

        if self.cfg.log_level == LogLevel::Verbose {
            log::verbose(&format!("GET {url}"));
        }

        let t0 = Instant::now();
        let mut resp = tokio::time::timeout(self.cfg.timeout, req.send())
            .await
            .map_err(|_| FetchError::Timeout)?
            .map_err(|e| FetchError::Http(e.to_string()))?;

        let status = resp.status().as_u16();
        let version = match resp.version() {
            reqwest::Version::HTTP_09 => "HTTP/0.9",
            reqwest::Version::HTTP_10 => "HTTP/1.0",
            reqwest::Version::HTTP_11 => "HTTP/1.1",
            reqwest::Version::HTTP_2 => "HTTP/2",
            reqwest::Version::HTTP_3 => "HTTP/3",
            _ => "desconhecido",
        }
        .to_string();
        let headers = resp.headers().clone();
        let ttfb = t0.elapsed().as_millis() as u64;

        // Corpo limitado — streaming com corte rígido.
        let limit = self.cfg.max_body_bytes;
        let mut body: Vec<u8> = Vec::new();
        let mut truncated = false;
        let t1 = Instant::now();
        loop {
            match tokio::time::timeout(self.cfg.timeout, resp.chunk()).await {
                Err(_) => return Err(FetchError::Timeout),
                Ok(Err(e)) => return Err(FetchError::Http(e.to_string())),
                Ok(Ok(None)) => break,
                Ok(Ok(Some(chunk))) => {
                    let remaining = limit.saturating_sub(body.len() as u64);
                    if (chunk.len() as u64) > remaining {
                        body.extend_from_slice(&chunk[..remaining as usize]);
                        truncated = true;
                        break;
                    }
                    body.extend_from_slice(&chunk);
                }
            }
        }
        let download = t1.elapsed().as_millis() as u64;

        Ok((status, headers, version, body, truncated, ttfb, download))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fetch_error_display_is_human() {
        let e = FetchError::Ssrf(SsrfError::BlockedAddress("127.0.0.1".parse().expect("ip")));
        assert!(e.to_string().contains("bloqueio de segurança"));
        assert_eq!(FetchError::Timeout.to_string(), "timeout excedido");
        assert_eq!(
            FetchError::TooManyRedirects.to_string(),
            "número máximo de redirects excedido"
        );
    }

    #[tokio::test]
    async fn client_builds_with_default_config() {
        let cfg = Arc::new(Config::default());
        let c = AuditClient::new(cfg);
        assert!(c.is_ok());
    }

    #[tokio::test]
    async fn preflight_blocks_loopback_when_protected() {
        let cfg = Arc::new(Config::default());
        let client = AuditClient::new(cfg).expect("client");
        let url = Url::parse("http://127.0.0.1/").expect("url");
        let err = client.preflight(&url).await.expect_err("deve bloquear");
        assert!(matches!(err, FetchError::Ssrf(_)));
    }

    #[tokio::test]
    async fn preflight_blocks_metadata_ip() {
        let cfg = Arc::new(Config::default());
        let client = AuditClient::new(cfg).expect("client");
        for u in [
            "http://169.254.169.254/",
            "http://10.0.0.1/",
            "http://192.168.1.1/",
        ] {
            let url = Url::parse(u).expect("url");
            assert!(
                client.preflight(&url).await.is_err(),
                "{u} deve ser bloqueado"
            );
        }
    }

    #[tokio::test]
    async fn preflight_allows_local_test_mode() {
        let cfg = Arc::new(Config::for_local_tests());
        let client = AuditClient::new(cfg).expect("client");
        let url = Url::parse("http://127.0.0.1:9/").expect("url");
        // Validação passa (proteção desativada em testes locais).
        assert!(client.preflight(&url).await.is_ok());
    }

    #[tokio::test]
    async fn fetch_timeout_on_unroutable() {
        let cfg = Arc::new(Config {
            timeout: Duration::from_millis(300),
            ssrf_protection: false,
            ..Config::default()
        });
        let client = AuditClient::new(cfg).expect("client");
        // Porta 1 em endereço não roteável (TEST-NET): deve dar erro, não travar.
        let url = Url::parse("http://192.0.2.1:1/").expect("url");
        let res = tokio::time::timeout(Duration::from_secs(10), client.fetch(&url)).await;
        assert!(res.is_err() || res.expect("tempo").is_err());
    }
}
