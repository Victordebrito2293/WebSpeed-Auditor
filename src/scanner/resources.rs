//! Coleta de subrecursos (CSS, JS, imagens, fontes) — tudo em memória,
//! com limites de quantidade, tamanho e concorrência.

use crate::models::{ResourceKind, ResourceRecord, TestStatus};
use crate::scanner::html::ResourceRef;
use crate::scanner::http::AuditClient;
use crate::utils::decode;
use crate::utils::log;
use crate::utils::sniff;
use reqwest::header::{CACHE_CONTROL, CONTENT_ENCODING, CONTENT_TYPE, ETAG, LAST_MODIFIED};
use url::Url;

/// Recurso buscado com corpo (apenas em memória durante a auditoria).
#[derive(Debug)]
pub struct FetchedResource {
    pub record: ResourceRecord,
    pub body: Vec<u8>,
}

/// Busca todos os recursos únicos (respeitando limites e concorrência).
pub async fn fetch_resources(client: &AuditClient, refs: &[ResourceRef]) -> Vec<FetchedResource> {
    let mut seen: Vec<String> = Vec::new();
    let mut unique: Vec<&ResourceRef> = Vec::new();
    for r in refs {
        if !seen.contains(&r.url) {
            seen.push(r.url.clone());
            unique.push(r);
        }
    }
    let limit = client.cfg.max_resources.min(unique.len());
    let selected = &unique[..limit];

    log::progress(&format!("Coletando {} recursos...", selected.len()));

    let mut handles = Vec::with_capacity(selected.len());
    for r in selected {
        let client = client.clone();
        let url = r.url.clone();
        let kind = r.kind;
        handles.push(tokio::spawn(async move {
            let fetched = fetch_one(&client, &url, kind).await;
            (url, kind, fetched)
        }));
    }

    let mut out = Vec::with_capacity(handles.len());
    for h in handles {
        if let Ok((_url, _kind, fetched)) = h.await {
            out.push(fetched);
        }
    }
    out
}

async fn fetch_one(client: &AuditClient, url: &str, kind: ResourceKind) -> FetchedResource {
    let parsed = match Url::parse(url) {
        Ok(u) => u,
        Err(e) => {
            return error_record(url, kind, format!("URL inválida: {e}"));
        }
    };
    match client.fetch(&parsed).await {
        Ok(fr) => {
            let content_type = fr.header_str(CONTENT_TYPE);
            let encoding = fr.header_str(CONTENT_ENCODING);
            let transfer_size = fr.body.len() as u64;

            // Descompressão em memória (limitada) para medir tamanho real.
            let decoded = if encoding.is_some() {
                decode::decompress(
                    encoding.as_deref(),
                    &fr.body,
                    client.cfg.max_body_bytes.min(16 * 1024 * 1024),
                )
                .ok()
                .map(|(b, _)| b)
            } else {
                Some(fr.body.clone())
            };
            let decoded_size = decoded.as_ref().map(|b| b.len() as u64);

            let sniffed_format = if kind == ResourceKind::Image {
                decoded
                    .as_ref()
                    .and_then(|b| sniff::sniff_image_format(b).map(|s| s.to_string()))
            } else {
                None
            };

            let status = if (200..300).contains(&fr.status_code) && !fr.body_truncated {
                TestStatus::Pass
            } else if fr.body_truncated {
                TestStatus::Warning
            } else if fr.status_code >= 400 {
                TestStatus::Fail
            } else {
                TestStatus::Warning
            };

            let record = ResourceRecord {
                url: url.to_string(),
                kind,
                status,
                status_code: Some(fr.status_code),
                content_type,
                content_encoding: encoding,
                transfer_size: Some(transfer_size),
                decoded_size,
                cache_control: fr.header_str(CACHE_CONTROL),
                etag: fr.headers.contains_key(ETAG),
                last_modified: fr.headers.contains_key(LAST_MODIFIED),
                timing_ms: fr.total_ms,
                error: if fr.body_truncated {
                    Some("corpo truncado no limite de tamanho".into())
                } else {
                    None
                },
                sniffed_format,
            };
            FetchedResource {
                record,
                body: decoded.unwrap_or_default(),
            }
        }
        Err(e) => error_record(url, kind, e.to_string()),
    }
}

fn error_record(url: &str, kind: ResourceKind, error: String) -> FetchedResource {
    FetchedResource {
        record: ResourceRecord {
            url: url.to_string(),
            kind,
            status: TestStatus::Error,
            status_code: None,
            content_type: None,
            content_encoding: None,
            transfer_size: None,
            decoded_size: None,
            cache_control: None,
            etag: false,
            last_modified: false,
            timing_ms: None,
            error: Some(error),
            sniffed_format: None,
        },
        body: Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn fetch_local_resources_in_test_mode() {
        // Servidor local mínimo criado apenas durante o teste.
        let server = crate::testserver::spawn_test_server();
        let cfg = crate::config::Config::for_local_tests();
        let client = AuditClient::new(std::sync::Arc::new(cfg)).expect("client");
        let refs = vec![
            ResourceRef {
                url: format!("{}/style.css", server.base),
                kind: ResourceKind::Css,
                external: false,
                has_dimensions: false,
                lazy: false,
                srcset: false,
                preloaded: false,
                blocking: true,
            },
            ResourceRef {
                url: format!("{}/missing.js", server.base),
                kind: ResourceKind::JavaScript,
                external: false,
                has_dimensions: false,
                lazy: false,
                srcset: false,
                preloaded: false,
                blocking: true,
            },
        ];
        let out = fetch_resources(&client, &refs).await;
        assert_eq!(out.len(), 2);
        let css = out
            .iter()
            .find(|r| r.record.url.ends_with("style.css"))
            .expect("css");
        assert_eq!(css.record.status_code, Some(200));
        assert_eq!(css.record.status, TestStatus::Pass);
        assert!(!css.body.is_empty());
        let js = out
            .iter()
            .find(|r| r.record.url.ends_with("missing.js"))
            .expect("js");
        assert_eq!(js.record.status_code, Some(404));
        assert_eq!(js.record.status, TestStatus::Fail);
    }

    #[tokio::test]
    async fn invalid_url_yields_error_record() {
        let cfg = crate::config::Config::for_local_tests();
        let client = AuditClient::new(std::sync::Arc::new(cfg)).expect("client");
        let refs = vec![ResourceRef {
            url: "not a url".into(),
            kind: ResourceKind::Other,
            external: false,
            has_dimensions: false,
            lazy: false,
            srcset: false,
            preloaded: false,
            blocking: false,
        }];
        let out = fetch_resources(&client, &refs).await;
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].record.status, TestStatus::Error);
        assert!(out[0].record.error.is_some());
    }
}
