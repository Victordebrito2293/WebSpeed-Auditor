//! Análise DNS: resolução, tempo, distribuição IPv4/IPv6.
//!
//! Não executa técnicas invasivas (zone transfer, enumeração de subdomínios).
//! CNAME não é coletado: exigiria um resolvedor DNS completo, mantido fora
//! do escopo para evitar dependências pesadas — registrado como NOT_TESTED.

use crate::models::{DnsInfo, TestStatus};
use crate::utils::ssrf;
use std::time::Instant;

/// Analisa a resolução do hostname. Nunca panica em falha de rede.
pub async fn analyze(host: &str) -> DnsInfo {
    let t = Instant::now();
    match ssrf::resolve_host(host).await {
        Ok(ips) => {
            let resolution_ms = t.elapsed().as_millis() as u64;
            let mut ipv4 = Vec::new();
            let mut ipv6 = Vec::new();
            for ip in &ips {
                match ip {
                    std::net::IpAddr::V4(v4) => ipv4.push(v4.to_string()),
                    std::net::IpAddr::V6(v6) => ipv6.push(v6.to_string()),
                }
            }
            let detail = format!(
                "{} endereço(s): {} IPv4, {} IPv6 ({} ms)",
                ips.len(),
                ipv4.len(),
                ipv6.len(),
                resolution_ms
            );
            DnsInfo {
                status: TestStatus::Pass,
                detail,
                ipv4,
                ipv6,
                resolution_ms: Some(resolution_ms),
            }
        }
        Err(e) => DnsInfo {
            status: TestStatus::Error,
            detail: format!("falha: {e}"),
            ipv4: vec![],
            ipv6: vec![],
            resolution_ms: None,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn resolves_localhost_without_panic() {
        // Resolução local — pode falhar em ambientes restritivos, mas nunca panic.
        let info = analyze("localhost").await;
        assert!(!info.detail.is_empty());
        match info.status {
            TestStatus::Pass => {
                assert!(!info.ipv4.is_empty() || !info.ipv6.is_empty());
                assert!(info.resolution_ms.is_some());
            }
            TestStatus::Error => assert!(info.ipv4.is_empty()),
            other => panic!("status inesperado: {other}"),
        }
    }

    #[tokio::test]
    async fn invalid_host_returns_error_status() {
        let info = analyze("this-host-should-not-exist-xyz-98765.invalid").await;
        assert_eq!(info.status, TestStatus::Error);
        assert!(info.resolution_ms.is_none());
    }
}
