//! Proteção contra SSRF (Server-Side Request Forgery).
//!
//! Toda URL fornecida é validada em duas camadas:
//! 1. Formato (esquema, ausência de credenciais, tamanho).
//! 2. Endereços resolvidos — apenas endereços públicamente roteáveis são
//!    aceitos. Loopback, redes privadas, link-local, metadata de cloud,
//!    endereços reservados e tradução NAT64/6to4/Teredo são bloqueados.
//!
//! A validação é refeita antes de cada requisição (inclusive a cada salto de
//! redirect) para reduzir o risco de DNS rebinding.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;
use url::Url;

use crate::config::Config;
use crate::config::MAX_URL_LENGTH;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SsrfError {
    InvalidScheme,
    MissingHost,
    UserInfoNotAllowed,
    UrlTooLong,
    InvalidHostname,
    ResolutionFailed(String),
    BlockedAddress(IpAddr),
    NoUsableAddress,
}

impl std::fmt::Display for SsrfError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SsrfError::InvalidScheme => write!(f, "esquema não suportado (apenas http/https)"),
            SsrfError::MissingHost => write!(f, "URL sem host"),
            SsrfError::UserInfoNotAllowed => {
                write!(f, "URL não pode conter credenciais (user:pass@)")
            }
            SsrfError::UrlTooLong => write!(f, "URL excede {MAX_URL_LENGTH} caracteres"),
            SsrfError::InvalidHostname => write!(f, "nome de host bloqueado"),
            SsrfError::ResolutionFailed(e) => write!(f, "falha na resolução DNS: {e}"),
            SsrfError::BlockedAddress(ip) => write!(f, "endereço bloqueado (não público): {ip}"),
            SsrfError::NoUsableAddress => write!(f, "nenhum endereço público resolvido"),
        }
    }
}

impl std::error::Error for SsrfError {}

/// Hostnames que nunca são aceitos mesmo antes do DNS.
fn hostname_blocked(host: &str) -> bool {
    let h = host.trim_end_matches('.').to_ascii_lowercase();
    h == "localhost"
        || h.ends_with(".localhost")
        || h == "metadata.google.internal"
        || h == "metadata"
        || h == "instance-data" // AWS/EC2 (sem DNS externo normalmente)
}

/// Valida somente o formato da URL (sem rede).
pub fn validate_url_shape(url: &Url) -> Result<(), SsrfError> {
    match url.scheme() {
        "http" | "https" => {}
        _ => return Err(SsrfError::InvalidScheme),
    }
    if url.username() != "" || url.password().is_some() {
        return Err(SsrfError::UserInfoNotAllowed);
    }
    let host = url.host_str().ok_or(SsrfError::MissingHost)?;
    if url.as_str().len() > MAX_URL_LENGTH {
        return Err(SsrfError::UrlTooLong);
    }
    if hostname_blocked(host) {
        return Err(SsrfError::InvalidHostname);
    }
    Ok(())
}

/// `true` quando o endereço NÃO deve ser acessado (bloqueado).
pub fn ip_is_blocked(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => ipv4_blocked(v4),
        IpAddr::V6(v6) => ipv6_blocked(v6),
    }
}

fn ipv4_blocked(v4: Ipv4Addr) -> bool {
    let o = v4.octets();
    v4.is_loopback()
        || v4.is_private()
        || v4.is_link_local()
        || v4.is_unspecified()
        || v4.is_broadcast()
        || v4.is_multicast()
        || v4.is_documentation()
        // 0.0.0.0/8
        || o[0] == 0
        // 100.64.0.0/10 (CGNAT) — inclui 100.100.100.200 (metadata Alibaba)
        || (o[0] == 100 && (o[1] & 0b1100_0000) == 64)
        // 192.0.0.0/24 (IETF protocol assignments)
        || (o[0] == 192 && o[1] == 0 && o[2] == 0)
        // 198.18.0.0/15 (benchmark)
        || (o[0] == 198 && (o[1] & 0b1111_1110) == 18)
        // 240.0.0.0/4 (reserved) — cobre 255.255.255.255
        || o[0] >= 240
        // Endpoint Azure (wire server / platform virtual IP)
        || v4 == Ipv4Addr::new(168, 63, 129, 16)
}

fn ipv6_blocked(v6: Ipv6Addr) -> bool {
    // IPv4 embutido/compatível herda a regra do IPv4.
    if let Some(v4) = v6.to_ipv4_mapped().or_else(|| v6.to_ipv4()) {
        return ipv4_blocked(v4);
    }
    let s = v6.segments();
    v6.is_loopback()
        || v6.is_unspecified()
        || v6.is_multicast()
        // 2001:db8::/32 — documentação (is_documentation de Ipv6 é instável)
        || (s[0] == 0x2001 && s[1] == 0x0db8)
        // fc00::/7 — unique local
        || (s[0] & 0xfe00) == 0xfc00
        // fe80::/10 — link-local
        || (s[0] & 0xffc0) == 0xfe80
        // 64:ff9b::/48 — NAT64 (pode traduzir para rede privada)
        || (s[0] == 0x0064 && s[1] == 0xff9b)
        // 2001::/32 — Teredo
        || (s[0] == 0x2001 && s[1] == 0)
        // 2001:db8::/32 já coberto por is_documentation
        // 2002::/16 — 6to4 (endereço IPv4 embutido)
        || s[0] == 0x2002
}

/// Verifica que TODOS os endereços são públicos. Retorna o primeiro bloqueado.
pub fn check_ips(ips: &[IpAddr]) -> Result<(), SsrfError> {
    if ips.is_empty() {
        return Err(SsrfError::NoUsableAddress);
    }
    for ip in ips {
        if ip_is_blocked(*ip) {
            return Err(SsrfError::BlockedAddress(*ip));
        }
    }
    Ok(())
}

/// Resolve um hostname em endereços IP (com timeout).
pub async fn resolve_host(host: &str) -> Result<Vec<IpAddr>, SsrfError> {
    let host = host.to_string();
    let fut = tokio::net::lookup_host((host.as_str(), 0u16));
    match tokio::time::timeout(Duration::from_secs(10), fut).await {
        Err(_) => Err(SsrfError::ResolutionFailed("timeout".into())),
        Ok(Err(e)) => Err(SsrfError::ResolutionFailed(e.to_string())),
        Ok(Ok(addrs)) => {
            let mut out: Vec<IpAddr> = addrs.map(|a| a.ip()).collect();
            out.dedup();
            Ok(out)
        }
    }
}

/// Valida uma URL completely: formato + (se proteção ativa) resolução e
/// endereços públicos. Retorna os endereços resolvidos.
pub async fn validate_url(cfg: &Config, url: &Url) -> Result<Vec<IpAddr>, SsrfError> {
    validate_url_shape(url)?;
    if !cfg.ssrf_protection {
        return Ok(vec![]);
    }
    let host = url.host_str().ok_or(SsrfError::MissingHost)?;
    let ips = resolve_host(host).await?;
    check_ips(&ips)?;
    Ok(ips)
}

/// Converte SocketAddr em apenas o IP (helper para o resolvedor do reqwest).
pub fn socket_ips(addrs: &[SocketAddr]) -> Vec<IpAddr> {
    addrs.iter().map(|a| a.ip()).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().expect("ip válido no teste")
    }

    #[test]
    fn blocks_loopback_and_private_v4() {
        for s in [
            "127.0.0.1",
            "127.1.2.3",
            "10.0.0.1",
            "10.255.255.255",
            "172.16.0.1",
            "172.31.255.255",
            "192.168.1.1",
            "169.254.169.254", // AWS/GCP/Azure metadata
            "169.254.0.1",
            "0.0.0.0",
            "0.1.2.3",
            "100.64.0.1",      // CGNAT
            "100.100.100.200", // metadata Alibaba
            "192.0.0.1",
            "192.0.2.1",  // TEST-NET-1
            "198.18.0.1", // benchmark
            "240.0.0.1",  // reserved
            "255.255.255.255",
            "224.0.0.1",     // multicast
            "168.63.129.16", // Azure platform
            "198.51.100.7",  // TEST-NET-2
            "203.0.113.9",   // TEST-NET-3
        ] {
            assert!(ip_is_blocked(ip(s)), "{s} deveria ser bloqueado");
        }
    }

    #[test]
    fn allows_public_v4() {
        for s in [
            "1.1.1.1",
            "8.8.8.8",
            "93.184.216.34",
            "172.64.0.1",
            "172.32.0.1",
        ] {
            assert!(!ip_is_blocked(ip(s)), "{s} deveria ser permitido");
        }
    }

    #[test]
    fn blocks_ipv6_special_ranges() {
        for s in [
            "::1",
            "::",
            "fe80::1",
            "fc00::1",
            "fd12:3456::1",
            "ff02::1",
            "::ffff:127.0.0.1",   // mapped loopback
            "::ffff:192.168.0.1", // mapped privado
            "::ffff:10.0.0.1",
            "64:ff9b::8.8.8.8", // NAT64
            "64:ff9b:1::1",
            "2001::1",           // Teredo
            "2002:7f00:0001::1", // 6to4 com 127.0.0.1 embutido
            "2001:db8::1",       // documentação
        ] {
            assert!(ip_is_blocked(ip(s)), "{s} deveria ser bloqueado");
        }
    }

    #[test]
    fn allows_public_ipv6() {
        for s in ["2606:4700:4700::1111", "2a00:1450:4001:80f::200e"] {
            assert!(!ip_is_blocked(ip(s)), "{s} deveria ser permitido");
        }
    }

    #[test]
    fn shape_rejects_bad_schemes() {
        for u in [
            "file:///etc/passwd",
            "ftp://example.com",
            "gopher://example.com",
            "javascript:alert(1)",
            "data:text/html,x",
        ] {
            let url = Url::parse(u).expect("parseável");
            assert_eq!(
                validate_url_shape(&url),
                Err(SsrfError::InvalidScheme),
                "{u}"
            );
        }
    }

    #[test]
    fn shape_rejects_userinfo() {
        let url = Url::parse("https://user:pass@example.com/").expect("parseável");
        assert_eq!(validate_url_shape(&url), Err(SsrfError::UserInfoNotAllowed));
    }

    #[test]
    fn shape_rejects_localhost_by_name() {
        for u in [
            "http://localhost/",
            "http://LOCALHOST./",
            "http://x.localhost/",
        ] {
            let url = Url::parse(u).expect("parseável");
            assert_eq!(
                validate_url_shape(&url),
                Err(SsrfError::InvalidHostname),
                "{u}"
            );
        }
    }

    #[test]
    fn shape_rejects_huge_urls() {
        let big = format!("https://example.com/{}", "a".repeat(5000));
        let url = Url::parse(&big).expect("parseável");
        assert_eq!(validate_url_shape(&url), Err(SsrfError::UrlTooLong));
    }

    #[test]
    fn shape_accepts_normal_https() {
        let url = Url::parse("https://example.com/path?q=1").expect("parseável");
        assert_eq!(validate_url_shape(&url), Ok(()));
    }

    #[test]
    fn check_ips_requires_public_only() {
        assert!(check_ips(&[]).is_err());
        assert!(check_ips(&[ip("8.8.8.8")]).is_ok());
        assert!(check_ips(&[ip("8.8.8.8"), ip("127.0.0.1")]).is_err());
        assert!(check_ips(&[ip("10.0.0.1")]).is_err());
    }

    #[test]
    fn malformed_urls_do_not_panic() {
        for s in ["", "not a url", "https://", "://x", "%", "http://[::1]"] {
            // Pode falhar no parse — nunca deve panicar.
            if let Ok(u) = Url::parse(s) {
                let _ = validate_url_shape(&u);
            }
        }
    }
}
