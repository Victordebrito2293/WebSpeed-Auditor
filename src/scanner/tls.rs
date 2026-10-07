//! Análise TLS: conexão, handshake, certificado e protocolo.
//!
//! Somente observação: a ferramenta não tenta explorar, quebrar ou rebaixar
//! o TLS. Uma conexão de sondagem é aberta apenas para ler o certificado.

use crate::models::{TestStatus, TlsInfo};
use crate::utils::timex;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, RootCertStore};
use std::net::{IpAddr, SocketAddr, TcpStream};
use std::sync::Arc;
use std::time::{Duration, Instant};
use x509_parser::prelude::*;

/// Resultado da sondagem TLS com tempos separados.
#[derive(Debug, Clone)]
pub struct TlsProbeResult {
    pub info: TlsInfo,
    pub connect_ms: Option<u64>,
    pub tls_ms: Option<u64>,
}

fn empty_info(status: TestStatus, detail: String) -> TlsInfo {
    TlsInfo {
        status,
        detail,
        protocol: None,
        cipher: None,
        subject: None,
        issuer: None,
        not_before: None,
        not_after: None,
        days_until_expiry: None,
        sans: vec![],
    }
}

fn not_tested(msg: &str) -> TlsProbeResult {
    TlsProbeResult {
        info: empty_info(TestStatus::NotTested, msg.to_string()),
        connect_ms: None,
        tls_ms: None,
    }
}

fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Verificador que aceita qualquer certificado — usado APENAS como fallback
/// quando a verificação padrão falha, para ler os detalhes do certificado
/// problemático. A falha de verificação continua sendo reportada.
#[derive(Debug)]
struct AcceptAllVerifier {
    provider: Arc<rustls::crypto::CryptoProvider>,
}

impl ServerCertVerifier for AcceptAllVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

fn verified_config(provider: Arc<rustls::crypto::CryptoProvider>) -> Result<ClientConfig, String> {
    let mut roots = RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let cfg = ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| e.to_string())?
        .with_root_certificates(roots)
        .with_no_client_auth();
    Ok(cfg)
}

fn accept_all_config(
    provider: Arc<rustls::crypto::CryptoProvider>,
) -> Result<ClientConfig, String> {
    let cfg = ClientConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()
        .map_err(|e| e.to_string())?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AcceptAllVerifier { provider }))
        .with_no_client_auth();
    Ok(cfg)
}

/// Extrai informações do certificado end-entity.
fn extract_cert(certs: &[CertificateDer<'static>]) -> TlsInfo {
    let Some(first) = certs.first() else {
        return empty_info(
            TestStatus::Error,
            "servidor não apresentou certificado".into(),
        );
    };
    let mut info = empty_info(TestStatus::Pass, "certificado apresentado".into());
    match X509Certificate::from_der(first) {
        Ok((_, cert)) => {
            info.subject = Some(cert.subject().to_string());
            info.issuer = Some(cert.issuer().to_string());
            info.not_before = Some(timex::unix_to_iso8601(
                cert.validity().not_before.timestamp().max(0) as u64,
            ));
            info.not_after = Some(timex::unix_to_iso8601(
                cert.validity().not_after.timestamp().max(0) as u64,
            ));
            let days = (cert.validity().not_after.timestamp() - now_unix()) / 86_400;
            info.days_until_expiry = Some(days);
            if let Ok(Some(san)) = cert.subject_alternative_name() {
                for gn in san.value.general_names.iter() {
                    match gn {
                        GeneralName::DNSName(d) => info.sans.push((*d).to_string()),
                        GeneralName::IPAddress(bytes) => match bytes.len() {
                            4 => info.sans.push(format!(
                                "{}.{}.{}.{}",
                                bytes[0], bytes[1], bytes[2], bytes[3]
                            )),
                            16 => {
                                let arr: [u8; 16] = (*bytes).try_into().unwrap_or([0; 16]);
                                info.sans.push(std::net::Ipv6Addr::from(arr).to_string());
                            }
                            _ => {}
                        },
                        _ => {}
                    }
                }
            }
        }
        Err(e) => {
            info.status = TestStatus::Warning;
            info.detail = format!("certificado não pôde ser parseado: {e}");
        }
    }
    info
}

/// Executa a sondagem em thread separada (não trava o runtime assíncrono).
pub async fn probe(host: String, port: u16, ips: Vec<IpAddr>, timeout: Duration) -> TlsProbeResult {
    match tokio::task::spawn_blocking(move || probe_blocking(&host, port, &ips, timeout)).await {
        Ok(r) => r,
        Err(_) => not_tested("sondagem TLS cancelada"),
    }
}

type HandshakeOk = (Vec<CertificateDer<'static>>, Option<String>, Option<String>);

fn probe_blocking(host: &str, port: u16, ips: &[IpAddr], timeout: Duration) -> TlsProbeResult {
    if ips.is_empty() {
        return not_tested("sem endereços resolvidos para sondar");
    }
    let provider = Arc::new(rustls::crypto::ring::default_provider());

    // 1. Conexão TCP (medida separadamente).
    let t0 = Instant::now();
    let sock = match connect_any(ips, port, timeout) {
        Ok(s) => s,
        Err(e) => {
            return TlsProbeResult {
                info: empty_info(TestStatus::Error, format!("conexão TCP falhou: {e}")),
                connect_ms: Some(t0.elapsed().as_millis() as u64),
                tls_ms: None,
            };
        }
    };
    let connect_ms = t0.elapsed().as_millis() as u64;
    let _ = sock.set_read_timeout(Some(timeout));
    let _ = sock.set_write_timeout(Some(timeout));
    let _ = sock.set_nodelay(true);

    // 2. Handshake com verificação padrão (caminho normal).
    let t1 = Instant::now();
    let verified = sock
        .try_clone()
        .map_err(|e| e.to_string())
        .and_then(|s| handshake(host, s, verified_config(provider.clone())?));
    let tls_ms = t1.elapsed().as_millis() as u64;

    let (mut info, verified_err) = match verified {
        Ok((certs, protocol, cipher)) => {
            let mut i = extract_cert(&certs);
            i.protocol = protocol;
            i.cipher = cipher;
            (i, None)
        }
        Err(verr) => {
            // Fallback somente-leitura para obter detalhes do certificado.
            let fallback = sock
                .try_clone()
                .map_err(|e| e.to_string())
                .and_then(|s| handshake(host, s, accept_all_config(provider.clone())?));
            match fallback {
                Ok((certs, protocol, cipher)) => {
                    let mut i = extract_cert(&certs);
                    i.protocol = protocol;
                    i.cipher = cipher;
                    (i, Some(verr))
                }
                Err(e2) => {
                    return TlsProbeResult {
                        info: empty_info(
                            TestStatus::Error,
                            format!("handshake TLS falhou: {verr}; fallback também falhou: {e2}"),
                        ),
                        connect_ms: Some(connect_ms),
                        tls_ms: Some(tls_ms),
                    };
                }
            }
        }
    };

    // Resultado final da verificação.
    match verified_err {
        None => {
            info.status = TestStatus::Pass;
            info.detail = "certificado válido e handshake concluído".into();
        }
        Some(e) => {
            info.status = TestStatus::Fail;
            info.detail = format!("verificação do certificado falhou: {e}");
        }
    }
    // Exiração próxima/ocorrida é reportada mesmo com verificação OK.
    if let Some(days) = info.days_until_expiry {
        if days < 0 {
            info.status = TestStatus::Fail;
            info.detail = format!("certificado expirado há {} dia(s)", -days);
        } else if days < 14 && info.status == TestStatus::Pass {
            info.status = TestStatus::Warning;
            info.detail = format!("certificado expira em {days} dia(s)");
        }
    }

    TlsProbeResult {
        info,
        connect_ms: Some(connect_ms),
        tls_ms: Some(tls_ms),
    }
}

fn connect_any(ips: &[IpAddr], port: u16, timeout: Duration) -> std::io::Result<TcpStream> {
    let mut last = None;
    for ip in ips {
        let addr = SocketAddr::new(*ip, port);
        match TcpStream::connect_timeout(&addr, timeout) {
            Ok(s) => return Ok(s),
            Err(e) => last = Some(e),
        }
    }
    Err(last.unwrap_or_else(|| std::io::Error::other("sem endereços")))
}

/// Handshake TLS: conclui a troca de chaves e lê o certificado do par.
fn handshake(host: &str, mut sock: TcpStream, config: ClientConfig) -> Result<HandshakeOk, String> {
    let server_name =
        ServerName::try_from(host.to_string()).map_err(|e| format!("SNI inválido: {e}"))?;
    let mut conn =
        rustls::ClientConnection::new(Arc::new(config), server_name).map_err(|e| e.to_string())?;
    conn.complete_io(&mut sock).map_err(|e| e.to_string())?;

    let certs: Vec<CertificateDer<'static>> = conn
        .peer_certificates()
        .map(|c| c.to_vec())
        .unwrap_or_default();
    let protocol = conn.protocol_version().map(|p| format!("{p:?}"));
    let cipher = conn
        .negotiated_cipher_suite()
        .map(|s| format!("{:?}", s.suite()));
    Ok((certs, protocol, cipher))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_probe_is_not_tested() {
        let r = probe_blocking("example.com", 443, &[], Duration::from_secs(1));
        assert_eq!(r.info.status, TestStatus::NotTested);
        assert!(r.connect_ms.is_none());
    }

    #[test]
    fn closed_port_reports_error_without_panic() {
        let r = probe_blocking(
            "192.0.2.1",
            1,
            &[IpAddr::from([192, 0, 2, 1])],
            Duration::from_millis(300),
        );
        assert_eq!(r.info.status, TestStatus::Error);
        assert!(r.connect_ms.is_some());
    }

    #[tokio::test]
    async fn probe_returns_on_timeout() {
        let r = probe(
            "192.0.2.1".into(),
            443,
            vec![IpAddr::from([192, 0, 2, 1])],
            Duration::from_millis(200),
        )
        .await;
        assert_eq!(r.info.status, TestStatus::Error);
    }

    #[test]
    fn configs_build() {
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        assert!(accept_all_config(provider.clone()).is_ok());
        assert!(verified_config(provider).is_ok());
    }

    #[test]
    fn extract_cert_handles_empty_chain() {
        let info = extract_cert(&[]);
        assert_eq!(info.status, TestStatus::Error);
    }

    #[test]
    fn extract_cert_handles_garbage() {
        let garbage = CertificateDer::from(vec![0u8; 32]);
        let info = extract_cert(&[garbage]);
        assert_eq!(info.status, TestStatus::Warning);
    }
}
