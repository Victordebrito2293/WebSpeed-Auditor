//! Modelos de dados compartilhados entre scanner, análise e relatório.
//!
//! Todos os tipos são serializáveis para que o relatório JSON/HTML seja
//! gerado a partir da mesma estrutura em memória. Nenhum dado do sistema
//! local (caminhos, env vars, identificadores) faz parte destes modelos.

use serde::{Deserialize, Serialize};
use std::fmt;

/// Severidade de uma descoberta, ordenada de menor (`Info`) para maior
/// (`Critical`) — `Ord` segue a ordem das variantes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Severity::Critical => "CRITICAL",
            Severity::High => "HIGH",
            Severity::Medium => "MEDIUM",
            Severity::Low => "LOW",
            Severity::Info => "INFO",
        };
        f.write_str(s)
    }
}

/// Estado de um teste individual.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum TestStatus {
    Pass,
    Warning,
    Fail,
    NotTested,
    Error,
}

impl fmt::Display for TestStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            TestStatus::Pass => "PASS",
            TestStatus::Warning => "WARNING",
            TestStatus::Fail => "FAIL",
            TestStatus::NotTested => "NOT_TESTED",
            TestStatus::Error => "ERROR",
        };
        f.write_str(s)
    }
}

/// Categoria de auditoria (usada no score e na organização do relatório).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Category {
    Performance,
    Network,
    Caching,
    Compression,
    Images,
    JavaScript,
    Css,
    Html,
    BestPractices,
}

impl Category {
    pub const ALL: [Category; 9] = [
        Category::Performance,
        Category::Network,
        Category::Caching,
        Category::Compression,
        Category::Images,
        Category::JavaScript,
        Category::Css,
        Category::Html,
        Category::BestPractices,
    ];

    /// Peso da categoria no score global (soma = 100).
    pub fn weight(self) -> u8 {
        match self {
            Category::Performance => 20,
            Category::Network => 15,
            Category::Caching => 10,
            Category::Compression => 10,
            Category::Images => 15,
            Category::JavaScript => 10,
            Category::Css => 5,
            Category::Html => 10,
            Category::BestPractices => 5,
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Category::Performance => "Performance",
            Category::Network => "Network",
            Category::Caching => "Caching",
            Category::Compression => "Compression",
            Category::Images => "Images",
            Category::JavaScript => "JavaScript",
            Category::Css => "CSS",
            Category::Html => "HTML",
            Category::BestPractices => "Best Practices",
        }
    }
}

impl fmt::Display for Category {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

/// Um teste executado: o que foi testado e o resultado.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TestItem {
    pub category: Category,
    pub name: String,
    pub status: TestStatus,
    /// Resultado concreto do teste (valor observado, motivo da falha etc.).
    pub detail: String,
    /// Evidência técnica adicional, quando aplicável.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub evidence: Option<String>,
}

impl TestItem {
    pub fn new(
        category: Category,
        name: impl Into<String>,
        status: TestStatus,
        detail: impl Into<String>,
    ) -> Self {
        Self {
            category,
            name: name.into(),
            status,
            detail: detail.into(),
            evidence: None,
        }
    }

    pub fn with_evidence(mut self, evidence: impl Into<String>) -> Self {
        self.evidence = Some(evidence.into());
        self
    }
}

/// Problema encontrado, com todos os campos exigidos pelo relatório.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub id: String,
    pub category: Category,
    pub severity: Severity,
    pub title: String,
    /// Descrição do problema.
    pub problem: String,
    /// Evidência técnica observada.
    pub evidence: String,
    /// Impacto estimado. Quando não quantificável:
    /// "Impacto não quantificado neste ambiente."
    pub impact: String,
    /// Como corrigir.
    pub recommendation: String,
}

/// Itens que não puderam ser testados, com o motivo.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Limitation {
    pub area: String,
    pub reason: String,
}

/// Score de uma categoria.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CategoryScore {
    pub category: Category,
    /// 0..=100
    pub score: u8,
    /// Total de verificações que afetam a pontuação nesta categoria.
    pub checks: u32,
    pub passed: u32,
    /// Dedução acumulada (para transparência da fórmula).
    pub deduction: u32,
}

/// Score geral.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OverallScore {
    /// 0..=100, média ponderada das categorias.
    pub score: u8,
    pub categories: Vec<CategoryScore>,
}

/// Tempos de rede medidos. `None` significa "não disponível neste ambiente".
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct HttpTimings {
    /// Resolução DNS (medida pela própria ferramenta).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dns_ms: Option<u64>,
    /// Estabelecimento da conexão TCP.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub connect_ms: Option<u64>,
    /// Handshake TLS.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tls_ms: Option<u64>,
    /// Tempo até receber os cabeçalhos da resposta (inclui conexão/TLS
    /// quando a conexão não é reutilizada).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ttfb_ms: Option<u64>,
    /// Download do corpo.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub download_ms: Option<u64>,
    /// Tempo total da operação.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub total_ms: Option<u64>,
}

/// Resultado de resolução DNS.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsInfo {
    pub status: TestStatus,
    pub detail: String,
    pub ipv4: Vec<String>,
    pub ipv6: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resolution_ms: Option<u64>,
}

/// Informações do certificado/TLS.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsInfo {
    pub status: TestStatus,
    pub detail: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub protocol: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cipher: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subject: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub issuer: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub not_before: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub not_after: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub days_until_expiry: Option<i64>,
    pub sans: Vec<String>,
}

/// Um salto de redirect.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RedirectHop {
    pub from: String,
    pub status: u16,
    pub to: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub latency_ms: Option<u64>,
}

/// Cadeia de redirects completa.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RedirectChain {
    pub status: TestStatus,
    pub detail: String,
    pub hops: Vec<RedirectHop>,
    pub final_url: String,
    pub loop_detected: bool,
}

/// Resumo do documento principal (HTTP).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpInfo {
    pub status: TestStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status_code: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub http_version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content_encoding: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transfer_size: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub decoded_size: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cache_control: Option<String>,
    pub etag: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_modified: Option<String>,
    /// Apenas contagem: valores de `Set-Cookie` nunca são persistidos.
    pub set_cookie_count: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub server: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vary: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub age: Option<String>,
    /// Presença do header HSTS (apenas o flag; valor não é persistido).
    pub hsts: bool,
    /// Presença do header X-Content-Type-Options.
    pub x_content_type_options: bool,
    pub timings: HttpTimings,
    /// `true` quando o corpo excedeu o limite e foi truncado.
    pub body_truncated: bool,
}

/// Tipo de recurso.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResourceKind {
    Html,
    Css,
    JavaScript,
    Image,
    Font,
    Other,
}

impl fmt::Display for ResourceKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            ResourceKind::Html => "html",
            ResourceKind::Css => "css",
            ResourceKind::JavaScript => "javascript",
            ResourceKind::Image => "image",
            ResourceKind::Font => "font",
            ResourceKind::Other => "other",
        };
        f.write_str(s)
    }
}

/// Um recurso analisado (coletado apenas em memória).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceRecord {
    pub url: String,
    pub kind: ResourceKind,
    pub status: TestStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status_code: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content_encoding: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transfer_size: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub decoded_size: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cache_control: Option<String>,
    pub etag: bool,
    pub last_modified: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timing_ms: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    /// Quando o formato real (magic bytes) difere do Content-Type declarado.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sniffed_format: Option<String>,
}

/// Estatísticas extraídas do HTML.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct HtmlInfo {
    pub bytes: u64,
    pub decoded_bytes: u64,
    pub elements: usize,
    pub script_tags: usize,
    pub scripts_blocking: usize,
    pub scripts_defer: usize,
    pub scripts_async: usize,
    pub scripts_module: usize,
    pub scripts_inline: usize,
    pub inline_script_bytes: usize,
    pub stylesheet_links: usize,
    pub inline_style_blocks: usize,
    pub inline_style_bytes: usize,
    pub images: usize,
    pub images_without_dimensions: usize,
    pub images_without_lazy: usize,
    pub images_srcset: usize,
    pub iframes: usize,
    pub total_links: usize,
    pub same_origin_links: usize,
    pub external_links: usize,
    pub preloads: usize,
    pub preconnects: usize,
    pub dns_prefetch: usize,
    pub external_origins: Vec<String>,
    pub duplicate_resources: Vec<String>,
    pub resources: Vec<String>,
}

/// Estatísticas de CSS coletadas.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CssInfo {
    pub file_count: usize,
    pub total_bytes: u64,
    pub inline_bytes: u64,
    pub external_urls: Vec<String>,
    pub duplicate_urls: Vec<String>,
}

/// Estatísticas de JavaScript coletadas.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct JsInfo {
    pub external_count: usize,
    pub inline_count: usize,
    pub total_external_bytes: u64,
    pub inline_bytes: u64,
    pub blocking: usize,
    pub defer: usize,
    pub r#async: usize,
    pub module: usize,
    pub duplicate_urls: Vec<String>,
    pub large_files: Vec<String>,
}

/// Estatísticas de imagens.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ImagesInfo {
    pub count: usize,
    pub total_bytes: u64,
    pub without_dimensions: usize,
    pub without_lazy: usize,
    pub with_srcset: usize,
    pub modern_format: usize,
    pub legacy_format: usize,
    pub oversized: Vec<String>,
    pub format_mismatch: Vec<String>,
}

/// Estatísticas de fontes.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct FontsInfo {
    pub count: usize,
    pub total_bytes: u64,
    pub external_count: usize,
    pub preloaded: usize,
    pub formats: Vec<String>,
    pub families: Vec<String>,
}

/// Resultado da análise de cache agregada.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CacheInfo {
    pub static_total: usize,
    pub static_without_policy: usize,
    pub immutable_candidates: usize,
    pub html_with_immutable: bool,
}

/// Resultado da análise de compressão agregada.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CompressionInfo {
    pub compressible_total: usize,
    pub compressed: usize,
    pub uncompressed: Vec<String>,
    pub used_encodings: Vec<String>,
}

/// Relatório completo — existe somente em memória até o usuário exportar.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditReport {
    pub tool: String,
    pub version: String,
    /// URL informada pelo usuário.
    pub url: String,
    /// URL final após redirects.
    pub final_url: String,
    /// Segundos desde o epoch (marca temporal da execução, sem dados locais).
    pub generated_at_unix: u64,
    pub generated_at_iso8601: String,
    pub duration_ms: u64,
    pub pages_analyzed: usize,
    pub requests_analyzed: usize,
    pub scores: OverallScore,
    /// O que foi testado e o resultado de cada teste.
    pub tests: Vec<TestItem>,
    /// Problemas encontrados, ordenados por severidade.
    pub findings: Vec<Finding>,
    /// O que já está otimizado (testes com PASS).
    pub optimized: Vec<TestItem>,
    /// O que não pôde ser testado e por quê.
    pub not_tested: Vec<Limitation>,
    pub dns: DnsInfo,
    pub tls: Option<TlsInfo>,
    pub redirects: RedirectChain,
    pub http: Option<HttpInfo>,
    pub html: Option<HtmlInfo>,
    pub css: CssInfo,
    pub javascript: JsInfo,
    pub images: ImagesInfo,
    pub fonts: FontsInfo,
    pub cache: CacheInfo,
    pub compression: CompressionInfo,
    /// Recursos analisados (URLs públicas do site alvo apenas).
    pub resources: Vec<ResourceRecord>,
    /// Páginas visitadas durante o crawl.
    pub pages: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn severity_order_is_info_to_critical() {
        assert!(Severity::Info < Severity::Low);
        assert!(Severity::Low < Severity::Medium);
        assert!(Severity::Medium < Severity::High);
        assert!(Severity::High < Severity::Critical);
    }

    #[test]
    fn category_weights_sum_to_100() {
        let total: u8 = Category::ALL.iter().map(|c| c.weight()).sum();
        assert_eq!(total, 100);
    }

    #[test]
    fn test_status_display() {
        assert_eq!(TestStatus::Pass.to_string(), "PASS");
        assert_eq!(TestStatus::NotTested.to_string(), "NOT_TESTED");
    }

    #[test]
    fn report_json_has_no_local_fields() {
        let report = AuditReport {
            tool: "x".into(),
            version: "0".into(),
            url: "https://example.com".into(),
            final_url: "https://example.com".into(),
            generated_at_unix: 0,
            generated_at_iso8601: "1970-01-01T00:00:00Z".into(),
            duration_ms: 1,
            pages_analyzed: 0,
            requests_analyzed: 0,
            scores: OverallScore {
                score: 0,
                categories: vec![],
            },
            tests: vec![],
            findings: vec![],
            optimized: vec![],
            not_tested: vec![],
            dns: DnsInfo {
                status: TestStatus::NotTested,
                detail: "x".into(),
                ipv4: vec![],
                ipv6: vec![],
                resolution_ms: None,
            },
            tls: None,
            redirects: RedirectChain {
                status: TestStatus::NotTested,
                detail: "x".into(),
                hops: vec![],
                final_url: String::new(),
                loop_detected: false,
            },
            http: None,
            html: None,
            css: CssInfo::default(),
            javascript: JsInfo::default(),
            images: ImagesInfo::default(),
            fonts: FontsInfo::default(),
            cache: CacheInfo::default(),
            compression: CompressionInfo::default(),
            resources: vec![],
            pages: vec![],
        };
        let json = serde_json::to_string(&report).expect("serializable");
        for forbidden in ["home_dir", "username", "env", "cwd", "hostname"] {
            assert!(
                !json.contains(forbidden),
                "relatório contém campo local: {forbidden}"
            );
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WaterfallEntry {
    pub url: String,
    pub kind: ResourceKind,
    pub domain: String,
    pub dns_ms: Option<u64>,
    pub connect_ms: Option<u64>,
    pub tls_ms: Option<u64>,
    pub request_ms: Option<u64>,
    pub ttfb_ms: Option<u64>,
    pub download_ms: Option<u64>,
    pub transfer_bytes: Option<u64>,
    pub total_ms: Option<u64>,
    pub priority: Option<String>,
    pub dependencies: Vec<String>,
    pub external: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct BenchmarkStats {
    pub runs: u32,
    pub avg_ms: Option<f64>,
    pub median_ms: Option<f64>,
    pub min_ms: Option<u64>,
    pub max_ms: Option<u64>,
    pub variation_pct: Option<f64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnvironmentProfile {
    pub name: String,
    pub user_agent: Option<String>,
    pub viewport_width: u32,
    pub viewport_height: u32,
    pub device_scale_factor: f64,
    pub is_mobile: bool,
    pub cpu_throttling_factor: f64,
    pub network_condition: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ThirdPartyImpact {
    pub domains: Vec<String>,
    pub total_requests: u32,
    pub total_bytes: u64,
    pub total_ms: Option<u64>,
    pub main_thread_block_ms: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DependencyNode {
    pub url: String,
    pub kind: ResourceKind,
    pub initiators: Vec<String>,
    pub children: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiagnosisItem {
    pub id: String,
    pub category: Category,
    pub severity: Severity,
    pub title: String,
    pub evidence: String,
    pub cause: String,
    pub impact: String,
    pub priority: String,
    pub recommendation: String,
    pub how_to_fix: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct CategoryScores {
    pub performance: Option<i32>,
    pub network: Option<i32>,
    pub images: Option<i32>,
    pub javascript: Option<i32>,
    pub css: Option<i32>,
    pub caching: Option<i32>,
    pub compression: Option<i32>,
    pub best_practices: Option<i32>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ComparisonResult {
    pub lcp_pct: Option<f64>,
    pub fcp_pct: Option<f64>,
    pub tbt_pct: Option<f64>,
    pub cls_pct: Option<f64>,
    pub inp_pct: Option<f64>,
    pub requests_pct: Option<f64>,
    pub transfer_pct: Option<f64>,
    pub total_bytes_pct: Option<f64>,
    pub total_time_pct: Option<f64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct CoreWebVitals {
    pub lcp_ms: Option<u64>,
    pub fcp_ms: Option<u64>,
    pub cls: Option<f64>,
    pub inp_ms: Option<u64>,
    pub tbt_ms: Option<u64>,
    pub ttfb_ms: Option<u64>,
    pub speed_index_ms: Option<u64>,
    pub dom_content_loaded_ms: Option<u64>,
    pub load_event_ms: Option<u64>,
    pub long_tasks: u32,
    pub js_execution_ms: Option<u64>,
}
