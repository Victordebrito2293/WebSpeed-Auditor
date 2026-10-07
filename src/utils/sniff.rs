//! Sniffing de tipo de conteúdo a partir de magic bytes e classificação de
//! recursos. Nenhum conteúdo é executado — apenas bytes são inspecionados.

use crate::models::{ResourceKind, TestStatus};

/// Detecta o formato real de uma imagem pelos primeiros bytes.
pub fn sniff_image_format(bytes: &[u8]) -> Option<&'static str> {
    if bytes.len() >= 3 && bytes[..3] == [0xFF, 0xD8, 0xFF] {
        return Some("jpeg");
    }
    if bytes.len() >= 8 && bytes[..8] == [0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A] {
        return Some("png");
    }
    if bytes.len() >= 6 && (&bytes[..6] == b"GIF87a" || &bytes[..6] == b"GIF89a") {
        return Some("gif");
    }
    if bytes.len() >= 12 && &bytes[..4] == b"RIFF" && &bytes[8..12] == b"WEBP" {
        return Some("webp");
    }
    if bytes.len() >= 12 && &bytes[4..8] == b"ftyp" {
        let brand = &bytes[8..12];
        if brand == b"avif" || brand == b"avis" {
            return Some("avif");
        }
        if brand == b"heic"
            || brand == b"heix"
            || brand == b"heif"
            || brand == b"mif1"
            || brand == b"msf1"
        {
            return Some("heic");
        }
        return Some("isobmff");
    }
    if bytes.len() >= 2 && bytes[..2] == [0x42, 0x4D] {
        return Some("bmp");
    }
    if bytes.len() >= 4 && bytes[..4] == [0x00, 0x00, 0x01, 0x00] {
        return Some("ico");
    }
    // SVG: texto começando com declaração XML ou <svg.
    if let Ok(text) = std::str::from_utf8(&bytes[..bytes.len().min(1024)]) {
        let t = text.trim_start();
        if t.starts_with("<svg") || (t.starts_with("<?xml") && t.contains("<svg")) {
            return Some("svg");
        }
    }
    None
}

/// Mapeia Content-Type para o tipo de recurso.
pub fn kind_from_content_type(ct: &str) -> ResourceKind {
    let ct = ct
        .split(';')
        .next()
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase();
    if ct.starts_with("text/html") || ct == "application/xhtml+xml" {
        ResourceKind::Html
    } else if ct.starts_with("text/css") {
        ResourceKind::Css
    } else if ct.starts_with("text/javascript")
        || ct.starts_with("application/javascript")
        || ct.starts_with("application/x-javascript")
        || ct.starts_with("module")
    {
        ResourceKind::JavaScript
    } else if ct.starts_with("image/") {
        ResourceKind::Image
    } else if ct.starts_with("font/")
        || ct.starts_with("application/font")
        || ct == "application/vnd.ms-fontobject"
    {
        ResourceKind::Font
    } else {
        // text/html, json, plain, vazio ou desconhecido: tipo genérico.
        ResourceKind::Other
    }
}

/// Mapeia a extensão da URL para o tipo de recurso (fallback sem rede).
pub fn kind_from_url_path(path: &str) -> ResourceKind {
    let lower = path.to_ascii_lowercase();
    let ext = lower.rsplit('.').next().unwrap_or("");
    match ext {
        "html" | "htm" | "xhtml" => ResourceKind::Html,
        "css" => ResourceKind::Css,
        "js" | "mjs" | "cjs" => ResourceKind::JavaScript,
        "png" | "jpg" | "jpeg" | "gif" | "webp" | "avif" | "svg" | "ico" | "bmp" | "heic" => {
            ResourceKind::Image
        }
        "woff" | "woff2" | "ttf" | "otf" | "eot" => ResourceKind::Font,
        _ => ResourceKind::Other,
    }
}

/// Formatos de imagem "antigos" que geralmente se beneficiam de conversão.
pub fn is_legacy_image_format(fmt: &str) -> bool {
    matches!(fmt, "jpeg" | "png" | "gif" | "bmp")
}

/// Formatos modernos que já são uma boa escolha.
pub fn is_modern_image_format(fmt: &str) -> bool {
    matches!(fmt, "webp" | "avif")
}

/// Tipos textualmente comprimíveis (gzip/br costumam ajudar).
pub fn is_compressible_content_type(ct: Option<&str>) -> bool {
    let Some(ct) = ct else { return false };
    let ct = ct
        .split(';')
        .next()
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase();
    ct.starts_with("text/")
        || ct.starts_with("application/javascript")
        || ct.starts_with("application/json")
        || ct.starts_with("application/xml")
        || ct.starts_with("application/rss")
        || ct.starts_with("application/atom")
        || ct.starts_with("image/svg")
        || ct.starts_with("application/xhtml")
        || ct.ends_with("+json")
        || ct.ends_with("+xml")
}

/// Converte Content-Type declarado vs formato sniffado em status de teste.
pub fn content_type_match_status(declared: Option<&str>, sniffed: &str) -> TestStatus {
    let Some(declared) = declared else {
        return TestStatus::Warning;
    };
    let declared = declared
        .split(';')
        .next()
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase();
    let compatible = match sniffed {
        "jpeg" => declared == "image/jpeg",
        "png" => declared == "image/png",
        "gif" => declared == "image/gif",
        "webp" => declared == "image/webp",
        "avif" => declared == "image/avif",
        "svg" => declared == "image/svg+xml",
        "bmp" => declared == "image/bmp",
        "ico" => declared == "image/x-icon" || declared == "image/vnd.microsoft.icon",
        "heic" => declared == "image/heic" || declared == "image/heif",
        _ => true, // isobmff desconhecido: não afirmamos incompatibilidade
    };
    if compatible {
        TestStatus::Pass
    } else {
        TestStatus::Fail
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sniffs_common_formats() {
        assert_eq!(sniff_image_format(&[0xFF, 0xD8, 0xFF, 0xE0]), Some("jpeg"));
        assert_eq!(
            sniff_image_format(&[0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A, 0, 0]),
            Some("png")
        );
        assert_eq!(sniff_image_format(b"GIF89a...."), Some("gif"));
        let mut webp = b"RIFF\x00\x00\x00\x00WEBP".to_vec();
        webp.extend_from_slice(b"VP8 ");
        assert_eq!(sniff_image_format(&webp), Some("webp"));
        let avif = b"\x00\x00\x00\x18ftypavif".to_vec();
        assert_eq!(sniff_image_format(&avif), Some("avif"));
        assert_eq!(sniff_image_format(b"<svg xmlns='x'></svg>"), Some("svg"));
        assert_eq!(
            sniff_image_format(b"<?xml version='1.0'?><svg/>"),
            Some("svg")
        );
        assert_eq!(sniff_image_format(b"random bytes"), None);
        assert_eq!(sniff_image_format(b""), None);
    }

    #[test]
    fn content_type_mapping() {
        assert_eq!(
            kind_from_content_type("text/html; charset=utf-8"),
            ResourceKind::Html
        );
        assert_eq!(kind_from_content_type("text/css"), ResourceKind::Css);
        assert_eq!(
            kind_from_content_type("application/x-javascript"),
            ResourceKind::JavaScript
        );
        assert_eq!(kind_from_content_type("image/png"), ResourceKind::Image);
        assert_eq!(kind_from_content_type("font/woff2"), ResourceKind::Font);
        assert_eq!(
            kind_from_content_type("application/octet-stream"),
            ResourceKind::Other
        );
        assert_eq!(kind_from_content_type(""), ResourceKind::Other);
    }

    #[test]
    fn url_kind_mapping() {
        assert_eq!(kind_from_url_path("/a/style.css"), ResourceKind::Css);
        assert_eq!(kind_from_url_path("/A/APP.JS"), ResourceKind::JavaScript);
        assert_eq!(kind_from_url_path("/img/photo.jpeg"), ResourceKind::Image);
        assert_eq!(kind_from_url_path("/f/inter.woff2"), ResourceKind::Font);
        assert_eq!(kind_from_url_path("/page"), ResourceKind::Other);
    }

    #[test]
    fn compressible_types() {
        assert!(is_compressible_content_type(Some("text/html")));
        assert!(is_compressible_content_type(Some(
            "application/json; charset=utf-8"
        )));
        assert!(is_compressible_content_type(Some("image/svg+xml")));
        assert!(!is_compressible_content_type(Some("image/png")));
        assert!(!is_compressible_content_type(Some("video/mp4")));
        assert!(!is_compressible_content_type(None));
    }

    #[test]
    fn mismatch_detection() {
        assert_eq!(
            content_type_match_status(Some("text/html"), "png"),
            TestStatus::Fail
        );
        assert_eq!(
            content_type_match_status(Some("image/png"), "png"),
            TestStatus::Pass
        );
        assert_eq!(content_type_match_status(None, "png"), TestStatus::Warning);
    }
}
