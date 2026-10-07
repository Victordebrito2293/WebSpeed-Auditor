//! Descompressão e decodificação de texto em memória, com limites rígidos
//! para mitigar zip bombs. Nada é gravado em disco.

use std::io::Read;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DecodeError {
    /// Encoding não suportado pela ferramenta.
    UnsupportedEncoding(String),
    /// Corpo comprimido corrompido.
    Corrupt,
    /// Saída excedeu o limite (proteção contra bomba).
    LimitExceeded,
    /// Falha de I/O interna.
    Io(String),
}

impl std::fmt::Display for DecodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DecodeError::UnsupportedEncoding(e) => write!(f, "encoding não suportado: {e}"),
            DecodeError::Corrupt => write!(f, "conteúdo comprimido corrompido"),
            DecodeError::LimitExceeded => write!(f, "conteúdo descomprimido excede o limite"),
            DecodeError::Io(e) => write!(f, "erro de I/O: {e}"),
        }
    }
}

impl std::error::Error for DecodeError {}

/// Lê de um decoder até `limit` bytes; estoura erro se exceder (anti zip bomb).
fn read_limited<R: Read>(mut decoder: R, limit: usize) -> Result<Vec<u8>, DecodeError> {
    let mut out: Vec<u8> = Vec::with_capacity(limit.min(1 << 20));
    let mut chunk = [0u8; 16 * 1024];
    loop {
        let n = decoder.read(&mut chunk).map_err(|_| DecodeError::Corrupt)?;
        if n == 0 {
            break;
        }
        if out.len() + n > limit {
            return Err(DecodeError::LimitExceeded);
        }
        out.extend_from_slice(&chunk[..n]);
    }
    Ok(out)
}

/// Descompacta `body` conforme `Content-Encoding`.
///
/// Retorna `(corpo_original_ou_descomprimido, foi_descomprimido)`.
pub fn decompress(
    content_encoding: Option<&str>,
    body: &[u8],
    limit: u64,
) -> Result<(Vec<u8>, bool), DecodeError> {
    let enc = content_encoding
        .map(|e| e.trim().to_ascii_lowercase())
        .unwrap_or_default();
    let enc = enc.split(',').next().unwrap_or("").trim().to_string();
    let limit = limit as usize;

    match enc.as_str() {
        "" | "identity" => Ok((body.to_vec(), false)),
        "gzip" | "x-gzip" => {
            let dec = flate2::read::GzDecoder::new(body);
            Ok((read_limited(dec, limit)?, true))
        }
        "deflate" => {
            // Servidores às vezes enviam deflate cru (sem header zlib).
            let zlib = flate2::read::ZlibDecoder::new(body);
            match read_limited(zlib, limit) {
                Ok(v) => Ok((v, true)),
                Err(DecodeError::Corrupt) | Err(DecodeError::Io(_)) => {
                    let raw = flate2::read::DeflateDecoder::new(body);
                    match read_limited(raw, limit) {
                        Ok(v) => Ok((v, true)),
                        Err(_) => Err(DecodeError::Corrupt),
                    }
                }
                Err(e) => Err(e),
            }
        }
        "br" => {
            let mut out: Vec<u8> = Vec::new();
            let mut input = body;
            brotli::BrotliDecompress(&mut input, &mut out).map_err(|_| DecodeError::Corrupt)?;
            if out.len() > limit {
                return Err(DecodeError::LimitExceeded);
            }
            Ok((out, true))
        }
        other => Err(DecodeError::UnsupportedEncoding(other.to_string())),
    }
}

/// Extrai o charset do Content-Type.
pub fn charset_from_content_type(content_type: Option<&str>) -> Option<String> {
    let ct = content_type?;
    for part in ct.split(';').skip(1) {
        let part = part.trim();
        if let Some((k, v)) = part.split_once('=')
            && k.trim().eq_ignore_ascii_case("charset")
        {
            return Some(v.trim().trim_matches('"').to_string());
        }
    }
    None
}

/// Decodifica bytes em texto usando o charset declarado (ou UTF-8).
/// Retorna `(texto, encoding_usado)`.
pub fn decode_text(content_type: Option<&str>, bytes: &[u8]) -> (String, &'static str) {
    if let Some(charset) = charset_from_content_type(content_type)
        && let Some(enc) = encoding_rs::Encoding::for_label(charset.as_bytes())
    {
        let (cow, _, _) = enc.decode(bytes);
        return (cow.into_owned(), enc.name());
    }
    // UTF-8 estrito primeiro.
    if let Ok(s) = std::str::from_utf8(bytes) {
        return (s.to_string(), "UTF-8");
    }
    // Fallback: substitui inválidos em vez de falhar.
    let s = String::from_utf8_lossy(bytes).into_owned();
    (s, "UTF-8 (lossy)")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn gzip_bytes(data: &[u8]) -> Vec<u8> {
        let mut e = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        e.write_all(data).expect("gzip");
        e.finish().expect("gzip finish")
    }

    fn zlib_bytes(data: &[u8]) -> Vec<u8> {
        let mut e = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
        e.write_all(data).expect("zlib");
        e.finish().expect("zlib finish")
    }

    fn brotli_bytes(data: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        let mut input = data;
        brotli::BrotliCompress(&mut input, &mut out, &Default::default()).expect("brotli");
        out
    }

    #[test]
    fn identity_passthrough() {
        let (out, done) = decompress(None, b"hello", 1024).expect("ok");
        assert_eq!(out, b"hello");
        assert!(!done);
        let (out, done) = decompress(Some("identity"), b"hello", 1024).expect("ok");
        assert_eq!(out, b"hello");
        assert!(!done);
    }

    #[test]
    fn gzip_roundtrip() {
        let original = b"<html>".repeat(100);
        let compressed = gzip_bytes(&original);
        let (out, done) = decompress(Some("gzip"), &compressed, 1 << 20).expect("ok");
        assert!(done);
        assert_eq!(out, original);
    }

    #[test]
    fn zlib_and_deflate_roundtrip() {
        let original = b"abcabcabcabc";
        let z = zlib_bytes(original);
        let (out, _) = decompress(Some("deflate"), &z, 1024).expect("zlib ok");
        assert_eq!(out, original);
        // deflate cru
        let mut e = flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::default());
        e.write_all(original).expect("write");
        let raw = e.finish().expect("finish");
        let (out, _) = decompress(Some("deflate"), &raw, 1024).expect("raw ok");
        assert_eq!(out, original);
    }

    #[test]
    fn brotli_roundtrip() {
        let original = b"performance audit ".repeat(50);
        let c = brotli_bytes(&original);
        let (out, done) = decompress(Some("br"), &c, 1 << 20).expect("ok");
        assert!(done);
        assert_eq!(out, original);
    }

    #[test]
    fn unsupported_encoding_is_explicit_error() {
        let e = decompress(Some("zstd"), b"x", 1024).expect_err("deve falhar");
        assert!(matches!(e, DecodeError::UnsupportedEncoding(_)));
        let e = decompress(Some("weird, gzip"), b"x", 1024).expect_err("deve falhar");
        assert!(matches!(e, DecodeError::UnsupportedEncoding(_)));
    }

    #[test]
    fn corrupt_gzip_is_error_not_panic() {
        let e = decompress(Some("gzip"), b"not-gzip-at-all", 1024).expect_err("deve falhar");
        assert!(matches!(e, DecodeError::Corrupt));
    }

    #[test]
    fn zip_bomb_hits_limit() {
        // 20 MiB de zeros comprimidos com limite de 1 MiB.
        let original = vec![0u8; 20 * 1024 * 1024];
        let c = gzip_bytes(&original);
        let e = decompress(Some("gzip"), &c, 1024 * 1024).expect_err("deve estourar limite");
        assert_eq!(e, DecodeError::LimitExceeded);
    }

    #[test]
    fn charset_extraction() {
        assert_eq!(
            charset_from_content_type(Some("text/html; charset=UTF-8")).as_deref(),
            Some("UTF-8")
        );
        assert_eq!(
            charset_from_content_type(Some("text/html;charset=\"iso-8859-1\"")).as_deref(),
            Some("iso-8859-1")
        );
        assert_eq!(charset_from_content_type(Some("text/html")), None);
        assert_eq!(charset_from_content_type(None), None);
    }

    #[test]
    fn text_decode_utf8_and_lossy() {
        let (s, enc) = decode_text(Some("text/html; charset=utf-8"), "olá".as_bytes());
        assert_eq!(s, "olá");
        assert_eq!(enc, "UTF-8");
        // Byte inválido não deve panicar.
        let (s, _) = decode_text(None, &[0xff, 0xfe, b'a']);
        assert!(s.contains('a'));
        // WHATWG mapeia iso-8859-1 para windows-1252 no decode (comportamento padrão de navegadores).
        let (s, enc) = decode_text(Some("text/html; charset=iso-8859-1"), &[0xe1]);
        assert_eq!(s, "á");
        assert_eq!(enc, "windows-1252");
    }
}
