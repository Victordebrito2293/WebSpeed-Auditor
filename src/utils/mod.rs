//! Utilitários internos: SSRF, robots.txt, decodificação, sniffing, tempo e
//! logs. Todos operam em memória e não persistem dados.

pub mod decode;
pub mod log;
pub mod robots;
pub mod sniff;
pub mod ssrf;
pub mod timex;

/// Escapa HTML para geração segura do relatório (prevenção de XSS no relatório).
pub fn html_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            _ => out.push(c),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escaping_prevents_injection() {
        assert_eq!(
            html_escape("<script>alert(\"x\")</script>"),
            "&lt;script&gt;alert(&quot;x&quot;)&lt;/script&gt;"
        );
        assert_eq!(html_escape("a & b"), "a &amp; b");
        assert_eq!(html_escape("'quote'"), "&#39;quote&#39;");
        assert_eq!(html_escape("normal text"), "normal text");
    }
}
