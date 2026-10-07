//! Relatório HTML autocontido: estilos inline, sem scripts, sem recursos
//! externos. Todo conteúdo dinâmico é escapado (prevenção de XSS).

use crate::models::{AuditReport, TestStatus};
use crate::utils::html_escape;
use crate::utils::timex;
use std::fmt::Write as _;

const STYLE: &str = r#"
:root{--bg:#0f141a;--panel:#171d26;--fg:#e6edf3;--muted:#8b98a5;--line:#2a3441;
--pass:#2ea043;--warn:#d29922;--fail:#f85149;--info:#58a6ff;--accent:#58a6ff;}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--fg);
font:15px/1.55 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif}
.wrap{max-width:960px;margin:0 auto;padding:32px 20px 64px}
header{border-bottom:1px solid var(--line);padding-bottom:20px;margin-bottom:24px}
h1{margin:0 0 6px;font-size:26px}
h2{font-size:19px;margin:34px 0 12px;padding-bottom:6px;border-bottom:1px solid var(--line)}
h3{font-size:15px;margin:18px 0 8px;color:var(--muted)}
.meta{color:var(--muted);font-size:13px}
.meta b{color:var(--fg);font-weight:600}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:12px;margin:18px 0}
.card{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:14px}
.card .num{font-size:30px;font-weight:700}
.card .lbl{color:var(--muted);font-size:12px;text-transform:uppercase;letter-spacing:.05em}
.scorebar{height:8px;background:#222b36;border-radius:6px;overflow:hidden;margin-top:8px}
.scorebar>i{display:block;height:100%;background:var(--pass)}
.badge{display:inline-block;padding:2px 9px;border-radius:20px;font-size:11.5px;font-weight:700;letter-spacing:.03em}
.b-pass{background:rgba(46,160,67,.18);color:var(--pass);border:1px solid rgba(46,160,67,.4)}
.b-warn{background:rgba(210,153,34,.15);color:var(--warn);border:1px solid rgba(210,153,34,.4)}
.b-fail{background:rgba(248,81,73,.15);color:var(--fail);border:1px solid rgba(248,81,73,.4)}
.b-nt{background:rgba(139,152,165,.12);color:var(--muted);border:1px solid rgba(139,152,165,.35)}
table{width:100%;border-collapse:collapse;background:var(--panel);border:1px solid var(--line);border-radius:10px;overflow:hidden}
th,td{text-align:left;padding:9px 12px;border-bottom:1px solid var(--line);font-size:13.5px;vertical-align:top}
th{color:var(--muted);font-weight:600;background:#1b2330;font-size:12px;text-transform:uppercase}
tr:last-child td{border-bottom:none}
.finding{background:var(--panel);border:1px solid var(--line);border-left:4px solid var(--warn);border-radius:8px;padding:14px 16px;margin:12px 0}
.finding.critical,.finding.high{border-left-color:var(--fail)}
.finding .t{font-weight:700;margin-bottom:6px}
.finding dl{margin:0;display:grid;grid-template-columns:96px 1fr;gap:4px 10px;font-size:13.5px}
.finding dt{color:var(--muted)}
.finding dd{margin:0}
ul.plain{list-style:none;padding:0;margin:0}
ul.plain li{padding:7px 12px;border:1px solid var(--line);border-radius:8px;margin-bottom:7px;background:var(--panel);font-size:13.5px}
.note{background:#121821;border:1px dashed var(--line);border-radius:8px;padding:12px 14px;color:var(--muted);font-size:13.5px}
code{background:#222b36;padding:1px 6px;border-radius:5px;font-size:12.5px}
footer{margin-top:44px;color:var(--muted);font-size:12.5px;border-top:1px solid var(--line);padding-top:14px}
a{color:var(--accent)}
.cb{color:var(--muted);font-size:12.5px;word-break:break-all}
"#;

fn esc(s: &str) -> String {
    html_escape(s)
}

fn status_badge(status: TestStatus) -> &'static str {
    match status {
        TestStatus::Pass => "b-pass",
        TestStatus::Warning => "b-warn",
        TestStatus::Fail | TestStatus::Error => "b-fail",
        TestStatus::NotTested => "b-nt",
    }
}

pub fn render(r: &AuditReport) -> String {
    let mut o = String::with_capacity(16 * 1024);
    let _ = write!(
        o,
        "<!DOCTYPE html>\n<html lang=\"pt-BR\">\n<head>\n<meta charset=\"utf-8\">\n\
         <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n\
         <meta name=\"robots\" content=\"noindex, nofollow\">\n\
         <title>WebSpeed Auditor — {}</title>\n<style>{STYLE}</style>\n</head>\n<body>\n\
         <div class=\"wrap\">\n<header>\n<h1>{} — relatório de auditoria</h1>\n\
         <div class=\"meta\">\n\
         URL: <b>{}</b><br>\n\
         URL final: <b>{}</b><br>\n\
         Gerado: <b>{}</b> · Duração: <b>{}</b><br>\n\
         Escopo: <b>{}</b> página(s) · <b>{}</b> requisição(ões)<br>\n\
         Ferramenta: <b>{} {}</b> (execução local; nenhum dado é enviado a terceiros)\n\
         </div>\n</header>\n",
        esc(&r.url),
        esc(&r.tool),
        esc(&r.url),
        esc(&r.final_url),
        esc(&r.generated_at_iso8601),
        esc(&timex::fmt_ms(r.duration_ms)),
        r.pages_analyzed,
        r.requests_analyzed,
        esc(&r.tool),
        esc(&r.version),
    );

    // Score geral.
    let score = r.scores.score;
    let color = if score >= 80 {
        "var(--pass)"
    } else if score >= 50 {
        "var(--warn)"
    } else {
        "var(--fail)"
    };
    let _ = write!(
        o,
        "<section><h2>Pontuação geral</h2>\n<div class=\"cards\">\n\
         <div class=\"card\"><div class=\"num\" style=\"color:{color}\">{score}</div>\
         <div class=\"lbl\">Score geral /100</div></div>\n"
    );
    for c in &r.scores.categories {
        let cc = if c.score >= 80 {
            "var(--pass)"
        } else if c.score >= 50 {
            "var(--warn)"
        } else {
            "var(--fail)"
        };
        let _ = writeln!(
            o,
            "<div class=\"card\"><div class=\"num\" style=\"color:{cc};font-size:22px\">{}</div>\
             <div class=\"lbl\">{}</div><div class=\"scorebar\"><i style=\"width:{}%;background:{cc}\"></i></div></div>",
            c.score,
            esc(c.category.label()),
            c.score
        );
    }
    let _ = write!(
        o,
        "</div>\n<p class=\"cb\">Pesos: Performance 20, Network 15, Images 15, Caching 10, Compression 10, JavaScript 10, HTML 10, CSS 5, Best Practices 5. Deduções por achado: Critical 30, High 15, Medium 8, Low 3, Info 0.</p>\n"
    );

    // Testes.
    let _ = write!(
        o,
        "<h2>O que foi testado ({})</h2>\n<table>\n<thead><tr><th>Categoria</th><th>Teste</th><th>Status</th><th>Resultado</th></tr></thead>\n<tbody>\n",
        r.tests.len()
    );
    for t in &r.tests {
        let _ = writeln!(
            o,
            "<tr><td>{}</td><td>{}</td><td><span class=\"badge {}\">{}</span></td><td>{}</td></tr>",
            esc(t.category.label()),
            esc(&t.name),
            status_badge(t.status),
            t.status,
            esc(&t.detail)
        );
        if let Some(e) = &t.evidence {
            let _ = writeln!(
                o,
                "<tr><td></td><td colspan=\"3\"><span class=\"cb\">evidência: {}</span></td></tr>",
                esc(e)
            );
        }
    }
    let _ = writeln!(o, "</tbody></table>");

    // Problemas.
    let _ = writeln!(o, "<h2>Problemas encontrados ({})</h2>", r.findings.len());
    if r.findings.is_empty() {
        o.push_str("<div class=\"note\">Nenhum problema foi identificado nas verificações executadas.</div>\n");
    }
    for f in &r.findings {
        let cls = match f.severity {
            crate::models::Severity::Critical | crate::models::Severity::High => "high",
            _ => "",
        };
        let _ = writeln!(
            o,
            "<div class=\"finding {cls}\">\
             <div class=\"t\"><span class=\"badge {}\">{}</span> {} <span class=\"cb\">({} · id <code>{}</code>)</span></div>\
             <dl>\
             <dt>Problema</dt><dd>{}</dd>\
             <dt>Evidência</dt><dd>{}</dd>\
             <dt>Impacto</dt><dd>{}</dd>\
             <dt>Correção</dt><dd>{}</dd>\
             </dl></div>",
            match f.severity {
                crate::models::Severity::Critical | crate::models::Severity::High => "b-fail",
                crate::models::Severity::Medium => "b-warn",
                _ => "b-nt",
            },
            esc(&f.severity.to_string()),
            esc(&f.title),
            esc(f.category.label()),
            esc(&f.id),
            esc(&f.problem),
            esc(&f.evidence),
            esc(&f.impact),
            esc(&f.recommendation),
        );
    }

    // Otimizado.
    let _ = writeln!(o, "<h2>Já está otimizado ({})</h2>", r.optimized.len());
    if r.optimized.is_empty() {
        o.push_str("<div class=\"note\">Nenhum teste terminou em PASS nesta execução.</div>\n");
    } else {
        o.push_str("<ul class=\"plain\">\n");
        for t in &r.optimized {
            let _ = writeln!(
                o,
                "<li><span class=\"badge b-pass\">PASS</span> <b>{}</b> — {}</li>",
                esc(&t.name),
                esc(&t.detail)
            );
        }
        o.push_str("</ul>\n");
    }

    // Não testado.
    let _ = writeln!(
        o,
        "<h2>Não testado neste ambiente ({})</h2>",
        r.not_tested.len()
    );
    if r.not_tested.is_empty() {
        o.push_str("<div class=\"note\">Todas as verificações previstas foram executadas.</div>\n");
    } else {
        o.push_str("<ul class=\"plain\">\n");
        for l in &r.not_tested {
            let _ = writeln!(o, "<li><b>{}</b> — {}</li>", esc(&l.area), esc(&l.reason));
        }
        o.push_str("</ul>\n");
    }

    // Detalhes técnicos.
    let _ = write!(o, "<h2>Detalhes técnicos</h2>\n<table>\n<tbody>\n");
    let _ = writeln!(
        o,
        "<tr><th>DNS</th><td>{} — {}</td></tr>",
        r.dns.status,
        esc(&r.dns.detail)
    );
    match &r.tls {
        Some(t) => {
            let _ = writeln!(
                o,
                "<tr><th>TLS</th><td>{} — {}</td></tr>",
                t.status,
                esc(&t.detail)
            );
        }
        None => {
            o.push_str("<tr><th>TLS</th><td>não disponível neste ambiente</td></tr>\n");
        }
    }
    let _ = writeln!(
        o,
        "<tr><th>Redirects</th><td>{} — {}</td></tr>",
        r.redirects.status,
        esc(&r.redirects.detail)
    );
    if !r.redirects.hops.is_empty() {
        o.push_str("<tr><th>Cadeia</th><td>");
        for h in &r.redirects.hops {
            let _ = write!(
                o,
                "{} → {} → <code>{}</code><br>",
                esc(&h.from),
                h.status,
                esc(&h.to)
            );
        }
        o.push_str("</td></tr>\n");
    }
    if let Some(h) = &r.http {
        let t = &h.timings;
        let _ = writeln!(
            o,
            "<tr><th>HTTP</th><td>{} {} · Content-Type: {} · encoding: {}</td></tr>",
            h.status_code.unwrap_or(0),
            esc(h.http_version.as_deref().unwrap_or("?")),
            esc(h.content_type.as_deref().unwrap_or("n/d")),
            esc(h.content_encoding.as_deref().unwrap_or("n/d")),
        );
        let _ = writeln!(
            o,
            "<tr><th>Tempos</th><td>DNS {} ms · conexão {} ms · TLS {} ms · TTFB {} · download {} · total {}</td></tr>",
            opt(t.dns_ms),
            opt(t.connect_ms),
            opt(t.tls_ms),
            opt_ms(t.ttfb_ms),
            opt_ms(t.download_ms),
            opt_ms(t.total_ms),
        );
        let _ = writeln!(
            o,
            "<tr><th>Transferência</th><td>{} transferido · {} descodificado · corpo truncado: {}</td></tr>",
            opt_bytes(h.transfer_size),
            opt_bytes(h.decoded_size),
            h.body_truncated
        );
        let _ = writeln!(
            o,
            "<tr><th>Cache-Control</th><td>{}</td></tr>",
            esc(h.cache_control.as_deref().unwrap_or("ausente"))
        );
        let _ = writeln!(
            o,
            "<tr><th>Set-Cookie</th><td>{} (valores não coletados)</td></tr>",
            h.set_cookie_count
        );
    } else {
        o.push_str("<tr><th>HTTP</th><td>documento principal indisponível</td></tr>\n");
    }

    // Páginas.
    if !r.pages.is_empty() {
        o.push_str("<tr><th>Páginas</th><td>");
        for p in &r.pages {
            let _ = write!(o, "{}<br>", esc(p));
        }
        o.push_str("</td></tr>\n");
    }

    // Recursos.
    if !r.resources.is_empty() {
        o.push_str("<tr><th>Recursos</th><td>");
        for res in &r.resources {
            let _ = write!(
                o,
                "<span class=\"cb\">{} — {} {}</span><br>",
                esc(&res.url),
                res.status,
                esc(res.content_type.as_deref().unwrap_or("-"))
            );
        }
        o.push_str("</td></tr>\n");
    }
    o.push_str("</tbody></table>\n");

    let _ = write!(
        o,
        "<footer>Gerado por <b>{} {}</b>. Este relatório é autocontido (sem scripts nem recursos externos) e contém apenas dados do site auditado. Nenhum dado local do operador está incluído.</footer>\n</div>\n</body>\n</html>\n",
        esc(&r.tool),
        esc(&r.version),
    );
    o
}

fn opt(v: Option<u64>) -> String {
    v.map(|x| x.to_string()).unwrap_or_else(|| "n/d".into())
}
fn opt_ms(v: Option<u64>) -> String {
    v.map(timex::fmt_ms).unwrap_or_else(|| "n/d".into())
}
fn opt_bytes(v: Option<u64>) -> String {
    v.map(timex::fmt_bytes).unwrap_or_else(|| "n/d".into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::report::fixtures::sample_report;

    #[test]
    fn html_report_escapes_dynamic_content() {
        let r = sample_report();
        let out = render(&r);
        assert!(out.starts_with("<!DOCTYPE html>"));
        // O script do fixture deve estar escapado.
        assert!(!out.contains("<script>alert(1)</script>"));
        assert!(out.contains("&lt;script&gt;alert(1)&lt;/script&gt;"));
    }

    #[test]
    fn html_report_has_no_external_resources_or_scripts() {
        let r = sample_report();
        let out = render(&r);
        assert!(!out.contains("<script"));
        assert!(!out.contains("http://") && !out.contains("https://cdn"));
        // Só a URL do alvo é permitida como texto (já escapada).
        assert!(out.contains("https://example.com/"));
        assert!(!out.contains("src="));
    }

    #[test]
    fn html_report_sections_present() {
        let r = sample_report();
        let out = render(&r);
        assert!(out.contains("Pontuação geral"));
        assert!(out.contains("O que foi testado"));
        assert!(out.contains("Problemas encontrados"));
        assert!(out.contains("Já está otimizado"));
        assert!(out.contains("Não testado neste ambiente"));
        assert!(out.contains("Detalhes técnicos"));
        assert!(out.contains("Core Web Vitals"));
    }
}
