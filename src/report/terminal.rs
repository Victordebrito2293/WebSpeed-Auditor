//! Relatório em texto para o terminal. Cores ANSI são aplicadas apenas
//! quando o stdout é um TTY — nunca em JSON/HTML.

use crate::models::{AuditReport, Severity, TestItem, TestStatus};
use crate::utils::timex;
use std::fmt::Write as _;

fn colorize(out: &mut String, color: &str, s: &str) {
    let tty = std::io::IsTerminal::is_terminal(&std::io::stdout());
    if tty {
        let _ = write!(out, "{color}{s}\x1b[0m");
    } else {
        out.push_str(s);
    }
}

const RED: &str = "\x1b[31m";
const GREEN: &str = "\x1b[32m";
const YELLOW: &str = "\x1b[33m";
const BOLD: &str = "\x1b[1m";
const DIM: &str = "\x1b[2m";

fn status_color(s: TestStatus) -> &'static str {
    match s {
        TestStatus::Pass => GREEN,
        TestStatus::Warning => YELLOW,
        TestStatus::Fail | TestStatus::Error => RED,
        TestStatus::NotTested => DIM,
    }
}

fn severity_color(s: Severity) -> &'static str {
    match s {
        Severity::Critical | Severity::High => RED,
        Severity::Medium => YELLOW,
        Severity::Low | Severity::Info => DIM,
    }
}

pub fn render(r: &AuditReport) -> String {
    let mut o = String::new();

    let _ = writeln!(o, "======================================================");
    colorize(&mut o, BOLD, &format!("{} {}", r.tool, r.version));
    let _ = writeln!(o);
    let _ = writeln!(o, "======================================================");
    let _ = writeln!(o, "URL:      {}", r.url);
    if r.final_url != r.url {
        let _ = writeln!(o, "URL final: {}", r.final_url);
    }
    let _ = writeln!(o, "Gerado:   {}", r.generated_at_iso8601);
    let _ = writeln!(o, "Duração:  {}", timex::fmt_ms(r.duration_ms));
    let _ = writeln!(
        o,
        "Escopo:   {} página(s), {} requisição(ões) analisada(s)",
        r.pages_analyzed, r.requests_analyzed
    );
    let _ = writeln!(o);

    // --- Score ---
    colorize(&mut o, BOLD, "PONTUAÇÃO GERAL");
    let _ = write!(o, ": ");
    let score_str = format!("{}/100", r.scores.score);
    colorize(
        &mut o,
        if r.scores.score >= 80 {
            GREEN
        } else if r.scores.score >= 50 {
            YELLOW
        } else {
            RED
        },
        &score_str,
    );
    let _ = writeln!(o);
    for c in &r.scores.categories {
        let _ = write!(o, "  {:<16}", format!("{}:", c.category));
        let bar_len = (c.score as usize) / 5;
        let bar: String = "█".repeat(bar_len);
        let pad: String = "░".repeat(20 - bar_len.min(20));
        colorize(
            &mut o,
            if c.score >= 80 {
                GREEN
            } else if c.score >= 50 {
                YELLOW
            } else {
                RED
            },
            &bar,
        );
        let _ = write!(o, "{pad} ");
        let _ = writeln!(o, "{:>3}/100 ({} checagem(ns))", c.score, c.checks);
    }
    let _ = writeln!(o);

    // --- Testes por status ---
    let (passes, warnings, failures, not_tested) = split_tests(&r.tests);

    colorize(&mut o, BOLD, "TESTES");
    let _ = writeln!(o, " ({})", r.tests.len());
    for (label, list, color) in [
        ("FALHAS", &failures, RED),
        ("AVISOS", &warnings, YELLOW),
        ("PASS", &passes, GREEN),
        ("NÃO TESTADOS", &not_tested, DIM),
    ] {
        if list.is_empty() {
            continue;
        }
        let _ = writeln!(o);
        colorize(&mut o, color, &format!("{label} ({})", list.len()));
        let _ = writeln!(o);
        for t in list {
            write_test(&mut o, t);
        }
    }

    // --- Problemas ---
    if !r.findings.is_empty() {
        let _ = writeln!(o);
        colorize(
            &mut o,
            BOLD,
            &format!("PROBLEMAS ENCONTRADOS ({})", r.findings.len()),
        );
        let _ = writeln!(o);
        for (i, f) in r.findings.iter().enumerate() {
            let _ = write!(o, "{:>2}. ", i + 1);
            colorize(
                &mut o,
                severity_color(f.severity),
                &format!("[{}]", f.severity),
            );
            let _ = write!(o, " {} ", f.title);
            colorize(&mut o, DIM, &format!("({})", f.category));
            let _ = writeln!(o);
            let _ = writeln!(o, "     Problema:  {}", f.problem);
            let _ = writeln!(o, "     Evidência: {}", f.evidence);
            let _ = writeln!(o, "     Impacto:   {}", f.impact);
            let _ = writeln!(o, "     Correção:  {}", f.recommendation);
            let _ = writeln!(o);
        }
    }

    // --- O que já está otimizado ---
    if !r.optimized.is_empty() {
        let _ = writeln!(o);
        colorize(
            &mut o,
            GREEN,
            &format!("JÁ OTIMIZADO ({} item(ns))", r.optimized.len()),
        );
        let _ = writeln!(o);
        for t in &r.optimized {
            let _ = writeln!(o, "  + {:<50} {}", t.name, t.detail);
        }
    }

    // --- Não testado ---
    if !r.not_tested.is_empty() {
        let _ = writeln!(o);
        colorize(&mut o, BOLD, "NÃO TESTADO NESTE AMBIENTE");
        let _ = writeln!(o);
        for l in &r.not_tested {
            let _ = writeln!(o, "  - {}: {}", l.area, l.reason);
        }
    }

    // --- Detalhes técnicos ---
    let _ = writeln!(o);
    colorize(&mut o, BOLD, "DETALHES TÉCNICOS");
    let _ = writeln!(o);
    let _ = writeln!(o, "  DNS:      {} — {}", r.dns.status, r.dns.detail);
    if let Some(t) = &r.tls {
        let _ = writeln!(o, "  TLS:      {} — {}", t.status, t.detail);
    } else {
        let _ = writeln!(o, "  TLS:      não disponível neste ambiente");
    }
    let _ = writeln!(
        o,
        "  Redirect: {} — {}",
        r.redirects.status, r.redirects.detail
    );
    if let Some(h) = &r.http {
        let _ = writeln!(
            o,
            "  HTTP:     {} {:?}",
            h.status_code.unwrap_or(0),
            h.http_version.as_deref().unwrap_or("?")
        );
        let t = &h.timings;
        let _ = writeln!(
            o,
            "            DNS {} ms | conect {} ms | TLS {} ms | TTFB {} | download {} | total {}",
            fmt_opt(t.dns_ms),
            fmt_opt(t.connect_ms),
            fmt_opt(t.tls_ms),
            fmt_opt_ms(t.ttfb_ms),
            fmt_opt_ms(t.download_ms),
            fmt_opt_ms(t.total_ms),
        );
        let _ = writeln!(
            o,
            "            transferido {} | descodificado {} | truncated={}",
            fmt_opt_bytes(h.transfer_size),
            fmt_opt_bytes(h.decoded_size),
            h.body_truncated
        );
    } else {
        let _ = writeln!(o, "  HTTP:     documento principal indisponível");
    }

    if !r.pages.is_empty() {
        let _ = writeln!(o, "  Páginas:");
        for p in &r.pages {
            let _ = writeln!(o, "    - {p}");
        }
    }

    o
}

fn write_test(o: &mut String, t: &TestItem) {
    let _ = write!(o, "  ");
    colorize(o, status_color(t.status), &format!("[{}]", t.status));
    let _ = writeln!(o, " {} — {}", t.name, t.detail);
    if let Some(e) = &t.evidence {
        let _ = writeln!(o, "          evidência: {e}");
    }
}

fn split_tests(
    tests: &[TestItem],
) -> (
    Vec<&TestItem>,
    Vec<&TestItem>,
    Vec<&TestItem>,
    Vec<&TestItem>,
) {
    let mut p = vec![];
    let mut w = vec![];
    let mut f = vec![];
    let mut n = vec![];
    for t in tests {
        match t.status {
            TestStatus::Pass => p.push(t),
            TestStatus::Warning => w.push(t),
            TestStatus::Fail | TestStatus::Error => f.push(t),
            TestStatus::NotTested => n.push(t),
        }
    }
    (p, w, f, n)
}

fn fmt_opt(v: Option<u64>) -> String {
    v.map(|x| x.to_string()).unwrap_or_else(|| "-".into())
}

fn fmt_opt_ms(v: Option<u64>) -> String {
    v.map(timex::fmt_ms).unwrap_or_else(|| "n/d".into())
}

fn fmt_opt_bytes(v: Option<u64>) -> String {
    v.map(timex::fmt_bytes).unwrap_or_else(|| "n/d".into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::report::fixtures::sample_report;

    #[test]
    fn terminal_report_contains_key_sections() {
        let r = sample_report();
        let out = render(&r);
        assert!(out.contains("PONTUAÇÃO GERAL"));
        assert!(out.contains("87/100"));
        assert!(out.contains("PROBLEMAS ENCONTRADOS"));
        assert!(out.contains("JÁ OTIMIZADO"));
        assert!(out.contains("NÃO TESTADO NESTE AMBIENTE"));
        assert!(out.contains("DETALHES TÉCNICOS"));
    }

    #[test]
    fn terminal_report_shows_finding_title_verbatim() {
        let r = sample_report();
        let out = render(&r);
        assert!(out.contains("Título <script>alert(1)</script>"));
    }
}
