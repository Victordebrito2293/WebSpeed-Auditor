//! Parser e verificação de robots.txt (conservador).
//!
//! Implementa o subconjunto essencial do RFC 9309: grupos de user-agent,
//! `Disallow`/`Allow` com curingas `*` e `$`. Regras `Crawl-delay` e
//! `Sitemap` são reconhecidas mas não alteram o comportamento além do
//! delay implícito da concorrência configurada.

#[derive(Debug, Default, Clone)]
pub struct Robots {
    /// Regras aplicáveis ao nosso user-agent (grupo específico ou `*`).
    rules: Vec<Rule>,
    /// Segundos de espera sugeridos entre requisições.
    pub crawl_delay_secs: Option<u64>,
}

#[derive(Debug, Clone)]
struct Rule {
    allow: bool,
    pattern: String,
}

/// Extrai o token de produto do User-Agent ("WebSpeed-Auditor").
pub fn ua_token(user_agent: &str) -> String {
    user_agent
        .split('/')
        .next()
        .unwrap_or(user_agent)
        .trim()
        .to_string()
}

/// Parse de robots.txt. `user_agent` é o User-Agent completo enviado.
pub fn parse(text: &str, user_agent: &str) -> Robots {
    let token = ua_token(user_agent).to_ascii_lowercase();

    // Coleta grupos: (agentes, retras, delay)
    let mut groups: Vec<(Vec<String>, Vec<Rule>, Option<u64>)> = Vec::new();
    let mut current_agents: Vec<String> = Vec::new();
    let mut current_rules: Vec<Rule> = Vec::new();
    let mut current_delay: Option<u64> = None;
    let mut saw_directive_after_agents = false;

    fn flush(
        groups: &mut Vec<(Vec<String>, Vec<Rule>, Option<u64>)>,
        agents: &mut Vec<String>,
        rules: &mut Vec<Rule>,
        delay: &mut Option<u64>,
        saw: &mut bool,
    ) {
        if !agents.is_empty() {
            groups.push((std::mem::take(agents), std::mem::take(rules), delay.take()));
        } else {
            rules.clear();
            delay.take();
        }
        *saw = false;
    }

    for raw in text.lines() {
        let line = raw.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        let Some((key, value)) = line.split_once(':') else {
            continue;
        };
        let key = key.trim().to_ascii_lowercase();
        let value = value.trim();
        match key.as_str() {
            "user-agent" => {
                if saw_directive_after_agents {
                    flush(
                        &mut groups,
                        &mut current_agents,
                        &mut current_rules,
                        &mut current_delay,
                        &mut saw_directive_after_agents,
                    );
                    // novo grupo começa
                }
                current_agents.push(value.to_ascii_lowercase());
            }
            "disallow" | "allow" => {
                if current_agents.is_empty() {
                    // Diretivas antes de qualquer agent: aplicam a `*` (comportamento comum).
                    current_agents.push("*".to_string());
                }
                saw_directive_after_agents = true;
                // `Disallow:` vazio significa "tudo permitido" — ignoramos a regra.
                if !value.is_empty() {
                    current_rules.push(Rule {
                        allow: key == "allow",
                        pattern: value.to_string(),
                    });
                }
            }
            "crawl-delay" => {
                saw_directive_after_agents = true;
                if let Ok(v) = value.parse::<u64>() {
                    current_delay = Some(v.min(30));
                }
            }
            // Outras diretivas (sitemap etc.) são ignoradas silenciosamente.
            _ => {}
        }
    }
    flush(
        &mut groups,
        &mut current_agents,
        &mut current_rules,
        &mut current_delay,
        &mut saw_directive_after_agents,
    );

    // Escolhe o grupo mais específico: match exato do token > `*`.
    let mut chosen: Option<&(Vec<String>, Vec<Rule>, Option<u64>)> = None;
    let mut star: Option<&(Vec<String>, Vec<Rule>, Option<u64>)> = None;
    for g in &groups {
        for a in &g.0 {
            if a == &token {
                chosen = Some(g);
            } else if a == "*" && star.is_none() {
                star = Some(g);
            }
        }
    }
    let (rules, delay) = match chosen.or(star) {
        Some(g) => (g.1.clone(), g.2),
        None => (vec![], None),
    };

    Robots {
        rules,
        crawl_delay_secs: delay,
    }
}

impl Robots {
    /// `true` quando o path pode ser rastreado. Sem regras = permitido.
    pub fn is_allowed(&self, path: &str) -> bool {
        if self.rules.is_empty() {
            return true;
        }
        let path = if path.is_empty() { "/" } else { path };
        let mut best: Option<(usize, bool)> = None; // (comprimento padrão, allow)
        for rule in &self.rules {
            if pattern_matches(&rule.pattern, path) {
                let len = rule.pattern.len();
                match best {
                    Some((blen, _)) if blen > len => {}
                    Some((blen, ballow)) if blen == len && !ballow && rule.allow => {
                        best = Some((len, true));
                    }
                    _ => best = Some((len, rule.allow)),
                }
            }
        }
        // Permitido, salvo se a regra vencedora for Disallow.
        !matches!(best, Some((_, false)))
    }
}

/// Matching de padrão de robots.txt com `*` (curinga) e `$` (fim).
fn pattern_matches(pattern: &str, path: &str) -> bool {
    // Algoritmo guloso simples com backtracking por recursão limitada.
    fn matches(p: &[u8], t: &[u8]) -> bool {
        if p.is_empty() {
            return true;
        }
        if p[0] == b'*' {
            for i in 0..=t.len() {
                if matches(&p[1..], &t[i..]) {
                    return true;
                }
            }
            return false;
        }
        if p[0] == b'$' {
            // `$` só pode estar no final (garantido pelo parser de padrão).
            return p.len() == 1 && t.is_empty();
        }
        if t.is_empty() {
            return false;
        }
        if p[0] == b'?' {
            // Compatibilidade com padrões literais de `?` não é exigida;
            // tratamos como curinga de um caractere.
            return matches(&p[1..], &t[1..]);
        }
        if p[0] != t[0] {
            return false;
        }
        matches(&p[1..], &t[1..])
    }

    // Limita o tamanho do caminho avaliado para evitar backtracking extremo.
    let path = if path.len() > 1024 {
        &path[..1024]
    } else {
        path
    };
    matches(pattern.as_bytes(), path.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    const UA: &str = "WebSpeed-Auditor/0.1.0";

    #[test]
    fn empty_robots_allows_everything() {
        let r = parse("", UA);
        assert!(r.is_allowed("/"));
        assert!(r.is_allowed("/any"));
    }

    #[test]
    fn disallow_root_blocks_all() {
        let r = parse("User-agent: *\nDisallow: /", UA);
        assert!(!r.is_allowed("/"));
        assert!(!r.is_allowed("/page"));
    }

    #[test]
    fn specific_group_overrides_star() {
        let txt = "User-agent: *\nDisallow: /\n\nUser-agent: webspeed-auditor\nDisallow:";
        let r = parse(txt, UA);
        assert!(r.is_allowed("/"));
    }

    #[test]
    fn path_specific_rules() {
        let txt = "User-agent: *\nDisallow: /private/\nAllow: /private/public.html";
        let r = parse(txt, UA);
        assert!(!r.is_allowed("/private/x"));
        assert!(r.is_allowed("/private/public.html"));
        assert!(r.is_allowed("/ok"));
    }

    #[test]
    fn wildcard_and_anchor() {
        let txt = "User-agent: *\nDisallow: /*.pdf$\nDisallow: /tmp/*";
        let r = parse(txt, UA);
        assert!(!r.is_allowed("/a/b.pdf"));
        assert!(r.is_allowed("/a/b.pdf.html"));
        assert!(!r.is_allowed("/tmp/"));
        assert!(r.is_allowed("/tmpx"));
    }

    #[test]
    fn comments_and_blank_lines_are_ignored() {
        let txt = "# comment\n\nUser-agent: *\n# another\nDisallow: /admin  # inline\n";
        let r = parse(txt, UA);
        assert!(!r.is_allowed("/admin"));
        assert!(r.is_allowed("/"));
    }

    #[test]
    fn crawl_delay_is_capped() {
        let r = parse("User-agent: *\nCrawl-delay: 99999", UA);
        assert_eq!(r.crawl_delay_secs, Some(30));
    }

    #[test]
    fn malformed_input_does_not_panic() {
        for txt in [
            "",
            ":::",
            "User-agent",
            "Disallow",
            "User-agent: *",
            "\u{feff}User-agent: *",
            &"x".repeat(10_000),
        ] {
            let r = parse(txt, UA);
            let _ = r.is_allowed("/test");
        }
    }

    #[test]
    fn long_paths_do_not_hang() {
        let r = parse("User-agent: *\nDisallow: /*a", UA);
        let path = format!("/{}", "b".repeat(5000));
        let _ = r.is_allowed(&path);
    }
}
