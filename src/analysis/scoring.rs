//! Sistema de scoring transparente e documentado.
//!
//! Fórmula (também documentada em `docs/SCORING.md` e no README):
//!
//! 1. Cada categoria começa em 100 pontos.
//! 2. Cada *finding* deduz um valor fixo pela severidade:
//!    - Critical: 30
//!    - High: 15
//!    - Medium: 8
//!    - Low: 3
//!    - Info: 0
//! 3. A pontuação da categoria é `100 - Σ(deduções)`, limitada a `[0, 100]`.
//!    Testes `NOT_TESTED`/`ERROR` não geram dedução — o que não foi medido
//!    não afeta a nota.
//! 4. Score global = média ponderada das categorias pelos pesos:
//!    Performance 20, Network 15, Caching 10, Compression 10, Images 15,
//!    JavaScript 10, CSS 5, HTML 10, Best Practices 5.
//!    Somente categorias com **ao menos uma verificação avaliada** (ou com
//!    dedução por finding) entram na média; os pesos são renormalizados.
//!    Assim, o que não foi medido nunca infla a nota. Se nenhuma categoria
//!    pôde ser avaliada, o score global é 0 (nada foi medido = nada conquistado).
//!
//! O cálculo usa apenas dados coletados. Nenhum modelo externo, IA ou
//! heurística proprietária está envolvida.

use crate::models::{
    Category, CategoryScore, Finding, OverallScore, Severity, TestItem, TestStatus,
};

/// Dedução por severidade (documentada acima).
pub fn deduction_for(severity: Severity) -> u32 {
    match severity {
        Severity::Critical => 30,
        Severity::High => 15,
        Severity::Medium => 8,
        Severity::Low => 3,
        Severity::Info => 0,
    }
}

/// Calcula o score global e por categoria.
pub fn compute(tests: &[TestItem], findings: &[Finding]) -> OverallScore {
    let mut categories = Vec::with_capacity(Category::ALL.len());

    for category in Category::ALL {
        let cat_tests: Vec<&TestItem> = tests.iter().filter(|t| t.category == category).collect();
        // Verificações efetivamente avaliadas (o que não foi medido não conta).
        let evaluated: Vec<&&TestItem> = cat_tests
            .iter()
            .filter(|t| {
                matches!(
                    t.status,
                    TestStatus::Pass | TestStatus::Warning | TestStatus::Fail
                )
            })
            .collect();
        let passed = evaluated
            .iter()
            .filter(|t| t.status == TestStatus::Pass)
            .count() as u32;

        let deduction: u32 = findings
            .iter()
            .filter(|f| f.category == category)
            .map(|f| deduction_for(f.severity))
            .sum();

        let score = 100u32.saturating_sub(deduction).min(100) as u8;

        categories.push(CategoryScore {
            category,
            score,
            checks: evaluated.len() as u32,
            passed,
            deduction,
        });
    }

    // Somente categorias avaliadas (checks > 0) ou com dedução entram na média.
    let measured: Vec<&CategoryScore> = categories
        .iter()
        .filter(|c| c.checks > 0 || c.deduction > 0)
        .collect();
    let total_weight: u32 = measured.iter().map(|c| c.category.weight() as u32).sum();
    let weighted: u32 = measured
        .iter()
        .map(|c| c.score as u32 * c.category.weight() as u32)
        .sum();
    let score = weighted
        .checked_div(total_weight)
        .map(|v| v.min(100) as u8)
        .unwrap_or(0);

    OverallScore { score, categories }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_item(category: Category, status: TestStatus) -> TestItem {
        TestItem::new(category, "t", status, "d")
    }

    fn finding(category: Category, severity: Severity) -> Finding {
        Finding {
            id: "f".into(),
            category,
            severity,
            title: "t".into(),
            problem: "p".into(),
            evidence: "e".into(),
            impact: "i".into(),
            recommendation: "r".into(),
        }
    }

    #[test]
    fn deduction_table_matches_documentation() {
        assert_eq!(deduction_for(Severity::Critical), 30);
        assert_eq!(deduction_for(Severity::High), 15);
        assert_eq!(deduction_for(Severity::Medium), 8);
        assert_eq!(deduction_for(Severity::Low), 3);
        assert_eq!(deduction_for(Severity::Info), 0);
    }

    #[test]
    fn no_checks_gives_zero_global_score() {
        // Nada medido = nada conquistado (nunca um 100 enganoso).
        let s = compute(&[], &[]);
        assert_eq!(s.score, 0);
        assert_eq!(s.categories.len(), 9);
        for c in &s.categories {
            assert_eq!(c.score, 100);
            assert_eq!(c.deduction, 0);
            assert_eq!(c.checks, 0);
        }
    }

    #[test]
    fn unmeasured_categories_do_not_inflate_global_score() {
        // Uma única categoria medida com achado Medium (92) — as outras
        // oito não foram medidas e não podem puxar a média para cima.
        let tests = vec![test_item(Category::Caching, TestStatus::Fail)];
        let findings = vec![finding(Category::Caching, Severity::Medium)];
        let s = compute(&tests, &findings);
        assert_eq!(s.score, 92);
    }

    #[test]
    fn findings_deduct_by_severity() {
        let tests = vec![test_item(Category::Caching, TestStatus::Fail)];
        let findings = vec![finding(Category::Caching, Severity::High)];
        let s = compute(&tests, &findings);
        let caching = s
            .categories
            .iter()
            .find(|c| c.category == Category::Caching)
            .expect("cat");
        assert_eq!(caching.score, 85);
        assert_eq!(caching.deduction, 15);
        // Só a categoria medida entra na média renormalizada.
        assert_eq!(s.score, 85);
    }

    #[test]
    fn score_never_negative() {
        let findings: Vec<Finding> = (0..10)
            .map(|_| finding(Category::Images, Severity::Critical))
            .collect();
        let s = compute(&[], &findings);
        let images = s
            .categories
            .iter()
            .find(|c| c.category == Category::Images)
            .expect("cat");
        assert_eq!(images.score, 0);
        assert!(s.score < 100);
        assert_eq!(s.score, 0); // única categoria com dedução
    }

    #[test]
    fn not_tested_and_error_do_not_affect_score() {
        let tests = vec![
            test_item(Category::Network, TestStatus::NotTested),
            test_item(Category::Network, TestStatus::Error),
        ];
        let s = compute(&tests, &[]);
        let net = s
            .categories
            .iter()
            .find(|c| c.category == Category::Network)
            .expect("cat");
        assert_eq!(net.score, 100);
        assert_eq!(net.checks, 0);
    }

    #[test]
    fn passed_checks_counted() {
        let tests = vec![
            test_item(Category::Html, TestStatus::Pass),
            test_item(Category::Html, TestStatus::Pass),
            test_item(Category::Html, TestStatus::Fail),
        ];
        let s = compute(&tests, &[]);
        let html = s
            .categories
            .iter()
            .find(|c| c.category == Category::Html)
            .expect("cat");
        assert_eq!(html.checks, 3);
        assert_eq!(html.passed, 2);
        // FAIL sem finding não deduz (findings são a fonte de dedução).
        assert_eq!(html.score, 100);
    }

    #[test]
    fn finding_without_tests_still_deducts() {
        let findings = vec![finding(Category::Css, Severity::Medium)];
        let s = compute(&[], &findings);
        let css = s
            .categories
            .iter()
            .find(|c| c.category == Category::Css)
            .expect("cat");
        assert_eq!(css.score, 92);
    }

    #[test]
    fn scores_are_byte_sized() {
        let findings: Vec<Finding> = (0..3)
            .map(|_| finding(Category::Performance, Severity::High))
            .collect();
        let s = compute(&[], &findings);
        assert!(s.score <= 100);
        let perf = s
            .categories
            .iter()
            .find(|c| c.category == Category::Performance)
            .expect("cat");
        assert_eq!(perf.score, 55); // 100 - 3*15
        assert_eq!(s.score, 55); // única categoria medida
    }
}
