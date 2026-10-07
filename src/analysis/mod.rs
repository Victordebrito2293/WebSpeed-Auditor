//! Análise: agregação de seções, scoring documentado e recomendações.

pub mod recommendations;
pub mod scoring;

use crate::models::{Finding, Limitation, TestItem};

/// Agregado de testes/descobertas/limitações produzido por cada verificação.
#[derive(Debug, Default)]
pub struct Section {
    pub tests: Vec<TestItem>,
    pub findings: Vec<Finding>,
    pub limitations: Vec<Limitation>,
}

impl Section {
    pub fn merge(&mut self, other: Section) {
        self.tests.extend(other.tests);
        self.findings.extend(other.findings);
        self.limitations.extend(other.limitations);
    }

    pub fn test(mut self, item: TestItem) -> Self {
        self.tests.push(item);
        self
    }

    pub fn finding(mut self, f: Finding) -> Self {
        self.findings.push(f);
        self
    }

    pub fn limitation(mut self, area: &str, reason: &str) -> Self {
        self.limitations.push(Limitation {
            area: area.to_string(),
            reason: reason.to_string(),
        });
        self
    }
}

/// Falha de uma etapa vira um item NOT_TESTED/ERROR com motivo explícito.
pub fn failed_step(category: crate::models::Category, name: &str, error: &str) -> Section {
    Section {
        tests: vec![TestItem::new(
            category,
            name,
            crate::models::TestStatus::Error,
            format!("falhou: {error}"),
        )],
        findings: vec![],
        limitations: vec![Limitation {
            area: name.to_string(),
            reason: format!("etapa não concluída: {error}"),
        }],
    }
}
