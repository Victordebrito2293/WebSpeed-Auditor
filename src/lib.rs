//! # WebSpeed Auditor
//!
//! Biblioteca de auditoria local de performance de websites.
//!
//! Princípios:
//! - **Privacidade**: nenhum dado é persistido; tudo existe em memória durante
//!   a execução e é descartado ao final.
//! - **Segurança**: toda URL é validada contra SSRF antes de cada requisição;
//!   conteúdo remoto é tratado como não confiável e nunca é executado.
//! - **Honestidade**: métricas não disponíveis são reportadas como tal; nada é
//!   inventado.

pub mod analysis;
pub mod audit;
pub mod browser;
pub mod cli;
pub mod config;
pub mod models;
pub mod report;
pub mod scanner;
pub mod utils;

/// Servidor HTTP de teste — usado apenas por testes unitários e de
/// integração; nunca é iniciado pela aplicação principal.
#[doc(hidden)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
pub mod testserver;
