//! Logs de execução — somente no terminal (stderr), nunca em arquivo.

use crate::config::LogLevel;
use std::io::{self, Write};
use std::sync::atomic::{AtomicU8, Ordering};

/// Nível global de log da execução atual.
static LEVEL: AtomicU8 = new_level(LogLevel::Normal);

const fn new_level(l: LogLevel) -> AtomicU8 {
    AtomicU8::new(level_to_u8(l))
}

const fn level_to_u8(l: LogLevel) -> u8 {
    match l {
        LogLevel::Quiet => 0,
        LogLevel::Normal => 1,
        LogLevel::Verbose => 2,
    }
}

/// Define o nível de log no início da execução.
pub fn set_level(level: LogLevel) {
    LEVEL.store(level_to_u8(level), Ordering::Relaxed);
}

fn current() -> u8 {
    LEVEL.load(Ordering::Relaxed)
}

/// Progresso normal (visível em modo normal e verbose).
pub fn progress(msg: &str) {
    if current() >= 1 {
        eprintln!("[...] {msg}");
    }
}

/// Detalhe verboso (somente `--verbose`).
pub fn verbose(msg: &str) {
    if current() >= 2 {
        eprintln!("[debug] {msg}");
    }
}

/// Aviso importante (visível em modo normal e verbose).
pub fn warn(msg: &str) {
    if current() >= 1 {
        eprintln!("[aviso] {msg}");
    }
}

/// Erro — sempre exibido, mesmo em modo quiet, pois indica que a análise
/// solicitada não pôde ser concluída.
pub fn error(msg: &str) {
    eprintln!("[erro] {msg}");
}

/// Escreve progresso com timestamps de uma etapa (verbose).
pub fn step(name: &str, status: &str) {
    if current() >= 1 {
        let _ = io::stderr().flush();
        eprintln!("  {name}: {status}");
    }
}
