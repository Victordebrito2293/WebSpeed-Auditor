//! Módulos de coleta (scanner). Cada scanner é independente: falha em um
//! não interrompe os demais.

pub mod cache;
pub mod compression;
pub mod crawling;
pub mod css;
pub mod dns;
pub mod fonts;
pub mod html;
pub mod http;
pub mod images;
pub mod javascript;
pub mod resources;
pub mod security_headers;
pub mod tls;
