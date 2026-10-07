#[cfg(feature = "browser")]
mod cdp;

#[cfg(feature = "browser")]
pub use cdp::run_browser_audit;

#[cfg(not(feature = "browser"))]
pub async fn run_browser_audit(
    _url: &str,
    _cfg: &crate::config::Config,
) -> Result<Option<crate::models::CoreWebVitals>, String> {
    Ok(None)
}

#[cfg(not(feature = "browser"))]
pub fn browser_available() -> bool {
    false
}

#[cfg(feature = "browser")]
pub fn browser_available() -> bool {
    cdp::browser_available()
}
