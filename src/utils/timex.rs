//! Formatação de tempo sem dependências externas.
//! Apenas marca temporal da execução — nenhum dado local é incluído.

use std::time::{SystemTime, UNIX_EPOCH};

/// Segundos desde o epoch (UTC).
pub fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Converte segundos desde epoch para ISO-8601 UTC (`YYYY-MM-DDTHH:MM:SSZ`).
pub fn unix_to_iso8601(secs: u64) -> String {
    let days = (secs / 86_400) as i64;
    let rem = secs % 86_400;
    let (h, mi, s) = (rem / 3600, (rem % 3600) / 60, rem % 60);
    let (y, m, d) = civil_from_days(days);
    format!("{y:04}-{m:02}-{d:02}T{h:02}:{mi:02}:{s:02}Z")
}

/// Algoritmo civil-from-days (H. Hinnant) — válido para datas pós-1970 aqui.
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

/// Formata milissegundos em texto legível.
pub fn fmt_ms(ms: u64) -> String {
    if ms < 1000 {
        format!("{ms} ms")
    } else if ms < 60_000 {
        format!("{:.2} s", ms as f64 / 1000.0)
    } else {
        format!("{} min {} s", ms / 60_000, (ms % 60_000) / 1000)
    }
}

/// Formata bytes em unidades legíveis.
pub fn fmt_bytes(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    let mut v = bytes as f64;
    let mut i = 0;
    while v >= 1024.0 && i < UNITS.len() - 1 {
        v /= 1024.0;
        i += 1;
    }
    if i == 0 {
        format!("{bytes} B")
    } else {
        format!("{v:.1} {}", UNITS[i])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn iso8601_epoch() {
        assert_eq!(unix_to_iso8601(0), "1970-01-01T00:00:00Z");
        assert_eq!(unix_to_iso8601(86_399), "1970-01-01T23:59:59Z");
        assert_eq!(unix_to_iso8601(86_400), "1970-01-02T00:00:00Z");
    }

    #[test]
    fn iso8601_known_dates() {
        // 2000-03-01 00:00:00 UTC = 951868800
        assert_eq!(unix_to_iso8601(951_868_800), "2000-03-01T00:00:00Z");
        // 2026-01-01 00:00:00 UTC = 1767225600
        assert_eq!(unix_to_iso8601(1_767_225_600), "2026-01-01T00:00:00Z");
    }

    #[test]
    fn fmt_values() {
        assert_eq!(fmt_ms(500), "500 ms");
        assert_eq!(fmt_ms(1500), "1.50 s");
        assert_eq!(fmt_bytes(0), "0 B");
        assert_eq!(fmt_bytes(1024), "1.0 KiB");
        assert_eq!(fmt_bytes(1536), "1.5 KiB");
    }
}
