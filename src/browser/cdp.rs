use std::process::{Command, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::net::TcpListener;
use tokio::process::Command as TokioCommand;
use tokio::sync::Mutex;

use crate::models::CoreWebVitals;
use futures_util::{SinkExt, StreamExt};
use serde_json::{Value, json};
use tokio_tungstenite::{connect_async, tungstenite::protocol::Message};

pub fn browser_available() -> bool {
    which::which("google-chrome").is_ok()
        || which::which("chromium").is_ok()
        || which::which("chromium-browser").is_ok()
        || std::path::Path::new("/Applications/Google Chrome.app/Contents/MacOS/Google Chrome")
            .exists()
        || std::path::Path::new("/Applications/Chromium.app/Contents/MacOS/Chromium").exists()
}

fn find_chrome_binary(custom: Option<&str>) -> Option<std::path::PathBuf> {
    if let Some(p) = custom {
        let pb = std::path::PathBuf::from(p);
        if pb.exists() {
            return Some(pb);
        }
    }
    for c in ["google-chrome", "chromium", "chromium-browser", "chrome"] {
        if let Ok(p) = which::which(c) {
            return Some(p);
        }
    }
    if cfg!(target_os = "macos") {
        for p in [
            "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
            "/Applications/Chromium.app/Contents/MacOS/Chromium",
        ] {
            if std::path::Path::new(p).exists() {
                return Some(std::path::PathBuf::from(p));
            }
        }
    }
    if cfg!(target_os = "windows") {
        for p in [
            r"C:\Program Files\Google\Chrome\Application\chrome.exe",
            r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe",
        ] {
            if std::path::Path::new(p).exists() {
                return Some(std::path::PathBuf::from(p));
            }
        }
    }
    None
}

async fn find_free_port() -> Result<u16, String> {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .map_err(|e| format!("bind: {e}"))?;
    let port = listener
        .local_addr()
        .map_err(|e| format!("local_addr: {e}"))?
        .port();
    drop(listener);
    Ok(port)
}

pub async fn run_browser_audit(
    url: &str,
    cfg: &crate::config::Config,
) -> Result<Option<CoreWebVitals>, String> {
    if !browser_available() {
        return Err("Chrome/Chromium não encontrado".into());
    }
    let binary = find_chrome_binary(cfg.browser_path.as_deref())
        .ok_or("Chrome/Chromium não encontrado no PATH")?;
    let port = find_free_port().await?;
    let user_data = tempfile::tempdir().map_err(|e| format!("temp dir: {e}"))?;
    let mut args = vec![
        "--headless=new".into(),
        "--disable-gpu".into(),
        "--no-first-run".into(),
        "--no-default-browser-check".into(),
        "--disable-extensions".into(),
        "--disable-background-networking".into(),
        "--disable-sync".into(),
        "--metrics-recording-only".into(),
        "--disable-component-update".into(),
        "--disable-default-apps".into(),
        "--disable-background-timer-throttling".into(),
        "--disable-renderer-backgrounding".into(),
        "--disable-features=TranslateUI,BlinkGenPropertyTrees".into(),
        format!("--remote-debugging-port={port}"),
        format!("--user-data-dir={}", user_data.path().display()),
        "--window-size=1366,768".into(),
    ];
    if cfg.profile == "mobile" || cfg.profile == "mobile-throttled" {
        args.push("--user-agent=Mozilla/5.0 (Linux; Android 10; Mobile) AppleWebKit/537.36".into());
    }
    let mut child = TokioCommand::new(&binary)
        .args(&args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("spawn chrome: {e}"))?;
    let stderr = child.stderr.take().ok_or("sem stderr")?;
    let mut reader = BufReader::new(stderr).lines();
    let ws_url = match tokio::time::timeout(Duration::from_secs(10), async {
        while let Ok(Some(line)) = reader.next_line().await {
            if line.contains("DevTools listening on ws://") {
                if let Some(start) = line.find("ws://") {
                    let url = &line[start..];
                    let end = url.find(' ').unwrap_or(url.len());
                    return Ok::<String, String>(url[..end].to_string());
                }
            }
        }
        Err("ws url não encontrado".into())
    })
    .await
    {
        Ok(r) => r?,
        Err(_) => return Err("timeout waiting for DevTools".into()),
    };
    let (ws_stream, _) = connect_async(&ws_url)
        .await
        .map_err(|e| format!("ws connect: {e}"))?;
    let (mut write, mut read) = ws_stream.split();
    let msg_id = Arc::new(Mutex::new(1u64));
    async fn send_cmd<W>(
        write: &mut W,
        msg_id: &Arc<Mutex<u64>>,
        method: &str,
        params: Value,
    ) -> Result<(), String>
    where
        W: futures_util::Sink<tokio_tungstenite::tungstenite::protocol::Message> + Unpin,
        W::Error: std::fmt::Display,
    {
        let id = {
            let mut g = msg_id.lock().await;
            *g += 1;
            *g
        };
        let msg = json!({"id": id, "method": method, "params": params});
        write
            .send(Message::Text(msg.to_string()))
            .await
            .map_err(|e| format!("send: {e}"))
    }
    send_cmd(
        &mut write,
        &msg_id,
        "Target.setDiscoverTargets",
        json!({"discover": true}),
    )
    .await?;
    let mut page_session_id: Option<String> = None;
    let start = Instant::now();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(60);
    let eval_script = r#"
        (() => {
            window.__wsa = { lcp: 0, cls: 0, clsEntries: [], fcp: 0, inp: null, longTasks: [], paint: [] };
            new PerformanceObserver(l => l.getEntries().forEach(e => {
                if (e.entryType === 'largest-contentful-paint') {
                    window.__wsa.lcp = Math.max(window.__wsa.lcp, e.startTime);
                }
            })).observe({type: 'largest-contentful-paint', buffered: true});
            new PerformanceObserver(l => l.getEntries().forEach(e => {
                e.hadRecentInput && (window.__wsa.inp = window.__wsa.inp ? Math.max(window.__wsa.inp, e.processingStart - e.startTime) : e.processingStart - e.startTime);
            })).observe({type: 'first-input', buffered: true});
            new PerformanceObserver(l => l.getEntries().forEach(e => {
                if (e.entryType === 'layout-shift' && !e.hadRecentInput) {
                    window.__wsa.cls += e.value;
                    window.__wsa.clsEntries.push({value: e.value, startTime: e.startTime});
                }
            })).observe({type: 'layout-shift', buffered: true});
            new PerformanceObserver(l => l.getEntries().forEach(e => {
                if (e.entryType === 'paint') window.__wsa.paint.push({name: e.name, startTime: e.startTime});
            })).observe({type: 'paint', buffered: true});
            new PerformanceObserver(l => l.getEntries().forEach(e => {
                if (e.entryType === 'longtask') window.__wsa.longTasks.push({startTime: e.startTime, duration: e.duration});
            })).observe({type: 'longtask', buffered: true});
        })()
    "#;
    while tokio::time::Instant::now() < deadline {
        tokio::select! {
            Some(Ok(msg)) = read.next() => {
                if let Message::Text(t) = msg {
                    if let Ok(v) = serde_json::from_str::<Value>(&t) {
                        if v.get("method").and_then(|m| m.as_str()) == Some("Target.targetCreated") {
                            if let Some(target) = v.get("params").and_then(|p| p.get("target")) {
                                if target.get("type").and_then(|t| t.as_str()) == Some("page") {
                                    let id = target.get("targetId").and_then(|i| i.as_str()).unwrap_or("");
                                    send_cmd(&mut write, &msg_id, "Target.attachToTarget", json!({"targetId": id, "flatten": true})).await?;
                                }
                            }
                        }
                        if let Some(sid) = v.get("sessionId").and_then(|i| i.as_str()) {
                            page_session_id = Some(sid.to_string());
                            send_cmd(&mut write, &msg_id, "Page.enable", json!({})).await?;
                            send_cmd(&mut write, &msg_id, "Network.enable", json!({})).await?;
                            send_cmd(&mut write, &msg_id, "Performance.enable", json!({})).await?;
                            send_cmd(&mut write, &msg_id, "Page.addScriptToEvaluateOnNewDocument", json!({"source": eval_script})).await?;
                            if cfg.profile == "mobile-throttled" {
                                send_cmd(&mut write, &msg_id, "Emulation.setCPUThrottlingRate", json!({"rate": 4})).await?;
                            }
                            if let Some(nc) = &cfg.network_condition {
                                let (lat, down, up) = match nc.as_str() {
                                    "slow-3g" => (300, 500.0*1024.0, 500.0*1024.0),
                                    "fast-3g" => (150, 1.5*1024.0*1024.0, 750.0*1024.0),
                                    "offline" => (0, 0.0, 0.0),
                                    _ => (0, 0.0, 0.0),
                                };
                                if lat > 0 {
                                    send_cmd(&mut write, &msg_id, "Network.emulateNetworkConditions", json!({"offline": false, "latency": lat, "downloadThroughput": down, "uploadThroughput": up})).await?;
                                }
                            }
                            send_cmd(&mut write, &msg_id, "Page.navigate", json!({"url": url})).await?;
                        }
                        if v.get("method").and_then(|m| m.as_str()) == Some("Page.loadEventFired") {
                            tokio::time::sleep(Duration::from_millis(500)).await;
                            break;
                        }
                    }
                }
            }
            _ = tokio::time::sleep(Duration::from_millis(100)) => {}
        }
    }
    let mut cwv = CoreWebVitals::default();
    if let Some(sid) = page_session_id {
        send_cmd(
            &mut write,
            &msg_id,
            "Runtime.evaluate",
            json!({"expression": "window.__wsa", "returnByValue": true, "sessionId": sid}),
        )
        .await?;
        while let Some(Ok(msg)) = read.next().await {
            if let Message::Text(t) = msg {
                if let Ok(v) = serde_json::from_str::<Value>(&t) {
                    if v.get("id").and_then(|i| i.as_u64()).is_some() {
                        if let Some(result) = v
                            .get("result")
                            .and_then(|r| r.get("result"))
                            .and_then(|r| r.get("value"))
                        {
                            if let Some(lcp) = result.get("lcp").and_then(|v| v.as_f64()) {
                                cwv.lcp_ms = Some(lcp.round() as u64);
                            }
                            if let Some(fcp) = result
                                .get("paint")
                                .and_then(|a| a.as_array())
                                .and_then(|arr| {
                                    arr.iter()
                                        .find(|e| {
                                            e.get("name").and_then(|n| n.as_str())
                                                == Some("first-contentful-paint")
                                        })
                                        .and_then(|e| e.get("startTime"))
                                        .and_then(|v| v.as_f64())
                                })
                            {
                                cwv.fcp_ms = Some(fcp.round() as u64);
                            }
                            if let Some(cls) = result.get("cls").and_then(|v| v.as_f64()) {
                                cwv.cls = Some(cls);
                            }
                            if let Some(inp) = result.get("inp").and_then(|v| v.as_f64()) {
                                cwv.inp_ms = Some(inp.round() as u64);
                            }
                            if let Some(tasks) = result.get("longTasks").and_then(|a| a.as_array())
                            {
                                cwv.long_tasks = tasks.len() as u32;
                                let mut total = 0u64;
                                for t in tasks {
                                    if let Some(d) = t.get("duration").and_then(|v| v.as_f64()) {
                                        total = total.saturating_add(d.max(0.0) as u64);
                                    }
                                }
                                cwv.tbt_ms = Some(total.saturating_sub(50 * cwv.long_tasks as u64));
                            }
                        }
                        break;
                    }
                }
            }
        }
        send_cmd(
            &mut write,
            &msg_id,
            "Performance.getMetrics",
            json!({"sessionId": sid}),
        )
        .await?;
        while let Some(Ok(msg)) = read.next().await {
            if let Message::Text(t) = msg {
                if let Ok(v) = serde_json::from_str::<Value>(&t) {
                    if v.get("id").and_then(|i| i.as_u64()).is_some() {
                        if let Some(metrics) = v
                            .get("result")
                            .and_then(|r| r.get("metrics"))
                            .and_then(|m| m.as_array())
                        {
                            for m in metrics {
                                if let Some(name) = m.get("name").and_then(|n| n.as_str()) {
                                    if let Some(val) = m.get("value").and_then(|v| v.as_f64()) {
                                        match name {
                                            "SpeedIndex" => {
                                                cwv.speed_index_ms = Some(val.round() as u64)
                                            }
                                            "DOMContentLoaded" => {
                                                cwv.dom_content_loaded_ms = Some(val.round() as u64)
                                            }
                                            "Load" => cwv.load_event_ms = Some(val.round() as u64),
                                            "ScriptDuration" => {
                                                cwv.js_execution_ms = Some(val.round() as u64)
                                            }
                                            _ => {}
                                        }
                                    }
                                }
                            }
                        }
                        break;
                    }
                }
            }
        }
        send_cmd(
            &mut write,
            &msg_id,
            "Target.closeTarget",
            json!({"targetId": sid}),
        )
        .await?;
    }
    let _ = child.kill().await;
    let _ = user_data.close();
    if cwv.lcp_ms.is_none() && cwv.fcp_ms.is_none() {
        Ok(None)
    } else {
        Ok(Some(cwv))
    }
}
