//! Servidor HTTP mínimo usado **apenas em testes**.
//!
//! O processo do servidor existe somente enquanto um teste o mantém vivo:
//! ele é encerrado no `Drop` da instância e nunca é iniciado pela aplicação
//! principal. Não há rede externa: bind exclusivamente em `127.0.0.1` porta
//! efêmera.
//!
//! Este módulo é `pub` apenas para permitir o compartilhamento entre testes
//! unitários e de integração; a aplicação nunca o referencia.

use std::io::{BufRead, BufReader, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::{self, JoinHandle};
use std::time::Duration;

/// Servidor local de teste.
pub struct TestServer {
    /// Ex.: `http://127.0.0.1:54321`
    pub base: String,
    addr: SocketAddr,
    shutdown: Arc<AtomicBool>,
    handle: Option<JoinHandle<()>>,
}

impl TestServer {
    /// Encerra o servidor (também ocorre no Drop).
    pub fn shutdown(&mut self) {
        self.shutdown.store(true, Ordering::SeqCst);
        // Acorda o accept() bloqueado.
        let _ = TcpStream::connect(self.addr);
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
    }
}

impl Drop for TestServer {
    fn drop(&mut self) {
        self.shutdown();
    }
}

/// Inicia um servidor de teste em 127.0.0.1:0.
pub fn spawn_test_server() -> TestServer {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind teste");
    let addr = listener.local_addr().expect("addr");
    let shutdown = Arc::new(AtomicBool::new(false));
    let flag = shutdown.clone();

    let handle = thread::Builder::new()
        .name("test-server".into())
        .spawn(move || {
            for stream in listener.incoming() {
                if flag.load(Ordering::SeqCst) {
                    break;
                }
                match stream {
                    Ok(s) => {
                        let _ = s.set_nodelay(true);
                        thread::spawn(move || {
                            let _ = handle_connection(s);
                        });
                    }
                    Err(_) => break,
                }
            }
        })
        .expect("spawn teste");

    TestServer {
        base: format!("http://{addr}"),
        addr,
        shutdown,
        handle: Some(handle),
    }
}

fn handle_connection(mut stream: TcpStream) -> std::io::Result<()> {
    let mut reader = BufReader::new(stream.try_clone()?);
    let mut request_line = String::new();
    reader.read_line(&mut request_line)?;
    // Consome headers (não precisamos deles para os testes).
    loop {
        let mut line = String::new();
        if reader.read_line(&mut line)? == 0 {
            break;
        }
        if line == "\r\n" || line == "\n" {
            break;
        }
    }
    let path = request_line
        .split_whitespace()
        .nth(1)
        .unwrap_or("/")
        .split('?')
        .next()
        .unwrap_or("/")
        .to_string();

    let (status, reason, content_type, extra, body) = route(&path);
    let header = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n{extra}\r\n",
        body.len()
    );
    stream.write_all(header.as_bytes())?;
    stream.write_all(&body)?;
    stream.flush()?;
    Ok(())
}

type RouteResponse = (&'static str, &'static str, &'static str, String, Vec<u8>);

fn route(path: &str) -> RouteResponse {
    match path {
        "/" => (
            "200",
            "OK",
            "text/html; charset=utf-8",
            "Cache-Control: no-cache\r\n".into(),
            home_page().as_bytes().to_vec(),
        ),
        "/style.css" => (
            "200",
            "OK",
            "text/css",
            "Cache-Control: public, max-age=31536000, immutable\r\nETag: \"css1\"\r\n".into(),
            b"body{margin:0;color:#222}.hero{padding:2rem}\n".to_vec(),
        ),
        "/app.js" => (
            "200",
            "OK",
            "application/javascript",
            "Cache-Control: public, max-age=31536000, immutable\r\n".into(),
            b"console.log('app');\n".to_vec(),
        ),
        "/logo.png" => (
            "200",
            "OK",
            "image/png",
            "Cache-Control: public, max-age=86400\r\n".into(),
            png_magic_and_padding(),
        ),
        "/photo.jpg" => (
            "200",
            "OK",
            "image/jpeg",
            String::new(),
            vec![0xFF, 0xD8, 0xFF, 0xE0, 0, 16, 74, 70, 73, 70, 0],
        ),
        "/font.woff2" => (
            "200",
            "OK",
            "font/woff2",
            "Cache-Control: public, max-age=31536000\r\n".into(),
            b"wOF2fontdata-not-real".to_vec(),
        ),
        "/page2" => (
            "200",
            "OK",
            "text/html; charset=utf-8",
            String::new(),
            b"<html><body><a href=\"/page3\">p3</a><a href=\"/\">home</a></body></html>".to_vec(),
        ),
        "/page3" => (
            "200",
            "OK",
            "text/html; charset=utf-8",
            String::new(),
            b"<html><body><p>pagina 3</p></body></html>".to_vec(),
        ),
        "/redirect" => (
            "301",
            "Moved Permanently",
            "text/html",
            "Location: /page2\r\n".into(),
            b"moved".to_vec(),
        ),
        "/redirect-chain" => (
            "302",
            "Found",
            "text/html",
            "Location: /redirect\r\n".into(),
            b"found".to_vec(),
        ),
        "/loop" => (
            "302",
            "Found",
            "text/html",
            "Location: /loop\r\n".into(),
            b"loop".to_vec(),
        ),
        "/loop2" => (
            "302",
            "Found",
            "text/html",
            "Location: /loop3\r\n".into(),
            b"loop2".to_vec(),
        ),
        "/loop3" => (
            "302",
            "Found",
            "text/html",
            "Location: /loop2\r\n".into(),
            b"loop3".to_vec(),
        ),
        "/slow" => {
            thread::sleep(Duration::from_secs(10));
            (
                "200",
                "OK",
                "text/html",
                String::new(),
                b"<html>slow</html>".to_vec(),
            )
        }
        "/huge" => {
            // ~12 MiB — excede o limite padrão de 10 MiB.
            let mut body = Vec::with_capacity(12 * 1024 * 1024);
            body.resize(12 * 1024 * 1024, b'a');
            ("200", "OK", "text/html", String::new(), body)
        }
        "/big.html" => {
            let mut body = String::from("<html><body>");
            for i in 0..30_000 {
                body.push_str(&format!("<p id=\"p{i}\">paragrafo de teste</p>"));
            }
            body.push_str("</body></html>");
            (
                "200",
                "OK",
                "text/html; charset=utf-8",
                String::new(),
                body.into_bytes(),
            )
        }
        "/gzip.html" => {
            use std::io::Write as _;
            let mut enc = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
            let _ = enc.write_all(b"<html><body>conteudo comprimido</body></html>");
            let gz = enc.finish().expect("gzip");
            (
                "200",
                "OK",
                "text/html; charset=utf-8",
                format!("Content-Encoding: gzip\r\nX-Test-Size: {}\r\n", gz.len()),
                gz,
            )
        }
        "/badcontent" => (
            "200",
            "OK",
            "text/html; charset=utf-8",
            String::new(),
            png_magic_and_padding(),
        ),
        "/robots.txt" => (
            "200",
            "OK",
            "text/plain",
            String::new(),
            b"User-agent: *\nDisallow: /private/\n".to_vec(),
        ),
        "/private/secret" => (
            "200",
            "OK",
            "text/html",
            String::new(),
            b"<html>private</html>".to_vec(),
        ),
        "/no-cache.css" => (
            "200",
            "OK",
            "text/css",
            String::new(),
            b".a{color:red}".to_vec(),
        ),
        "/html-immutable" => (
            "200",
            "OK",
            "text/html",
            "Cache-Control: public, max-age=31536000, immutable\r\n".into(),
            b"<html><body>cacheado</body></html>".to_vec(),
        ),
        "/status-500" => (
            "500",
            "Internal Server Error",
            "text/plain",
            String::new(),
            b"erro".to_vec(),
        ),
        _ => (
            "404",
            "Not Found",
            "text/html; charset=utf-8",
            String::new(),
            b"<html><body>404</body></html>".to_vec(),
        ),
    }
}

fn png_magic_and_padding() -> Vec<u8> {
    let mut v = vec![0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A];
    v.extend_from_slice(&[0; 64]);
    v
}

fn home_page() -> &'static str {
    r#"<!DOCTYPE html>
<html lang="pt-BR">
<head>
<meta charset="utf-8">
<title> Pagina de teste </title>
<link rel="stylesheet" href="/style.css">
<link rel="preload" href="/font.woff2" as="font" type="font/woff2" crossorigin>
<link rel="preconnect" href="https://cdn.example.com">
<script src="/app.js"></script>
<script src="/page2" defer></script>
<style>.inline{display:block}</style>
</head>
<body>
<h1>Teste</h1>
<img src="/logo.png">
<img src="/photo.jpg" width="600" height="400" loading="lazy" srcset="/photo.jpg 1x">
<iframe src="/page3"></iframe>
<a href="/page2">pagina 2</a>
<a href="/private/secret">privada</a>
<a href="https://external.example.org/">externa</a>
</body>
</html>"#
}
