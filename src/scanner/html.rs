//! Análise estática de HTML (sem executar JavaScript).
//!
//! O conteúdo remoto é tratado como não confiável: apenas parsing de bytes
//! em memória, com limites de tamanho aplicados pelo cliente HTTP.

use crate::models::{HtmlInfo, ResourceKind};
use scraper::{ElementRef, Html, Selector};
use url::Url;

/// Referência a um recurso citado no HTML, com atributos relevantes.
#[derive(Debug, Clone)]
pub struct ResourceRef {
    pub url: String,
    pub kind: ResourceKind,
    /// Possui atributos width e height (evita layout shift).
    pub has_dimensions: bool,
    /// loading="lazy".
    pub lazy: bool,
    /// Possui srcset (imagem responsiva).
    pub srcset: bool,
    /// Veio de <link rel=preload>.
    pub preloaded: bool,
    /// Bloqueia renderização (script sem defer/async, stylesheet).
    pub blocking: bool,
    /// Origem diferente do documento.
    pub external: bool,
}

/// Resultado da análise do HTML.
#[derive(Debug, Clone)]
pub struct HtmlAnalysis {
    pub info: HtmlInfo,
    pub resources: Vec<ResourceRef>,
    /// Links absolutos encontrados (para o crawler).
    pub links: Vec<String>,
}

fn sel(s: &str) -> Option<Selector> {
    Selector::parse(s).ok()
}

/// Retorna o tipo MIME JS assumido como JavaScript executável.
fn is_js_type(type_attr: Option<&str>) -> bool {
    match type_attr {
        None => true,
        Some(t) => {
            let t = t.trim().to_ascii_lowercase();
            t == "module"
                || t == "text/javascript"
                || t == "application/javascript"
                || t == "application/x-javascript"
                || t == "text/ecmascript"
                || t == "application/ecmascript"
        }
    }
}

fn attr(el: ElementRef<'_>, name: &str) -> Option<String> {
    el.value().attr(name).map(|s| s.to_string())
}

fn join(base: &Url, href: &str) -> Option<String> {
    let href = href.trim();
    if href.is_empty()
        || href.starts_with('#')
        || href.starts_with("data:")
        || href.starts_with("javascript:")
    {
        return None;
    }
    let u = base.join(href).ok()?;
    if u.scheme() != "http" && u.scheme() != "https" {
        return None;
    }
    Some(u.to_string())
}

/// Analisa o HTML já decodificado. Nunca panica com HTML malformado.
pub fn analyze(html_text: &str, base: &Url) -> HtmlAnalysis {
    let document = Html::parse_document(html_text);

    let mut info = HtmlInfo {
        bytes: html_text.len() as u64,
        decoded_bytes: html_text.len() as u64,
        ..HtmlInfo::default()
    };
    let mut resources: Vec<ResourceRef> = Vec::new();
    let mut links: Vec<String> = Vec::new();
    let mut resource_urls: Vec<String> = Vec::new();
    let mut origins: Vec<String> = Vec::new();

    // Contagem de elementos.
    if let Some(all) = sel("*") {
        info.elements = document.select(&all).count();
    }

    // <script>
    if let Some(scripts) = sel("script") {
        for el in document.select(&scripts) {
            let type_attr = attr(el, "type");
            if !is_js_type(type_attr.as_deref()) {
                continue; // JSON-LD e afins não são executados como JS
            }
            match attr(el, "src") {
                Some(src) => {
                    info.script_tags += 1;
                    let is_async = el.value().attr("async").is_some();
                    let is_defer = el.value().attr("defer").is_some();
                    let is_module = type_attr.as_deref() == Some("module");
                    if is_async {
                        info.scripts_async += 1;
                    } else if is_defer || is_module {
                        info.scripts_defer += 1;
                    } else {
                        info.scripts_blocking += 1;
                    }
                    if is_module {
                        info.scripts_module += 1;
                    }
                    if let Some(abs) = join(base, &src) {
                        resources.push(ResourceRef {
                            url: abs.clone(),
                            kind: ResourceKind::JavaScript,
                            external: false,
                            has_dimensions: false,
                            lazy: false,
                            srcset: false,
                            preloaded: false,
                            blocking: !is_async && !is_defer && !is_module,
                        });
                        resource_urls.push(abs);
                    }
                }
                None => {
                    // Script inline (não executamos; apenas medimos).
                    info.scripts_inline += 1;
                    info.inline_script_bytes += el.inner_html().len();
                }
            }
        }
    }

    // <link rel=stylesheet> e preloads.
    if let Some(links_sel) = sel("link[href]") {
        for el in document.select(&links_sel) {
            let rel = attr(el, "rel").unwrap_or_default().to_ascii_lowercase();
            let href = attr(el, "href").unwrap_or_default();
            let as_attr = attr(el, "as").unwrap_or_default().to_ascii_lowercase();
            if rel.split_whitespace().any(|r| r == "stylesheet") {
                info.stylesheet_links += 1;
                if let Some(abs) = join(base, &href) {
                    resources.push(ResourceRef {
                        url: abs.clone(),
                        kind: ResourceKind::Css,
                        external: false,
                        has_dimensions: false,
                        lazy: false,
                        srcset: false,
                        preloaded: false,
                        blocking: true,
                    });
                    resource_urls.push(abs);
                }
            } else if rel.split_whitespace().any(|r| r == "preload") {
                info.preloads += 1;
                let kind = match as_attr.as_str() {
                    "style" => ResourceKind::Css,
                    "script" => ResourceKind::JavaScript,
                    "font" => ResourceKind::Font,
                    "image" => ResourceKind::Image,
                    _ => ResourceKind::Other,
                };
                if let Some(abs) = join(base, &href) {
                    resources.push(ResourceRef {
                        url: abs.clone(),
                        kind,
                        external: false,
                        has_dimensions: false,
                        lazy: false,
                        srcset: false,
                        preloaded: true,
                        blocking: false,
                    });
                    resource_urls.push(abs);
                }
            } else if rel.split_whitespace().any(|r| r == "preconnect") {
                info.preconnects += 1;
                if let Some(origin) = origin_of(&href, base) {
                    origins.push(origin);
                }
            } else if rel.split_whitespace().any(|r| r == "dns-prefetch") {
                info.dns_prefetch += 1;
                if let Some(origin) = origin_of(&href, base) {
                    origins.push(origin);
                }
            }
        }
    }

    // <style> inline.
    if let Some(styles) = sel("style") {
        for el in document.select(&styles) {
            info.inline_style_blocks += 1;
            info.inline_style_bytes += el.inner_html().len();
        }
    }

    // <img>
    if let Some(imgs) = sel("img") {
        for el in document.select(&imgs) {
            info.images += 1;
            let has_dim = el.value().attr("width").is_some() && el.value().attr("height").is_some();
            if !has_dim {
                info.images_without_dimensions += 1;
            }
            let lazy = el
                .value()
                .attr("loading")
                .map(|l| l.eq_ignore_ascii_case("lazy"))
                .unwrap_or(false);
            if !lazy {
                info.images_without_lazy += 1;
            }
            let srcset = el.value().attr("srcset").is_some();
            if srcset {
                info.images_srcset += 1;
            }
            if let Some(src) = attr(el, "src") {
                if let Some(abs) = join(base, &src) {
                    resources.push(ResourceRef {
                        url: abs.clone(),
                        kind: ResourceKind::Image,
                        external: false,
                        has_dimensions: has_dim,
                        lazy,
                        srcset,
                        preloaded: false,
                        blocking: false,
                    });
                    resource_urls.push(abs);
                }
            } else if let Some(ss) = attr(el, "srcset")
                && let Some(first) = ss.split(',').next()
            {
                let url_part = first.split_whitespace().next().unwrap_or("");
                if let Some(abs) = join(base, url_part) {
                    resources.push(ResourceRef {
                        url: abs.clone(),
                        kind: ResourceKind::Image,
                        external: false,
                        has_dimensions: has_dim,
                        lazy,
                        srcset,
                        preloaded: false,
                        blocking: false,
                    });
                    resource_urls.push(abs);
                }
            }
        }
    }

    // <picture><source srcset>
    if let Some(sources) = sel("source[srcset]") {
        for el in document.select(&sources) {
            if let Some(ss) = attr(el, "srcset")
                && let Some(first) = ss.split(',').next()
            {
                let url_part = first.split_whitespace().next().unwrap_or("");
                if let Some(abs) = join(base, url_part) {
                    resources.push(ResourceRef {
                        url: abs.clone(),
                        kind: ResourceKind::Image,
                        external: false,
                        has_dimensions: false,
                        lazy: false,
                        srcset: true,
                        preloaded: false,
                        blocking: false,
                    });
                    resource_urls.push(abs);
                    info.images_srcset += 1;
                }
            }
        }
    }

    // <iframe>
    if let Some(iframes) = sel("iframe") {
        info.iframes = document.select(&iframes).count();
    }

    // <a href>
    if let Some(anchors) = sel("a[href]") {
        for el in document.select(&anchors) {
            if let Some(href) = attr(el, "href")
                && let Some(abs) = join(base, &href)
            {
                info.total_links += 1;
                if let Ok(u) = Url::parse(&abs) {
                    if u.host_str() == base.host_str() && u.scheme() == base.scheme() {
                        info.same_origin_links += 1;
                    } else {
                        info.external_links += 1;
                    }
                }
                links.push(abs);
            }
        }
    }

    // Origens externas de recursos.
    let mut seen_origins: Vec<String> = Vec::new();
    for r in &resources {
        if let Ok(u) = Url::parse(&r.url)
            && (u.host_str() != base.host_str() || u.scheme() != base.scheme())
        {
            let origin = format!("{}://{}", u.scheme(), u.host_str().unwrap_or(""));
            if !seen_origins.contains(&origin) {
                seen_origins.push(origin.clone());
            }
            if !origins.contains(&origin) {
                origins.push(origin);
            }
        }
    }
    info.external_origins = origins.clone();

    // Recursos duplicados.
    let mut dupes: Vec<String> = Vec::new();
    let mut checked: Vec<String> = Vec::new();
    for u in &resource_urls {
        if checked.contains(u) {
            if !dupes.contains(u) {
                dupes.push(u.clone());
            }
        } else {
            checked.push(u.clone());
        }
    }
    info.duplicate_resources = dupes;
    info.resources = {
        let mut all = resource_urls.clone();
        all.sort();
        all.dedup();
        all
    };

    // Marca recursos de outras origens.
    for r in &mut resources {
        if let Ok(u) = Url::parse(&r.url) {
            r.external = u.host_str() != base.host_str() || u.scheme() != base.scheme();
        }
    }

    HtmlAnalysis {
        info,
        resources,
        links,
    }
}

fn origin_of(href: &str, base: &Url) -> Option<String> {
    let u = base.join(href).ok()?;
    Some(format!("{}://{}", u.scheme(), u.host_str()?))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(html: &str) -> HtmlAnalysis {
        analyze(
            html,
            &Url::parse("https://example.com/index.html").expect("url"),
        )
    }

    #[test]
    fn counts_scripts_and_blocking() {
        let html = r#"
        <html><head>
        <script src="/a.js"></script>
        <script src="/b.js" defer></script>
        <script src="/c.js" async></script>
        <script type="module" src="/d.js"></script>
        <script type="application/ld+json">{"@type":"WebSite"}</script>
        <script>var x = 1;</script>
        </head><body></body></html>"#;
        let a = run(html);
        assert_eq!(a.info.script_tags, 4);
        assert_eq!(a.info.scripts_blocking, 1);
        assert_eq!(a.info.scripts_defer, 2); // defer + module
        assert_eq!(a.info.scripts_async, 1);
        assert_eq!(a.info.scripts_module, 1);
        assert_eq!(a.info.scripts_inline, 1);
        assert!(a.info.inline_script_bytes > 0);
    }

    #[test]
    fn counts_stylesheets_and_inline_css() {
        let html = r#"
        <link rel="stylesheet" href="/main.css">
        <link rel="preload" href="/print.css" as="style">
        <style>body{margin:0}</style>"#;
        let a = run(html);
        assert_eq!(a.info.stylesheet_links, 1);
        assert_eq!(a.info.preloads, 1);
        assert_eq!(a.info.inline_style_blocks, 1);
        assert!(a.info.inline_style_bytes >= 10);
    }

    #[test]
    fn image_attributes() {
        let html = r#"
        <img src="/a.png">
        <img src="/b.png" width="100" height="50" loading="lazy">
        <img srcset="/c-1x.png 1x, /c-2x.png 2x" src="/c.png" width="1" height="1">
        "#;
        let a = run(html);
        assert_eq!(a.info.images, 3);
        assert_eq!(a.info.images_without_dimensions, 1);
        assert_eq!(a.info.images_without_lazy, 2);
        assert_eq!(a.info.images_srcset, 1);
    }

    #[test]
    fn counts_iframes_and_links() {
        let html = r##"
        <iframe src="https://other.com/frame"></iframe>
        <a href="/page1">1</a>
        <a href="https://external.com/x">2</a>
        <a href="#anchor">3</a>
        <a href="mailto:x@y.z">4</a>
        "##;
        let a = run(html);
        assert_eq!(a.info.iframes, 1);
        assert_eq!(a.info.total_links, 2);
        assert_eq!(a.info.same_origin_links, 1);
        assert_eq!(a.info.external_links, 1);
    }

    #[test]
    fn preconnect_and_dns_prefetch() {
        let html = r#"
        <link rel="preconnect" href="https://cdn.example.com">
        <link rel="dns-prefetch" href="https://fonts.example.com">
        "#;
        let a = run(html);
        assert_eq!(a.info.preconnects, 1);
        assert_eq!(a.info.dns_prefetch, 1);
        assert!(
            a.info
                .external_origins
                .iter()
                .any(|o| o.contains("cdn.example.com"))
        );
    }

    #[test]
    fn detects_duplicate_resources() {
        let html = r#"
        <link rel="stylesheet" href="/x.css">
        <script src="/x.css"></script>
        "#;
        let a = run(html);
        assert_eq!(a.info.duplicate_resources.len(), 1);
        assert!(a.info.duplicate_resources[0].ends_with("/x.css"));
    }

    #[test]
    fn malformed_html_does_not_panic() {
        for html in [
            "",
            "<html><body><div><span></body>",
            "<<<>>> && &",
            "&amp;&lt;",
            "<img src=>",
            "<script src>",
            "\u{feff}<html>\u{0}\u{1}",
            &"<div>".repeat(5000),
            "<a href='%%%%'>",
        ] {
            let a = run(html);
            let _ = a.info.elements;
        }
    }

    #[test]
    fn huge_html_is_parsed_with_limit_semantics() {
        let big = format!("<html>{}</html>", "<p>texto</p>".repeat(20_000));
        let a = run(&big);
        assert!(a.info.bytes > 100_000);
        assert!(a.info.elements >= 20_000);
    }

    #[test]
    fn unicode_content_is_handled() {
        let html = "<html><body><p>ação — coração 🚀</p><a href='/páginas'>x</a></body></html>";
        let a = run(html);
        assert_eq!(a.info.total_links, 1);
        assert!(a.links[0].contains("p"));
    }

    #[test]
    fn resources_have_absolute_urls() {
        let html = r#"<img src="img/a.png"><link rel="stylesheet" href="//cdn.example.com/s.css">"#;
        let a = run(html);
        assert!(
            a.resources
                .iter()
                .any(|r| r.url == "https://example.com/img/a.png")
        );
        assert!(
            a.resources
                .iter()
                .any(|r| r.url == "https://cdn.example.com/s.css")
        );
    }

    #[test]
    fn stylesheet_detected_as_blocking_resource() {
        let a = run(r#"<link rel="stylesheet" href="/s.css">"#);
        let css = a
            .resources
            .iter()
            .find(|r| r.kind == ResourceKind::Css)
            .expect("css");
        assert!(css.blocking);
        assert!(css.url.ends_with("/s.css"));
    }
}
