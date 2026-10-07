# WebSpeed Auditor

Auditoría **local**, **offline** y **orientada a la privacidad** del rendimiento y las buenas prácticas de sitios web. Una herramienta en Rust 100 % open source, sin cuentas, sin claves de API, sin telemetría — nada se envía a terceros salvo las peticiones HTTP hechas **al sitio que está auditando**.

```
webspeed-auditor https://example.com
```

## Por qué

Las herramientas de auditoría de rendimiento suelen enviar su URL a un servidor en la nube, exigen registro o ejecutan código de terceros en el navegador. WebSpeed Auditor se ejecuta **en su máquina**, lee solo lo que el propio sitio publica y genera un informe que responde a cinco preguntas:

1. **¿Qué se probó y cuál fue el resultado?**
2. **¿Qué problemas existen** — con gravedad, evidencia, impacto y cómo corregirlos?
3. **¿Qué ya está optimizado?**
4. **¿Qué no se pudo probar en este entorno** (y por qué)?
5. **¿Cuál es la puntuación general?**

## Instalación

### Compilar desde el código (recomendado)

Requisitos: [Rust 1.88+](https://rustup.rs) (edición 2024).

```bash
git clone https://github.com/webspeed-auditor/webspeed-auditor.git
cd webspeed-auditor
cargo build --release
./target/release/webspeed-auditor --help
```

### Binarios precompilados

El workflow de release genera binarios firmados como artefactos para Linux (x86_64/aarch64), macOS (x86_64/aarch64) y Windows (x86_64) en la página de releases de GitHub.

## Uso

```bash
# Informe en terminal (por defecto)
webspeed-auditor https://example.com

# JSON para CI/CD
webspeed-auditor https://example.com --format json --output reporte.json

# HTML autocontenido (sin scripts, sin recursos externos)
webspeed-auditor https://example.com --format html --output reporte.html

# Solo la página inicial, con más detalle
webspeed-auditor https://example.com --no-crawl --verbose

# Modo silencioso (solo el informe final)
webspeed-auditor https://example.com --quiet --format json
```

Sin URL, la herramienta muestra un banner y pide la URL interactivamente.

### Opciones

| Opción | Por defecto | Descripción |
|---|---|---|
| `--max-pages <N>` | 5 | Máximo de páginas en el crawl (1–50; 1 = solo la inicial) |
| `--timeout <S>` | 15 | Timeout por operación de red, en segundos (1–120) |
| `--concurrency <N>` | 4 | Peticiones simultáneas (1–16) |
| `--output <FILE>` | — | Graba el informe en archivo (nada se graba sin esto) |
| `--format <FMT>` | terminal | `terminal`, `json` o `html` |
| `--no-crawl` | — | No seguir enlaces internos |
| `--quiet` | — | Sin logs de progreso (solo el informe final) |
| `--verbose` | — | Detalla cada paso y petición (stderr) |

El informe va a **stdout** y el progreso a **stderr**, seguro para pipelines:

```bash
webspeed-auditor https://example.com --format json --quiet > reporte.json
```

### Códigos de salida

| Código | Significado |
|---|---|
| 0 | Auditoría completada (el informe se genera incluso con fallos parciales) |
| 1 | Fallo al generar/grabar el informe |
| 2 | Entrada inválida o URL rechazada por seguridad |

## Qué se verifica

- **Red**: resolución DNS, direcciones IPv4/IPv6, handshake TLS, validez y expiración del certificado, cadena de redirecciones, versión de protocolo (HTTP/1.1, HTTP/2), TTFB.
- **Rendimiento**: peso total de la página, tamaño del documento, TTFB.
- **HTML**: estructura, enlaces (interno/externo), iframes, `<meta>` de viewport, orígenes externos distintos, tamaño del documento, compatibilidad de contenido con `Content-Type` declarado.
- **CSS**: volumen total e inline, hojas duplicadas, CSS inline excesivo, recuperación de hojas con error.
- **JavaScript**: volumen, scripts bloqueantes vs `defer`/`async`/`module`, scripts duplicados, tamaños de archivos individuales.
- **Imágenes**: formatos legados vs modernos (WebP/AVIF), imágenes por encima del umbral de tamaño, `srcset`/`sizes`.
- **Fuentes**: volumen de fuentes externas e inline, preload de fuentes externas.
- **Caché**: `Cache-Control`, `ETag`/`Last-Modified`, `immutable` en HTML.
- **Compresión**: gzip/brotli/deflate por tipo de recurso, cabecera `Vary`.
- **Buenas prácticas**: cabeceras de seguridad (HSTS y `X-Content-Type-Options`), cookies (`Set-Cookie` solo contado — valores nunca recopilados), `Content-Type` declarado vs real (sniffing), HTTPS, redirecciones y cadena de redirección.

Umbrales completos: [`docs/SCORING.md`](docs/SCORING.md).

## Privacidad

- **Ningún dato se persiste**: la auditoría completa vive en memoria durante la ejecución y se descarta al final.
- **Ningún archivo se crea sin `--output`**, y nada se graba automáticamente.
- **Sin telemetría, sin analytics, sin reportes de fallos, sin actualizador automático, sin cuentas, sin claves de API.**
- El único tráfico externo son las peticiones **al sitio auditado** (y el DNS necesario para resolverlo). Ningún dato se envía a terceros.
- El informe contiene solo datos del sitio objetivo — nunca datos locales del operador (rutas, usuario, entorno).
- Set-Cookie: solo se reporta el **conteo**; los valores nunca se leen, guardan ni loguean.
- El User-Agent identifica la herramienta y el proyecto, nunca al operador.

Detalles: [`docs/SECURITY.md`](docs/SECURITY.md) y [`SECURITY.md`](SECURITY.md).

## Seguridad

- **SSRF (Server-Side Request Forgery)**: toda URL se valida antes de cada petición — incluyendo **en cada salto de redirección** y **en cada resolución DNS** (defensa contra DNS rebinding). Loopback, redes privadas, link-local, metadatos de cloud (169.254.169.254 etc.), CGNAT, direcciones reservadas y traducciones NAT64/6to4/Teredo son bloqueadas.
- **Sin flag CLI para desactivar la protección SSRF.** Solo puede desactivarse por código en tests locales.
- Límites absolutos: 10 MiB por cuerpo, 60 subrecursos, 10 redirecciones, URL máx. 2048 caracteres, concurrencia 1–16, timeout 1–120 s.
- El contenido remoto se trata como **nunca confiable**: HTML malformado no puede hacer panic, el informe HTML escapa todo contenido dinámico y el informe es autocontenido (sin `<script>`, sin recursos externos).
- `unsafe` está **prohibido** en todo el código (`#![forbid(unsafe_code)]`).

## Cómo funciona la puntuación

Cada categoría empieza en 100. Los hallazgos deducen valores fijos y documentados (Critical −30, High −15, Medium −8, Low −3, Info 0). La media ponderada se calcula **solo sobre las categorías realmente medidas** — lo que no se midió nunca infla la nota. Si nada se pudo medir, la puntuación es 0 y el informe lo indica explícitamente.

Fórmula completa, pesos y umbrales: [`docs/SCORING.md`](docs/SCORING.md).

## Limitaciones honestas

Esta herramienta no hace magia y declara lo que **no** mide:

- **Core Web Vitals (LCP/CLS/INP)**: no hay navegador real — la medición es HTTP estática.
- **HTTP/3 (QUIC)**: no se sonda (evita dependencias problemáticas).
- **JavaScript no se ejecuta**: páginas renderizadas solo por JS tienen análisis parcial.
- **Registros DNS (CNAME)**: no se recogen; solo resolución e IPs.
- **Accesibilidad**: solo aspectos ligados a rendimiento (dimensiones de imágenes, lazy loading).
- **Entorno de medición**: los tiempos varían con la red, CDN y carga del objetivo.

Todas las limitaciones aparecen en la sección "No testado" de cada informe.

## Desarrollo

```bash
cargo test          # 135+ tests (unidad + integración + SSRF)
cargo fmt --check
cargo clippy --all-targets
```

- Uso completo: [`docs/USAGE.md`](docs/USAGE.md)
- Arquitectura: [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md)
- Contribuir: [`CONTRIBUTING.md`](CONTRIBUTING.md)
- Build y releases: [`docs/BUILD.md`](docs/BUILD.md)

## Licencia

[MIT](LICENSE).
