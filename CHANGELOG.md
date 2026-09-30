# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [0.2.0] - 2026-09-30

### Added
- Embedded JavaScript execution engine (QuickJS) for subscription payload transformation via the `/{host}/{path}/{headers}/{script}` route.
- Asynchronous script execution context supporting exported handlers to modify response headers and JSON or plaintext response bodies.
- Bot and crawler detection layer rejecting requests that lack a `User-Agent` header or match known automated user agents.
- Extended automated client signature list incorporating messenger link unfurlers, search spiders, SEO scanners, and non-respecting AI agents (Crawl4AI, Devin, Cursor, Scrapy, Manus, Firecrawl, etc.).
- Immediate HTTP 403 (Forbidden) termination for detected automated traffic to eliminate upstream proxy fetch overhead.
- Dedicated `/robots.txt` endpoint delivering universal `Disallow: /` directives and restrictive crawler headers with bot middleware exemption.
- Dedicated `/llms.txt` endpoint delivering structured machine-readable service documentation, workflow instructions, and AI crawler policies.

### Security
- Automated link-preview mitigation to prevent upstream proxy execution and bandwidth consumption from chat platforms.
- Targeted token matching avoiding false positives on standard desktop/mobile browsers and dedicated proxy clients (Clash, sing-box, Shadowrocket, v2ray, Quantumult, Surge).
- Preservation of standard developer HTTP library access (`curl`, `wget`, `python-requests`, etc.).

---

## [0.1.0] - 2026-07-13

### Added
- Initial release of the stateless VPN subscription proxy service.
- Client identity and header capture endpoint (`/whoami`) encoding client headers into serialized profile parameters.
- Stateless subscription proxying route (`/{host}/{path}/{headers}`) resolving parameters from URL-safe Base64 path segments.
- Whitelist enforcement for client headers and subscription response headers.
- Rate limiting middleware with IP extraction, burst capacity handling, and periodic tracker pruning.
- Structured JSON response formatting and standardized error templates.
- Production deployment assets for Angie/Nginx reverse proxying (HTTP/2, HTTP/3 QUIC) and systemd service management.

### Security
- Server-Side Request Forgery (SSRF) protection validating upstream targets against private, loopback, broadcast, and reserved IP ranges.
- Explicit non-redirect policy disabling HTTP redirect following to prevent bounce attacks.
- Header input size constraints rejecting payloads exceeding 2 KB.
