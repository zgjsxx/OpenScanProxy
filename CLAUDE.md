# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Build & Test Commands

### Backend (C++)

```bash
# Configure and build (Debug, with tests)
./build.sh

# Release build without tests
./build.sh --release --no-tests

# Full cycle: configure, build, run tests
./build.sh --tests --run-tests

# Build a single target
./build.sh --target http_message_test

# Run already-built tests
./test.sh                          # all tests
./test.sh --regex policy           # filter by test name
./test.sh --list                   # list tests without running
./test.sh --verbose                # verbose output
```

### Frontend (Vue 3, in `web/`)

```bash
cd web
npm install            # first time only
npm run dev            # Vite dev server
npm run build          # production build → web/dist/
```

### Running the proxy

```bash
./build/openscanproxy configs/config.json
# Proxy on :8080, Admin UI on :9090
```

## Architecture

OpenScanProxy is a C++20 HTTP forward proxy with file extraction, virus scanning, policy enforcement, and audit logging. The only external dependency is OpenSSL.

### Request flow

Client → `ProxyServer` (accepts TCP, handles HTTP forward + CONNECT tunnel) → authentication check (Basic or cookie-based Portal) → `FileExtractor` (multipart uploads, attachment downloads) → `IScanner` (MockScanner or ClamAVScanner) → `PolicyEngine` (allow/block/log decision) → `AuditLogger` + `StatsRegistry` → upstream forwarding or block response.

### Key subsystems (each has a header in `include/openscanproxy/<name>/` and impl in `src/<name>/`)

| Subsystem | Role |
|---|---|
| `proxy` | Main proxy server, MITM integration, auth. `Runtime` struct wires all shared instances together. |
| `http` | `HttpRequest`/`HttpResponse` structs, header parsing, chunked encoding/decoding, serialization. |
| `extractor` | Extracts files from multipart uploads and download responses (Content-Disposition / Content-Type). |
| `scanner` | `IScanner` interface + `MockScanner` + `ClamAVScanner` (Unix socket or TCP). |
| `policy` | Evaluates scan results into actions; domain/user/URL/category whitelist/blacklist + custom rules; loads CSV domain category data. |
| `audit` | JSONL audit logging + in-memory ring buffer for admin API queries. |
| `stats` | Atomic counters (requests, scans, results) + Prometheus `/metrics` text export. |
| `config` | `AppConfig` flat struct, JSON config loader (MVP parser, covers current schema only). |
| `tlsmitm` | OpenSSL wrapper: loads CA cert/key, dynamically issues per-hostname leaf certs with optional filesystem caching. |
| `admin` | HTTP server for management REST API (`/api/*`, `/healthz`, `/metrics`) + static file serving for the Vue frontend (`web/dist`). |
| `auth` | HTTPS server for interactive portal authentication (login page, session management, token issuance). |

### Entry point

`cmd/openscanproxy/main.cpp` — loads config, constructs `Runtime`, initializes scanner and TLS MITM, then starts `AdminServer`, `ProxyServer`, and optionally `AuthPortalServer` in parallel threads.

### Auth modes

- `basic` — Proxy-Authorization header
- `portal` — cookie-based interactive login with token issuance and domain-scoped cookies
- `other` — both simultaneously

### Tests

Unit tests (7) each link only the source files they need. The integration test (`tests/integration_test.cpp`) links everything and starts a real proxy + mock upstream on loopback sockets. It is POSIX-only (excluded on Windows/MSVC). Tests run via CTest; working directory is the project root.

## Important Constraints

- **MVP scope**: HTTP parser is simplified (no connection reuse, incomplete chunked support), no streaming scan (full buffering), no async queue.
- **HTTPS MITM**: Currently only terminates TLS and forwards; decrypted HTTP is not yet scanned.
- **Config parser**: Covers only the current JSON schema — adding new config keys requires parser changes.
- **Portal auth workaround** (see `KNOWN_ISSUES.md`): Script-driven fetch/XHR traffic with `Sec-Fetch-Mode: cors/no-cors` and `Sec-Fetch-Dest: empty` bypasses portal auth to avoid breaking page rendering.
- **Web frontend** must be built separately into `web/dist/` before the C++ binary can serve it. The CMake variable `ADMIN_STATIC_DIR_DEFAULT` controls where the admin server looks for static files.
