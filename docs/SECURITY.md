# Security and privacy design

## Principles
1. **Look, never touch.** Links are never opened (so Sentra cannot be used to probe other servers, and nobody's
   address is revealed). App files are read as data and never installed or run.
2. **Keep nothing.** Messages are processed in memory and discarded. Uploaded files are written to a temporary file
   only so the reader can open them, and that file is deleted in a `finally` block. Logs record the *type* of an error,
   never the content. The browser History keeps only the result, the kind of check and the time, in the user's own
   browser, never the text.
3. **Fail safely.** One analyzer failing never breaks a check; every error the user sees is generic.

## Controls (each one has an automated test in `tests/test_api.py` or `tests/test_robustness.py`)

| Risk | Control |
|---|---|
| Oversized input | Text capped at 5,000 characters; uploads capped at 50 MB; requests declaring a huge body are refused with 413 before being read |
| Fake or malicious app files | Must end in `.apk`, start with the zip signature, contain `AndroidManifest.xml`, have at most 20,000 entries, unpack to under 400 MB, and not show a decompression-bomb ratio |
| Malformed addresses and QR payloads | Parsing is wrapped so bad URLs, bad ports, broken UPI strings, huge strings and control characters never crash a check (fuzz-style test) |
| Abuse and flooding | In-memory sliding-window rate limit per client address on `/api/scan` (30 per minute by default, `SENTRA_RATE` to change), answered with 429 |
| Information leakage | Global handlers return one generic message for validation errors and crashes; no stack traces, paths or exception text reach the user (tested with a simulated crash) |
| Leftover uploads | Temporary file removed even when reading fails (tested, including a simulated failure) |
| Browser attacks | Content-Security-Policy (same-origin scripts plus the QR reader CDN fallback, no framing), `X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy`, `Permissions-Policy`; the page builds results with `textContent`, so scanned text cannot inject markup |
| Extra surface | Interactive API docs and the OpenAPI file are switched off in production |
| Camera privacy | QR codes are decoded inside the browser; the picture is never uploaded |

## Residual risks (stated honestly)
- **Request-body enforcement is incomplete.** The middleware rejects requests whose declared `Content-Length` exceeds the configured limit, but it does not count streamed request bytes. Multipart parsing happens before the `/api/scan` handler, so a chunked request or a request with a misleading/missing length may consume memory or temporary disk before the handler's 50 MB APK read cap is applied. Enforce a hard body limit at the reverse proxy and add an ASGI receive-layer byte counter before treating the upload cap as a complete denial-of-service control.
- The rate limiter is in memory and per server instance, so it resets on restart and is not shared across instances.
  It trusts the `X-Forwarded-For` header, which is correct behind Render's proxy but spoofable elsewhere.
- App files are parsed by the Androguard library; a bug in a parser is always possible. Size and structure checks
  reduce the exposure and nothing is executed.
- No authentication: Sentra is a public tool by design.
- Free-tier hosting sleeps when idle.
