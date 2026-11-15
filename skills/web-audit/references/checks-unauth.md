# Manual unauthenticated checks

Scripts cover the mechanical checks. These need judgement — pick the ones relevant to the
attack surface in `notes.md`. Stay within rate limits; observe behaviour, don't hammer.

## Open redirect
- Look in recon for params named `next`, `return`, `returnUrl`, `redirect`, `url`, `continue`,
  `dest`, `callback`, `RelayState`, and OAuth `redirect_uri`.
- Try `https://evil.example`, `//evil.example`, `/\evil.example`, `https:evil.example`,
  `https://<allowed-host>.evil.example`. Only record if the `Location` header (or a JS/meta
  redirect) actually points off-site. CWE-601. Medium if on login/OAuth flow, else low.

## Reflected input / XSS indicators
- For GET params seen in recon, send a harmless unique marker like `zq7x"'<b>zq7x` and check
  whether it comes back unencoded in HTML (not inside JSON with correct content-type).
- Note context (HTML body, attribute, script block). Do not attempt payloads that execute
  actions; a reflected unencoded `<b>` in HTML context plus no CSP is enough evidence.
- Check `Content-Type` on JSON endpoints — `text/html` JSON reflecting input is an XSS risk.

## SQL/template injection indicators (observe only)
- A single `'` or `{{7*7}}` in a parameter: look for DB error strings, stack traces or `49`
  rendered. Record as candidate injection with the error as evidence. Do **not** run sqlmap
  or extraction payloads unless the scope explicitly allows active exploitation.

## Authentication surface
- **User enumeration:** compare login / forgot-password / register responses for an existing
  test account vs a random address (message text, status, length, timing). CWE-204.
- **Rate limiting / lockout:** send at most 10 wrong-password attempts for a *test* account at
  the scope rps and note whether there is throttling, CAPTCHA or lockout. Never other accounts.
- **Password reset:** token in URL sent to third parties (Referer), token reuse, no expiry
  (only if a test mailbox is available), host-header-derived reset links (send `X-Forwarded-Host:
  evil.example` on the reset request and check the emailed link — needs test mailbox).
- **Login over GET**, credentials in URL, autocomplete on password fields (info only).

## Exposure in client-side code
- Read the largest JS bundles from recon for: API keys (Google, Stripe pk vs sk, Firebase
  config is normally public), internal hostnames, hard-coded credentials, admin routes,
  feature flags, source maps (`.map`) that reveal source. Secret keys = high; public keys = info.

## API specifics
- `OPTIONS` on API endpoints: overly broad `Allow` methods.
- GraphQL: introspection enabled in production (`{"query":"{__schema{types{name}}}"}`) — low/medium.
- Swagger/OpenAPI exposed: info, but read it — it's the best map of auth-required endpoints
  to replay anonymously.

## Platform-specific quick hits
- **PHP:** `?XDEBUG_SESSION_START`, `phpinfo`, `.php~`/`.php.bak`/`.php.swp` copies of found
  pages, `display_errors` warnings revealing paths, `composer.lock` (exact component versions).
- **WordPress:** `/wp-json/wp/v2/users` (user enumeration), `xmlrpc.php` enabled, plugin
  versions in asset `?ver=`.
- **ASP.NET:** `trace.axd`, `elmah.axd`, detailed YSOD errors, `X-AspNet-Version`.
- **Laravel:** `APP_DEBUG` Ignition error page, `/_ignition/health-check`, `/telescope`, `/horizon`.
- **Next.js / SPA:** `/_next/static/.../_buildManifest.js` lists all routes; check routes that
  render data server-side without auth.
- **Spring:** `/actuator/*`.
