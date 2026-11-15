# Manual authenticated checks

## Access control (highest value — spend most time here)
`authz_replay.py` does the bulk replay. Your job is to feed it the right endpoints and judge results.

**ID maps.** For endpoints with object IDs, create `ids.json`:
```json
{
  "templates": [
    "https://staging.example.com/api/orders/{id}",
    "https://staging.example.com/invoices/{id}/pdf"
  ],
  "user_a": ["1001", "1002"],
  "user_b": ["2001"]
}
```
The script requests user_a's IDs as user_b (and vice versa) and as anonymous.

**What counts as IDOR:** user_b gets HTTP 2xx *and* the body contains user_a's
`identity_markers` or is near-identical to what user_a receives. A 200 with an empty list,
a generic page, or a redirect to login is not IDOR.

**Also try by hand:**
- IDs in POST bodies / JSON (`"userId"`, `"accountId"`, `"tenantId"`) — only if
  `allow_state_changing` is true, and only with harmless reads like a search/filter endpoint.
- Sequential vs UUID IDs: sequential IDs make IDOR exploitable at scale (raise severity).
- Function-level: admin URLs from recon/JS (`/admin`, `/api/admin/*`, `/manage`) requested
  as user_a. Use `--admin admin` in the script if you have an admin session.
- Tenant boundaries: if users are in different orgs/tenants, cross-tenant access is critical.
- File downloads (`/files/`, `/attachments/`, signed URLs): do links work without a session?
  Do signed URLs expire?

## Session management
- **Rotation on login:** note the session cookie before and after login (capture_session
  logs both). Same value = session fixation risk (CWE-384).
- **Logout:** copy user_a's cookie, log out in the browser, then replay an authenticated GET
  with the old cookie. Still works = session not invalidated server-side (CWE-613).
  (Logout is in excluded_paths for scripts — do it manually via the browser and ask the user
  first, because it invalidates the saved session.)
- **Timeout:** check cookie `Expires`/`Max-Age` and JWT `exp`. Multi-day sessions on
  sensitive apps = low/medium.
- **Concurrent sessions / password change** invalidation — note only if testable.

## JWT
Decode (base64) any bearer tokens or JWT cookies — never paste real tokens into online tools.
- `alg: none` or `HS256` where the app expects RS256 (only test if scope allows active tests).
- Missing `exp`, very long expiry, sensitive data in claims (PII, roles that the server trusts).
- Token stored in `localStorage` (XSS → token theft) — info/low, raise if XSS also found.

## CSRF
- For state-changing forms found in recon (as an authenticated user): is there an anti-CSRF
  token? Is the session cookie `SameSite=Lax/Strict`? Do JSON endpoints accept
  `Content-Type: text/plain` or form-encoded bodies (CSRF-able)?
- Only *demonstrate* with a real state change if `allow_state_changing` is true and the action
  is harmless (e.g. update a test account's display name).

## Mass assignment / excessive data exposure
- Read authenticated JSON responses: do they include fields the UI never shows (password
  hashes, other users' emails, internal flags, `role`, `isAdmin`, cost prices)? That's
  sensitive-data-exposure even without exploitation.
- If state changes are allowed: add `"role":"admin"` or `"isAdmin":true` to a profile update
  of the test account and see if it sticks.

## Client-side authorization
- Hidden admin menus in JS, role checks done only in the SPA, feature flags in localStorage.
  These are hints — confirm with a server request before raising a finding.
