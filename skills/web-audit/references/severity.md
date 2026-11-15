# Severity calibration

Rate by **realistic impact × ease of exploitation in this app**, not by the category name.

| Severity | Typical examples |
|---|---|
| **critical** | Cross-tenant data access; unauthenticated access to admin or bulk customer data; exposed `.env`/`.git` containing live secrets (DB passwords, API secret keys); auth bypass; RCE/SQLi confirmed by error + controllable behaviour |
| **high** | IDOR on personal/financial data between users (sequential IDs); authenticated endpoints fully readable anonymously; stored/reflected XSS on an authenticated page without CSP; CORS reflecting arbitrary origin **with credentials** on an authenticated API; session not invalidated on logout + long-lived tokens; secret keys in JS |
| **medium** | IDOR on low-sensitivity objects or with unguessable IDs; open redirect on login/OAuth flow; missing CSRF protection on meaningful actions; user enumeration + no rate limiting on login; verbose stack traces revealing internals; GraphQL introspection in prod; TLS 1.0/1.1 enabled |
| **low** | Missing HSTS; missing CSP (no XSS found); cookie missing `Secure`/`HttpOnly`/`SameSite` on non-session cookies; clickjacking on pages without sensitive actions; open redirect elsewhere; version disclosure of a currently-supported version |
| **info** | Technology fingerprint; public API keys (Maps, Stripe publishable); robots.txt entries; best-practice headers (Permissions-Policy, Referrer-Policy) |

Adjust:
- **Up one** if it's production, chained with another finding, or affects many users.
- **Down one** if it requires an unlikely precondition or the data is non-sensitive.
- Session cookie missing `HttpOnly` or `Secure` is **medium** (it's the session).

Confidence:
- `confirmed` — reproduced with evidence showing impact (e.g. user_b sees user_a's email).
- `firm` — behaviour clearly present, impact inferred (e.g. header missing).
- `tentative` — indicator only (e.g. DB error string after a quote). Tentative findings should
  usually be verified further or reported as info.
