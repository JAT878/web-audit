# Scope file template

Save as `<out>/scope.json`. Fill every field; `scope_check.py` will tell you what's missing.

```json
{
  "target": "https://staging.example.com",
  "allowed_hosts": ["staging.example.com", "api.staging.example.com"],
  "environment": "staging",
  "authorization": {
    "authorized_by": "Jane Citizen, Head of Technology",
    "reference": "CHG-1234 / email 2026-11-15",
    "date": "2026-11-15",
    "window": "2026-11-16 09:00–17:00 AEDT"
  },
  "mode": "both",
  "max_rps": 3,
  "allow_state_changing": false,
  "excluded_paths": ["/logout", "/signout", "/account/delete", "/checkout", "/api/payments", "/contact"],
  "user_agent_tag": "authorised-security-test (contact: security@example.com)",
  "notes": "Test accounts: audit_a@example.com, audit_b@example.com (same tenant, role=member)."
}
```

`excluded_paths` are prefix matches against the URL path. `user_agent_tag` is appended to
the User-Agent so the site owner can identify test traffic in logs/WAF.

# sessions.json (separate file, contains secrets — never commit or include in reports)

```json
{
  "user_a": { "cookies": { "session": "abc..." }, "headers": {}, "identity_markers": ["audit_a@example.com", "Alice Audit"] },
  "user_b": { "cookies": {}, "headers": { "Authorization": "Bearer eyJ..." }, "identity_markers": ["audit_b@example.com"] },
  "admin":  { "cookie_header": "session=xyz; csrftoken=...", "identity_markers": ["admin@example.com"] }
}
```

- `cookies` (dict), `cookie_header` (raw string) and `headers` can be mixed.
- `identity_markers` are strings that only appear in that user's own data (email, name,
  account number). The authz replay uses them to prove user_b actually received user_a's data.
- `capture_session.py` writes entries in this format, including `storage_state` path for Playwright.
