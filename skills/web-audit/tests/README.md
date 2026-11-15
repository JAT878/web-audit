# Self-test

`vuln_app.py` is a deliberately vulnerable local app (127.0.0.1:8088) for checking the skill works.
Expected candidates: .env and .git exposed (critical), IDOR on /orders/{id}, unauthenticated /reports/latest,
CORS reflection with credentials on /api/me, stack trace on `/?id='`, directory listing on /uploads/,
cookie flags, version headers, missing security headers, plain HTTP, GraphQL introspection,
an unsigned JWT (`alg: none`, no expiry, sensitive claim) in the `guest_token` cookie,
reflected input on `/search?q=` (XSS indicator), a database error on `/?id=` (SQLi indicator),
and a `/js-only` page reachable only via a JS-injected link (found by `--browser`, missed by the static crawl).

```
python3 tests/vuln_app.py &
mkdir -p /tmp/selftest && cp tests/*.json /tmp/selftest/ && mv /tmp/selftest/sessions.example.json /tmp/selftest/sessions.json
python3 scripts/recon.py --scope /tmp/selftest/scope.json --out /tmp/selftest
python3 scripts/recon.py --scope /tmp/selftest/scope.json --out /tmp/selftest --sessions /tmp/selftest/sessions.json --session user_a
python3 scripts/passive_checks.py --scope /tmp/selftest/scope.json --out /tmp/selftest
python3 scripts/exposed_files.py --scope /tmp/selftest/scope.json --out /tmp/selftest
python3 scripts/extra_checks.py --scope /tmp/selftest/scope.json --out /tmp/selftest --sessions /tmp/selftest/sessions.json
python3 scripts/param_probe.py --scope /tmp/selftest/scope.json --out /tmp/selftest
python3 scripts/recon.py --scope /tmp/selftest/scope.json --out /tmp/selftest --browser   # optional: JS-rendering crawl
python3 scripts/authz_replay.py --scope /tmp/selftest/scope.json --out /tmp/selftest --sessions /tmp/selftest/sessions.json --id-map /tmp/selftest/ids.json
python3 scripts/report.py --scope /tmp/selftest/scope.json --findings /tmp/selftest/findings.json --out /tmp/selftest/report.md --include-candidates
```
If you use an HTTP proxy, set `NO_PROXY=127.0.0.1`.
