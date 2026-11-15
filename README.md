# web-audit

Turn Claude Code into a web security auditor. Point it at a live site, with or without a login,
and get back a short list of verified vulnerabilities, each with evidence and a fix.

This is designed to complement [Cloudflare's security-audit skill](https://github.com/cloudflare/security-audit-skill),
which reads your source code to find vulnerabilities. web-audit covers the final leg: it tests the
**running** site to confirm those issues are actually reachable, and to verify that fixes and
deployments landed successfully — the part source review alone can't check.

> **Only test sites you own or have written permission to test.**
> The skill won't send a single request until you've recorded who approved the test.

---

## Contents

- [Quick start](#quick-start)
- [How it works](#how-it-works)
- [Testing logged-in areas](#testing-logged-in-areas)
- [What you get](#what-you-get)
- [What it checks](#what-it-checks)
- [Safety](#safety)
- [Try it locally](#try-it-locally)
- [Limitations](#limitations)

---

## Quick start

**1. Install the skill**

```bash
npx skills add JAT878/web-audit --skill web-audit -a claude-code -g
```

Or copy it in by hand:

```bash
git clone https://github.com/JAT878/web-audit
cp -r web-audit/skills/web-audit ~/.claude/skills/
```

**2. Install the Python packages**

```bash
pip install -r ~/.claude/skills/web-audit/requirements.txt
```

Only `requests` is required. The rest are optional and the skill works without them.

**3. Run an audit**

Open Claude Code and type one of these:

```
/web-audit noauth https://staging.example.com
/web-audit auth https://staging.example.com
/web-audit both https://staging.example.com
```

| Mode | What it tests |
|---|---|
| `noauth` | The public side of the site only |
| `auth` | Logged-in areas, including whether one user can see another user's data |
| `both` | Everything |

You can also just ask in plain English, e.g. *"audit staging, no login"*.

> Run it from Claude Code on your own machine or a build server. It needs network access to the site,
> so it won't work from a sandboxed chat.

---

## How it works

Every audit runs through the same six steps.

1. **Scope.** You confirm the site, the hosts allowed, who approved the test, and any pages to avoid
   (logout, payments, contact forms). This is saved to `scope.json`.
2. **Map the site.** It crawls pages, reads `robots.txt` and the sitemap, and pulls API endpoints out of
   the site's JavaScript. For single-page apps it can render pages in a real browser, or import a HAR
   file you record by clicking through the app yourself.
3. **Test the public side.** Headers, cookies, TLS, CORS, exposed files, error pages and more.
4. **Test logged-in areas.** It replays each user's pages as a different user and as a logged-out visitor
   to catch data leaks.
5. **Double-check.** Every possible issue is re-tested from scratch. Anything that doesn't hold up is
   thrown out.
6. **Report.** You get a readable report and a machine-readable findings file.

---

## Testing logged-in areas

You never have to hand over a password. Pick whichever suits you:

| Option | How |
|---|---|
| **Log in yourself** (recommended) | A browser window opens, you log in as normal (MFA and SSO work), and only the session is saved. |
| **Paste a session** | Log in in your own browser, copy the session cookie or token from DevTools, and paste it in. |
| **Automatic login** | For repeat runs. You set the password in an environment variable, never in chat. |

**Tips**

- Use test accounts with dummy data, not real ones.
- Use **two accounts** at the same level so it can check whether one user can see the other's data.
- Log those accounts out when you're done. Sessions are saved in `sessions.json`, which is git-ignored.

The "log in yourself" option needs Playwright:

```bash
pip install playwright
python3 -m playwright install chromium
```

---

## What you get

Results are saved to `./audit-<site>-<date>/`:

| File | What's in it |
|---|---|
| `report.md` | Summary, then each issue with severity, evidence, steps to reproduce and how to fix it |
| `findings.json` | The same results as structured data, for Jira or other tools |
| `requests.jsonl` | Every request sent, so the test can be audited |

Example finding from a report:

```
### Insecure direct object reference: another user's data is readable

Severity: High · Confidence: confirmed · CWE-639
URL: GET https://staging.example.com/orders/1001

user_b requested an order belonging to user_a and received it.

Impact: Any logged-in user can read other users' orders by changing the
number in the URL.

Reproduce:
  1. Log in as user_b
  2. Open /orders/1001 (belongs to user_a)
  3. The page shows user_a's order

Fix: Check on the server that the logged-in user owns the order before
returning it.
```

---

## What it checks

**Public side**

- HTTPS, TLS version and certificate expiry
- Security headers (CSP, HSTS, framing, content type)
- Cookie flags (`Secure`, `HttpOnly`, `SameSite`)
- CORS settings that let other sites read your data
- Software versions shown in headers
- Error pages that leak stack traces
- Open directory listings
- About 50 files that should never be public, such as `.git`, `.env`, backups, database dumps,
  `phpinfo`, and debug consoles for Laravel, Symfony, Spring and ASP.NET
- GraphQL schemas left open
- Weak login tokens (unsigned JWTs, tokens that never expire, sensitive data inside tokens)
- Reflected input (possible XSS) and database errors (possible SQL injection) across every parameter it finds

**Logged-in areas**

- Pages that work without logging in when they shouldn't
- One user reading another user's records by changing an ID
- Normal users reaching admin pages
- Guided manual checks for sessions, logout, CSRF and hidden fields

---

## Safety

- Read-only by default. It only sends `GET`, `HEAD` and `OPTIONS` requests.
- Stays on the hosts you list, and won't follow links or redirects anywhere else.
- Skips the pages you exclude.
- Rate limited, and stops if the site starts returning errors.
- Hides passwords, tokens and cookies in the report.
- Proves a problem exists without exploiting it. No data dumps, no brute forcing.

---

## Try it locally

The repo includes a small, deliberately broken web app so you can see the skill working before
pointing it at a real site. Instructions are in
[`skills/web-audit/tests/README.md`](skills/web-audit/tests/README.md).

---

## Limitations

- It only finds pages it can reach by crawling or spot in the JavaScript. Add any hidden pages
  as starting points.
- It's not a full penetration test, and doesn't replace tools like Burp Suite or OWASP ZAP.
- Always read the report before acting on it.

---

## License

[MIT](LICENSE)
