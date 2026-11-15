"""Deliberately vulnerable local app for testing the skill. Never deploy."""
import base64
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from http.cookies import SimpleCookie
from urllib.parse import urlparse, parse_qs

USERS = {"tok-alice-7f3a9c": {"email": "alice@example.com", "name": "Alice Audit"},
         "tok-bob-2b8e1d": {"email": "bob@example.com", "name": "Bob Audit"}}
ORDERS = {"1001": ("alice@example.com", "Order 1001: 3x widgets, ship to 1 Alice St"),
          "1002": ("alice@example.com", "Order 1002: 1x gadget, ship to 1 Alice St"),
          "2001": ("bob@example.com", "Order 2001: 9x sprockets, ship to 2 Bob Rd")}


def _b64(d):
    return base64.urlsafe_b64encode(json.dumps(d).encode()).rstrip(b"=").decode()


# Unsigned JWT, no exp, with a sensitive-looking claim
WEAK_JWT = _b64({"alg": "none", "typ": "JWT"}) + "." + _b64({"sub": "guest", "password": "hunter2xyz"}) + "."


class H(BaseHTTPRequestHandler):
    server_version = "VulnApp/1.2.3"
    sys_version = ""

    def user(self):
        c = SimpleCookie(self.headers.get("Cookie", ""))
        return USERS.get(c["session"].value) if "session" in c else None

    def send(self, code, body, ctype="text/html", extra=None):
        b = body.encode() if isinstance(body, str) else body
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("X-Powered-By", "PHP/7.4.3")
        self.send_header("Set-Cookie", "PHPSESSID=abc123def456; Path=/")
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)

    def page(self, title, inner):
        return f"<html><head><title>{title}</title><script src='/static/app.js'></script></head><body><h1>{title}</h1>{inner}</body></html>"

    def log_message(self, *a):
        pass

    def do_GET(self):
        u = urlparse(self.path)
        p, q = u.path, parse_qs(u.query)
        me = self.user()
        if p == "/" and "id" in q and "'" in q["id"][0]:
            return self.send(500, "<pre>Traceback (most recent call last):\n  File \"/srv/app/views.py\", line 42, in index\n    cursor.execute(\"SELECT * FROM items WHERE id='%s'\" % id)\nsqlite3.OperationalError: near \"'\": syntax error</pre>")
        if p == "/graphql" and "__schema" in q.get("query", [""])[0]:
            return self.send(200, json.dumps({"data": {"__schema": {"queryType": {"name": "Query"},
                             "types": [{"name": "Query"}, {"name": "User"}, {"name": "Order"}, {"name": "AdminSettings"}]}}}), "application/json")
        if p == "/":
            return self.send(200, self.page("Home", "<a href='/about'>About</a> <a href='/login'>Login</a> <a href='/dashboard'>Dashboard</a> "
                             "<a href='/search?q=test'>Search</a> <a href='/?id=1'>Item 1</a>"
                             "<div id='app'></div><script>document.getElementById('app').innerHTML=\"<a href='/js-only'>JS page</a>\";</script>"),
                             extra={"Set-Cookie": f"guest_token={WEAK_JWT}; Path=/"})
        if p == "/search":
            term = q.get("q", [""])[0]
            return self.send(200, self.page("Search", f"<p>Results for: {term}</p>"))  # reflected unescaped
        if p == "/js-only":
            return self.send(200, self.page("JS Only", "<p>Reachable only via a JS-injected link.</p>"))
        if p == "/about":
            return self.send(200, self.page("About", "We sell widgets."))
        if p == "/login":
            return self.send(200, self.page("Login", "<form method='post' action='/login'><input name='email'><input type='password' name='password'><button type='submit'>Sign in</button></form>"))
        if p == "/robots.txt":
            return self.send(200, "User-agent: *\nDisallow: /uploads/\n", "text/plain")
        if p == "/static/app.js":
            return self.send(200, "fetch('/api/me');const o='/api/orders/';const k='/api/admin/users';", "application/javascript")
        if p == "/.env":
            return self.send(200, "APP_ENV=staging\nDB_PASSWORD=supersecret123\n", "text/plain")
        if p == "/.git/HEAD":
            return self.send(200, "ref: refs/heads/main\n", "text/plain")
        if p == "/uploads/":
            return self.send(200, "<html><title>Index of /uploads</title><body><h1>Index of /uploads</h1><a href='invoice-1001.pdf'>invoice-1001.pdf</a></body></html>")
        if p == "/api/me":
            origin = self.headers.get("Origin")
            extra = {"Access-Control-Allow-Origin": origin, "Access-Control-Allow-Credentials": "true"} if origin else {}
            if not me:
                return self.send(401, json.dumps({"error": "unauthenticated"}), "application/json", extra)
            return self.send(200, json.dumps(me), "application/json", extra)
        if p == "/dashboard":
            if not me:
                return self.send(302, "", extra={"Location": "/login"})
            links = "".join(f"<a href='/orders/{k}'>{k}</a> " for k, (o, _) in ORDERS.items() if o == me["email"])
            return self.send(200, self.page("Dashboard", f"<p>Welcome {me['email']}</p>{links}<a href='/reports/latest'>Report</a>"))
        if p.startswith("/orders/"):
            if not me:
                return self.send(302, "", extra={"Location": "/login"})
            oid = p.split("/")[2]
            if oid not in ORDERS:
                return self.send(404, self.page("Not found", ""))
            owner, text = ORDERS[oid]
            return self.send(200, self.page(f"Order {oid}", f"<p>{text}</p><p>Customer: {owner}</p>"))  # IDOR: no owner check
        if p == "/reports/latest":
            # Missing auth: always returns alice's report
            return self.send(200, self.page("Report", "<p>Monthly report for alice@example.com — spend $1,234</p>"))
        # soft 404
        return self.send(200, self.page("Oops", "<p>Sorry, that page could not be found.</p>"))


if __name__ == "__main__":
    ThreadingHTTPServer(("127.0.0.1", 8088), H).serve_forever()
