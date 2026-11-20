#!/usr/bin/env python3
"""Phase 2: probe for sensitive files/endpoints that should not be public. Soft-404 aware."""
import argparse
import difflib
import os
import re
import sys
import uuid

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from common import (Client, Findings, asset_of, cap_fields, describe_request, excerpt,  # noqa: E402
                    id_shape_of, load_scope_or_exit, slug)

# (path, signature regex that must match the body to confirm, severity, title, category)
PROBES = [
    ("/.git/HEAD", r"^ref: refs/|^[0-9a-f]{40}\s*$", "critical", "Git repository exposed", "sensitive-data-exposure"),
    ("/.git/config", r"\[core\]", "critical", "Git config exposed", "sensitive-data-exposure"),
    ("/.svn/entries", r"^\d+\s*$|svn:", "high", "SVN metadata exposed", "sensitive-data-exposure"),
    ("/.hg/hgrc", r"\[paths\]", "high", "Mercurial metadata exposed", "sensitive-data-exposure"),
    ("/.env", r"(?m)^[A-Z][A-Z0-9_]{2,}=", "critical", ".env file exposed", "sensitive-data-exposure"),
    ("/.env.local", r"(?m)^[A-Z][A-Z0-9_]{2,}=", "critical", ".env.local exposed", "sensitive-data-exposure"),
    ("/.env.production", r"(?m)^[A-Z][A-Z0-9_]{2,}=", "critical", ".env.production exposed", "sensitive-data-exposure"),
    ("/.env.bak", r"(?m)^[A-Z][A-Z0-9_]{2,}=", "critical", ".env backup exposed", "sensitive-data-exposure"),
    ("/config.php.bak", r"<\?php|define\(|\$db", "critical", "PHP config backup exposed", "sensitive-data-exposure"),
    ("/wp-config.php.bak", r"DB_PASSWORD|<\?php", "critical", "WordPress config backup exposed", "sensitive-data-exposure"),
    ("/wp-config.php~", r"DB_PASSWORD|<\?php", "critical", "WordPress config editor backup exposed", "sensitive-data-exposure"),
    ("/web.config", r"<configuration", "high", "web.config readable", "sensitive-data-exposure"),
    ("/appsettings.json", r"\"(ConnectionStrings|Logging)\"", "high", "appsettings.json exposed", "sensitive-data-exposure"),
    ("/appsettings.Development.json", r"\"(ConnectionStrings|Logging)\"", "high", "appsettings.Development.json exposed", "sensitive-data-exposure"),
    ("/.DS_Store", r"Bud1", "low", ".DS_Store exposed (lists directory contents)", "information-disclosure"),
    ("/phpinfo.php", r"PHP Version|phpinfo\(\)", "medium", "phpinfo() page exposed", "information-disclosure"),
    ("/info.php", r"PHP Version|phpinfo\(\)", "medium", "phpinfo() page exposed", "information-disclosure"),
    ("/server-status", r"Apache Server Status", "medium", "Apache server-status exposed", "information-disclosure"),
    ("/server-info", r"Apache Server Information", "medium", "Apache server-info exposed", "information-disclosure"),
    ("/composer.json", r"\"require\"", "low", "composer.json exposed", "information-disclosure"),
    ("/composer.lock", r"\"packages\"", "low", "composer.lock exposed (exact dependency versions)", "information-disclosure"),
    ("/package.json", r"\"(dependencies|scripts)\"", "low", "package.json exposed", "information-disclosure"),
    ("/backup.zip", r"^PK\x03\x04", "critical", "Backup archive downloadable", "sensitive-data-exposure"),
    ("/backup.sql", r"(?i)(CREATE TABLE|INSERT INTO)", "critical", "SQL dump downloadable", "sensitive-data-exposure"),
    ("/dump.sql", r"(?i)(CREATE TABLE|INSERT INTO)", "critical", "SQL dump downloadable", "sensitive-data-exposure"),
    ("/db.sql", r"(?i)(CREATE TABLE|INSERT INTO)", "critical", "SQL dump downloadable", "sensitive-data-exposure"),
    ("/site.tar.gz", r"^\x1f\x8b", "critical", "Site archive downloadable", "sensitive-data-exposure"),
    ("/actuator", r"\"_links\"", "medium", "Spring Boot actuator index exposed", "information-disclosure"),
    ("/actuator/env", r"\"propertySources\"|\"activeProfiles\"", "critical", "Spring actuator /env exposed", "sensitive-data-exposure"),
    ("/actuator/heapdump", r"JAVA PROFILE", "critical", "Spring actuator heapdump exposed", "sensitive-data-exposure"),
    ("/swagger.json", r"\"(swagger|openapi)\"", "info", "Swagger/OpenAPI spec exposed", "information-disclosure"),
    ("/openapi.json", r"\"openapi\"", "info", "OpenAPI spec exposed", "information-disclosure"),
    ("/v2/api-docs", r"\"swagger\"", "info", "Swagger spec exposed", "information-disclosure"),
    ("/swagger-ui.html", r"swagger-ui", "info", "Swagger UI exposed", "information-disclosure"),
    ("/trace.axd", r"Application Trace", "high", "ASP.NET trace.axd exposed", "information-disclosure"),
    ("/elmah.axd", r"Error Log for", "high", "ELMAH error log exposed", "sensitive-data-exposure"),
    ("/_ignition/health-check", r"\"can_execute_commands\"", "high", "Laravel Ignition exposed (debug mode)", "security-misconfiguration"),
    ("/telescope", r"Laravel Telescope|telescope", "high", "Laravel Telescope exposed", "sensitive-data-exposure"),
    ("/horizon", r"Laravel Horizon|horizon", "medium", "Laravel Horizon exposed", "information-disclosure"),
    ("/debug/default/view", r"Yii Debugger", "high", "Yii debug toolbar exposed", "information-disclosure"),
    ("/_profiler", r"Symfony Profiler", "high", "Symfony profiler exposed", "sensitive-data-exposure"),
    ("/wp-json/wp/v2/users", r"\"slug\"\s*:", "medium", "WordPress REST API lists users", "information-disclosure"),
    ("/xmlrpc.php", r"XML-RPC server accepts POST requests only", "low", "WordPress xmlrpc.php enabled", "security-misconfiguration"),
    ("/adminer.php", r"Adminer", "high", "Adminer DB console exposed", "security-misconfiguration"),
    ("/phpmyadmin/", r"phpMyAdmin", "high", "phpMyAdmin exposed", "security-misconfiguration"),
    ("/.well-known/security.txt", r"(?i)contact:", "info", "security.txt present", "other"),
    ("/crossdomain.xml", r"allow-access-from domain=\"\*\"", "low", "Permissive crossdomain.xml", "security-misconfiguration"),
    ("/.htaccess", r"(?i)(RewriteRule|Deny from|Require )", "low", ".htaccess readable", "information-disclosure"),
    ("/.npmrc", r"_authToken|registry=", "high", ".npmrc exposed", "sensitive-data-exposure"),
    ("/.aws/credentials", r"aws_access_key_id", "critical", "AWS credentials exposed", "sensitive-data-exposure"),
    ("/docker-compose.yml", r"services:", "medium", "docker-compose.yml exposed", "information-disclosure"),
    ("/Dockerfile", r"(?m)^FROM ", "low", "Dockerfile exposed", "information-disclosure"),
]

FIX = {
    "sensitive-data-exposure": "Remove the file from the web root, block dotfiles and backups at the web server/CDN, and rotate any secrets it contained.",
    "information-disclosure": "Remove or restrict this resource to internal networks/authenticated admins.",
    "security-misconfiguration": "Disable or restrict this component outside development.",
    "other": "No action needed; recorded for completeness.",
}


def soft404_baseline(c, scope):
    base = []
    for ext in ("", ".php", ".json", ".zip"):
        r = c.get(f"{scope.target}/zz-{uuid.uuid4().hex[:10]}{ext}")
        if r is not None:
            base.append((r.status_code, r.text[:3000] if r.text else ""))
    return base


def looks_like_baseline(r, base):
    body = r.text[:3000] if r.text else ""
    for st, b in base:
        if st == r.status_code and difflib.SequenceMatcher(None, b, body).quick_ratio() > 0.9:
            return True
    return False


def caps_for(path, cat):
    """Capability fields for an exposed-file finding (see CONTRACT guidance table).
    Secrets-bearing files grant knowledge:secret; schema docs grant knowledge:schema;
    every disclosure gets chain_role 'disclosure'."""
    low = path.lower()
    if any(s in low for s in ("swagger", "openapi", "api-docs", "graphql")):
        grants = ["knowledge:schema"]
    elif cat == "sensitive-data-exposure":
        grants = ["knowledge:secret"]
    else:
        grants = []
    return cap_fields(grants=grants, chain_role="disclosure",
                      assets=[asset_of(path)], id_shape=id_shape_of(path))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--scope", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--extra", help="file with extra paths, one per line (no signature check — reported as tentative)")
    a = ap.parse_args()
    scope = load_scope_or_exit(a.scope)
    c = Client(scope, a.out, "anonymous")
    F = Findings(a.out, scope.target)
    hits = 0
    try:
        base = soft404_baseline(c, scope)
        probes = list(PROBES)
        if a.extra:
            with open(a.extra, encoding="utf-8") as f:
                for line in f:
                    p = line.strip()
                    if p and not p.startswith("#"):
                        probes.append(("/" + p.lstrip("/"), None, "info", f"Interesting path responds: /{p.lstrip('/')}", "information-disclosure"))
        for path, sig, sev, title, cat in probes:
            url = scope.target + path
            if scope.excluded(url):
                continue
            r = c.get(url, stream=False)
            if r is None or r.status_code != 200 or looks_like_baseline(r, base):
                continue
            body = r.content[:20000]
            text = body.decode("utf-8", "replace")
            if sig:
                target_text = text if not sig.startswith("^PK") and not sig.startswith("^\\x1f") else body.decode("latin-1")
                if not re.search(sig, target_text):
                    continue
            hits += 1
            F.add(id=f"EXPOSED-{slug(path, 36)}", title=title, severity=sev,
                  confidence="confirmed" if sig else "tentative", category=cat, auth_context="anonymous", url=url,
                  description=f"{path} is publicly reachable (HTTP 200, {len(r.content)} bytes)" + (" and its content matches the expected file format." if sig else "."),
                  impact="Attackers can read source, configuration or secrets directly." if cat == "sensitive-data-exposure" else "Gives attackers internal details that make other attacks easier.",
                  evidence={"request": describe_request(r), "response_status": 200,
                            "response_excerpt": excerpt(text if text.isprintable() or "\n" in text else repr(body[:200]), 400)},
                  remediation=FIX[cat], cwe="CWE-538" if cat == "sensitive-data-exposure" else "CWE-200", source="exposed_files",
                  **caps_for(path, cat))
    finally:
        F.save()
        print(f"Exposed files: {c.count} requests, {hits} hits, {F.added} new candidate findings -> {F.path}")


if __name__ == "__main__":
    main()
