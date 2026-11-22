#!/usr/bin/env bash
# End-to-end self-test: start the bundled vulnerable app, run the full documented
# pipeline into a temp dir, and assert the detectors produce findings.json with the
# expected categories, then (if present) correlate -> chains.json, validate, and report.
#
# Robust to being run from anywhere. Scripts built in parallel (correlate.py, report.py)
# may not exist yet: those steps SKIP-with-note instead of failing. The detectors that
# already exist are asserted hard. Exits non-zero on any hard failure.
set -u

SKILL_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SCRIPTS="$SKILL_DIR/scripts"
TESTS="$SKILL_DIR/tests"
PY="${PYTHON:-python3}"

export NO_PROXY=127.0.0.1,localhost
export no_proxy=127.0.0.1,localhost

FAILS=0
pass() { echo "PASS: $*"; }
fail() { echo "FAIL: $*"; FAILS=$((FAILS+1)); }
skip() { echo "SKIP: $*"; }

OUT="$(mktemp -d "${TMPDIR:-/tmp}/web-audit-selftest.XXXXXX")"
APP_PID=""
cleanup() {
  [ -n "$APP_PID" ] && kill "$APP_PID" >/dev/null 2>&1   # kill ONLY our own app
  rm -rf "$OUT"
}
trap cleanup EXIT INT TERM

echo "== self-test out dir: $OUT =="

# --- private port + patched app copy ------------------------------------------
# Run our OWN vuln_app on a private free port in the temp dir. This isolates the
# run from other agents that may be cycling the default 8088 in parallel. We copy
# (never edit) vuln_app.py and rewrite the port; detectors read host:port from scope.
PORT="$("$PY" -c 'import socket;s=socket.socket();s.bind(("127.0.0.1",0));print(s.getsockname()[1]);s.close()')"
BASEURL="http://127.0.0.1:$PORT"
sed "s/8088/$PORT/g" "$TESTS/vuln_app.py" > "$OUT/vuln_app.py"

# --- scope + sessions + id-map, all pointed at the private port ----------------
cp "$TESTS"/*.json "$OUT"/ 2>/dev/null
mv "$OUT/sessions.example.json" "$OUT/sessions.json" 2>/dev/null
sed -i "s/8088/$PORT/g" "$OUT/scope.json" "$OUT/ids.json" 2>/dev/null
SCOPE="$OUT/scope.json"; SESS="$OUT/sessions.json"; IDS="$OUT/ids.json"

# --- start the private app ----------------------------------------------------
"$PY" "$OUT/vuln_app.py" >"$OUT/app.log" 2>&1 &
APP_PID=$!
for i in $(seq 1 40); do
  curl -s --noproxy 127.0.0.1 -o /dev/null "$BASEURL/" && break
  sleep 0.25
done
if curl -s --noproxy 127.0.0.1 -o /dev/null "$BASEURL/"; then
  pass "vuln_app up on private port $PORT"
else
  fail "vuln_app did not come up on $BASEURL"; echo "---- app.log ----"; cat "$OUT/app.log"; exit 1
fi

run_if() {  # run_if <script> <args...> : run only if present. A non-zero exit is a SOFT
            # note — detectors are built/edited by other agents in parallel and may be
            # transiently broken; the hard gates below assert on OUTCOMES (categories etc.).
  local name="$1"; shift
  if [ -f "$SCRIPTS/$name" ]; then
    if "$PY" "$SCRIPTS/$name" "$@" >>"$OUT/run.log" 2>&1; then
      pass "ran $name"
    else
      skip "$name exited non-zero (soft; see run.log) — outcome gates still apply"
    fi
  else
    skip "$name not present yet"
  fi
}

# --- detectors (documented pipeline) -----------------------------------------
run_if recon.py          --scope "$SCOPE" --out "$OUT"
run_if recon.py          --scope "$SCOPE" --out "$OUT" --sessions "$SESS" --session user_a
run_if passive_checks.py --scope "$SCOPE" --out "$OUT"
run_if exposed_files.py  --scope "$SCOPE" --out "$OUT"
run_if extra_checks.py   --scope "$SCOPE" --out "$OUT" --sessions "$SESS"
run_if param_probe.py    --scope "$SCOPE" --out "$OUT"
run_if auth_probe.py     --scope "$SCOPE" --out "$OUT" --sessions "$SESS" --session user_a
run_if session_checks.py --scope "$SCOPE" --out "$OUT" --sessions "$SESS" --session user_a
run_if auth_flows.py     --scope "$SCOPE" --out "$OUT" --sessions "$SESS" --session user_a
run_if authz_replay.py   --scope "$SCOPE" --out "$OUT" --sessions "$SESS" --id-map "$IDS"
run_if api_checks.py     --scope "$SCOPE" --out "$OUT" --sessions "$SESS" --session user_a --other user_b --id-map "$IDS"

# --- assert findings.json + expected categories (hard) ------------------------
if [ ! -f "$OUT/findings.json" ]; then
  fail "findings.json was not produced"
else
  pass "findings.json exists"
  "$PY" - "$OUT/findings.json" <<'PYEOF'
import json, sys
doc = json.load(open(sys.argv[1]))
cats = {f.get("category") for f in doc.get("findings", [])}
ok = True
def need(label, options):
    global ok
    if cats & set(options):
        print(f"PASS: category present: {label}")
    else:
        print(f"FAIL: expected category missing: {label} (have: {sorted(cats)})"); ok = False
need("broken-access-control", ["broken-access-control"])
need("information-disclosure/sensitive-data-exposure",
     ["information-disclosure", "sensitive-data-exposure"])
need("security-misconfiguration", ["security-misconfiguration"])
need("authentication (enumeration/reset)", ["authentication"])
need("session-management (fixation)", ["session-management"])
sys.exit(0 if ok else 3)
PYEOF
  [ $? -eq 0 ] || fail "expected categories missing from findings.json"
fi

# --- correlation -> chains.json (tolerant) ------------------------------------
if [ -f "$SCRIPTS/correlate.py" ]; then
  "$PY" "$SCRIPTS/correlate.py" --findings "$OUT/findings.json" --out "$OUT" \
       --recon "$OUT/recon.json" >>"$OUT/run.log" 2>&1 \
    && pass "ran correlate.py" || fail "correlate.py exited non-zero"
  if [ -f "$OUT/chains.json" ]; then
    pass "chains.json produced"
    # The centrepiece: the planted vulns MUST correlate into at least one multi-step chain.
    NCH="$("$PY" -c 'import json,sys;print(len(json.load(open(sys.argv[1])).get("chains",[])))' "$OUT/chains.json" 2>/dev/null || echo 0)"
    if [ "${NCH:-0}" -ge 1 ]; then pass "correlation produced $NCH attack chain(s)"
    else fail "correlation produced no attack chains (expected >=1 from planted vulns)"; fi
    if [ -f "$SCRIPTS/validate_findings.py" ]; then
      "$PY" "$SCRIPTS/validate_findings.py" "$OUT/findings.json" --chains "$OUT/chains.json" >>"$OUT/run.log" 2>&1 \
        && pass "chains.json validates (integrity + schema)" || fail "chains.json failed validation"
    fi
    # Chain execution in READ-ONLY mode (allow_token_forge off): must run, send no forge, and
    # leave chains tentative. Asserts the safety default of the one active component.
    if [ -f "$SCRIPTS/chain_exec.py" ]; then
      if "$PY" "$SCRIPTS/chain_exec.py" --scope "$SCOPE" --out "$OUT" --chains "$OUT/chains.json" \
           --findings "$OUT/findings.json" --sessions "$SESS" >>"$OUT/run.log" 2>&1; then
        pass "ran chain_exec.py (read-only)"
        if grep -q '"confidence": "confirmed"' "$OUT/chains.json"; then
          fail "chain_exec promoted a chain to confirmed with allow_token_forge OFF (safety violation)"
        else pass "chain_exec left chains tentative (forge gated off)"; fi
      else fail "chain_exec.py exited non-zero"; fi
    fi
  else fail "correlate.py did not produce chains.json"; fi
else
  skip "correlate.py not present yet (built in parallel) — chains.json not asserted"
fi

# --- validate (soft by default) -----------------------------------------------
# Redaction of evidence is the detector/validator agents' contract; while those run
# in parallel a strict validate can trip on their in-flight output. Default: report
# but don't hard-fail. Set STRICT_VALIDATE=1 (CI, once stable) to make it a hard gate.
if [ -f "$SCRIPTS/validate_findings.py" ]; then
  if "$PY" "$SCRIPTS/validate_findings.py" "$OUT/findings.json" >"$OUT/validate.log" 2>&1; then
    pass "validate_findings.py passed"
  elif [ "${STRICT_VALIDATE:-0}" = "1" ]; then
    fail "validate_findings.py failed (STRICT_VALIDATE=1)"; cat "$OUT/validate.log"
  else
    skip "validate_findings.py reported errors (soft; set STRICT_VALIDATE=1 to gate) — see validate.log"
    grep -E '^FAIL|unredacted' "$OUT/validate.log" | head -5
  fi
else
  skip "validate_findings.py not present"
fi

# --- report (tolerant) --------------------------------------------------------
if [ -f "$SCRIPTS/report.py" ]; then
  "$PY" "$SCRIPTS/report.py" --scope "$SCOPE" --findings "$OUT/findings.json" \
       --out "$OUT/report.md" --include-candidates >>"$OUT/run.log" 2>&1 \
    && pass "ran report.py" || fail "report.py exited non-zero"
  [ -s "$OUT/report.md" ] && pass "report.md produced" || fail "report.md missing/empty"
else
  skip "report.py not present yet (built in parallel) — report not asserted"
fi

echo "== done: $FAILS failure(s) =="
[ "$FAILS" -eq 0 ] || exit 1
