#!/usr/bin/env bash
#
# mayhem/test.sh — behavioral oracle for hashcat-utils' CPU rule engine.
#
# Runs the CLEAN (non-sanitized), dynamically-linked rules_probe (built by
# mayhem/build.sh, linking the real src/cpu_rules.c) on fixed rule+word inputs
# and asserts the EXACT mangled output. These are known-answer tests: a PATCH
# that neuters the engine to a no-op (or the verify-repo sabotage shim that
# _exit(0)s the probe) produces no/empty output, so every assertion FAILS.
#
# Emits a CTRF summary + a compact `CTRF {...}` stdout marker; exits non-zero
# iff failed>0.
set -uo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH
SRC="${SRC:-/mayhem}"
cd "$SRC"

PROBE=/mayhem/rules_probe

emit_ctrf() {
  local tool="$1" passed="$2" failed="$3" skipped="${4:-0}" pending="${5:-0}" other="${6:-0}"
  local tests=$(( passed + failed + skipped + pending + other ))
  cat > "${CTRF_REPORT:-$SRC/ctrf-report.json}" <<JSON
{
  "results": {
    "tool": { "name": "$tool" },
    "summary": {
      "tests": $tests,
      "passed": $passed,
      "failed": $failed,
      "pending": $pending,
      "skipped": $skipped,
      "other": $other
    }
  }
}
JSON
  printf 'CTRF {"results":{"tool":{"name":"%s"},"summary":{"tests":%d,"passed":%d,"failed":%d,"pending":%d,"skipped":%d,"other":%d}}}\n' \
    "$tool" "$tests" "$passed" "$failed" "$pending" "$skipped" "$other"
  [ "$failed" -eq 0 ]
}

# Fail loudly if build.sh did not produce the probe (that is a build bug, not a skip).
if [ ! -x "$PROBE" ]; then
  echo "FATAL: $PROBE missing/not executable — mayhem/build.sh did not build the oracle" >&2
  emit_ctrf "hashcat-utils-rules-kat" 0 1 0
  exit 1
fi

passed=0
failed=0

# kat <rule> <word> <expected-exact-output>
kat() {
  local rule="$1" word="$2" want="$3" got
  got="$("$PROBE" "$rule" "$word" 2>/dev/null)"
  if [ "$got" = "$want" ]; then
    echo "PASS  rule='$rule' word='$word' -> '$got'"
    passed=$((passed + 1))
  else
    echo "FAIL  rule='$rule' word='$word' : want='$want' got='$got'"
    failed=$((failed + 1))
  fi
}

# Known-answer tests against the documented rule semantics (src/cpu_rules.c):
kat 'u'   'hello'  'HELLO'   # urest: upper-case all
kat 'l'   'HeLLo'  'hello'   # lrest: lower-case all
kat 'r'   'abc'    'cba'     # reverse
kat '$1'  'hello'  'hello1'  # append '1'
kat '^x'  'abc'    'xabc'    # prepend 'x'
kat 'd'   'ab'     'abab'    # dupeword
kat ':'   'nochange' 'nochange'  # noop passthrough

emit_ctrf "hashcat-utils-rules-kat" "$passed" "$failed" 0
