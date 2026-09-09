#!/usr/bin/env bash
#
# mayhem/build.sh — build hashcat-utils' fuzz targets + the behavioral oracle probe.
#
# Targets (one mayhem/Mayhemfile_* each, ALL built here):
#
#   CLI tools — the package's PUBLIC interface ("a set of small utilities ... all work with STDIN and
#   STDOUT", README). 28 of the 29 tools that src/Makefile's `native:` rule builds are compiled
#   from the same sources, with the Makefile's own flags (-W -Wall -Wextra -pipe -std=gnu99 -O2,
#   -DLEN_MAX=512 for the combinators) MINUS `-march=native` (host-specific code, not reproducible) and
#   MINUS `-s` (strips the DWARF the spec requires), PLUS $SANITIZER_FLAGS + $DEBUG_FLAGS and
#   -fsanitize=fuzzer-no-link (SanitizerCoverage — Mayhem derives edge coverage from it on a raw
#   target; plain ASan+UBSan finalizes to 0 edges, cf. the chaos/cc65/qcbor/xdelta integrations).
#   Installed at /mayhem/cli/<tool>. They are RAW (non-libFuzzer, process-per-input) targets: Mayhem
#   feeds each tool's stdin, or its file argument(s) via `@@`, exactly the way the tools are used in
#   production. Three tools take their untrusted input ONLY on the command line (ct3_to_ntlm,
#   generate-rules, keyspace): the fuzz build renames upstream's main() (-Dmain=<tool>_main — fuzz
#   build only, no upstream file is edited) and links mayhem/harnesses/argv_main.c, which turns the
#   `@@` input file into argv, one argument per line (the fleet's documented -Dmain adapter pattern).
#   No target carries a wall-clock watchdog (#1298): a slow or hanging input is bounded by Mayhem's
#   own per-test timeout, the explicit `timeout:` on every raw target's Mayhemfile cmd. Two tools have
#   a KNOWN upstream blow-up that no timeout lets finish, so their fuzz builds also carry a
#   deterministic WORK budget (a count, never a clock) that ends the run with a normal exit status 3:
#   permute (n! output lines for an n-byte line) stops after 4 MiB of output
#   (mayhem/harnesses/output_budget.c), and generate-rules refuses a request for more than 250 rules
#   (ARGV_COUNT_MAX in mayhem/harnesses/argv_main.c). Details at each build step below.
#   The 29th tool, cap2hccapx, is a deprecation stub upstream (main() prints a notice and returns -1
#   before it ever touches argv[1] — src/cap2hccapx.c `if (1) {...}`): it reads no input, so it has no
#   fuzzable surface and gets no target.
#
#   fuzz_rules — in-process libFuzzer harness over src/cpu_rules.c's apply_rule_cpu() (hashcat's CPU
#   rule-mangling engine, ~40 opcodes, BLOCK_SIZE buffers), the engine behind rules_optimize. Kept
#   alongside the CLI targets: it drives the engine with attacker-controlled rule+word PAIRS, which
#   the rules_optimize CLI only exercises through its fixed built-in test words, and it carries run
#   history + a confirmed defect (mayhem/fuzz_rules/known-findings/).
#
# The PROJECT code is compiled with $SANITIZER_FLAGS AND -fsanitize=fuzzer-no-link UNCONDITIONALLY so
# the fuzzed code carries SanCov instrumentation (otherwise 0 edges in Mayhem), plus $DEBUG_FLAGS for
# DWARF<4 ($DEBUG_FLAGS comes AFTER $SANITIZER_FLAGS so its -gdwarf-3 wins over the base's plain -g).
#
# LeakSanitizer is switched off at BUILD time for every ASan-built binary via mayhem/lsan_off.cc
# (__lsan_is_turned_off hook, fleet policy — PORTING.md); ASan + UBSan stay on and halting.
#
# The oracle probe (rules_probe) is a SEPARATE clean build with the project's NORMAL flags — no
# sanitizer, no -gdwarf-3, no LSan hook — so mayhem/test.sh is an honest functional oracle.
set -euo pipefail

[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

: "${SANITIZER_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer}"
: "${DEBUG_FLAGS:=-g -gdwarf-3}"
: "${CC:=clang}" ; : "${CXX:=clang++}"
: "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"
: "${STANDALONE_FUZZ_MAIN:=/opt/mayhem/StandaloneFuzzTargetMain.c}"
: "${MAYHEM_JOBS:=$(nproc)}"

SRC="${SRC:-/mayhem}"
cd "$SRC"

SRCDIR="$SRC/src"
HDIR="$SRC/mayhem/harnesses"
PDIR="$SRC/mayhem/probes"
BUILD="$SRC/mayhem-build"
CLI="$SRC/cli"
mkdir -p "$BUILD" "$CLI"

echo "== build.sh: SANITIZER_FLAGS=[$SANITIZER_FLAGS] DEBUG_FLAGS=[$DEBUG_FLAGS] =="

# ---------------------------------------------------------------------------
# 0) LeakSanitizer build-time off-switch — linked into every sanitized binary below.
# ---------------------------------------------------------------------------
LSAN_OFF="$BUILD/lsan_off.o"
$CXX $SANITIZER_FLAGS $DEBUG_FLAGS -c "$SRC/mayhem/lsan_off.cc" -o "$LSAN_OFF"

# ---------------------------------------------------------------------------
# 1) Instrument the PROJECT library: cpu_rules.c (used by fuzz_rules and rules_optimize).
# ---------------------------------------------------------------------------
$CC $SANITIZER_FLAGS $DEBUG_FLAGS -fsanitize=fuzzer-no-link \
    -I"$SRCDIR" -c "$SRCDIR/cpu_rules.c" -o "$BUILD/cpu_rules.san.o"

# ---------------------------------------------------------------------------
# 2) fuzz_rules — the libFuzzer binary, and its standalone run-once reproducer.
# ---------------------------------------------------------------------------
$CC $SANITIZER_FLAGS $DEBUG_FLAGS -fsanitize=fuzzer-no-link \
    -I"$SRCDIR" -c "$HDIR/fuzz_rules.c" -o "$BUILD/fuzz_rules.o"

$CC $SANITIZER_FLAGS $DEBUG_FLAGS $LIB_FUZZING_ENGINE \
    "$BUILD/fuzz_rules.o" "$BUILD/cpu_rules.san.o" "$LSAN_OFF" \
    -o /mayhem/fuzz_rules

# Standalone (non-fuzzer) reproducer: same harness object, StandaloneFuzzTargetMain
# driver (a C file) instead of the libFuzzer engine.
$CC $SANITIZER_FLAGS $DEBUG_FLAGS -x c -c "$STANDALONE_FUZZ_MAIN" \
    -o "$BUILD/standalone_main.o"
$CC $SANITIZER_FLAGS $DEBUG_FLAGS \
    "$BUILD/standalone_main.o" "$BUILD/fuzz_rules.o" "$BUILD/cpu_rules.san.o" "$LSAN_OFF" \
    -o /mayhem/fuzz_rules-standalone

# ---------------------------------------------------------------------------
# 3) CLI tools — sanitized + SanCov-instrumented builds of every tool src/Makefile ships
#    (its `native:` list), one raw Mayhem target each at /mayhem/cli/<tool>.
#    Flags = the Makefile's CFLAGS minus -march=native and minus -s (see header).
# ---------------------------------------------------------------------------
CLI_CFLAGS="-W -Wall -Wextra -pipe -std=gnu99 -O2 $SANITIZER_FLAGS $DEBUG_FLAGS -fsanitize=fuzzer-no-link -I$SRCDIR"

# (a) tools that read stdin and/or a file argument — the Makefile's own sources + flags, each linked
#     with its OWN upstream main() (no rename, no wrapper), so Mayhem drives the tool's real
#     command-line interface. A slow input is bounded by the Mayhemfile's per-test `timeout:` (5 s;
#     60 s for morph, which pays a fixed ~0.5 s sanitized key-table build per execution — see
#     Mayhemfile_morph), not in-process — except permute's output budget:
#     permute prints all n! permutations of every line, so a 16-byte line is ~2*10^13 lines and can
#     never finish (a saved corpus input like that failed Mayhem's start-up check, permute run #5).
#     Its fuzz build renames the tool's ONE output call (fwrite() in out_flush()) with
#     -Dfwrite=hcu_budget_fwrite and links mayhem/harnesses/output_budget.c, which forwards every
#     write to the real fwrite() and ends the process with exit status 3 once PERMUTE_OUTPUT_BUDGET
#     bytes have been printed. This budget counts OUTPUT, not line length: lines of ~2-8 KiB overflow
#     out_push()'s stack buffer within a few permutations (ASan, src/permute.c:46), and a line-length
#     cap would hide that bug; the overflow, and the 1-byte-line one at src/permute.c:81, both fire
#     before the line's first flush, which is the only place the budget is checked.
PERMUTE_OUTPUT_BUDGET=4194304   # 4 MiB >= 9!*10 bytes: any single line of up to 9 bytes still prints all its permutations
$CC $CLI_CFLAGS -DOUTPUT_BUDGET_BYTES="${PERMUTE_OUTPUT_BUDGET}ULL" -c "$HDIR/output_budget.c" -o "$BUILD/output_budget.o"

STREAM_TOOLS="cleanup-rules combinator combinator3 combinatorX combipow cutb expander gate
hcstatgen hcstat2gen len mli2 morph ngramX permute permute_exist prepare req-include req-exclude rli rli2
rules_optimize splitlen strip-bsr strip-bsn"
for t in $STREAM_TOOLS; do
  extra=""
  case "$t" in
    combinator|combinator3) extra="-DLEN_MAX=512" ;;   # src/Makefile: COMBINATOR_LEN_MAX := 512
    # combinatorX: same LEN_MAX, plus ONE narrowly relaxed UBSan check. Its output loop does
    # memcpy(dst, ptr_in[i], 0) for every unused --file3..--file8 slot (ptr_in[i] == NULL), which trips
    # UBSan's `nonnull-attribute` on EVERY combination — a benign zero-length copy, not a memory bug —
    # and, halting, would abort every single input. Relax exactly that check for this one tool
    # (PORTING.md "benign UB that floods under halting UBSan"); ASan + the rest of UBSan stay halting.
    combinatorX) extra="-DLEN_MAX=512 -fno-sanitize=nonnull-attribute" ;;
    permute) extra="-Dfwrite=hcu_budget_fwrite" ;;     # output budget, see (a) above
  esac
  # shellcheck disable=SC2086
  $CC $CLI_CFLAGS $extra -c "$SRCDIR/$t.c" -o "$BUILD/$t.tool.o"
  objs="$BUILD/$t.tool.o"
  [ "$t" = rules_optimize ] && objs="$objs $BUILD/cpu_rules.san.o"   # Makefile links cpu_rules.c too
  [ "$t" = permute ] && objs="$objs $BUILD/output_budget.o"
  # shellcheck disable=SC2086
  $CC $SANITIZER_FLAGS $DEBUG_FLAGS -fsanitize=fuzzer-no-link $objs "$LSAN_OFF" -o "$CLI/$t"
done
# The output budget must really be wired: permute's object has to call hcu_budget_fwrite and no plain
# fwrite() (a future upstream change to its output path would otherwise silently drop the budget).
permute_syms="$(nm "$BUILD/permute.tool.o")"
if ! grep -qE '^ +U hcu_budget_fwrite$' <<<"$permute_syms" || grep -qE '^ +U fwrite$' <<<"$permute_syms"; then
  echo "FATAL: src/permute.c output no longer goes through hcu_budget_fwrite — re-check the output budget" >&2; exit 1
fi

# (b) tools whose only untrusted input is argv — upstream main() renamed in the FUZZ build only and
#     wrapped by the argv adapter (mayhem/harnesses/argv_main.c: `@@` file -> one argument per line).
#     keyspace cannot run at all without a Markov table (it exits on a missing hcstat before parsing
#     the mask), so build.sh generates a deterministic one with the package's own hcstatgen from a
#     fixed wordlist, and keyspace's adapter passes `--markov-hcstat <that file>` ahead of the fuzzed
#     arguments (ARGV_PREFIX) — the mask / custom-charset parsing is then what Mayhem drives.
#     generate-rules `number [seed]` prints `number` random rules (the tool accepts up to 10^9, ~0.17 ms
#     each sanitized), so a count above ~30,000 cannot finish inside the 5 s `timeout:`. Its adapter is built
#     with a deterministic count budget (ARGV_COUNT_MAX): a request the tool would run with more than
#     GENRULES_COUNT_MAX rules is refused with exit status 3 before the tool starts. Counts the tool
#     rejects itself (<1 or >ARGV_COUNT_TOOL_MAX, the limit in src/generate-rules.c) still reach it.
#     The loop reads nothing from the input except that count, so no input-driven code is cut off.
GENRULES_COUNT_MAX=250   # ~0.05 s sanitized, ~0.4 s even under strace (every rule is ~40 syscalls): far below the 5 s timeout
grep -qF '(num > 1000000000)' "$SRCDIR/generate-rules.c" || {
  echo "FATAL: src/generate-rules.c rule-count limit changed — update ARGV_COUNT_TOOL_MAX below" >&2; exit 1; }
HCSTAT="$CLI/hashcat.hcstat"
printf '%s\n' password 123456 qwerty letmein dragon baseball iloveyou trustno1 sunshine master welcome \
  shadow ashley football jesus michael ninja mustang password1 admin secret P@ssw0rd 'Summer2024!' > "$BUILD/hcstat-words.txt"
"$CLI/hcstatgen" "$HCSTAT" < "$BUILD/hcstat-words.txt" >/dev/null
[ -s "$HCSTAT" ] || { echo "FATAL: hcstatgen produced no $HCSTAT" >&2; exit 1; }

ARGV_TOOLS="ct3_to_ntlm generate-rules keyspace"
for t in $ARGV_TOOLS; do
  m="$(printf '%s' "$t" | tr '-' '_')_main"
  prefix=""
  [ "$t" = keyspace ] && prefix="-DARGV_PREFIX=\"--markov-hcstat\",\"$HCSTAT\""   # ~0.5 s fixed table setup per exec (Mayhemfile timeout: 60)
  [ "$t" = generate-rules ] && prefix="-DARGV_COUNT_MAX=$GENRULES_COUNT_MAX -DARGV_COUNT_TOOL_MAX=1000000000"   # count budget, see (b) above
  $CC $CLI_CFLAGS -Dmain="$m" -c "$SRCDIR/$t.c" -o "$BUILD/$t.tool.o"
  # shellcheck disable=SC2086
  $CC $CLI_CFLAGS -DTOOL_MAIN="$m" $prefix -c "$HDIR/argv_main.c" -o "$BUILD/$t.argv.o"
  $CC $SANITIZER_FLAGS $DEBUG_FLAGS -fsanitize=fuzzer-no-link \
      "$BUILD/$t.tool.o" "$BUILD/$t.argv.o" "$LSAN_OFF" -o "$CLI/$t"
done

# Every declared Mayhemfile target binary must exist — fail the build otherwise (not just the first).
for mf in "$SRC"/mayhem/Mayhemfile_*; do
  bin="$(grep -m1 -E 'cmd:' "$mf" | sed 's/.*cmd:[[:space:]]*//' | awk '{print $1}')"
  [ -x "$bin" ] || { echo "FATAL: $(basename "$mf") target $bin was not built" >&2; exit 1; }
done

# ---------------------------------------------------------------------------
# 4) Oracle probe — CLEAN build (NORMAL flags; NO sanitizer, NO -gdwarf-3, NO LSan hook),
#    dynamically linked so mayhem/test.sh's LD_PRELOAD sabotage check bites.
# ---------------------------------------------------------------------------
$CC -O2 -std=gnu99 -I"$SRCDIR" \
    "$PDIR/rules_probe.c" "$SRCDIR/cpu_rules.c" \
    -o /mayhem/rules_probe

# Guard the oracle's honesty: it MUST be dynamically linked (else the neuter
# shim can't reach it and the oracle silently degrades to a false green).
if ! file /mayhem/rules_probe | grep -q 'dynamically linked'; then
  echo "FATAL: rules_probe is not dynamically linked — oracle would be un-neuterable" >&2
  file /mayhem/rules_probe >&2
  exit 1
fi

echo "== build.sh: OK =="
ls -l /mayhem/fuzz_rules /mayhem/fuzz_rules-standalone /mayhem/rules_probe
ls -l "$CLI"
