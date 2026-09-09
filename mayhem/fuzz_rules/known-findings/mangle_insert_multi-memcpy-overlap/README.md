# Finding: memcpy-param-overlap in `mangle_insert_multi` (CPU rule engine)

- **Target:** `fuzz_rules` (harness over `src/cpu_rules.c` `apply_rule_cpu`)
- **Type:** `AddressSanitizer: memcpy-param-overlap` (undefined behavior; source/dest overlap in `memcpy`)
- **Reproducer:** `reproducer.bin` (33 bytes). Layout is `[1-byte rule_len][rule][word]`:
  the first byte `0x0b` (=11) makes an 11-byte rule program `:X2A2Y2Y\xb7Y`, and the
  remainder is the word. The `X` op (`RULE_OP_MANGLE_EXTRACT_MEMORY`) is the trigger.

## Crash site
```
#0 __asan_memcpy
#1 mangle_insert_multi   src/cpu_rules.c:269
#2 apply_rule_cpu        src/cpu_rules.c:843   (case RULE_OP_MANGLE_EXTRACT_MEMORY, 'X')
#3 LLVMFuzzerTestOneInput
```

## Cause
The `X` rule (extract-from-memory) calls `mangle_insert_multi()` to splice a slice of the
memorized word (`mem`) back into `out`. `mangle_insert_multi` does a raw `memcpy` whose
source and destination ranges can **overlap** within the same 64-byte `mem`/`out` buffer
for adversarial position/length arguments. `memcpy` with overlapping ranges is undefined
behavior (ASan flags it; on some libc/opt combos it also corrupts data). Related overflow
crashes in the same engine surface here too (the mangle ops write into fixed `BLOCK_SIZE`
= 64 buffers with incomplete bounds checks).

## Impact
Reachable from untrusted rule files (`-r` rules fed to hashcat / rules_optimize). UB /
potential buffer corruption while applying a crafted rule to a candidate word.

## One-line fix
Use `memmove` instead of `memcpy` in `mangle_insert_multi` (src/cpu_rules.c:269) so
overlapping in-buffer splices are well-defined, and bound the computed copy length to
`BLOCK_SIZE`.

## Reproduce
```
/mayhem/fuzz_rules-standalone mayhem/fuzz_rules/known-findings/mangle_insert_multi-memcpy-overlap/reproducer.bin
```
This is a REPRODUCER, deliberately kept OUT of `testsuite/` (a crash seed would abort
Mayhem's per-run sanity replay).
