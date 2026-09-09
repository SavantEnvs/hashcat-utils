/*
 * output_budget.c — deterministic OUTPUT budget for the `permute` CLI target (#1308, follow-up of
 * #1298). It counts bytes, never time: the same input always stops at exactly the same point.
 *
 * Why: permute prints every permutation of every input line — n! lines for an n-byte line (a
 * 16-byte line is ~2*10^13 lines). Such an input cannot finish inside any per-test timeout, and one
 * saved in the server-side corpus made Mayhem's start-up check fail ("Your target did not
 * terminate", permute run #5).
 *
 * How: mayhem/build.sh compiles the UNMODIFIED src/permute.c with -Dfwrite=hcu_budget_fwrite (fuzz
 * build only; no upstream file is edited), so the tool's single output call — fwrite() in
 * out_flush() — goes through hcu_budget_fwrite() below. It forwards to the real fwrite() and counts
 * the bytes. When a flush would take the total past OUTPUT_BUDGET_BYTES, the process ends with a
 * NORMAL exit (status OUTPUT_BUDGET_EXIT) and a one-line note on stderr instead of printing more.
 * The tool's main(), input reading and permutation code are untouched.
 *
 * Why an output budget and not a cap on the line length: permute has real memory bugs on LONG
 * lines. out_push() appends each permutation to an 8 KiB stack buffer and only flushes once fewer
 * than 300 bytes are left, so a line of roughly 2 KiB to 7.9 KiB overflows that buffer within a few
 * permutations (ASan stack-buffer-overflow / memcpy-param-overlap at src/permute.c:46, reached in
 * under a second by the original build). Rejecting long lines up front would hide those. With this
 * budget every line still starts, and a line's out_push() overflow happens before that line's
 * first flush — the only place the budget is checked — so no in-line crash is ever pre-empted. The
 * known 1-byte-line overflow in next_permutation() (src/permute.c:81) likewise fires before any
 * flush. The budget only ends inputs that have ALREADY printed OUTPUT_BUDGET_BYTES.
 *
 * Bound: every permutation pushes at least 2 bytes (a character and '\n'), so a run does at most
 * ~OUTPUT_BUDGET_BYTES/2 permutations plus work linear in the input size. 4 MiB covers the complete
 * output of any single line of up to 9 bytes (9! * 10 = 3,628,800 bytes); reaching the budget takes
 * about 0.15 s in the sanitized build, far below the Mayhemfile's 5 s `timeout:`.
 */
#include <stdio.h>
#include <stdlib.h>

#ifndef OUTPUT_BUDGET_BYTES
#define OUTPUT_BUDGET_BYTES 4194304ULL /* 4 MiB; mayhem/build.sh passes the value explicitly */
#endif

#ifndef OUTPUT_BUDGET_EXIT
#define OUTPUT_BUDGET_EXIT 3 /* distinct from permute's own statuses (0, and 255 for a usage error) */
#endif

size_t hcu_budget_fwrite(const void *ptr, size_t size, size_t nmemb, FILE *stream);

static unsigned long long hcu_emitted; /* bytes handed to fwrite() so far; never above the budget */

size_t hcu_budget_fwrite(const void *ptr, size_t size, size_t nmemb, FILE *stream)
{
  size_t bytes;

  if (__builtin_mul_overflow(size, nmemb, &bytes) ||
      (unsigned long long) bytes > (unsigned long long) OUTPUT_BUDGET_BYTES - hcu_emitted)
  {
    fprintf(stderr,
            "fuzz-build output budget reached: %llu bytes printed, next write of %zu bytes would pass "
            "the %llu-byte limit; stopping (deterministic work bound, mayhem/harnesses/output_budget.c)\n",
            hcu_emitted, bytes, (unsigned long long) OUTPUT_BUDGET_BYTES);
    exit(OUTPUT_BUDGET_EXIT);
  }

  hcu_emitted += bytes;

  return fwrite(ptr, size, nmemb, stream);
}
