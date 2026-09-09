/*
 * argv_main.c — argv adapter for command-line tools whose ONLY untrusted input is their
 * argument vector (no stdin, no input file): ct3_to_ntlm, generate-rules, keyspace.
 *
 * Fleet -Dmain adapter pattern: the FUZZ build compiles the upstream tool with `-Dmain=<tool>_main`
 * (fuzz build only — no upstream file is edited, the additive invariant holds) and links this file, whose
 * real main() reads the Mayhem-staged input file (`@@`), splits it into arguments — ONE
 * ARGUMENT PER LINE — and calls the renamed original with that argv. The tool's own option
 * parsing, hex decoding, mask parsing, etc. then run on attacker-controlled arguments exactly
 * as they would from a shell. Output still goes to the tool's stdout/stderr.
 *
 * ARGV_PREFIX (optional, compile-time): fixed arguments inserted before the file-derived ones. Used
 * for keyspace, which cannot run without a Markov table: build.sh generates a deterministic
 * hashcat.hcstat with the package's own hcstatgen and the prefix passes `--markov-hcstat <that file>`
 * (a read of the read-only image, like loading the binary itself), so the fuzzer drives the mask and
 * custom-charset parsing instead of failing on a missing table.
 *
 * ARGV_COUNT_MAX (optional, compile-time): a deterministic WORK budget, never a clock (#1298), for
 * generate-rules, whose first argument is a repetition count: `generate-rules number [seed]` prints
 * `number` random rules (the tool itself accepts up to 10^9), about 0.17 ms each in the sanitized
 * build (every random value is an fopen/fread/fclose of /dev/urandom), so a count above ~30,000
 * cannot finish inside the 5 s Mayhemfile `timeout:` (14 of the 136 saved server-side corpus inputs
 * ask for 30,090 to 555,555,655 rules). The rule loop reads nothing from the input except that
 * count, so a large count runs exactly the same code as a small one. When the tool WOULD run its loop (argc 2 or 3, and a count
 * inside the tool's own accepted range 1..ARGV_COUNT_TOOL_MAX) with more than ARGV_COUNT_MAX rules,
 * the adapter refuses the input with a normal exit status (ARGV_BUDGET_EXIT) and a note on stderr
 * before the tool starts. Every other argument set, including every count the tool rejects itself,
 * reaches the tool unchanged. The count is read with atoi(), the tool's own parser, on the same
 * string, so the adapter and the tool always agree on its value.
 *
 * There is deliberately NO in-process time bound here (#1298): each input is its own process (raw,
 * non-libFuzzer target), and anything the budget above does not cover is bounded by Mayhem's
 * per-test `timeout:` on the target's Mayhemfile cmd.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef TOOL_MAIN
#error "compile with -DTOOL_MAIN=<tool>_main (and the tool itself with -Dmain=<tool>_main)"
#endif

int TOOL_MAIN(int argc, char **argv);

#ifdef ARGV_COUNT_MAX
#ifndef ARGV_COUNT_TOOL_MAX
#error "ARGV_COUNT_MAX needs ARGV_COUNT_TOOL_MAX (the tool's own upper limit for the count)"
#endif
#ifdef ARGV_PREFIX
#error "ARGV_COUNT_MAX reads the count from argv[1]; it cannot be combined with ARGV_PREFIX"
#endif
#ifndef ARGV_BUDGET_EXIT
#define ARGV_BUDGET_EXIT 3 /* distinct from the adapter's own usage error (2) and the tool's statuses */
#endif
#endif

#define MAX_ARGS  64
#define MAX_BYTES 65536

int main(int argc, char **argv)
{
  static char buf[MAX_BYTES + 1];
  char *av[MAX_ARGS + 2];
  int ac = 0;

  if (argc != 2)
  {
    fprintf(stderr, "usage: %s <argv-file>   (one tool argument per line)\n", argv[0]);
    return 2;
  }

  FILE *f = fopen(argv[1], "rb");
  if (f == NULL) { perror(argv[1]); return 2; }
  size_t n = fread(buf, 1, MAX_BYTES, f);
  fclose(f);
  buf[n] = '\0';

  av[ac++] = argv[0];
#ifdef ARGV_PREFIX
  {
    static const char *const prefix[] = { ARGV_PREFIX, NULL };
    for (int i = 0; prefix[i] != NULL && ac <= MAX_ARGS; i++) av[ac++] = (char *) prefix[i];
  }
#endif
  char *p = buf;
  while (ac <= MAX_ARGS)
  {
    char *nl = strchr(p, '\n');
    if (nl != NULL) *nl = '\0';
    if (*p != '\0') av[ac++] = p;
    if (nl == NULL) break;
    p = nl + 1;
  }
  av[ac] = NULL;

#ifdef ARGV_COUNT_MAX
  if (ac == 2 || ac == 3) /* the only argument counts with which generate-rules runs its loop */
  {
    const int count = atoi(av[1]); /* the tool's own parse of the same string */

    if (count > ARGV_COUNT_MAX && count <= ARGV_COUNT_TOOL_MAX)
    {
      fprintf(stderr,
              "%s: fuzz-build work budget: %d requested, limit %d; not run "
              "(deterministic count bound, mayhem/harnesses/argv_main.c)\n",
              argv[0], count, ARGV_COUNT_MAX);
      return ARGV_BUDGET_EXIT;
    }
  }
#endif

  return TOOL_MAIN(ac, av);
}
