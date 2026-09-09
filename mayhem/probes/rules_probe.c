/*
 * rules_probe — a tiny dynamically-linked known-answer driver for the CPU rule
 * engine (src/cpu_rules.c). Used ONLY by mayhem/test.sh as the behavioral
 * oracle: it links the real project code (cpu_rules.c, NORMAL flags), applies
 * argv[1] (a rule program) to argv[2] (a word), and prints the exact result to
 * stdout. test.sh asserts the exact output value, so neutering the project code
 * to a no-op makes this print nothing and the oracle FAILS.
 *
 *   usage: rules_probe <rule> <word>
 */
#include <stdio.h>
#include <string.h>

#include "cpu_rules.h"   /* BLOCK_SIZE, RP_RULE_BUFSIZ, apply_rule_cpu() */

/* cpu_rules.c references `extern int max_len` (normally in rules_optimize.c). */
int max_len = 0;

int main(int argc, char *argv[])
{
  if (argc < 3) { fprintf(stderr, "usage: %s <rule> <word>\n", argv[0]); return 2; }

  char rule[RP_RULE_BUFSIZ];
  char in[BLOCK_SIZE];
  char out[BLOCK_SIZE];

  int rule_len = (int) strlen(argv[1]);
  int in_len   = (int) strlen(argv[2]);

  if (rule_len > RP_RULE_BUFSIZ) rule_len = RP_RULE_BUFSIZ;
  if (in_len   > BLOCK_SIZE)     in_len   = BLOCK_SIZE;

  if (rule_len) memcpy(rule, argv[1], (size_t) rule_len);
  if (in_len)   memcpy(in,   argv[2], (size_t) in_len);

  int out_len = apply_rule_cpu(rule, rule_len, in, in_len, out);

  if (out_len < 0) { printf("REJECT\n"); return 0; }

  fwrite(out, 1, (size_t) out_len, stdout);
  fputc('\n', stdout);
  return 0;
}
