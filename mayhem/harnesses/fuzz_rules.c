/*
 * libFuzzer harness for hashcat-utils' CPU rule engine (src/cpu_rules.c).
 *
 * apply_rule_cpu() is the core of hashcat's password-mangling "rules" language
 * (the same engine driven by rules_optimize.bin). It walks a rule program byte
 * by byte and rewrites a candidate word in fixed BLOCK_SIZE (64) buffers. It is
 * a rich, self-contained parser with ~40 opcodes and no file/global state — an
 * ideal in-process target.
 *
 * Byte-in only, no file I/O: the fuzzer input is split into a rule program and
 * an input word. Layout: [1 byte rule_len][rule bytes][word bytes].
 */
#include <stdint.h>
#include <stddef.h>
#include <string.h>

#include "cpu_rules.h"   /* BLOCK_SIZE, RP_RULE_BUFSIZ, apply_rule_cpu() */

/* cpu_rules.c references `extern int max_len` (normally defined in
   rules_optimize.c). apply_rule_cpu() never touches it, but the symbol must
   resolve at link time. */
int max_len = 0;

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
  if (size < 2) return 0;

  size_t rule_len = data[0];          /* 0..255 */
  const uint8_t *p = data + 1;
  size_t avail = size - 1;

  if (rule_len > avail) rule_len = avail;

  const uint8_t *word = p + rule_len;
  size_t word_len = avail - rule_len;

  if (word_len == 0) return 0;

  /* Mirror how the real tools call the engine: words live in a BLOCK_SIZE
     buffer, rules in an RP_RULE_BUFSIZ buffer. Cap to those bounds. */
  if (word_len > BLOCK_SIZE)      word_len = BLOCK_SIZE;
  if (rule_len > RP_RULE_BUFSIZ)  rule_len = RP_RULE_BUFSIZ;

  char rule[RP_RULE_BUFSIZ];
  char in[BLOCK_SIZE];
  char out[BLOCK_SIZE];

  if (rule_len) memcpy(rule, p, rule_len);
  memcpy(in, word, word_len);

  apply_rule_cpu(rule, (int) rule_len, in, (int) word_len, out);

  return 0;
}
