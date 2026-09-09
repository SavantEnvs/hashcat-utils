// mayhem/lsan_off.cc — disable LeakSanitizer at BUILD time for every ASan-built target (fleet
// policy, PORTING.md). Leaks are not the bug class this fleet fuzzes for; ASan's memory-corruption
// checks and UBSan stay fully on. `-fsanitize=address` always bundles LSan in, so the sanctioned
// off-switch is this weak-interface hook linked into every sanitized binary (fuzzer, -standalone
// reproducer and CLI targets) — never a runtime LSan disable/enable wrap, never a compiled-in
// sanitizer default-options override and never a Mayhemfile ASAN_OPTIONS line (all three are gate
// FAILs; Mayhem alone owns the runtime option set).
extern "C" int __lsan_is_turned_off(void) { return 1; }
