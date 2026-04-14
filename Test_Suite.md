# Selftest only
./forge_test_suite --selftest

# Execute a .fozbin contract
./forge_test_suite --file token.fozbin

# Benchmark 1M iterations, project 16-core TPS
./forge_test_suite --file token.fozbin --bench 1000000 --threads 16

# Raw hex bytecode
./forge_test_suite --hex "930002002001007300000000"

# Full suite: selftest + exec + bench → JSON for CI
./forge_test_suite --all token.fozbin --bench 50000 --threads 8 --json