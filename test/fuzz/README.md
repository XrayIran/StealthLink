# Fuzzing Tests

This directory contains fuzzing tests for StealthLink parsers and decoders.

## Purpose

**Fuzzing catches panic/crash inputs, property tests catch logic bugs.**

### What Fuzzing Tests Do

Fuzzing tests use Go's native fuzzing support (`go test -fuzz`) to:
- Generate random, malformed, and edge-case inputs automatically
- Detect crashes, panics, and undefined behavior in parsers and decoders
- Find buffer overruns, integer overflows, and memory safety issues
- Discover inputs that violate basic safety assumptions (e.g., "this parser should never panic")

**Use fuzzing when:** You want to ensure code doesn't crash on unexpected inputs, especially for:
- Protocol parsers (XHTTP, FakeTCP, smux)
- Configuration parsers (YAML, JSON)
- Binary decoders and encoders
- Any code that processes untrusted external input

### What Property-Based Tests Do

Property-based tests (in `test/generators/`) use `pgregory.net/rapid` to:
- Verify logical correctness and business rules across many inputs
- Test invariants that must hold for all valid inputs (e.g., "encode then decode = identity")
- Find logic bugs that don't cause crashes but produce wrong results
- Validate complex state machines and protocol behavior

**Use property tests when:** You want to verify correctness properties, such as:
- Round-trip encoding/decoding correctness
- State machine invariants
- Mathematical properties (commutativity, associativity)
- Business logic rules that must always hold

### Why Both Are Essential

- **Fuzzing** finds safety violations (crashes, panics, memory corruption)
- **Property tests** find correctness violations (wrong results, broken invariants)
- **Together** they provide comprehensive test coverage: safety + correctness

Example: A parser might never crash (passes fuzzing) but still decode data incorrectly (fails property tests). Or it might decode correctly for valid inputs (passes property tests) but crash on malformed inputs (fails fuzzing).

Both types of tests are complementary and essential for robust code.

## Fuzz Targets

### FuzzXHTTPMetaDecode
Tests XHTTP metadata encoding/decoding for all placement types (path, query, header, cookie).

**What it catches:**
- Panics from malformed session IDs, sequence numbers, or mode strings
- URL parsing crashes with special characters
- Header/cookie injection vulnerabilities
- Path traversal attempts

**Run:**
```bash
go test -fuzz=FuzzXHTTPMetaDecode -fuzztime=30s ./test/fuzz
```

### FuzzFakeTCPPacketDecode
Tests FakeTCP packet parsing with various malformed inputs.

**What it catches:**
- Buffer overruns from incorrect length fields
- Panics from truncated packets
- Integer overflow in sequence/ack numbers
- Invalid packet types or flags

**Run:**
```bash
go test -fuzz=FuzzFakeTCPPacketDecode -fuzztime=30s ./test/fuzz
```

### FuzzSmuxFrameParse
Tests smux frame header parsing with malformed inputs.

**What it catches:**
- Panics from invalid frame headers
- Buffer overruns from incorrect length fields
- Invalid command types
- Stream ID collisions or overflows

**Run:**
```bash
go test -fuzz=FuzzSmuxFrameParse -fuzztime=30s ./test/fuzz
```

### FuzzConfigYAMLParse
Tests YAML config parsing with various malformed inputs.

**What it catches:**
- YAML parser crashes
- Infinite loops in recursive structures
- Memory exhaustion from deeply nested configs
- Type confusion errors

**Run:**
```bash
go test -fuzz=FuzzConfigYAMLParse -fuzztime=30s ./test/fuzz
```

## Running All Fuzz Tests

Run all fuzz tests with a 30-second budget per target:

```bash
make fuzz
```

Or manually:

```bash
go test -fuzz=FuzzXHTTPMetaDecode -fuzztime=30s ./test/fuzz
go test -fuzz=FuzzFakeTCPPacketDecode -fuzztime=30s ./test/fuzz
go test -fuzz=FuzzSmuxFrameParse -fuzztime=30s ./test/fuzz
go test -fuzz=FuzzConfigYAMLParse -fuzztime=30s ./test/fuzz
```

## CI Integration

Fuzzing tests run automatically in CI with a 30-second budget per target. This provides continuous fuzzing coverage without excessive CI time.

For longer fuzzing runs (e.g., overnight), increase the budget:

```bash
go test -fuzz=FuzzXHTTPMetaDecode -fuzztime=2h ./test/fuzz
```

## Corpus Management

Go's fuzzing engine automatically maintains a corpus of interesting inputs in `testdata/fuzz/`. These inputs are:

- Automatically discovered by the fuzzer
- Committed to the repository for regression testing
- Used as seeds for future fuzzing runs

To add manual seed inputs, add them to the `f.Add()` calls in each fuzz test.

## Interpreting Results

### Success
```
fuzz: elapsed: 30s, execs: 123456 (4115/sec), new interesting: 5 (total: 10)
PASS
```

### Failure (Crash Found)
```
fuzz: elapsed: 5s, execs: 12345 (2469/sec), new interesting: 2 (total: 7)
--- FAIL: FuzzXHTTPMetaDecode (5.23s)
    --- FAIL: FuzzXHTTPMetaDecode (0.00s)
        panic: runtime error: index out of range [10] with length 5
```

When a crash is found:
1. The failing input is saved to `testdata/fuzz/`
2. Fix the bug in the code
3. Re-run the fuzz test to verify the fix
4. The failing input becomes a regression test

## Best Practices

1. **Keep fuzz tests fast**: Avoid expensive operations in fuzz targets
2. **Focus on parsers/decoders**: Fuzz tests are most effective on input parsing code
3. **Use property tests for logic**: Complex business logic is better tested with property-based tests
4. **Commit interesting inputs**: The corpus in `testdata/fuzz/` should be committed
5. **Run long fuzzing sessions locally**: CI runs short sessions; run longer sessions before releases

## References

- [Go Fuzzing Documentation](https://go.dev/doc/fuzz/)
- [Fuzzing Best Practices](https://github.com/google/fuzzing/blob/master/docs/good-fuzz-target.md)
- StealthLink Property-Based Tests: `test/generators/`
