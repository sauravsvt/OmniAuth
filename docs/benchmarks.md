# Benchmarks

Single source of truth for measured numbers used in the paper, the README, and release notes. Required by `.cursor/rules/benchmarks.mdc`.

## How To Add A Benchmark

1. Decide what is being measured and why the paper or release notes need it.
2. Implement using `criterion` (Rust), Go's `testing.B` (Go), or a reproducible Jest / Detox harness (mobile).
3. Add an entry to the table below with the command to reproduce it.
4. Commit the script that produced any plot to `docs/research/figures/` alongside the figure.
5. Re-run before release tags and before paper submission.

## Required Per Phase

- Phase 0: ML-KEM-768 keygen / encaps / decaps; ML-DSA-65 keygen / sign / verify; vault open / close round-trip; ZK age proof gen / verify; ZK range proof gen / verify; proof serialization size.
- Phase 1: t-of-n share generation; partial sign; threshold verify.
- Phase 2: behavioral baselines; continuous-auth tick latency.
- Phase 3: MPC fragment unlock; social recovery end-to-end.
- Phase 4: extension cold start; OS daemon idle; intercept-to-prove latency.
- Phase 5: full re-run with final parameters.

## Catalog

| Name | What It Measures | Command | Last Result | Hardware | OS | Toolchain | Date |
|------|------------------|---------|-------------|----------|----|-----------|----|
| _placeholder_ | _fill in_ | _fill in_ | _fill in_ | _fill in_ | _fill in_ | _fill in_ | _fill in_ |

## Regression Policy

If a benchmark regresses by more than 20% between runs, stop the autonomous loop, investigate, and record the cause in `docs/research/research-log.md` before continuing.
