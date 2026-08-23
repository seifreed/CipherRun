# Remote timing methodology

CipherRun treats remote timing as supporting evidence, not proof of a TLS padding
oracle. Network scheduling, routing, congestion, and rate limiting can dominate the
signal. A positive remote Sleeping POODLE signal is therefore reported as
**inconclusive** and requires confirmation from a controlled, low-latency network.

## Sampling

- Sleeping POODLE collects up to 30 interleaved valid-padding and invalid-padding
  observations, with 150 ms between pairs.
- At least 10 observations are required in each population.
- Lucky13 is reported from cryptographic prerequisites only; CipherRun does not claim
  to confirm Lucky13 from a remote timing oracle.

## Published statistics

Each population reports its arithmetic mean, median, nearest-rank p95, population
standard deviation, sample standard error, sample count, and a normal-approximation
95% confidence interval for the mean. The difference of means reports
`SE(diff) = hypot(SE(valid), SE(invalid))` and `diff +/- 1.96 * SE(diff)`.

## Decision gates

All gates must pass before a timing signal is emitted:

1. Both populations contain at least 10 samples.
2. Both coefficients of variation are below 0.5; otherwise the result is inconclusive.
3. The absolute mean difference exceeds 15 ms. When the valid population coefficient
   of variation exceeds 0.3, this threshold becomes `15 * (1 + CV)` milliseconds.
4. The difference exceeds its 95% confidence margin plus a 10 ms noise floor.

Failure to collect enough samples or excessive variance yields an inconclusive result.
A signal that passes every gate is still inconclusive when measured remotely; it is
never promoted to a confirmed vulnerability without controlled validation.
