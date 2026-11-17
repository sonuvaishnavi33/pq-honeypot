# Research result tables

Generated from the checked-in CSV outputs. Model/reference results are labeled separately from live-system observations.

## Prior live honeypot and provenance observations

| Metric | Variant | Result | Denominator | Evidence / interpretation |
| --- | --- | --- | --- | --- |
| Encoded-indicator matches | Raw-only matcher replay | 0 | 5 curated encoded indicators | Computed by applying the configured regexes to raw stimuli without URL decoding; not a historical live run |
| Encoded-indicator matches | Raw-plus-decoded live matcher | 5 | 5 curated encoded indicators | All five matched R6 and were tagged R6D |
| Benign-control R6 alerts | Raw-only matcher replay | 0 | 5 benign encoded controls | No false matches in this small selected control set |
| Benign-control R6 alerts | Raw-plus-decoded live matcher | 0 | 5 benign encoded controls | No R6 or R6D on these five controls |
| Decoded-only provenance tags | Post-fix live matcher | 5 | 5 curated encoded indicators | R6D is zero-weight and records that matching required decoding |
| Same live SQL-like route score | Before normalization fix | 35 | 100 | R5 and R7; R6 missed |
| Same live SQL-like route score | After normalization fix with scanner user-agent | 65 | 100 | R5 R6 R6D R7; R6D adds zero score |
| Local submission success | Three sequential trials | 300 | 300 requests | Single machine, sequential local traffic |
| Client-observed median latency | Three sequential trials | 29.227 | 300 requests | Includes HTTP, rule evaluation, DB insertion, and event hashing |
| Client-observed p95 latency | Three sequential trials | 51.775 | 300 requests | Nearest-rank percentile; scheduled forwarding could overlap |
| Tamper detection | Collector | CHAIN_BROKEN | 1 controlled altered row | Altered seq 321 rejected; valid seq 321 replacement accepted |
| Post-experiment collector records | Collector | 333 | 333 expected records | 333 source records and 333 collector records; 0 pending at capture |
| Live self-checks | Updated implementation | 17 | 17 checks | All checks passed on Java 25 |
| JUnit tests | Updated implementation | 6 | 6 tests | All tests passed on Java 25 |

## Current source verification

| Check | Passed | Failed/errors | Notes |
| --- | --- | --- | --- |
| Maven/Surefire | 27 | 0 | Current source; Java 25.0.5; skipped: 0 |
| ResearchSelfCheck | 22 | 0 | Standalone primitive/reference self-check; not a live-service test |

## Latest retained-data integrity snapshot

Read-only state after the progress-aware recovery; this operational snapshot is separate from the isolated benchmark trials.

| Scope | Source records | Collector records | Pending | Unsealed | Verification | Latest audit UTC | Latest audit |
| --- | --- | --- | --- | --- | --- | --- | --- |
| post-recovery retained dataset | 374 | 374 | 0 | 0 | OK | 2026-11-16T22:49:40.000+00:00 | OK: stored 374-374 |

## Live detection-rule check

Small curated local corpus; the counts are functionality checks, not population-level accuracy estimates.

| Positive cases | Benign cases | True positive | False negative | False positive | True negative | Collector verification |
| --- | --- | --- | --- | --- | --- | --- |
| 5 | 5 | 5 | 0 | 0 | 5 | OK |

## Isolated CHAIN-mode tamper check

| Scenario | Integrity mode | Forward response | Collector records | Verification | Outcome |
| --- | --- | --- | --- | --- | --- |
| mutated-pending-event | CHAIN | CHAIN_BROKEN (seq 1-1) | 0 | OK | REJECTED |
| clean-event-after-reset | CHAIN | OK (seq 1-1) | 1 | OK | ACCEPTED |

## Live service forwarding comparison

Five events per transfer; 30 fresh-session trials per condition. Sequential exploratory measurements; confidence intervals overlap.

| Integrity mode | KEM mode | Trials | Accepted | Mean ms | 95% bootstrap CI (ms) | Median ms | p95 ms |
| --- | --- | --- | --- | --- | --- | --- | --- |
| CHAIN | ML_KEM_768 | 30 | 30/30 | 97.61 | 83.995–116.524 | 84.795 | 189.56 |
| FULL | ML_KEM_768 | 30 | 30/30 | 141.3 | 125.943–160.877 | 124.521 | 300.882 |
| FULL | X25519 | 30 | 30/30 | 137.618 | 122.541–155.985 | 116.068 | 251.551 |
| FULL | HYBRID | 30 | 30/30 | 135.125 | 122.765–149.167 | 119.21 | 209.908 |

## Exposure-window reference model

2,000 Poisson-process trials per setting; this is a simulation, not a live-service measurement.

| Epoch size | Seal interval (ms) | Rate/s | Mean exposed | 95% bootstrap CI | p95 | Max |
| --- | --- | --- | --- | --- | --- | --- |
| 100 | 500 | 5.0 | 1.569 | 1.508–1.633 | 4.0 | 9 |
| 500 | 10000 | 50.0 | 240.755 | 234.717–247.384 | 468.0 | 499 |
| 50 | 500 | 50.0 | 12.765 | 12.395–13.125 | 27.0 | 39 |
| 50 | 10000 | 50.0 | 24.696 | 24.061–25.329 | 47.0 | 49 |

## Java 25 cryptographic primitive microbenchmark

30 runs × 200 operations/run, with 300 warmups. Each row is host/provider-specific; the included operation setup is described in the paper.

| Scheme | Operation | Mean ms | 95% bootstrap CI (ms) | Key bytes | Payload bytes | Wire bytes |
| --- | --- | --- | --- | --- | --- | --- |
| X25519 | keygen | 0.23843 | 0.20966–0.27314 | 44 | 0 | 44 |
| X25519 | agree | 0.17937 | 0.17637–0.18278 | 44 | 32 | 44 |
| ECDH-P256 | keygen | 0.27198 | 0.25754–0.28698 | 91 | 0 | 91 |
| ECDH-P256 | agree | 1.23834 | 1.15584–1.33037 | 91 | 32 | 91 |
| ML-KEM-768 | keygen | 0.08591 | 0.07859–0.09392 | 1206 | 0 | 1206 |
| ML-KEM-768 | encapsulate | 0.10007 | 0.08438–0.11812 | 1206 | 1088 | 1088 |
| ML-KEM-768 | decapsulate | 0.11663 | 0.10912–0.12423 | 1206 | 1088 | 1088 |
| RSA-2048-OAEP | encrypt | 0.09845 | 0.09011–0.10750 | 294 | 256 | 256 |
| RSA-2048-OAEP | decrypt | 1.38411 | 1.30991–1.46574 | 294 | 256 | 256 |
| ML-DSA-65 | keygen | 0.23097 | 0.22175–0.24230 | 1974 | 0 | 1974 |
| ML-DSA-65 | sign | 0.79747 | 0.78010–0.81468 | 1974 | 3309 | 3309 |
| ML-DSA-65 | verify | 0.21198 | 0.20109–0.22597 | 1974 | 3309 | 3309 |

## Attack matrix semantic reference model

These rows come from `ReferenceTarget`, not the live honeypot or collector.

| Mode | Attack | Trials | Detected | Rate | 95% Wilson CI |
| --- | --- | --- | --- | --- | --- |
| NONE | A7_tail_truncation | 200 | 0 | 0.0000 | 0.0000–0.0188 |
| NONE | A10_backlog_rewrite_during_outage | 200 | 0 | 0.0000 | 0.0000–0.0188 |
| NONE | A11_inject_into_unsealed_epoch | 200 | 0 | 0.0000 | 0.0000–0.0188 |
| NONE | A12_collector_db_consistent_rewrite | 200 | 0 | 0.0000 | 0.0000–0.0188 |
| CHAIN | A7_tail_truncation | 200 | 0 | 0.0000 | 0.0000–0.0188 |
| CHAIN | A10_backlog_rewrite_during_outage | 200 | 0 | 0.0000 | 0.0000–0.0188 |
| CHAIN | A11_inject_into_unsealed_epoch | 200 | 0 | 0.0000 | 0.0000–0.0188 |
| CHAIN | A12_collector_db_consistent_rewrite | 200 | 0 | 0.0000 | 0.0000–0.0188 |
| CHAIN_ANCHOR | A7_tail_truncation | 200 | 0 | 0.0000 | 0.0000–0.0188 |
| CHAIN_ANCHOR | A10_backlog_rewrite_during_outage | 200 | 0 | 0.0000 | 0.0000–0.0188 |
| CHAIN_ANCHOR | A11_inject_into_unsealed_epoch | 200 | 0 | 0.0000 | 0.0000–0.0188 |
| CHAIN_ANCHOR | A12_collector_db_consistent_rewrite | 200 | 200 | 1.0000 | 0.9812–1.0000 |
| CHAIN_RATCHET | A7_tail_truncation | 200 | 0 | 0.0000 | 0.0000–0.0188 |
| CHAIN_RATCHET | A10_backlog_rewrite_during_outage | 200 | 200 | 1.0000 | 0.9812–1.0000 |
| CHAIN_RATCHET | A11_inject_into_unsealed_epoch | 200 | 0 | 0.0000 | 0.0000–0.0188 |
| CHAIN_RATCHET | A12_collector_db_consistent_rewrite | 200 | 0 | 0.0000 | 0.0000–0.0188 |
| FULL | A7_tail_truncation | 200 | 0 | 0.0000 | 0.0000–0.0188 |
| FULL | A10_backlog_rewrite_during_outage | 200 | 200 | 1.0000 | 0.9812–1.0000 |
| FULL | A11_inject_into_unsealed_epoch | 200 | 0 | 0.0000 | 0.0000–0.0188 |
| FULL | A12_collector_db_consistent_rewrite | 200 | 200 | 1.0000 | 0.9812–1.0000 |
