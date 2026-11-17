# Research limitations and implementation status

## What the live experiments establish

- The Java 25.0.5 Maven suite passed 27/27 tests in the manuscript-revision verification run.
- A loopback detector check classified 5/5 selected encoded indicators with R6/R6D and 0/5 benign controls with R6. One malformed-percent benign input separately raised R6M; this is not counted as an R6 injection match.
- All ten detection-test events were forwarded in two batches and the collector reported `/api/verify` status `OK`.
- Four isolated live-service conditions each completed 30/30 fresh-session transfers; all 600 events were accepted and verified. Mean client-observed latency ranged from 97.610 ms (CHAIN/ML-KEM-768) to 141.300 ms (FULL/ML-KEM-768). The 95% bootstrap intervals overlap; the design does not establish a performance ranking.
- A controlled CHAIN-mode mutation of a pending event was rejected as `CHAIN_BROKEN`. A clean event after resetting only the isolated demo databases was accepted and verified.
- The historical R6D capture ended with 333 records and was kept separate from newer experiments on 8081/9091. A later progress-aware recovery on the retained 8080/9090 databases preserved existing rows, forwarded sequences 372–373, and a subsequent read-only snapshot observed 374 source records = 374 collector records, 0 pending, 0 unsealed, and `/api/verify` `OK`. The new record count is an operational snapshot, not a benchmark result.

## Important limits

- Detection used only five hand-selected positive and five benign inputs. The planned 1,000-positive / 500-benign evaluation, an independent public corpus, and population-level accuracy estimates have not been completed.
- The service benchmark is single-host, sequential, and exploratory. It measures five-event fresh-session forwarding, not sustained throughput, concurrent load, resource use, or a controlled causal comparison. Integrity mode and KEM mode are not independently isolated in every comparison.
- Live FULL-mode happy-path acceptance was observed, but targeted negative tests for forged seals/checkpoints, replay, rollback, re-chaining, and tail truncation have not been completed. The broad attack matrix remains a reference model; its percentages are not service measurements.
- The chain tamper experiment exercised the CHAIN mode. It is not evidence that the epoch ratchet or ML-DSA checkpoint mechanisms withstand an adaptive attacker.
- The Java tests and local experiments are not a formal cryptographic or penetration review. The PSK-based handshake and local key/database configuration are prototype choices, not a production deployment recommendation.
- No result demonstrates superiority over the cited honeypot or another system. The datasets, workloads, and environments are not comparable.

## Reproducible artifacts

- `results/live-detection-rules.csv` and `results/live-detection-rules-summary.csv` contain the isolated live detector run.
- `results/live-chain-tamper.csv` contains the live CHAIN-mode tamper rejection and clean-state acceptance.
- The four `results/live-service-*-summary.csv` files and corresponding raw trial CSVs contain the 30-trial service measurements.
- `results/live-service-comparison.csv` and `results/live-service-comparison.png` summarize and plot those measurements.
- `results/live-retained-state.csv` records the latest read-only retained-data snapshot.
- `research-figures/figure-8-integrity-backfill.png` illustrates the progress-aware retained-data recovery; earlier rejected backfill attempts remain in the audit.
- `reproduce-live-detection.ps1`, `reproduce-live-chain-tamper.ps1`, and `reproduce-live-service-benchmark.ps1` reproduce the corresponding local runs. They require demo mode and must only target the dedicated research databases.
- `generate-live-service-figure.py` rebuilds the comparison CSV and figure from the four benchmark summaries.

See `research-paper.md` for methods, tables, figure, and interpretation. Do not treat synthetic exposure/attack model output as empirical service evidence.
