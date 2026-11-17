import csv
import re
from pathlib import Path


ROOT = Path(__file__).resolve().parent
RESULTS = ROOT / "results"


def read_csv(path):
    with path.open(encoding="utf-8-sig", newline="") as stream:
        return list(csv.DictReader(stream))


def md_table(headers, rows):
    lines = ["| " + " | ".join(headers) + " |",
             "| " + " | ".join("---" for _ in headers) + " |"]
    lines.extend("| " + " | ".join(str(value).replace("|", "\\|") for value in row) + " |"
                 for row in rows)
    return "\n".join(lines)


def main():
    sections = ["# Research result tables",
                "",
                "Generated from the checked-in CSV outputs. Model/reference results are labeled separately from live-system observations.",
                ""]

    comparison = read_csv(ROOT / "research-comparison-metrics.csv")
    sections.extend(["## Prior live honeypot and provenance observations",
                     "",
                     md_table(["Metric", "Variant", "Result", "Denominator", "Evidence / interpretation"],
                              [[row["metric"], row["variant"], row["result"], row["denominator"],
                                row["interpretation"]]
                               for row in comparison if row["evidence_type"] != "literature-reported claim"]),
                     ""])

    report_dir = ROOT / "target" / "surefire-reports"
    test_totals = [0, 0, 0, 0]
    for report in report_dir.glob("*.txt"):
        match = re.search(r"Tests run: (\d+), Failures: (\d+), Errors: (\d+), Skipped: (\d+)",
                          report.read_text(encoding="utf-8", errors="replace"))
        if match:
            for index, value in enumerate(match.groups()):
                test_totals[index] += int(value)
    selfcheck_path = RESULTS / "research-selfcheck.txt"
    selfcheck_passes = sum(line.startswith("PASS ") for line in
                           selfcheck_path.read_text(encoding="utf-8-sig").splitlines()) \
        if selfcheck_path.exists() else "not captured"
    sections.extend(["## Current source verification",
                     "",
                     md_table(["Check", "Passed", "Failed/errors", "Notes"],
                              [["Maven/Surefire", test_totals[0],
                                test_totals[1] + test_totals[2],
                                "Current source; Java 25.0.5; skipped: {}".format(test_totals[3])],
                               ["ResearchSelfCheck", selfcheck_passes, 0,
                                "Standalone primitive/reference self-check; not a live-service test"]]),
                     ""])

    retained = read_csv(RESULTS / "live-retained-state.csv")
    sections.extend(["## Latest retained-data integrity snapshot",
                     "",
                     "Read-only state after the progress-aware recovery; this operational snapshot is separate from the isolated benchmark trials.",
                     "",
                     md_table(["Scope", "Source records", "Collector records", "Pending", "Unsealed",
                               "Verification", "Latest audit UTC", "Latest audit"],
                              [[row["scope"], row["source_records"], row["collector_records"],
                                row["pending_events"], row["unsealed_events"], row["verify_status"],
                                row["latest_audit_at_utc"],
                                "{}: {}".format(row["latest_audit_result"], row["latest_audit_detail"])]
                               for row in retained]),
                     ""])

    detector = read_csv(RESULTS / "live-detection-rules-summary.csv")
    sections.extend(["## Live detection-rule check",
                     "",
                     "Small curated local corpus; the counts are functionality checks, not population-level accuracy estimates.",
                     "",
                     md_table(["Positive cases", "Benign cases", "True positive", "False negative",
                               "False positive", "True negative", "Collector verification"],
                              [[row["positive_cases"], row["benign_cases"], row["true_positive"],
                                row["false_negative"], row["false_positive"], row["true_negative"],
                                row["collector_verification"]] for row in detector]),
                     ""])

    tamper = read_csv(RESULTS / "live-chain-tamper.csv")
    sections.extend(["## Isolated CHAIN-mode tamper check",
                     "",
                     md_table(["Scenario", "Integrity mode", "Forward response", "Collector records",
                               "Verification", "Outcome"],
                              [[row["scenario"], row["integrity_mode"], row["forward_response"],
                                row["collector_records"], row["verification"], row["outcome"]]
                               for row in tamper]),
                     ""])

    service = read_csv(RESULTS / "live-service-comparison.csv")
    sections.extend(["## Live service forwarding comparison",
                     "",
                     "Five events per transfer; 30 fresh-session trials per condition. Sequential exploratory measurements; confidence intervals overlap.",
                     "",
                     md_table(["Integrity mode", "KEM mode", "Trials", "Accepted", "Mean ms",
                               "95% bootstrap CI (ms)", "Median ms", "p95 ms"],
                              [[row["mode"], row["kem_mode"], row["trials"],
                                "{}/{}".format(row["trials"], row["trials"])
                                if row["all_accepted"].lower() == "true" else "not all",
                                row["mean_ms"],
                                "{}–{}".format(row["mean_ci95_low_ms"], row["mean_ci95_high_ms"]),
                                row["median_ms"], row["p95_ms"]] for row in service]),
                     ""])

    exposure = read_csv(RESULTS / "exposure_tradeoff_model.csv")
    selected = [
        min(exposure, key=lambda row: float(row["mean_exposed"])),
        max(exposure, key=lambda row: float(row["mean_exposed"])),
        next(row for row in exposure if row["epoch_size"] == "50"
             and row["seal_interval_ms"] == "500" and row["rate_per_s"] == "50.0"),
        next(row for row in exposure if row["epoch_size"] == "50"
             and row["seal_interval_ms"] == "10000" and row["rate_per_s"] == "50.0"),
    ]
    sections.extend(["## Exposure-window reference model",
                     "",
                     "2,000 Poisson-process trials per setting; this is a simulation, not a live-service measurement.",
                     "",
                     md_table(["Epoch size", "Seal interval (ms)", "Rate/s", "Mean exposed", "95% bootstrap CI",
                              "p95", "Max"],
                              [[row["epoch_size"], row["seal_interval_ms"], row["rate_per_s"],
                                row["mean_exposed"],
                                f'{row["ci95_low"]}–{row["ci95_high"]}', row["p95_exposed"],
                                row["max_exposed"]] for row in selected]),
                     ""])

    kem = read_csv(RESULTS / "kem_micro.csv")
    sections.extend(["## Java 25 cryptographic primitive microbenchmark",
                     "",
                     "30 runs × 200 operations/run, with 300 warmups. Each row is host/provider-specific; the included operation setup is described in the paper.",
                     "",
                     md_table(["Scheme", "Operation", "Mean ms", "95% bootstrap CI (ms)", "Key bytes",
                              "Payload bytes", "Wire bytes"],
                              [[row["scheme"], row["operation"], row["mean_ms"],
                                f'{row["ci95_low_ms"]}–{row["ci95_high_ms"]}', row["key_bytes"],
                                row["payload_bytes"], row["wire_bytes"]] for row in kem]),
                     ""])

    matrix_path = RESULTS / "reference_attack_matrix.csv"
    if matrix_path.exists():
        matrix = read_csv(matrix_path)
        selected_ids = {"A10_backlog_rewrite_during_outage", "A12_collector_db_consistent_rewrite",
                        "A7_tail_truncation", "A11_inject_into_unsealed_epoch"}
        sections.extend(["## Attack matrix semantic reference model",
                         "",
                         "These rows come from `ReferenceTarget`, not the live honeypot or collector.",
                         "",
                         md_table(["Mode", "Attack", "Trials", "Detected", "Rate", "95% Wilson CI"],
                                  [[row["mode"], row["attack"], row["trials"], row["detected"],
                                    row["rate"], f'{row["wilson_low"]}–{row["wilson_high"]}']
                                   for row in matrix if row["attack"] in selected_ids]),
                         ""])

    out = RESULTS / "tables.md"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text("\n".join(sections), encoding="utf-8")
    print(f"Wrote {out}")


if __name__ == "__main__":
    main()
