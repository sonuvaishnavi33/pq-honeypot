import csv
from pathlib import Path

import matplotlib

matplotlib.use("Agg")

import matplotlib.pyplot as plt


ROOT = Path(__file__).resolve().parent
RESULTS = ROOT / "results"
CONDITIONS = (
    ("CHAIN", "ML_KEM_768", "CHAIN\nML-KEM-768", "#6B7280"),
    ("FULL", "ML_KEM_768", "FULL\nML-KEM-768", "#2563EB"),
    ("FULL", "X25519", "FULL\nX25519", "#059669"),
    ("FULL", "HYBRID", "FULL\nHybrid", "#D97706"),
)
FIELDS = (
    "mode",
    "kem_mode",
    "trials",
    "all_accepted",
    "mean_ms",
    "mean_ci95_low_ms",
    "mean_ci95_high_ms",
    "median_ms",
    "p95_ms",
    "min_ms",
    "max_ms",
)


def load_summary(mode, kem_mode):
    path = RESULTS / "live-service-{}-{}-summary.csv".format(mode, kem_mode)
    with path.open("r", encoding="utf-8-sig", newline="") as stream:
        rows = list(csv.DictReader(stream))
    if len(rows) != 1:
        raise ValueError("{} must contain exactly one summary row".format(path))
    row = rows[0]
    if row["mode"] != mode or row["kem_mode"] != kem_mode:
        raise ValueError("{} contains a mismatched condition".format(path))
    if row["all_accepted"].lower() != "true":
        raise ValueError("{} includes an unaccepted transfer".format(path))
    if int(row["trials"]) < 1:
        raise ValueError("{} has no trials".format(path))
    return {field: row[field] for field in FIELDS}


def main():
    summaries = []
    labels = []
    colors = []
    for mode, kem_mode, label, color in CONDITIONS:
        summaries.append(load_summary(mode, kem_mode))
        labels.append(label)
        colors.append(color)

    comparison_path = RESULTS / "live-service-comparison.csv"
    with comparison_path.open("w", encoding="utf-8", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=FIELDS)
        writer.writeheader()
        writer.writerows(summaries)

    means = [float(row["mean_ms"]) for row in summaries]
    lows = [float(row["mean_ci95_low_ms"]) for row in summaries]
    highs = [float(row["mean_ci95_high_ms"]) for row in summaries]
    lower_errors = [mean - low for mean, low in zip(means, lows)]
    upper_errors = [high - mean for mean, high in zip(means, highs)]
    counts = [int(row["trials"]) for row in summaries]

    figure, axis = plt.subplots(figsize=(8.4, 5.2))
    figure.subplots_adjust(bottom=0.22, top=0.88)
    positions = list(range(len(summaries)))
    axis.bar(positions, means, color=colors, width=0.62, edgecolor="#1F2937", linewidth=0.6)
    axis.errorbar(
        positions,
        means,
        yerr=[lower_errors, upper_errors],
        fmt="none",
        ecolor="#111827",
        elinewidth=1.4,
        capsize=5,
    )
    for position, mean, count in zip(positions, means, counts):
        axis.annotate(
            "{:.1f} ms".format(mean),
            (position, mean),
            xytext=(0, 9),
            textcoords="offset points",
            ha="center",
            fontsize=9,
        )

    axis.set_xticks(positions)
    axis.set_xticklabels(labels)
    axis.set_ylabel("Fresh-session forwarding latency (ms)")
    axis.set_title("Live service forwarding latency by integrity/KEM mode")
    axis.grid(axis="y", alpha=0.25, linewidth=0.7)
    axis.set_axisbelow(True)
    axis.spines["top"].set_visible(False)
    axis.spines["right"].set_visible(False)
    axis.set_ylim(0, max(highs) * 1.24)
    figure.text(
        0.5,
        0.025,
        "5 events/transfer; n={} per condition; error bars are 95% bootstrap CIs. "
        "Exploratory single-host measurements.".format(counts[0]),
        ha="center",
        fontsize=8,
        color="#374151",
    )

    figure_path = RESULTS / "live-service-comparison.png"
    figure.savefig(figure_path, dpi=220, bbox_inches="tight")
    plt.close(figure)
    print("Comparison data: {}".format(comparison_path))
    print("Figure: {}".format(figure_path))


if __name__ == "__main__":
    main()
