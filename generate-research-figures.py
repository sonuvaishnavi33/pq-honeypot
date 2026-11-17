import csv
import re
from pathlib import Path
from urllib.parse import unquote_plus

import matplotlib.pyplot as plt
from matplotlib.patches import FancyArrowPatch, FancyBboxPatch


ROOT = Path(__file__).resolve().parent
OUT = ROOT / "research-figures"
OUT.mkdir(exist_ok=True)

BLUE = "#176B87"
TEAL = "#35A7A0"
ORANGE = "#E18A3B"
RED = "#BF4B4B"
INK = "#263238"
MUTED = "#65737E"
GRID = "#DCE3E7"

plt.rcParams.update({
    "font.family": "DejaVu Sans",
    "font.size": 10,
    "axes.titlesize": 14,
    "axes.labelsize": 11,
    "figure.facecolor": "white",
    "axes.facecolor": "white",
    "savefig.facecolor": "white",
})


def save(fig, name):
    fig.savefig(OUT / name, dpi=220, bbox_inches="tight")
    plt.close(fig)


def architecture():
    fig, ax = plt.subplots(figsize=(13, 4.7))
    ax.set_xlim(0, 13)
    ax.set_ylim(0, 4.6)
    ax.axis("off")

    nodes = [
        (0.25, 1.65, 1.55, 1.55, "Local test\nstimulus", "#EEF5F8", BLUE),
        (2.15, 1.25, 2.45, 2.35, "Honeypot rules\nR1–R8\n\nR6: injection\nR6D: decoded-only\n(zero weight)", "#E8F4F2", TEAL),
        (4.95, 1.35, 2.2, 2.15, "Event record\n\nRule evidence in\ncanonical hash chain\n\nEpoch seals\nSigned checkpoints", "#EEF5F8", BLUE),
        (7.5, 1.25, 2.35, 2.35, "Protected transfer\n\nML-KEM-768 /\nX25519 / hybrid\nHKDF-SHA-256\nAES-256-GCM", "#FFF4E8", ORANGE),
        (10.2, 1.25, 2.45, 2.35, "Collector verification\n\nauthentication\nsequence + hash chain\nseal / checkpoint checks", "#F8EEEE", RED),
    ]
    for x, y, w, h, text, fill, edge in nodes:
        box = FancyBboxPatch((x, y), w, h, boxstyle="round,pad=0.08,rounding_size=0.12",
                             linewidth=1.6, edgecolor=edge, facecolor=fill)
        ax.add_patch(box)
        ax.text(x + w / 2, y + h / 2, text, ha="center", va="center", color=INK,
                fontsize=10 if w > 2 else 9.5, linespacing=1.25)
    for start, end in [((1.8, 2.43), (2.15, 2.43)),
                       ((4.6, 2.43), (4.95, 2.43)),
                       ((7.15, 2.43), (7.5, 2.43)),
                       ((9.85, 2.43), (10.2, 2.43))]:
        ax.add_patch(FancyArrowPatch(start, end, arrowstyle="-|>", mutation_scale=14,
                                     color=MUTED, linewidth=1.5))
    ax.text(6.5, 0.62,
            "Latest retained-data snapshot: 374 source = 374 collector; 0 pending / unsealed; verify OK",
            ha="center", va="center", color=INK, fontsize=11, weight="bold")
    ax.text(6.5, 0.25, "Single-host prototype evaluation; not a deployment or security certification",
            ha="center", va="center", color=MUTED, fontsize=9)
    save(fig, "figure-1-system-workflow.png")


def latency():
    rows = list(csv.DictReader((ROOT / "research-latency-samples.csv").open(
        encoding="utf-8-sig", newline="")))
    trials = sorted({int(row["trial"]) for row in rows})
    values = [[float(row["latency_ms"]) for row in rows if int(row["trial"]) == trial]
              for trial in trials]
    fig, ax = plt.subplots(figsize=(8, 5))
    bp = ax.boxplot(values, labels=["Trial 1", "Trial 2", "Trial 3"], patch_artist=True,
                    showfliers=True, medianprops={"color": "white", "linewidth": 2})
    for box, color in zip(bp["boxes"], [BLUE, TEAL, ORANGE]):
        box.set_facecolor(color)
        box.set_alpha(0.82)
    for whisker in bp["whiskers"]:
        whisker.set_color(MUTED)
    for cap in bp["caps"]:
        cap.set_color(MUTED)
    for flier in bp["fliers"]:
        flier.set_markerfacecolor(RED)
        flier.set_markeredgecolor(RED)
        flier.set_alpha(0.65)
    ax.set_ylabel("Client-observed latency (ms)")
    ax.set_title("Sequential local event-submission latency")
    ax.grid(axis="y", color=GRID, linewidth=0.8)
    ax.set_axisbelow(True)
    ax.text(0.98, 0.96, "n = 100 per trial\ncombined median = 29.227 ms\ncombined p95 = 51.775 ms",
            transform=ax.transAxes, ha="right", va="top",
            bbox={"boxstyle": "round,pad=0.45", "facecolor": "white", "edgecolor": GRID},
            color=INK, fontsize=9)
    ax.text(0.01, -0.18,
            "Includes local HTTP, rule evaluation, DB insertion and hashing; scheduled forwarding could overlap.",
            transform=ax.transAxes, color=MUTED, fontsize=8.5)
    save(fig, "figure-2-latency.png")


def matcher_patterns():
    patterns = [
        re.compile(r"union\s+select", re.I),
        re.compile(r"<script", re.I),
        re.compile(r"\.\./"),
        re.compile(r";\s*(cat|ls|wget|curl)\s", re.I),
        re.compile(r"'\s*or\s+'?1'?='?1", re.I),
    ]
    return patterns


def provenance():
    with (ROOT / "research-provenance-corpus.csv").open(encoding="utf-8-sig", newline="") as f:
        rows = list(csv.DictReader(f))
    patterns = matcher_patterns()
    groups = {"attack": [], "benign": []}
    for row in rows:
        raw = row["query"]
        decoded = unquote_plus(raw, encoding="utf-8", errors="replace")
        raw_match = any(p.search(raw) for p in patterns)
        decoded_match = any(p.search(decoded) for p in patterns)
        groups[row["label"]].append((raw_match, decoded_match))

    raw_attack = sum(raw for raw, _ in groups["attack"])
    decoded_attack = sum(decoded for _, decoded in groups["attack"])
    raw_benign = sum(raw for raw, _ in groups["benign"])
    decoded_benign = sum(decoded for _, decoded in groups["benign"])

    fig, axes = plt.subplots(1, 2, figsize=(10, 4.7), sharey=True)
    categories = ["Curated attacks\nmatched", "Benign controls\nflagged"]
    variants = [
        ("Raw-only replay", [raw_attack, raw_benign], BLUE),
        ("Raw + decoded live", [decoded_attack, decoded_benign], TEAL),
    ]
    x = [0, 1]
    width = 0.32
    for ax, idx, title in [(axes[0], 0, "Attack detection"), (axes[1], 1, "Benign-control alerts")]:
        for j, (name, counts, color) in enumerate(variants):
            pos = x[idx] + (j - 0.5) * width
            val = counts[idx]
            ax.bar(pos, val, width=width, color=color, label=name if idx == 0 else None)
            ax.text(pos, val + 0.12, "{}/5".format(val), ha="center", va="bottom",
                    fontsize=10, color=INK, weight="bold")
        ax.set_title(title)
        ax.set_xticks([x[idx]])
        ax.set_xticklabels([categories[idx]])
        ax.set_ylim(0, 6.2)
        ax.set_yticks(range(0, 6))
        ax.grid(axis="y", color=GRID, linewidth=0.8)
        ax.set_axisbelow(True)
    axes[0].set_ylabel("Count in curated corpus (n = 5 per class)")
    axes[0].legend(frameon=False, loc="upper left")
    fig.suptitle("URL-decoding ablation and live provenance check", y=1.02, fontsize=14)
    fig.text(0.5, -0.03,
             "Raw-only is a deterministic replay of the configured regexes; normalized results are live local requests. "
             "Small curated set, not a general accuracy estimate.",
             ha="center", color=MUTED, fontsize=8.5)
    save(fig, "figure-3-detection-provenance.png")


def integrity():
    fig, ax = plt.subplots(figsize=(9, 4.4))
    ax.set_xlim(0, 4)
    ax.set_ylim(-0.2, 2.2)
    ax.axis("off")
    items = [
        (0.25, "Seq 1–320", "Accepted\n10 OK batches", TEAL),
        (1.25, "Seq 321", "Altered row\nCHAIN_BROKEN", RED),
        (2.25, "Seq 321", "Valid replacement\naccepted", TEAL),
        (3.25, "Seq 322–333", "Post-fix evidence\naccepted", BLUE),
    ]
    for x, title, detail, color in items:
        ax.scatter([x + 0.28], [1.25], s=230, color=color, zorder=3, edgecolor="white", linewidth=1.5)
        ax.text(x + 0.28, 1.72, title, ha="center", va="center", weight="bold", color=INK)
        ax.text(x + 0.28, 0.78, detail, ha="center", va="center", color=INK, fontsize=9)
    for x in [0.53, 1.53, 2.53]:
        ax.add_patch(FancyArrowPatch((x, 1.25), (x + 0.72, 1.25), arrowstyle="-|>",
                                     mutation_scale=14, color=MUTED, linewidth=1.4))
    ax.text(2.0, 0.12, "Final observed state: 333 source records, 333 collector records, 0 pending",
            ha="center", va="center", color=INK, fontsize=10, weight="bold")
    ax.set_title("Collector sequence and tamper-recovery observations", pad=10)
    save(fig, "figure-4-integrity-recovery.png")


def backfill_recovery():
    fig, ax = plt.subplots(figsize=(12, 4.4))
    ax.set_xlim(0, 4)
    ax.set_ylim(-0.2, 2.3)
    ax.axis("off")
    items = [
        ("Before repair", "Source: 373 records\nCollector: 371 records\n2 events pending", RED),
        ("Progress-aware backfill", "Authenticated progress\nMissing seals + checkpoints\nHistorical hashes checked", ORANGE),
        ("Recovered transfer", "Sequences 372–373 accepted\nAudit: OK\nNo source reset", TEAL),
        ("Follow-up snapshot", "374 source = collector\n0 pending / unsealed\n/api/verify: OK", BLUE),
    ]
    for index, (title, detail, color) in enumerate(items):
        x = index + 0.5
        ax.scatter([x], [1.35], s=250, color=color, zorder=3,
                   edgecolor="white", linewidth=1.5)
        ax.text(x, 1.85, title, ha="center", va="center",
                weight="bold", color=INK, fontsize=9.5)
        ax.text(x, 0.78, detail, ha="center", va="center",
                color=INK, fontsize=8.5, linespacing=1.3)
        if index < len(items) - 1:
            ax.add_patch(FancyArrowPatch((x + 0.15, 1.35), (x + 0.85, 1.35),
                                         arrowstyle="-|>", mutation_scale=14,
                                         color=MUTED, linewidth=1.4))
    ax.set_title("Retained-data integrity backfill and recovery", pad=10)
    fig.text(0.5, 0.02,
             "One local integration recovery; earlier BAD_SEAL / BAD_CHECKPOINT attempts remain in the audit. "
             "Not an adversarial security evaluation.",
             ha="center", color=MUTED, fontsize=8.5)
    save(fig, "figure-8-integrity-backfill.png")


def exposure_model():
    rows = list(csv.DictReader((ROOT / "results" / "exposure_tradeoff_model.csv").open(
        encoding="utf-8-sig", newline="")))
    fig, axes = plt.subplots(1, 2, figsize=(12, 4.8), sharey=True)
    colors = [BLUE, TEAL, ORANGE]
    for ax, rate in zip(axes, [5.0, 50.0]):
        rate_rows = [row for row in rows if float(row["rate_per_s"]) == rate]
        for color, interval in zip(colors, [500, 2000, 10000]):
            selected = sorted((row for row in rate_rows
                               if int(row["seal_interval_ms"]) == interval),
                              key=lambda row: int(row["epoch_size"]))
            ax.plot([int(row["epoch_size"]) for row in selected],
                    [float(row["mean_exposed"]) for row in selected],
                    marker="o", linewidth=2, color=color, label=f"{interval / 1000:g} s")
        ax.set_xscale("log")
        ax.set_xticks([10, 50, 100, 500], labels=["10", "50", "100", "500"])
        ax.set_xlabel("Epoch-size threshold (events)")
        ax.set_title(f"Arrival rate = {rate:g} events/s")
        ax.grid(color=GRID, linewidth=0.8)
        ax.set_axisbelow(True)
    axes[0].set_ylabel("Mean unsealed events at compromise")
    axes[1].legend(title="Seal interval", frameon=False)
    fig.suptitle("Poisson exposure-window model (2,000 trials per setting)", y=1.02, fontsize=14)
    fig.text(0.5, -0.02,
             "Synthetic reference model; not measured from the running honeypot. Error bars omitted; see CSV for bootstrap 95% CIs.",
             ha="center", color=MUTED, fontsize=8.5)
    save(fig, "figure-6-exposure-model.png")


def crypto_microbenchmark():
    rows = list(csv.DictReader((ROOT / "results" / "kem_micro.csv").open(
        encoding="utf-8-sig", newline="")))
    rows.sort(key=lambda row: float(row["mean_ms"]))
    labels = [f'{row["scheme"]} {row["operation"]}' for row in rows]
    values = [float(row["mean_ms"]) for row in rows]
    lower = [value - float(row["ci95_low_ms"]) for value, row in zip(values, rows)]
    upper = [float(row["ci95_high_ms"]) - value for value, row in zip(values, rows)]
    fig, ax = plt.subplots(figsize=(10.5, 6.2))
    y = list(range(len(rows)))
    ax.barh(y, values, color=[TEAL if row["scheme"].startswith("ML-") else BLUE for row in rows],
            alpha=0.85)
    ax.errorbar(values, y, xerr=[lower, upper], fmt="none", ecolor=INK, capsize=2, linewidth=1)
    for index, row in enumerate(rows):
        ax.text(float(row["ci95_high_ms"]) + 0.025, index,
                f'{row["mean_ms"]} ms · {row["wire_bytes"]} B wire',
                va="center", fontsize=8, color=INK)
    ax.set_yticks(y, labels)
    ax.invert_yaxis()
    ax.set_xlim(0, max(values) + 1.0)
    ax.set_xlabel("Mean operation latency (ms; 95% bootstrap CI)")
    ax.set_title("Java 25 cryptographic primitive microbenchmarks")
    ax.grid(axis="x", color=GRID, linewidth=0.8)
    ax.set_axisbelow(True)
    fig.text(0.5, 0.01,
             "30 runs × 200 operations/run; 300 warmups. API setup is included; results are host/provider-specific.",
             ha="center", color=MUTED, fontsize=8.5)
    save(fig, "figure-5-crypto-microbench.png")


def main():
    architecture()
    latency()
    provenance()
    integrity()
    backfill_recovery()
    exposure_model()
    crypto_microbenchmark()
    for path in sorted(OUT.glob("*.png")):
        print("{}: {} bytes".format(path.relative_to(ROOT), path.stat().st_size))


if __name__ == "__main__":
    main()
