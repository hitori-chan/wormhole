#!/usr/bin/env python3
"""Generate the benchmark charts in docs/img/ (SVG).

Data: 5-run medians/spreads from `bench/run4way.sh` (loopback, local echo
backend, 2026-09-20, laptop x86_64, Linux 6.17). Run:

    python3 bench/make_charts.py
"""
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

# Per-run values (5 runs each), from bench/run4way.sh output.
# 2026-09-22 run: wormhole v0.3.0 with the zero-copy data path
# (Frame::Data(id, Bytes), batch-safe writer, EOF-draining reader),
# latency = 2000x 64B ping-pong, bandwidth = one-way 256MB drain+ACK.
TOOL = ["direct", "wormhole", "rathole", "frp"]
LAT_P50 = [
    [0.00, 0.00, 0.00, 0.00, 0.00],  # direct
    [0.01, 0.02, 0.02, 0.02, 0.02],  # wormhole
    [0.02, 0.01, 0.01, 0.02, 0.01],  # rathole
    [0.03, 0.03, 0.03, 0.03, 0.03],  # frp
]
LAT_P99 = [
    [0.01, 0.01, 0.01, 0.01, 0.01],
    [0.03, 0.03, 0.03, 0.04, 0.03],
    [0.03, 0.02, 0.03, 0.03, 0.02],
    [0.05, 0.05, 0.05, 0.04, 0.04],
]
BANDWIDTH = [  # one-way Gbps
    [105.3, 98.3, 103.0, 105.1, 103.5],
    [51.5, 45.7, 45.7, 44.2, 41.0],
    [23.3, 19.7, 24.0, 23.4, 28.9],
    [14.3, 14.2, 14.3, 14.6, 13.9],
]
CONC_MS = [  # 96 concurrent round-trips, total wall time
    [11, 12, 12, 12, 12],
    [14, 13, 13, 12, 12],
    [15, 14, 14, 13, 13],
    [17, 17, 17, 18, 16],
]

COLORS = ["#9aa0a6", "#3f51b5", "#e8871e", "#43a047"]
MED = lambda xs: sorted(xs)[len(xs) // 2]


def style(ax):
    for s in ("top", "right"):
        ax.spines[s].set_visible(False)
    ax.grid(axis="y", color="#eee", linewidth=0.8)
    ax.set_axisbelow(True)


def med_bars(ax, data, fmt="{:.2f}", unit=""):
    med = [MED(d) for d in data]
    bars = ax.bar(TOOL, med, color=COLORS, width=0.62, zorder=3)
    for b, m in zip(bars, med):
        ax.annotate(
            fmt.format(m) + unit, (b.get_x() + b.get_width() / 2, m),
            ha="center", va="bottom", fontsize=9,
        )
    style(ax)


def spread_bars(ax, data, fmt="{:.1f}", unit=""):
    lo = [min(d) for d in data]
    hi = [max(d) for d in data]
    med = [MED(d) for d in data]
    err = [[m - l for m, l in zip(med, lo)], [h - m for m, h in zip(med, hi)]]
    ax.errorbar(TOOL, med, yerr=err, fmt="none", ecolor="#555",
                elinewidth=1.2, capsize=4, zorder=4)
    bars = ax.bar(TOOL, med, color=COLORS, width=0.62, zorder=3)
    for b, m in zip(bars, med):
        ax.annotate(
            fmt.format(m) + unit, (b.get_x() + b.get_width() / 2, max(hi) * 1.02),
            ha="center", va="bottom", fontsize=9,
        )
    style(ax)


# --- latency: p50 and p99 side by side -----------------------------------
fig, axes = plt.subplots(1, 2, figsize=(8, 3.2), sharey=True)
med_bars(axes[0], LAT_P50, fmt="{:.2f}", unit=" ms")
axes[0].set_title("latency p50 (64 B ping-pong, 2000 samples)", fontsize=10)
spread_bars(axes[1], LAT_P99, fmt="{:.2f}", unit=" ms")
axes[1].set_title("latency p99 (median, bar = min–max of 5 runs)", fontsize=10)
fig.supxlabel("ms")
fig.tight_layout()
fig.savefig("docs/img/latency.svg")
plt.close(fig)

# --- bandwidth -------------------------------------------------------------
fig, ax = plt.subplots(figsize=(6.0, 3.2))
spread_bars(ax, BANDWIDTH, fmt="{:.1f}", unit=" Gbps")
ax.set_ylabel("one-way Gbps")
ax.set_title("bulk bandwidth (256 MB, one-way; median + 5-run spread)",
             fontsize=10)
fig.tight_layout()
fig.savefig("docs/img/bandwidth.svg")
plt.close(fig)

# --- concurrency -------------------------------------------------------------
fig, ax = plt.subplots(figsize=(6.0, 3.2))
med_bars(ax, CONC_MS, fmt="{:.0f}", unit=" ms")
ax.set_ylabel("ms")
ax.set_title("96 concurrent round-trips, wall time (96/96 for all)",
             fontsize=10)
fig.tight_layout()
fig.savefig("docs/img/concurrency.svg")
plt.close(fig)

print("wrote docs/img/{latency,bandwidth,concurrency}.svg")
