#!/usr/bin/env python3
"""
Visualization module for the Network Traffic Analyzer.

Generates three charts from a TrafficStats object:
  1. Protocol breakdown (pie chart)
  2. Top talkers (horizontal bar chart)
  3. Bandwidth usage over time (line chart)

Can be called automatically from analyzer.py (--plot flag), or run
standalone against exported CSV files.
"""

import csv
import sys
from datetime import datetime

import matplotlib
matplotlib.use("Agg")  # non-interactive backend, safe for headless/server use
import matplotlib.pyplot as plt


def generate_charts(stats, output_prefix="capture"):
    """Generate all charts from a live TrafficStats object (used by analyzer.py)."""
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")

    _plot_protocol_breakdown(stats.protocol_counts, f"{output_prefix}_protocols_{ts}.png")
    _plot_top_talkers(stats.top_talkers(10), stats.talker_packets, f"{output_prefix}_talkers_{ts}.png")
    _plot_bandwidth(stats.bandwidth_per_second, f"{output_prefix}_bandwidth_{ts}.png")

    print(f"Charts saved: {output_prefix}_protocols_{ts}.png, "
          f"{output_prefix}_talkers_{ts}.png, {output_prefix}_bandwidth_{ts}.png")


def _plot_protocol_breakdown(protocol_counts, filename):
    if not protocol_counts:
        return
    labels = list(protocol_counts.keys())
    sizes = list(protocol_counts.values())

    fig, ax = plt.subplots(figsize=(7, 6))
    colors = plt.cm.Set2.colors
    ax.pie(sizes, labels=labels, autopct="%1.1f%%", startangle=90, colors=colors)
    ax.set_title("Protocol Breakdown (by packet count)")
    ax.axis("equal")
    fig.tight_layout()
    fig.savefig(filename, dpi=150)
    plt.close(fig)


def _plot_top_talkers(top_talkers, packet_counts, filename, n=10):
    if not top_talkers:
        return
    ips = [ip for ip, _ in top_talkers][:n]
    byte_counts = [b for _, b in top_talkers][:n]
    kb_counts = [b / 1024 for b in byte_counts]

    fig, ax = plt.subplots(figsize=(8, 6))
    bars = ax.barh(ips[::-1], kb_counts[::-1], color="#4C72B0")
    ax.set_xlabel("KB transferred")
    ax.set_title(f"Top {len(ips)} Talkers (by bytes sent)")
    for bar, ip in zip(bars, ips[::-1]):
        width = bar.get_width()
        ax.text(width, bar.get_y() + bar.get_height() / 2,
                f" {packet_counts.get(ip, 0)} pkts", va="center", fontsize=8)
    fig.tight_layout()
    fig.savefig(filename, dpi=150)
    plt.close(fig)


def _plot_bandwidth(bandwidth_per_second, filename):
    if not bandwidth_per_second:
        return
    seconds = sorted(bandwidth_per_second.keys())
    start = seconds[0]
    relative_times = [s - start for s in seconds]
    kb_per_sec = [bandwidth_per_second[s] / 1024 for s in seconds]

    fig, ax = plt.subplots(figsize=(10, 5))
    ax.plot(relative_times, kb_per_sec, color="#DD8452", linewidth=2, marker="o", markersize=3)
    ax.fill_between(relative_times, kb_per_sec, alpha=0.2, color="#DD8452")
    ax.set_xlabel("Time (seconds into capture)")
    ax.set_ylabel("KB/sec")
    ax.set_title("Bandwidth Usage Over Time")
    ax.grid(True, alpha=0.3)
    fig.tight_layout()
    fig.savefig(filename, dpi=150)
    plt.close(fig)


def generate_from_csv(protocols_csv, talkers_csv, bandwidth_csv, output_prefix="capture_fromcsv"):
    """Standalone mode: rebuild charts from previously exported CSV files."""
    protocol_counts = {}
    with open(protocols_csv) as f:
        for row in csv.DictReader(f):
            protocol_counts[row["protocol"]] = int(row["packet_count"])

    talker_bytes = []
    talker_packets = {}
    with open(talkers_csv) as f:
        for row in csv.DictReader(f):
            talker_bytes.append((row["ip_address"], int(row["byte_count"])))
            talker_packets[row["ip_address"]] = int(row["packet_count"])
    talker_bytes.sort(key=lambda x: x[1], reverse=True)

    bandwidth = {}
    with open(bandwidth_csv) as f:
        for row in csv.DictReader(f):
            bandwidth[int(row["unix_second"])] = int(row["bytes"])

    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    _plot_protocol_breakdown(protocol_counts, f"{output_prefix}_protocols_{ts}.png")
    _plot_top_talkers(talker_bytes, talker_packets, f"{output_prefix}_talkers_{ts}.png")
    _plot_bandwidth(bandwidth, f"{output_prefix}_bandwidth_{ts}.png")
    print(f"Charts regenerated from CSV with prefix '{output_prefix}_{ts}'")


if __name__ == "__main__":
    if len(sys.argv) != 4:
        print("Usage: python3 visualize.py <protocols.csv> <talkers.csv> <bandwidth.csv>")
        sys.exit(1)
    generate_from_csv(sys.argv[1], sys.argv[2], sys.argv[3])
