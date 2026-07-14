#!/usr/bin/env python3
"""
Network Traffic Analyzer
-------------------------
Captures live packets on a local network interface using Scapy,
then produces:
  - Protocol breakdown (TCP/UDP/ICMP/Other)
  - Top talkers (by source IP, bytes transferred)
  - Bandwidth usage over time (bytes/sec)

Usage:
    sudo python3 analyzer.py -i eth0 -d 30
    sudo python3 analyzer.py --list        # list available interfaces
    sudo python3 analyzer.py -i eth0 -c 500  # stop after 500 packets

Requires root/administrator privileges to sniff packets.
"""

import argparse
import csv
import sys
import time
from collections import defaultdict
from datetime import datetime

try:
    from scapy.all import sniff, get_if_list, IP, TCP, UDP, ICMP
except ImportError:
    print("Scapy is not installed. Install it with: pip install scapy --break-system-packages")
    sys.exit(1)


class TrafficStats:
    """Holds running statistics collected during a capture session."""

    def __init__(self):
        self.protocol_counts = defaultdict(int)      # protocol -> packet count
        self.protocol_bytes = defaultdict(int)        # protocol -> byte count
        self.talker_bytes = defaultdict(int)           # src_ip -> byte count
        self.talker_packets = defaultdict(int)         # src_ip -> packet count
        self.conversation_bytes = defaultdict(int)     # (src, dst) -> byte count
        self.bandwidth_per_second = defaultdict(int)   # unix_second -> byte count
        self.total_packets = 0
        self.total_bytes = 0
        self.start_time = None
        self.end_time = None

    def record(self, pkt):
        if self.start_time is None:
            self.start_time = time.time()

        size = len(pkt)
        self.total_packets += 1
        self.total_bytes += size

        second_bucket = int(time.time())
        self.bandwidth_per_second[second_bucket] += size

        if IP in pkt:
            src = pkt[IP].src
            dst = pkt[IP].dst
            self.talker_bytes[src] += size
            self.talker_packets[src] += 1
            self.conversation_bytes[(src, dst)] += size

            if TCP in pkt:
                proto = "TCP"
            elif UDP in pkt:
                proto = "UDP"
            elif ICMP in pkt:
                proto = "ICMP"
            else:
                proto = "Other IP"
        else:
            proto = pkt.name if hasattr(pkt, "name") else "Non-IP"

        self.protocol_counts[proto] += 1
        self.protocol_bytes[proto] += size

    def finalize(self):
        self.end_time = time.time()

    def duration(self):
        if self.start_time and self.end_time:
            return max(self.end_time - self.start_time, 0.001)
        return 0.001

    def top_talkers(self, n=10):
        return sorted(self.talker_bytes.items(), key=lambda x: x[1], reverse=True)[:n]

    def top_conversations(self, n=10):
        return sorted(self.conversation_bytes.items(), key=lambda x: x[1], reverse=True)[:n]

    def print_summary(self):
        print("\n" + "=" * 60)
        print("CAPTURE SUMMARY")
        print("=" * 60)
        print(f"Duration:       {self.duration():.2f} sec")
        print(f"Total packets:  {self.total_packets}")
        print(f"Total bytes:    {self.total_bytes:,} ({self.total_bytes/1024:.2f} KB)")
        print(f"Avg throughput: {self.total_bytes / self.duration():.2f} bytes/sec")

        print("\n--- Protocol Breakdown ---")
        for proto, count in sorted(self.protocol_counts.items(), key=lambda x: x[1], reverse=True):
            pct = (count / self.total_packets * 100) if self.total_packets else 0
            print(f"  {proto:<10} {count:>6} packets  ({pct:5.1f}%)  {self.protocol_bytes[proto]:,} bytes")

        print("\n--- Top Talkers (by bytes sent) ---")
        for ip, byte_count in self.top_talkers(10):
            print(f"  {ip:<18} {byte_count:>10,} bytes  ({self.talker_packets[ip]} packets)")

        print("\n--- Top Conversations ---")
        for (src, dst), byte_count in self.top_conversations(10):
            print(f"  {src:<15} -> {dst:<15} {byte_count:>10,} bytes")
        print("=" * 60 + "\n")

    def export_csv(self, prefix="capture"):
        """Export collected stats to CSV files for later analysis / reports."""
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")

        with open(f"{prefix}_protocols_{ts}.csv", "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(["protocol", "packet_count", "byte_count"])
            for proto, count in self.protocol_counts.items():
                writer.writerow([proto, count, self.protocol_bytes[proto]])

        with open(f"{prefix}_talkers_{ts}.csv", "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(["ip_address", "byte_count", "packet_count"])
            for ip, byte_count in self.top_talkers(50):
                writer.writerow([ip, byte_count, self.talker_packets[ip]])

        with open(f"{prefix}_bandwidth_{ts}.csv", "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(["unix_second", "bytes"])
            for second, byte_count in sorted(self.bandwidth_per_second.items()):
                writer.writerow([second, byte_count])

        print(f"Exported: {prefix}_protocols_{ts}.csv, {prefix}_talkers_{ts}.csv, {prefix}_bandwidth_{ts}.csv")
        return ts


def list_interfaces():
    print("Available interfaces:")
    for iface in get_if_list():
        print(f"  - {iface}")


def main():
    parser = argparse.ArgumentParser(description="Capture and analyze LAN traffic with Scapy.")
    parser.add_argument("-i", "--interface", help="Network interface to sniff on (e.g. eth0, wlan0)")
    parser.add_argument("-d", "--duration", type=int, default=30, help="Capture duration in seconds (default: 30)")
    parser.add_argument("-c", "--count", type=int, default=0, help="Stop after N packets (0 = unlimited, use duration instead)")
    parser.add_argument("-f", "--filter", default="ip", help="BPF filter, e.g. 'tcp port 80' (default: 'ip')")
    parser.add_argument("--list", action="store_true", help="List available network interfaces and exit")
    parser.add_argument("--csv", action="store_true", help="Export results to CSV after capture")
    parser.add_argument("--plot", action="store_true", help="Generate charts after capture (requires visualize.py)")
    args = parser.parse_args()

    if args.list:
        list_interfaces()
        return

    if not args.interface:
        print("Error: specify an interface with -i (or use --list to see options)")
        sys.exit(1)

    stats = TrafficStats()

    print(f"Capturing on '{args.interface}' | filter='{args.filter}' | "
          f"{'count=' + str(args.count) if args.count else 'duration=' + str(args.duration) + 's'}")
    print("Press Ctrl+C to stop early.\n")

    try:
        sniff(
            iface=args.interface,
            filter=args.filter,
            prn=stats.record,
            timeout=args.duration if not args.count else None,
            count=args.count if args.count else 0,
        )
    except KeyboardInterrupt:
        print("\nCapture stopped by user.")
    except PermissionError:
        print("Permission denied. Try running with sudo/administrator privileges.")
        sys.exit(1)

    stats.finalize()
    stats.print_summary()

    csv_prefix = None
    if args.csv or args.plot:
        ts = stats.export_csv()
        csv_prefix = ts

    if args.plot:
        try:
            from visualize import generate_charts
            generate_charts(stats)
        except ImportError:
            print("visualize.py not found — skipping chart generation. Run visualize.py separately on the CSV output.")


if __name__ == "__main__":
    main()
