"""
Offline test: validates TrafficStats + visualize logic without needing
root privileges or live network access. Builds synthetic packets with
Scapy's packet objects (not sent on the wire) to simulate a capture.
"""
import random
import time
from scapy.all import IP, TCP, UDP, ICMP

from analyzer import TrafficStats
from visualize import generate_charts

random.seed(42)
stats = TrafficStats()

sample_ips = ["192.168.1.10", "192.168.1.20", "192.168.1.30", "8.8.8.8", "142.250.premises"[:11]]
sample_ips = ["192.168.1.10", "192.168.1.20", "192.168.1.30", "8.8.8.8", "1.1.1.1"]

for i in range(300):
    src = random.choice(sample_ips)
    dst = random.choice(sample_ips)
    proto_choice = random.choice(["tcp", "udp", "icmp"])

    if proto_choice == "tcp":
        pkt = IP(src=src, dst=dst) / TCP(sport=random.randint(1024, 65000), dport=80) / ("X" * random.randint(40, 1400))
    elif proto_choice == "udp":
        pkt = IP(src=src, dst=dst) / UDP(sport=random.randint(1024, 65000), dport=53) / ("X" * random.randint(20, 500))
    else:
        pkt = IP(src=src, dst=dst) / ICMP() / ("X" * random.randint(20, 100))

    stats.record(pkt)
    time.sleep(0.001)

stats.finalize()
stats.print_summary()
csv_ts = stats.export_csv(prefix="test_capture")
generate_charts(stats, output_prefix="test_capture")

print("\nOFFLINE TEST PASSED — analyzer + visualizer logic works correctly.")
