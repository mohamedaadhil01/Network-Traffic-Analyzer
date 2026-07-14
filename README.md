# Network Traffic Analyzer

A Python + Scapy tool that captures live packets on your local network and
visualizes traffic patterns: protocol breakdown, top talkers, and bandwidth
usage over time.

Built for a networking/cybersecurity college project — captures on **your
own LAN only**.

## Features

- Live packet capture via Scapy (TCP/UDP/ICMP/other)
- Protocol breakdown (pie chart)
- Top talkers by bytes transferred (bar chart)
- Top conversations (src → dst pairs)
- Bandwidth usage over time (line chart, KB/sec)
- CSV export for use in reports / further analysis in Excel
- Works with BPF filters (e.g. only capture HTTP or DNS traffic)

## Requirements

- Python 3.8+
- Root/administrator privileges (packet sniffing requires elevated access)
- A network interface in monitor-capable mode (regular Wi-Fi/Ethernet works
  fine for capturing your own traffic; promiscuous mode needed to see other
  devices' traffic on a hub/some switches)

## Installation

```bash
pip install -r requirements.txt
```

## Usage

### 1. List available interfaces
```bash
sudo python3 analyzer.py --list
```

### 2. Capture for 30 seconds and print a summary
```bash
sudo python3 analyzer.py -i eth0 -d 30
```

### 3. Capture, export to CSV, and generate charts
```bash
sudo python3 analyzer.py -i eth0 -d 60 --csv --plot
```

### 4. Capture a fixed number of packets instead of a time window
```bash
sudo python3 analyzer.py -i eth0 -c 500 --plot
```

### 5. Use a custom BPF filter (e.g. only web traffic)
```bash
sudo python3 analyzer.py -i eth0 -d 30 -f "tcp port 80 or tcp port 443" --plot
```

### Regenerate charts later from saved CSVs
```bash
python3 visualize.py capture_protocols_TS.csv capture_talkers_TS.csv capture_bandwidth_TS.csv
```

## How to find your interface name

- **Linux/macOS:** `ifconfig` or `ip a` (common names: `eth0`, `wlan0`, `en0`)
- **Windows:** run `sudo python3 analyzer.py --list` — Scapy will show
  interface GUIDs/names (Npcap must be installed: https://npcap.com)

## Project Structure

```
network_traffic_analyzer/
├── analyzer.py       # Capture engine + stats aggregation (CLI entry point)
├── visualize.py       # Chart generation (matplotlib)
├── test_offline.py    # Offline test using synthetic packets (no root needed)
├── requirements.txt
└── README.md
```

## How It Works (for your report)

1. **Capture** — `scapy.sniff()` pulls raw packets off the chosen interface.
   For each packet, `TrafficStats.record()` is called as a callback.
2. **Aggregation** — Each packet is inspected for its IP layer and
   transport-layer protocol (TCP/UDP/ICMP). Byte counts and packet counts are
   tallied per protocol, per source IP, and per (source, destination) pair.
   A per-second bucket also tracks bytes seen in that second, which forms
   the bandwidth-over-time series.
3. **Reporting** — After capture ends (timeout, packet count, or Ctrl+C),
   a text summary prints to the console. Optionally, stats are exported to
   CSV and rendered as charts (pie chart for protocols, bar chart for top
   talkers, line chart for bandwidth).

## Suggested Report Sections

- **Objective**: monitor and characterize LAN traffic patterns
- **Tools used**: Python, Scapy, Matplotlib
- **Methodology**: capture setup, BPF filters used, capture duration
- **Results**: include the 3 generated charts + summary stats table
- **Analysis**: which protocol dominated your traffic? Who were the top
  talkers, and does that match expected devices on your network? Any
  unexpected spikes in the bandwidth chart — what caused them (video
  streaming, backups, etc.)?
- **Limitations**: single-interface capture, no deep packet inspection
  (payload content not analyzed), promiscuous mode restrictions on switched
  networks
- **Future work**: add DNS query logging, GeoIP lookup for external IPs,
  real-time dashboard (Flask + WebSocket), anomaly detection

## Ethical / Legal Note

Only run this on networks you own or have explicit permission to monitor.
Capturing traffic on networks without authorization may violate wiretapping
laws (e.g. the U.S. Computer Fraud and Abuse Act) and your institution's
acceptable use policy. This tool is intended for personal LAN analysis and
educational use only.
