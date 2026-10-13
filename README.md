# ThreatFox Daily IOC Feeds for Threat Hunting

Automated daily collection and filtering of Indicators of Compromise (IOCs) from [abuse.ch ThreatFox](https://threatfox.abuse.ch/), curated for threat hunting and detection engineering.

---

## 🎯 Target Threats & Tags

ThreatFox ingests thousands of generic indicators daily. This repository filters the feed down to active, high-priority threats and delivery mechanisms:

| Tag / Threat | Description | Common Malware / Techniques |
| :--- | :--- | :--- |
| **`clickfix`** | Fake update / error-dialog lure technique instructing users to paste malicious PowerShell / MSHTA into the Windows Run dialog. | DarkGate, Lumma, Stealc, NetSupport |
| **`etherhiding`** | Hiding malicious payload retrieval URLs inside Binance Smart Chain / Ethereum blockchain transactions. | Fake browser updates, Web3 drainers |
| **`c2`** | Active Command & Control servers (`botnet_cc`). | Cobalt Strike, ValleyRAT, AsyncRAT, Sliver |
| **`stealer`** | Information stealers targeting browser credentials, cookies, and crypto wallets. | Vidar, Lumma, RedLine, Stealc, Agent Tesla |

---

## 📁 Repository Structure

```
├── iocs/
│   ├── latest.csv             # The most recent daily feed snapshot
│   ├── YYYY-MM-DD.csv         # Historical daily snapshots
├── scripts/
│   └── fetch_iocs.py          # Standalone ingestion and Git automation script
└── README.md
```

---

## 📊 CSV Data Schema

Each daily CSV file includes the following columns:

| Column | Description |
| :--- | :--- |
| `id` | ThreatFox internal IOC record ID |
| `ioc` | The indicator value (Domain, IP:Port, URL, or File Hash) |
| `ioc_type` | Type indicator (`ip:port`, `domain`, `url`, `sha256_hash`, etc.) |
| `threat_type` | Type of threat (e.g. `botnet_cc`, `payload_delivery`) |
| `malware_printable` | Friendly malware family name (e.g. `Vidar`, `Cobalt Strike`) |
| `confidence_level` | ThreatFox confidence score (0–100%) |
| `first_seen` | Timestamp when the indicator was first observed (UTC) |
| `matched_criteria` | Specific target tags that triggered ingestion |
| `tags` | Full tag list assigned by ThreatFox and community reporters |
| `reporter` | Contributor or organization that reported the IOC |
| `malware_malpedia` | Link to Fraunhofer FKIE Malpedia reference (if available) |
| `reference` | Public reference or analysis link (e.g., Twitter/X, sandbox) |

---

## ⚙️ Automation & Pipeline

1. **Schedule:** Runs automatically every evening at **18:00 (6:00 PM)**.
2. **Ingestion:** Queries the ThreatFox API (`get_iocs`, past 24 hours), normalizes tags, and matches against the target criteria.
3. **Commit & Push:** Generates `iocs/<YYYY-MM-DD>.csv` and `iocs/latest.csv`, commits changes, and pushes directly to this repository.

---

## 🔍 How to Use in Threat Hunts

### 1. Direct Consumption via GitHub URL
Point your SIEM, SOAR, or hunt notebook directly to the raw URL of the latest snapshot:

```
https://raw.githubusercontent.com/navaneethkrishnan1-TW/threatfox-iocs/main/iocs/latest.csv
```

### 2. Python / Pandas Quick Analysis
```python
import pandas as pd

url = "https://raw.githubusercontent.com/navaneethkrishnan1-TW/threatfox-iocs/main/iocs/latest.csv"
df = pd.read_csv(url)

# Filter for ClickFix or EtherHiding IOCs
lures = df[df['matched_criteria'].str.contains('clickfix|etherhiding', case=False, na=False)]
print(lures[['ioc', 'ioc_type', 'malware_printable', 'tags']])
```

### 3. Splunk Lookup or CrowdStrike / Defender IOC Matching
* **Network Logs / Zeek / Firewall:** Match against `ioc_type == 'ip:port'` or `ip`.
* **DNS Logs / Web Gateway:** Match against `ioc_type == 'domain'` or `url`.
* **EDR Process Executions:** Match against `ioc_type == 'sha256_hash'`.

---

## 📜 Source & Attribution
Data provided by [abuse.ch ThreatFox Community](https://threatfox.abuse.ch/).