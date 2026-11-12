# CTF Write-up: Radar Silence

## Overview
- **Challenge Type:** Network Forensics / DNS Exfiltration Analysis
- **Source Station:** `rdr37` (IP: `192.0.2.37`)
- **Logging Station:** `OPS40` (IP: `192.0.2.40`)
- **Objective:** Determine whether a bearer token leaked from `rdr37` prior to the scheduled cutover and recover it for reissue.

---

## Methodology & Investigation Steps

### 1. Initial HTTP Authorization Check
We first checked if the bearer token leaked in plain text via standard HTTP headers:
```bash
tshark -r radar-silence.pcapng -Y "http.authorization" -T fields -e http.authorization
```
* **Purpose:** Inspect the capture for any HTTP `Authorization: Bearer` headers originating from the suspicious station. *(Resulted in no direct HTTP hits, indicating alternative exfiltration mechanisms).*

### 2. General ASCII String Search
Next, we scanned the raw capture file for keywords related to the incident:
```python
import re

with open("radar-silence.pcapng", "rb") as f:
    content = f.read()

strings = re.findall(rb"[ -~]{6,}", content)
for s in strings:
    if any(k in s.lower() for k in [b"bearer", b"token", b"auth", b"rdr37"]):
        print(s.decode('utf-8', errors='ignore'))
```
* **Purpose:** Extract printable ASCII strings and filter for terms like `bearer`, `token`, `auth`, or `rdr37-diag` to uncover textual artifacts or endpoint indicators.

### 3. Extracting DNS Exfiltration Queries
Realizing the communication relied on covert channels, we listed all DNS query names issued in the capture:
```bash
tshark -r radar-silence.pcapng -Y "dns.qry.name" -T fields -e dns.qry.name
```
* **Purpose:** Enumerate all DNS resolutions. This revealed sequential data chunks embedded inside the subdomains querying `svc-telemetry.example`:
  - `00`: `miytaojxmy3gk`
  - `01`: `ojxg4ydcnldmf`
  - `02`: `rtamrzg5sgiyz`
  - `03`: `tgmztknjqhfta`

### 4. Reassembly & Base32 Decoding
We sorted the extracted chunks by their index, padded the string correctly, and decoded the Base32 payload:
```python
import base64

chunks = [
    ("00", "miytaojxmy3gk"),
    ("01", "ojxg4ydcnldmf"),
    ("02", "rtamrzg5sgiyz"),
    ("03", "tgmztknjqhfta"),
]

sorted_chunks = sorted(chunks, key=lambda x: x[0])
assembled = "".join([c[1] for c in sorted_chunks])
padded = assembled.upper() + "=" * ((8 - len(assembled) % 8) % 8)
decoded = base64.b32decode(padded)

print("Hex token:", decoded.hex())
```
* **Purpose:** Reconstruct the exfiltrated sequence in the correct chronological order and convert the Base32 encoding back into the original 32-character hex bearer token (`b1097f6e977015cac0297ddc3335509f`).

---

## Solution / Flag

```text
CSCTF{rdr37_rotation_b1097f6e977015cac0297ddc3335509f}
```
