# Network Forensic Analysis: Comprehensive Guide

## Context: SIH26148 — Network Forensic Analysis Module

## 1. Capture Infrastructure

### TAPs vs SPAN Ports
- TAP (Test Access Point): Hardware device that mirrors network traffic at Layer 1/2. Passive, no packet loss, but requires physical access.
- SPAN (Switched Port Analyzer): Software-based port mirroring on managed switches. Easy to configure but may drop packets under high load.

### Packet Capture Tools
- **tcpdump:** Command-line packet analyzer for Linux/Unix. Essential for real-time capture and BPF filtering.
- **Wireshark:** GUI-based protocol analyzer for deep packet inspection and stream reconstruction.
- **TShark:** Command-line version of Wireshark for scripted analysis.
- **dumpcap:** Underlying capture engine used by Wireshark/tshark.

## 2. Flow Analysis vs Full Packet Capture

### Flow Analysis (Metadata Analysis)
Captures the "who, what, when, where, and how much" of network communication without recording payload:
- Source/destination IPs, port numbers, protocol type, timestamps, packet/byte counts
- Tools: SiLK, ntopng, Elastic Stack, PMACCT, NetFlow/IPFIX/sFlow collectors
- Use cases: Detecting data exfiltration, DDoS, historical tracking over months

### Full Packet Capture (Content Analysis)
Records entire network payload — the gold standard for deep investigation:
- Protocol decoding/parsing regardless of port numbers
- Session reconstruction and conversation extraction
- File extraction from HTTP, FTP, SMB, SMTP transfers
- Tools: Arkime (Moloch), Zeek (metadata), Suricata (alerts + PCAP)

## 3. Investigation Workflow

### Phase 1: Preparation & Acquisition
```bash
# Rolling buffer capture
tcpdump -i eth0 -w /data/captures/investigation_%Y-%m-%d_%H.pcap -G 3600 -C 100
# BPF filtering
tcpdump -nnvvS host 192.168.1.50 and not port 22 -w target.pcap
```

### Phase 2: Automated Triage
- **Zeek:** Generates structured semantic logs (conn.log, dns.log, http.log, ssl.log, files.log)
- **Suricata:** Signature-based detection producing alert logs (eve.json)
```bash
zeek -r /data/captures/target.pcap
suricata -c /etc/suricata/suricata.yaml -r target.pcap -l /data/logs/
```

### Phase 3: Deep-Dive Inspection
```bash
# Following TCP streams in Wireshark
# Display filters for forensics
ip.addr == 192.168.1.50 && ip.addr == 10.0.0.15
http.request.method == "POST"
dns.qry.name.len > 50
tcp.flags.syn == 1 && tcp.flags.ack == 0
```

### Phase 4: Reporting
Document IOCs (IPs, domains, JA3 hashes, file hashes), build timeline of compromise, share artifacts for broader response.

## 4. Attack Vector Signatures

### Scanning/Reconnaissance
- Port scans: TCP SYN, UDP, ACK sweeps
- Network mapping: Nmap-style enumeration
- Service detection: Banner grabbing

### Command & Control (C2)
- Beaconing: Periodic outbound connections to C2 servers
- DNS tunneling: Data exfiltration via DNS queries
- HTTPS C2: Encrypted traffic to suspicious domains
- JA3/JA3S fingerprinting: TLS fingerprint identification

### Lateral Movement
- Pass-the-hash: Authentication reuse across systems
- WMI/PSRemoting: Remote execution via management protocols
- SMB exploitation: EternalBlue-style attacks

### Data Exfiltration
- Large outbound transfers to external IPs
- Cloud storage uploads (Mega, Dropbox, Google Drive)
- DNS exfiltration: Encoding data in DNS queries

## 5. Encrypted Traffic Forensics

### DNS Analysis
- DNS query frequency and volume anomalies
- DGA (Domain Generation Algorithm) detection
- Subdomain enumeration patterns
- DNS tunneling detection (long queries, high entropy)

### TLS/SSL Analysis
- JA3/JA3S fingerprinting: Identify client/server TLS fingerprints
- Certificate analysis: Self-signed, expired, or rogue certificates
- Cipher suite analysis: Weak or deprecated cipher negotiation
- TLS decryption: Using server private keys (where available)

## 6. Advanced Tooling

- **Zeek:** Network analysis framework producing rich semantic logs
- **Suricata:** IDS/IPS with deep protocol parsing and alert generation
- **NetworkMiner:** Network forensic analysis tool for extracting files from PCAPs
- **Arkime (Moloch):** Large-scale full packet capture and search engine
- **Velociraptor:** Endpoint monitoring with network artifact collection
- **Moloch/Arkime:** Scalable packet capture and indexed search

## 7. Legal Admissibility & Chain of Custody

- Hash all evidence (SHA-256) before and after acquisition
- Use write-blockers during disk imaging
- Document every action with timestamps and operator identity
- Follow Federal Rules of Evidence (FRE 902, 901) for digital evidence
- Maintain chain-of-custody forms throughout investigation

## 8. Correlation: Network ↔ Process ↔ Timeline

- Map network connections to processes (netstat + /proc/[pid]/fd)
- Correlate network timestamps with system event logs
- Build unified timelines combining network, process, and file system events
- Use YARA rules to identify known malware patterns in network artifacts

---

*Word count: ~1200 words | Sources: Zeek, Suricata, NIST SP 800-86, SANS Forensic Blog*
