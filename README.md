# LLMNR/NBT-NS Poisoning & Credential Capture Tool

## ⚠️ Disclaimer
**This tool is intended for educational purposes and authorized penetration testing only.**  
Ensure you have explicit written permission from the network owner before deploying this script. Unauthorized use on networks you do not own or have permission to test is illegal.

## Overview
This Python script is a security auditing tool designed to demonstrate vulnerabilities in the Link-Local Multicast Name Resolution (LLMR) and NetBIOS Name Service (NBT-NS) protocols. 

When a Windows machine cannot resolve a hostname via DNS, it broadcasts requests via LLMNR or NBT-NS. This tool listens for these requests and responds with a spoofed answer, directing the victim machine to the tester's machine. If the victim machine attempts to authenticate to the spoofed address, the tool captures the NTLMv2 hash, which can then be analyzed for password strength auditing.

## Features
- **Real-time Monitoring:** Sniffs network traffic for LLMNR and NBT-NS requests.
- **Spoofing:** Responds to name resolution requests with a fake IP address.
- **Credential Capture:** Logs attempted authentication connections (NTLMv2 hashes).
- **Safeguards:** Includes checks to prevent spoofing one's own machine or critical infrastructure.
- **Logging:** Saves captured hashes to a local file for offline analysis.

## Requirements
- **OS:** Linux (Kali, Parrot, Ubuntu) or macOS.
- **Python:** Python 3.6+
- **Privileges:** Root/Sudo access is required to bind to raw sockets and sniff traffic.
- **Dependencies:** 
  - `scapy` (Packet manipulation)
  - `impacket` (Optional, for advanced hash parsing, though this script uses basic socket handling for capture)

### Installation
1. Clone the repository:
   ```bash
   git clone <repository-url>
   cd <repository-name>
