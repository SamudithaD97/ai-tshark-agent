# Agentic AI Network Security Analyzer

An agentic AI system that automatically analyzes network packet captures (PCAPs) using TShark and an OpenAI model. The AI agent can choose different network analysis tools, investigate suspicious activity, and generate an evidence-based security report.

## Overview

Network traffic analysis with Wireshark normally requires a security analyst to manually inspect packets, apply filters, identify suspicious hosts, and investigate unusual behavior.

This project explores how agentic AI can automate part of that workflow.

The system uses TShark, the command-line version of Wireshark, to analyze PCAP files. Instead of following only a fixed sequence of checks, an AI agent is given a set of security analysis tools and can decide which tools to use based on the evidence it receives.

The basic workflow is:

```text
PCAP File
    |
    v
AI Security Agent
    |
    v
Selects Analysis Tool
    |
    v
Python + TShark
    |
    v
Network Evidence
    |
    v
AI Evaluates Results
    |
    +----> Additional Investigation
    |             |
    |             v
    |        TShark Tools
    |             |
    +-------------+
    |
    v
Final Security Report
```

## Features

The current prototype can:

- Analyze PCAP and PCAPNG files with TShark
- Summarize TCP SYN connection attempts
- Analyze DNS queries
- Identify unusually long DNS names for further investigation
- Detect possible broad TCP port scanning
- Analyze TCP flag patterns such as SYN, ACK, FIN, and RST
- Investigate activity associated with a specific IPv4 address
- Allow an AI agent to autonomously choose analysis tools
- Perform multi-step network investigations
- Generate an evidence-based security report
- Validate AI-generated IP addresses before passing them to TShark

## Agentic AI

The AI model does not have unrestricted command-line access.

Instead, it can choose from a controlled set of Python/TShark security tools:

```text
get_syn_summary()
get_dns_summary()
get_tcp_flag_summary()
detect_port_scan()
detect_dns_anomalies()
investigate_ip()
```

The results from one tool can influence what the agent decides to investigate next.

For example:

```text
AI Agent
   |
   v
get_syn_summary()
   |
   v
Finds suspicious host
   |
   v
investigate_ip()
   |
   v
Additional evidence
   |
   v
AI Agent
   |
   v
Final Security Report
```

This tool-based design also limits what actions the AI is allowed to perform.

## Example Results

The system has been tested with normal network traffic and public Nmap packet captures.

| Capture | Traffic | Result |
|---|---|---|
| normal.pcapng | Normal browsing traffic | No confirmed port scan |
| nmap_standard_scan | Standard Nmap scan | Broad port scan detected |
| nmap_OS_scan | Nmap OS/port scanning | Broad port scan detected |
| nmap_ACK_scan_on_port_80 | ACK probing | ACK-only probing identified |
| nmap_ACK_scan_on_port_80_2 | ACK probing | ACK-only probing identified |
| nmap_zombie_scan | Zombie/idle scan | Not specifically identified |

The zombie/idle scan demonstrates a current limitation of the prototype. The agent observed the TCP SYN/SYN-ACK/RST behavior but did not have enough flow-level analysis to identify the specific scan technique.

## Project Structure

```text
ai-tshark-agent/
|
|-- captures/
|   |-- nmap_standard_scan
|   |-- nmap_OS_scan
|   |-- nmap_ACK_scan_on_port_80
|   |-- nmap_ACK_scan_on_port_80_2
|   `-- nmap_zombie_scan
|
|-- reports/
|
|-- src/
|   |-- tshark_tools.py
|   |-- ai_agent.py
|   |-- rule_agent.py
|   `-- openai_test.py
|
|-- .gitignore
`-- README.md
```

## Requirements

- Python 3
- Wireshark / TShark
- OpenAI Python library
- OpenAI API key

Install the OpenAI Python package:

```bash
python -m pip install openai
```

TShark must also be installed and available from the command line.

Check with:

```bash
tshark --version
```

## OpenAI API Key

The OpenAI API key should be stored as an environment variable.

Do **not** place an API key directly in the source code or commit it to GitHub.

On Windows:

```cmd
setx OPENAI_API_KEY "YOUR_API_KEY"
```

Open a new terminal after setting the variable.

## Running the Project

By default, the project can analyze the configured/default PCAP.

Run the AI agent with:

```bash
python src/ai_agent.py
```

To select another capture on Windows:

```cmd
set PCAP_FILE=captures\nmap_standard_scan
python src\ai_agent.py
```

For example:

```cmd
set PCAP_FILE=captures\nmap_OS_scan
python src\ai_agent.py
```

## Security Considerations

The project follows several security principles:

- The AI does not receive unrestricted shell access.
- The agent can only use predefined analysis tools.
- AI-generated IP addresses are validated before being used in TShark filters.
- Network-derived strings are treated as untrusted data.
- Unusual behavior is not automatically classified as malicious.
- Reports distinguish observations, suspicious indicators, and confirmed findings.

## Limitations

This is a prototype and does not detect every type of network attack.

Current limitations include:

- Simple heuristic-based port-scan detection
- Limited flow-level analysis
- DNS anomaly detection currently uses basic indicators
- Some advanced scanning techniques may not be identified
- AI conclusions depend on the evidence exposed by the available tools

The system is intended to assist network security investigation rather than replace a security analyst.

## Future Work

Possible improvements include:

- Additional TCP scan detection techniques
- DNS tunneling analysis
- Flow and timing analysis
- Threat-intelligence integration
- Automatic report saving
- Streamlit-based user interface
- Additional labeled PCAP evaluation datasets

## Technologies

- Python
- TShark / Wireshark
- OpenAI API
- PCAP / PCAPNG

## Disclaimer

This project is intended for educational and defensive cybersecurity research. Only analyze network traffic and systems that you own or have permission to investigate.
