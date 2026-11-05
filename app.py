import os
import re
import sys
import subprocess
import tempfile
from datetime import datetime
from pathlib import Path

import streamlit as st

PROJECT_ROOT = Path(__file__).resolve().parent
CAPTURES_DIR = PROJECT_ROOT / "captures"
REPORTS_DIR = PROJECT_ROOT / "reports"
AGENT_SCRIPT = PROJECT_ROOT / "src" / "ai_agent.py"

CAPTURES_DIR.mkdir(parents=True, exist_ok=True)
REPORTS_DIR.mkdir(parents=True, exist_ok=True)

st.set_page_config(page_title="Agentic AI Network Security Analyzer", page_icon="🛡️", layout="wide")


def run_tshark(pcap_path, arguments):
    result = subprocess.run(
        ["tshark", "-r", str(pcap_path), *arguments],
        cwd=PROJECT_ROOT, capture_output=True, text=True, timeout=90,
        encoding="utf-8", errors="replace",
    )
    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip() or "TShark failed")
    return result.stdout


def capture_statistics(pcap_path):
    """Independent packet-level metrics; not inferred from AI prose."""
    output = run_tshark(pcap_path, [
        "-T", "fields", "-e", "ip.src", "-e", "ip.dst",
        "-e", "tcp.flags.syn", "-e", "tcp.flags.ack",
        "-e", "dns.flags.response", "-e", "dns.qry.name",
    ])
    syn_count = dns_count = packet_count = 0
    destinations = set()
    for line in output.splitlines():
        packet_count += 1
        fields = line.split("\t")
        fields += [""] * (6 - len(fields))
        source, destination, syn, ack, dns_response, dns_name = fields[:6]
        if destination:
            destinations.add(destination)
        if syn.lower() in ("true", "1") and ack.lower() not in ("true", "1"):
            syn_count += 1
        if dns_response.lower() in ("false", "0") and dns_name:
            dns_count += 1
    return {
        "packets": packet_count,
        "syn_attempts": syn_count,
        "dns_queries": dns_count,
        "destination_ips": len(destinations),
    }


def parse_agent_output(output):
    """Extract a final Markdown report and readable tool-call history."""
    marker = "FINAL SECURITY REPORT"
    pos = output.rfind(marker)
    if pos < 0:
        return "", [], output.strip()

    prefix = output[:pos]
    remainder = output[pos + len(marker):]
    lines = remainder.splitlines()
    while lines and (not lines[0].strip() or set(lines[0].strip()) <= {"="}):
        lines.pop(0)
    report = "\n".join(lines).strip()
    # If the agent's save_report function printed a footer, remove it.
    report = re.split(r"\n\[Report\] Saved to:", report, maxsplit=1)[0].strip()

    steps = []
    for line in prefix.splitlines():
        if "[Agent] Investigation round" in line:
            steps.append(line.strip())
        elif "[AI Agent] Selected tool:" in line:
            steps.append(line.strip())
        elif "[AI Agent] Tool arguments:" in line:
            steps.append(line.strip())
    return report, steps, prefix.strip()


def analyze_capture(pcap_path):
    env = os.environ.copy()
    env["PCAP_FILE"] = str(pcap_path)
    result = subprocess.run(
        [sys.executable, str(AGENT_SCRIPT)],
        cwd=PROJECT_ROOT, env=env, capture_output=True, text=True,
        timeout=300, encoding="utf-8", errors="replace",
    )
    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip() or result.stdout.strip() or "Agent failed")
    report, steps, raw_log = parse_agent_output(result.stdout)
    if not report:
        raise RuntimeError("The AI agent did not produce a final report. Check its terminal output:\n" + result.stdout[-3000:])
    return {"report": report, "steps": steps, "log": raw_log}


def capture_live(interface, duration):
    """Bounded, authorized capture; interface must be selected explicitly."""
    if not re.fullmatch(r"[0-9]+", interface.strip()):
        raise ValueError("Choose a numeric TShark interface number.")
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    capture_path = CAPTURES_DIR / f"live_{timestamp}.pcapng"
    result = subprocess.run(
        ["tshark", "-i", interface.strip(), "-a", f"duration:{duration}", "-w", str(capture_path)],
        cwd=PROJECT_ROOT, capture_output=True, text=True,
        timeout=duration + 30, encoding="utf-8", errors="replace",
    )
    if result.returncode != 0 or not capture_path.is_file():
        raise RuntimeError(result.stderr.strip() or "Live capture failed")
    return capture_path


def available_interfaces():
    result = subprocess.run(
        ["tshark", "-D"], cwd=PROJECT_ROOT, capture_output=True,
        text=True, timeout=15, encoding="utf-8", errors="replace",
    )
    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip() or "Could not list interfaces")
    choices = []
    for line in result.stdout.splitlines():
        match = re.match(r"^\s*(\d+)\.\s+(.+)$", line)
        if match:
            choices.append((match.group(1), match.group(2)))
    return choices


def show_results():
    data = st.session_state.get("analysis")
    if not data:
        return
    st.divider()
    st.subheader("Network Overview")
    st.caption(f"Capture: {data['filename']} · Metrics extracted directly using TShark")
    stats = data["stats"]
    cols = st.columns(4)
    cols[0].metric("Packets", f"{stats['packets']:,}")
    cols[1].metric("TCP SYN attempts", f"{stats['syn_attempts']:,}")
    cols[2].metric("DNS queries", f"{stats['dns_queries']:,}")
    cols[3].metric("Destination IPs", f"{stats['destination_ips']:,}")

    st.subheader("AI Investigation Steps")
    if data["steps"]:
        for step in data["steps"]:
            if "Investigation round" in step:
                st.markdown(f"**{step.replace('[Agent] ', '')}**")
            else:
                st.write("• " + step.replace("[AI Agent] ", ""))
    else:
        st.info("No tool calls were recorded in the agent output.")

    with st.expander("View investigation log"):
        st.code(data["log"], language="text")

    st.subheader("Final Security Report")
    st.markdown(data["report"])
    st.download_button(
        "Download report (.md)", data=data["report"],
        file_name=data["report_name"], mime="text/markdown",
    )


st.title("🛡️ Agentic AI Network Security Analyzer")
st.write("Analyze packet captures using TShark and an OpenAI-powered investigation agent.")
st.caption("Run locally. Network captures and extracted summaries may contain sensitive information.")

mode = st.radio("Choose analysis mode", ["Upload PCAP", "Live Capture"], horizontal=True)
st.divider()

if mode == "Upload PCAP":
    st.subheader("Upload Network Capture")
    uploaded = st.file_uploader("Choose a PCAP or PCAPNG file", type=["pcap", "pcapng", "cap"])
    if uploaded:
        st.success(f"Selected: {uploaded.name} ({uploaded.size / (1024 * 1024):.2f} MB)")
        if st.button("Analyze Traffic", type="primary"):
            if not os.getenv("OPENAI_API_KEY"):
                st.error("OPENAI_API_KEY is not configured in the Streamlit process.")
            elif uploaded.size > 100 * 1024 * 1024:
                st.error("This demo limits uploads to 100 MB.")
            else:
                try:
                    with tempfile.TemporaryDirectory() as temp_dir:
                        suffix = Path(uploaded.name).suffix.lower()
                        capture_path = Path(temp_dir) / ("uploaded" + suffix)
                        capture_path.write_bytes(uploaded.getvalue())
                        with st.spinner("TShark and the AI agent are analyzing the capture..."):
                            stats = capture_statistics(capture_path)
                            result = analyze_capture(capture_path)
                    result.update({
                        "stats": stats, "filename": uploaded.name,
                        "report_name": f"security_report_{datetime.now():%Y%m%d_%H%M%S}.md",
                    })
                    st.session_state["analysis"] = result
                except Exception as error:
                    st.error(f"Analysis failed: {error}")

else:
    st.subheader("Live Network Capture")
    st.info("Capture only traffic you own or are authorized to monitor. Captures are saved locally.")
    try:
        interfaces = available_interfaces()
    except Exception as error:
        st.error(str(error))
        interfaces = []
    selected = st.selectbox(
        "Network interface",
        options=interfaces,
        format_func=lambda x: f"{x[0]} — {x[1]}",
        index=next((i for i, item in enumerate(interfaces) if "Wi-Fi" in item[1]), 0) if interfaces else None,
    )
    duration = st.selectbox("Capture duration (seconds)", [10, 30, 60], index=1)
    if st.button("Start Capture & Analyze", type="primary", disabled=not bool(interfaces)):
        if not os.getenv("OPENAI_API_KEY"):
            st.error("OPENAI_API_KEY is not configured in the Streamlit process.")
        else:
            try:
                with st.spinner(f"Capturing traffic for {duration} seconds..."):
                    capture_path = capture_live(selected[0], duration)
                st.success(f"Capture saved: {capture_path.name}")
                with st.spinner("TShark and the AI agent are analyzing the capture..."):
                    stats = capture_statistics(capture_path)
                    result = analyze_capture(capture_path)
                result.update({
                    "stats": stats, "filename": capture_path.name,
                    "report_name": f"security_report_{capture_path.stem}.md",
                })
                st.session_state["analysis"] = result
            except Exception as error:
                st.error(f"Capture or analysis failed: {error}")

show_results()
