import streamlit as st
import nmap

NMAP_PATH = r"C:\Program Files (x86)\Nmap\nmap.exe"

SERVICE_MAP = {
    80: "HTTP (Web Server)",
    443: "HTTPS",
    22: "SSH",
    21: "FTP",
    23: "Telnet",
    25: "SMTP",
    110: "POP3",
    135: "RPC",
    139: "NetBIOS",
    445: "SMB",
    3306: "MySQL",
    3389: "Remote Desktop (RDP)",
    902: "VMware",
    912: "VMware"
}

def scan_target(target):
    scanner = nmap.PortScanner(nmap_search_path=[NMAP_PATH])
    scanner.scan(target, '1-1024')

    results = []

    for host in scanner.all_hosts():
        for proto in scanner[host].all_protocols():
            ports = scanner[host][proto].keys()
            for port in ports:
                state = scanner[host][proto][port]['state']
                service = SERVICE_MAP.get(port, "Unknown Service")

                risk = "🔴 High Risk" if state == "open" else "🟡 Filtered/Unknown"

                results.append({
                    "Port": port,
                    "State": state,
                    "Service": service,
                    "Risk": risk
                })

    return results

st.title("🔍 SecureScan – Network Vulnerability Scanner")
st.write("A beginner-friendly cybersecurity scanner built using **Python + Nmap + Streamlit**.")

target = st.text_input("Enter IP or Domain", "localhost")

if st.button("Start Scan"):
    st.write(f"### Scanning: {target} ...")
    try:
        data = scan_target(target)
        st.success("Scan Completed Successfully ✔")

        st.table(data)

    except Exception as e:
        st.error(f"Error occurred: {e}")
