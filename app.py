import streamlit as st
import json
import os
import re
import html
import pandas as pd
from datetime import datetime
from scanner import scan_target
from analyzer import analyze_scan
from history import load_history, save_history
from validators import validate_ports, validate_range
from security import get_security_status
# =========================================================
# PAGE CONFIGURATION
# =========================================================
st.set_page_config(
    page_title="Network Port Scanner",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)
HISTORY_FILE = "scan_history.json"
# =========================================================
# SESSION STATE
# =========================================================
defaults = {
    "theme": "Dark",
    "page": "Dashboard",
    "scan_results": [],
    "target": "127.0.0.1",
    "scan_time": None,
    "scan_profile": "Service Detection",
    "scan_arguments": "-sV",
    "scan_duration": 0.0
}
for key, value in defaults.items():
    if key not in st.session_state:
        st.session_state[key] = value
# =========================================================
# SCAN PROFILE
# =========================================================
def get_scan_arguments(
    profile,
    custom_ports="",
    custom_range=""
):
    """
    Convert selected profile into Nmap arguments.
    """
    if profile == "Quick Scan":
        return "-F"
    if profile == "Standard Scan":
        return "-p 1-1000"
    if profile == "Service Detection":
        return "-sV"
    if profile == "Custom Scan":
        if custom_ports:
            return f"-sV -p {custom_ports}"
        if custom_range:
            return f"-sV -p {custom_range}"
        return "-sV"
    return "-sV"
# =========================================================
# THEME
# =========================================================
st.sidebar.markdown("## 🎨 Appearance")
theme = st.sidebar.selectbox(
    "Theme",
    [
        "Dark",
        "Light"
    ],
    index=(
        0
        if st.session_state.theme == "Dark"
        else 1
    )
)
st.session_state.theme = theme
# =========================================================
# DARK THEME
# =========================================================
if theme == "Dark":
    st.markdown(
        """
<style>
.stApp {
    background-color: #0b0f17;
    color: #f1f5f9;
}
[data-testid="stSidebar"] {
    background-color: #111827;
}
h1, h2, h3 {
    color: #f8fafc !important;
}
p, label {
    color: #cbd5e1 !important;
}
.dashboard-card {
    background: #111827;
    border: 1px solid #263244;
    border-radius: 14px;
    padding: 20px;
    min-height: 125px;
}
.card-title {
    color: #94a3b8;
    font-size: 14px;
}
.card-value {
    color: #f8fafc;
    font-size: 28px;
    font-weight: 700;
    margin-top: 8px;
}
.card-sub {
    color: #94a3b8;
    font-size: 12px;
    margin-top: 5px;
}
.status-card {
    background: #111827;
    border: 1px solid #263244;
    border-radius: 14px;
    padding: 22px;
    margin-bottom: 20px;
}
.finding-card {
    background: #111827;
    border: 1px solid #263244;
    border-radius: 12px;
    padding: 18px;
    margin-bottom: 12px;
}
.small-muted {
    color: #94a3b8;
    font-size: 13px;
}
</style>
""",
        unsafe_allow_html=True
    )
# =========================================================
# LIGHT THEME
# =========================================================
else:
    st.markdown(
        """
<style>
.stApp {
    background-color: #f8fafc;
    color: #0f172a;
}
[data-testid="stSidebar"] {
    background-color: #e2e8f0;
}
h1, h2, h3 {
    color: #0f172a !important;
}
p, label {
    color: #334155 !important;
}
.dashboard-card {
    background: #ffffff;
    border: 1px solid #cbd5e1;
    border-radius: 14px;
    padding: 20px;
    min-height: 125px;
}
.card-title {
    color: #64748b;
    font-size: 14px;
}
.card-value {
    color: #0f172a;
    font-size: 28px;
    font-weight: 700;
    margin-top: 8px;
}
.card-sub {
    color: #64748b;
    font-size: 12px;
    margin-top: 5px;
}
.status-card {
    background: #ffffff;
    border: 1px solid #cbd5e1;
    border-radius: 14px;
    padding: 22px;
    margin-bottom: 20px;
}
.finding-card {
    background: #ffffff;
    border: 1px solid #cbd5e1;
    border-radius: 12px;
    padding: 18px;
    margin-bottom: 12px;
}
.small-muted {
    color: #64748b;
    font-size: 13px;
}
</style>
""",
        unsafe_allow_html=True
    )
# =========================================================
# SIDEBAR
# =========================================================
with st.sidebar:
    st.markdown("# 🛡️ Network")
    st.markdown("# Port Scanner")
    st.caption(
        "Scan • Analyze • Secure"
    )
    st.divider()
    st.markdown(
        "### 🧭 Navigation"
    )
    if st.button(
        "🏠  Dashboard",
        use_container_width=True
    ):
        st.session_state.page = "Dashboard"
        st.rerun()
    if st.button(
        "🕐  Scan History",
        use_container_width=True
    ):
        st.session_state.page = "History"
        st.rerun()
    if st.button(
        "🔐  Security Analysis",
        use_container_width=True
    ):
        st.session_state.page = "Analysis"
        st.rerun()
    st.divider()
    st.markdown(
        "### 📥 Quick Actions"
    )
    if st.session_state.scan_results:
        current_df = pd.DataFrame(
            st.session_state.scan_results
        )
        st.download_button(
            "📥 Download CSV",
            data=current_df.to_csv(
                index=False
            ),
            file_name="network_scan_report.csv",
            mime="text/csv",
            use_container_width=True
        )
        st.download_button(
            "📥 Download JSON",
            data=json.dumps(
                st.session_state.scan_results,
                indent=4
            ),
            file_name="network_scan_report.json",
            mime="application/json",
            use_container_width=True
        )
    else:
        st.caption(
            "Run a scan to enable downloads."
        )
    st.divider()
    st.caption(
        "Authorized testing only"
    )
    st.caption(
        "© Network Port Scanner"
    )
# =========================================================
# DASHBOARD
# =========================================================
if st.session_state.page == "Dashboard":
    # -----------------------------------------------------
    # HEADER
    # -----------------------------------------------------
    header1, header2 = st.columns(
        [6, 1]
    )
    with header1:
        st.markdown(
            "# 🛡️ Network Port Scanner"
        )
        st.markdown(
            "Discover open ports, identify services "
            "and analyze basic network security exposure."
        )
    with header2:
        st.success(
            "● Ready"
        )
    st.divider()
    # -----------------------------------------------------
    # TARGET + PROFILE
    # -----------------------------------------------------
    st.markdown(
        "### 🎯 Scan Configuration"
    )
    target_col, profile_col, scan_col = st.columns(
        [4, 2, 1]
    )
    with target_col:
        target = st.text_input(
            "Target IP / Domain",
            value=st.session_state.target,
            placeholder="127.0.0.1"
        )
    with profile_col:
        profiles = [
            "Quick Scan",
            "Standard Scan",
            "Service Detection",
            "Custom Scan"
        ]
        scan_profile = st.selectbox(
            "Scan Profile",
            profiles,
            index=profiles.index(
                st.session_state.scan_profile
            )
        )
    with scan_col:
        st.write("")
        start_scan = st.button(
            "▶ Start Scan",
            use_container_width=True,
            type="primary"
        )
    st.caption(
        "Use only systems you own or are explicitly authorized to test."
    )
    # -----------------------------------------------------
    # PROFILE INFORMATION
    # -----------------------------------------------------
    profile_info = {
        "Quick Scan":
            "Fast discovery using Nmap's common-port scan.",
        "Standard Scan":
            "TCP scan of ports 1-1000.",
        "Service Detection":
            "Detects services, products and available versions.",
        "Custom Scan":
            "Scan specific ports or a user-defined port range."
    }
    st.info(
        profile_info[scan_profile]
    )
    # -----------------------------------------------------
    # CUSTOM OPTIONS
    # -----------------------------------------------------
    custom_ports = ""
    custom_range = ""
    if scan_profile == "Custom Scan":
        st.markdown(
            "### ⚙️ Custom Port Selection"
        )
        custom1, custom2 = st.columns(2)
        with custom1:
            custom_ports = st.text_input(
                "Specific Ports",
                placeholder="22,80,443,8080"
            )
        with custom2:
            custom_range = st.text_input(
                "Port Range",
                placeholder="1-1000"
            )
        st.caption(
            "Enter specific ports OR a port range, not both."
        )
    # -----------------------------------------------------
    # SCAN EXECUTION
    # -----------------------------------------------------
    if start_scan:
        # ---------------------------------------------
        # Validation
        # ---------------------------------------------
        if not target.strip():
            st.error(
                "Please enter a target."
            )
            st.stop()
        if scan_profile == "Custom Scan":
            if custom_ports and custom_range:
                st.error(
                    "Enter either specific ports or a port range, not both."
                )
                st.stop()
            if custom_ports:
                if not validate_ports(
                    custom_ports
                ):
                    st.error(
                        "Invalid port format. Example: 22,80,443"
                    )
                    st.stop()
            if custom_range:
                if not validate_range(
                    custom_range
                ):
                    st.error(
                        "Invalid port range. Example: 1-1000"
                    )
                    st.stop()
            if not custom_ports and not custom_range:
                st.warning(
                    "No custom ports were entered. "
                    "Service Detection will be used."
                )
        # ---------------------------------------------
        # Prepare scan
        # ---------------------------------------------
        scan_arguments = get_scan_arguments(
            scan_profile,
            custom_ports,
            custom_range
        )
        st.session_state.target = target
        st.session_state.scan_profile = scan_profile
        st.session_state.scan_arguments = scan_arguments
        # ---------------------------------------------
        # Run scan
        # ---------------------------------------------
        with st.spinner(
            f"Scanning {target}..."
        ):
            try:
                start_time = datetime.now()
                scanner = scan_target(
                    target,
                    scan_arguments
                )
                results = analyze_scan(
                    scanner
                )
                end_time = datetime.now()
                duration = (
                    end_time - start_time
                ).total_seconds()
                st.session_state.scan_results = results
                st.session_state.scan_time = (
                    datetime.now().strftime(
                        "%Y-%m-%d %H:%M:%S"
                    )
                )
                st.session_state.scan_duration = duration
                # -----------------------------------------
                # Save history
                # -----------------------------------------
                history = load_history()
                history.append(
                    {
                        "target": target,
                        "scan_time":
                            st.session_state.scan_time,
                        "scan_profile":
                            scan_profile,
                        "scan_arguments":
                            scan_arguments,
                        "scan_duration":
                            duration,
                        "results":
                            results
                    }
                )
                # Keep latest 20 scans
                history = history[-20:]
                save_history(
                    history
                )
                st.success(
                    "Scan completed successfully!"
                )
            except Exception as error:
                st.error(
                    f"Scan failed: {error}"
                )
    # =====================================================
    # RESULTS
    # =====================================================
    results = st.session_state.scan_results
    if results:
        # -------------------------------------------------
        # COUNTS
        # -------------------------------------------------
        high_count = sum(
            1
            for item in results
            if item["risk"] == "HIGH"
        )
        medium_count = sum(
            1
            for item in results
            if item["risk"] == "MEDIUM"
        )
        low_count = sum(
            1
            for item in results
            if item["risk"] == "LOW"
        )
        open_ports = len(
            results
        )
        services = len(
            set(
                item["service"]
                for item in results
            )
        )
        recommendation_count = len(
            set(
                item["recommendation"]
                for item in results
            )
        )
        # -------------------------------------------------
        # SECURITY STATUS
        # -------------------------------------------------
        icon, status, status_text = (
            get_security_status(
                high_count,
                medium_count,
                low_count
            )
        )
        st.markdown(
            "### 🛡️ Security Status"
        )
        st.markdown(
            f"""
            <div class="status-card">
                <h2>{icon} {status}</h2>
                <p>{status_text}</p>
                <p class="small-muted">
                    Target: {html.escape(target)}
                    &nbsp; | &nbsp;
                    Profile: {html.escape(scan_profile)}
                    &nbsp; | &nbsp;
                    Duration: {st.session_state.scan_duration:.2f}s
                </p>
            </div>
            """,
            unsafe_allow_html=True
        )
        # -------------------------------------------------
        # SUMMARY CARDS
        # -------------------------------------------------
        st.markdown(
            "### 📊 Scan Overview"
        )
        c1, c2, c3, c4 = st.columns(4)
        with c1:
            st.markdown(
                f"""
                <div class="dashboard-card">
                    <div class="card-title">
                        🔓 Open Ports
                    </div>
                    <div class="card-value">
                        {open_ports}
                    </div>
                    <div class="card-sub">
                        Detected open services
                    </div>
                </div>
                """,
                unsafe_allow_html=True
            )
        with c2:
            st.markdown(
                f"""
                <div class="dashboard-card">
                    <div class="card-title">
                        ⚠️ High Risk
                    </div>
                    <div class="card-value">
                        {high_count}
                    </div>
                    <div class="card-sub">
                        Services requiring attention
                    </div>
                </div>
                """,
                unsafe_allow_html=True
            )
        with c3:
            st.markdown(
                f"""
                <div class="dashboard-card">
                    <div class="card-title">
                        🔎 Services
                    </div>
                    <div class="card-value">
                        {services}
                    </div>
                    <div class="card-sub">
                        Unique services detected
                    </div>
                </div>
                """,
                unsafe_allow_html=True
            )
        with c4:
            st.markdown(
                f"""
                <div class="dashboard-card">
                    <div class="card-title">
                        ⏱️ Scan Duration
                    </div>
                    <div class="card-value">
                        {st.session_state.scan_duration:.2f}s
                    </div>
                    <div class="card-sub">
                        Total scan time
                    </div>
                </div>
                """,
                unsafe_allow_html=True
            )
        # -------------------------------------------------
        # RISK ANALYTICS
        # -------------------------------------------------
        st.markdown(
            "### 📈 Risk Analytics"
        )
        chart_col1, chart_col2 = st.columns(2)
        with chart_col1:
            risk_data = pd.DataFrame(
                {
                    "Risk Level": [
                        "HIGH",
                        "MEDIUM",
                        "LOW"
                    ],
                    "Count": [
                        high_count,
                        medium_count,
                        low_count
                    ]
                }
            )
            st.bar_chart(
                risk_data.set_index(
                    "Risk Level"
                )
            )
        with chart_col2:
            service_counts = {}
            for item in results:
                service = (
                    item["service"]
                    or "unknown"
                )
                service_counts[service] = (
                    service_counts.get(
                        service,
                        0
                    ) + 1
                )
            service_data = pd.DataFrame(
                {
                    "Service": list(
                        service_counts.keys()
                    ),
                    "Count": list(
                        service_counts.values()
                    )
                }
            )
            st.bar_chart(
                service_data.set_index(
                    "Service"
                )
            )
        # -------------------------------------------------
        # SCAN INFORMATION
        # -------------------------------------------------
        st.markdown(
            "### 🔎 Scan Information"
        )
        info1, info2, info3 = st.columns(3)
        with info1:
            st.write(
                f"**Target:** {target}"
            )
        with info2:
            st.write(
                f"**Profile:** {scan_profile}"
            )
        with info3:
            st.write(
                f"**Nmap Arguments:** "
                f"`{st.session_state.scan_arguments}`"
            )
        # -------------------------------------------------
        # RESULTS TABLE
        # -------------------------------------------------
        st.markdown(
            "### 📋 Discovered Services"
        )
        table_data = []
        for item in results:
            table_data.append(
                {
                    "Port":
                        item["port"],
                    "Protocol":
                        item.get(
                            "protocol",
                            "tcp"
                        ),
                    "Service":
                        item["service"],
                    "Product":
                        item["product"],
                    "Version":
                        item["version"],
                    "Risk":
                        item["risk"]
                }
            )
        st.dataframe(
            pd.DataFrame(
                table_data
            ),
            use_container_width=True,
            hide_index=True
        )
        # -------------------------------------------------
        # DETAILED FINDINGS
        # -------------------------------------------------
        st.markdown(
            "### 🛡️ Security Findings"
        )
        for item in results:
            risk = item["risk"]
            if risk == "HIGH":
                icon = "🔴"
            elif risk == "MEDIUM":
                icon = "🟠"
            else:
                icon = "🟢"
            with st.expander(
                f"{icon} Port "
                f"{item['port']} — "
                f"{item['service'].upper()} — "
                f"{risk}"
            ):
                finding1, finding2 = st.columns(2)
                with finding1:
                    st.write(
                        f"**Port:** "
                        f"{item['port']}"
                    )
                    st.write(
                        f"**Protocol:** "
                        f"{item.get('protocol', 'tcp')}"
                    )
                    st.write(
                        f"**Service:** "
                        f"{item['service']}"
                    )
                with finding2:
                    st.write(
                        f"**Product:** "
                        f"{item['product']}"
                    )
                    st.write(
                        f"**Version:** "
                        f"{item['version']}"
                    )
                    st.write(
                        f"**Risk:** "
                        f"{risk}"
                    )
                st.markdown(
                    "**Why it matters**"
                )
                st.write(
                    item["reason"]
                )
                st.markdown(
                    "**Recommendation**"
                )
                st.success(
                    item["recommendation"]
                )
        # -------------------------------------------------
        # EXPORT
        # -------------------------------------------------
        st.markdown(
            "### 📥 Export Scan Report"
        )
        export1, export2, export3 = st.columns(3)
        export_df = pd.DataFrame(
            results
        )
        with export1:
            st.download_button(
                "📄 Download CSV",
                data=export_df.to_csv(
                    index=False
                ),
                file_name=(
                    "network_scan_report.csv"
                ),
                mime="text/csv",
                use_container_width=True
            )
        with export2:
            st.download_button(
                "📦 Download JSON",
                data=json.dumps(
                    results,
                    indent=4
                ),
                file_name=(
                    "network_scan_report.json"
                ),
                mime="application/json",
                use_container_width=True
            )
        # -------------------------------------------------
        # HTML SECURITY REPORT
        # -------------------------------------------------
        html_rows = ""
        for item in results:
            html_rows += f"""
            <tr>
                <td>{html.escape(str(item["port"]))}</td>
                <td>{html.escape(str(item.get("protocol", "tcp")))}</td>
                <td>{html.escape(str(item["service"]))}</td>
                <td>{html.escape(str(item["product"]))}</td>
                <td>{html.escape(str(item["version"]))}</td>
                <td>{html.escape(str(item["risk"]))}</td>
                <td>{html.escape(str(item["recommendation"]))}</td>
            </tr>
            """
        report_html = f"""
<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<title>Network Security Scan Report</title>
<style>
body {{
    font-family: Arial, sans-serif;
    margin: 40px;
    color: #222;
}}
h1 {{
    color: #1f2937;
}}
.summary {{
    background: #f1f5f9;
    padding: 20px;
    border-radius: 10px;
    margin-bottom: 25px;
}}
table {{
    width: 100%;
    border-collapse: collapse;
}}
th, td {{
    border: 1px solid #cbd5e1;
    padding: 10px;
    text-align: left;
}}
th {{
    background: #e2e8f0;
}}
</style>
</head>
<body>
<h1>Network Port Scanner & Service Analyzer</h1>
<div class="summary">
<p><strong>Target:</strong> {html.escape(target)}</p>
<p><strong>Scan Profile:</strong> {html.escape(scan_profile)}</p>
<p><strong>Scan Time:</strong> {html.escape(str(st.session_state.scan_time))}</p>
<p><strong>Duration:</strong> {st.session_state.scan_duration:.2f} seconds</p>
<p><strong>Open Ports:</strong> {open_ports}</p>
<p><strong>High Risk:</strong> {high_count}</p>
<p><strong>Medium Risk:</strong> {medium_count}</p>
<p><strong>Low Risk:</strong> {low_count}</p>
<p><strong>Security Status:</strong> {html.escape(status)}</p>
</div>
<h2>Discovered Services</h2>
<table>
<tr>
<th>Port</th>
<th>Protocol</th>
<th>Service</th>
<th>Product</th>
<th>Version</th>
<th>Risk</th>
<th>Recommendation</th>
</tr>
{html_rows}
</table>
<h2>Note</h2>
<p>
This report was generated by the Network Port Scanner & Service Analyzer
for authorized security testing and educational purposes.
</p>
</body>
</html>
"""
        with export3:
            st.download_button(
                "📄 Security Report",
                data=report_html,
                file_name=(
                    "network_security_report.html"
                ),
                mime="text/html",
                use_container_width=True
            )
        # -------------------------------------------------
        # PREVIOUS SCAN COMPARISON
        # -------------------------------------------------
        history = load_history()
        if len(history) >= 2:
            previous_scan = history[-2]
            previous_results = previous_scan.get(
                "results",
                []
            )
            current_ports = set(
                item["port"]
                for item in results
            )
            previous_ports = set(
                item["port"]
                for item in previous_results
            )
            new_ports = (
                current_ports
                - previous_ports
            )
            removed_ports = (
                previous_ports
                - current_ports
            )
            st.markdown(
                "### 🔄 Current vs Previous Scan"
            )
            compare1, compare2, compare3 = st.columns(3)
            with compare1:
                st.metric(
                    "Current Open Ports",
                    len(current_ports)
                )
            with compare2:
                st.metric(
                    "New Ports",
                    len(new_ports)
                )
            with compare3:
                st.metric(
                    "Removed Ports",
                    len(removed_ports)
                )
            if new_ports:
                st.warning(
                    "Newly detected ports: "
                    +
                    ", ".join(
                        str(port)
                        for port in sorted(
                            new_ports
                        )
                    )
                )
            else:
                st.success(
                    "No new open ports compared with the previous scan."
                )
            if removed_ports:
                st.info(
                    "Ports no longer detected: "
                    +
                    ", ".join(
                        str(port)
                        for port in sorted(
                            removed_ports
                        )
                    )
                )
    else:
        st.markdown(
            "### 📡 Ready to Scan"
        )
        st.info(
            "Enter an authorized target, "
            "select a scan profile and click Start Scan."
        )
# =========================================================
# HISTORY PAGE
# =========================================================
elif st.session_state.page == "History":
    st.markdown(
        "# 🕐 Scan History"
    )
    history = load_history()
    if history:
        history_rows = []
        for number, item in enumerate(
            reversed(history),
            start=1
        ):
            history_rows.append(
                {
                    "Scan #":
                        number,
                    "Target":
                        item.get(
                            "target",
                            "Unknown"
                        ),
                    "Date & Time":
                        item.get(
                            "scan_time",
                            "Unknown"
                        ),
                    "Profile":
                        item.get(
                            "scan_profile",
                            "Unknown"
                        ),
                    "Open Ports":
                        len(
                            item.get(
                                "results",
                                []
                            )
                        ),
                    "Duration":
                        f"{item.get('scan_duration', 0):.2f}s"
                }
            )
        st.dataframe(
            pd.DataFrame(
                history_rows
            ),
            use_container_width=True,
            hide_index=True
        )
        st.markdown(
            "### 📋 Scan Details"
        )
        for number, item in enumerate(
            reversed(history),
            start=1
        ):
            with st.expander(
                f"Scan #{number} • "
                f"{item.get('target')} • "
                f"{item.get('scan_time')}"
            ):
                col1, col2, col3 = st.columns(3)
                with col1:
                    st.write(
                        f"**Profile:** "
                        f"{item.get('scan_profile')}"
                    )
                with col2:
                    st.write(
                        f"**Arguments:** "
                        f"`{item.get('scan_arguments')}`"
                    )
                with col3:
                    st.write(
                        f"**Duration:** "
                        f"{item.get('scan_duration', 0):.2f}s"
                    )
                results = item.get(
                    "results",
                    []
                )
                if results:
                    st.dataframe(
                        pd.DataFrame(
                            results
                        ),
                        use_container_width=True,
                        hide_index=True
                    )
                else:
                    st.info(
                        "No open ports were detected."
                    )
        st.divider()
        if st.button(
            "🗑️ Clear All Scan History",
            type="secondary"
        ):
            save_history([])
            st.success(
                "Scan history cleared."
            )
            st.rerun()
    else:
        st.info(
            "No previous scans available."
        )
# =========================================================
# SECURITY ANALYSIS PAGE
# =========================================================
elif st.session_state.page == "Analysis":
    st.markdown(
        "# 🔐 Security Analysis"
    )
    results = st.session_state.scan_results
    if results:
        high = sum(
            1
            for item in results
            if item["risk"] == "HIGH"
        )
        medium = sum(
            1
            for item in results
            if item["risk"] == "MEDIUM"
        )
        low = sum(
            1
            for item in results
            if item["risk"] == "LOW"
        )
        icon, status, description = (
            get_security_status(
                high,
                medium,
                low
            )
        )
        st.info(
            f"{icon} {status} — {description}"
        )
        for item in results:
            risk = item["risk"]
            if risk == "HIGH":
                icon = "🔴"
            elif risk == "MEDIUM":
                icon = "🟠"
            else:
                icon = "🟢"
            with st.expander(
                f"{icon} Port "
                f"{item['port']} — "
                f"{item['service'].upper()} — "
                f"{risk}"
            ):
                st.write(
                    f"**Protocol:** "
                    f"{item.get('protocol', 'tcp')}"
                )
                st.write(
                    f"**Product:** "
                    f"{item['product']}"
                )
                st.write(
                    f"**Version:** "
                    f"{item['version']}"
                )
                st.markdown(
                    "**Why it matters**"
                )
                st.write(
                    item["reason"]
                )
                st.markdown(
                    "**Security Recommendation**"
                )
                st.success(
                    item["recommendation"]
                )
    else:
        st.info(
            "Run a scan from the Dashboard "
            "to view security analysis."
        )
# =========================================================
# FOOTER
# =========================================================
st.divider()
st.caption(
    "Network Port Scanner & Service Analyzer "
    "• Python • Nmap • Streamlit "
    "• Authorized Security Testing"
)
