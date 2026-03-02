#!/usr/bin/env python3
"""
vSphere Security Hardening Scanner
Oracle Cloud Infrastructure | Enterprise Security Operations Center (SOC)

Automated SOC compliance scanning and remediation for VMware vSphere 8 environments.
"""
from __future__ import annotations

import base64
import json
import os
import re
import ssl
from dataclasses import asdict, dataclass
from datetime import datetime
from io import BytesIO
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

try:
    import paramiko as _paramiko
    _PARAMIKO = True
except ImportError:
    _PARAMIKO = False

try:
    from reportlab.lib import colors as rl_colors
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import cm
    from reportlab.platypus import (
        HRFlowable, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle,
    )
    _REPORTLAB = True
except ImportError:
    _REPORTLAB = False

import oci
import pandas as pd
import streamlit as st
from pyVim import connect
from pyVmomi import vim

# ─── Paths & Configuration ───────────────────────────────────────────────────
# Assets dir: look next to this script first, then the dev Mac path as fallback
_script_dir = Path(__file__).parent
ASSETS_DIR = (
    _script_dir / "assets"
    if (_script_dir / "assets" / "oracle_logo.png").exists()
    else Path("/Users/kay/Documents/Chatgpt_Codex/Enterprise_vCenter_MCP/app/assets")
)
CSV_PATH = Path.home() / "vsphere-scanner" / "vmware-vsphere-security-configuration-guide-8-controls.csv"

OCI_GENAI_ENDPOINT = os.getenv(
    "OCI_GENAI_ENDPOINT",
    "https://inference.generativeai.ap-hyderabad-1.oci.oraclecloud.com",
)
OCI_GENAI_MODEL_OCID = os.getenv(
    "OCI_GENAI_MODEL_OCID",
    "ocid1.generativeaimodel.oc1.ap-hyderabad-1.amaaaaaask7dceyaaccktjkitpfn3zp3xnkg6yclc6izeahggh2hkwawfjna",
)
OCI_COMPARTMENT_OCID = os.getenv(
    "OCI_COMPARTMENT_OCID",
    "ocid1.compartment.oc1..aaaaaaaaj7w5lilu5pgyscpkgodrpuvs254ixag5wy5k27j6x5wwbeughjia",
)

# ─── Enterprise CSS ──────────────────────────────────────────────────────────
ENTERPRISE_CSS = """
<style>
/* Oracle Enterprise Dark Theme */
[data-testid="stAppViewContainer"] {
    background: linear-gradient(180deg, #0d0d12 0%, #0f1117 100%);
}
[data-testid="stSidebar"] {
    background: linear-gradient(180deg, #111118 0%, #18181f 100%);
    border-right: 2px solid #C74634;
}
.main .block-container { padding-top: 1rem; }

/* Oracle Header */
.oracle-header {
    display: flex;
    align-items: center;
    gap: 16px;
    padding-bottom: 14px;
    border-bottom: 2px solid #C74634;
    margin-bottom: 18px;
}
.oracle-title { font-size: 1.55rem; font-weight: 700; color: #FFFFFF; margin: 0; letter-spacing: -0.3px; }
.oracle-subtitle {
    color: #9999bb;
    font-size: 0.73rem;
    margin-top: 3px;
    text-transform: uppercase;
    letter-spacing: 1.5px;
}

/* Metric Cards */
.metric-grid {
    display: grid;
    grid-template-columns: repeat(5, 1fr);
    gap: 10px;
    margin: 14px 0 20px 0;
}
.metric-card {
    background: linear-gradient(135deg, #16162a 0%, #1a1a2e 100%);
    border: 1px solid #24243a;
    border-radius: 10px;
    padding: 14px 10px;
    text-align: center;
    transition: border-color 0.2s, transform 0.15s;
}
.metric-card:hover { border-color: #C74634; transform: translateY(-2px); }
.metric-value { font-size: 2.1rem; font-weight: 800; line-height: 1; }
.metric-label {
    font-size: 0.68rem;
    text-transform: uppercase;
    letter-spacing: 1.2px;
    color: #777799;
    margin-top: 5px;
}
.mv-total   { color: #c8c8e8; }
.mv-pass    { color: #00C853; }
.mv-fail    { color: #FF1744; }
.mv-unknown { color: #FFA000; }
.mv-manual  { color: #7c9aff; }

/* Status Badges */
.badge {
    display: inline-block;
    padding: 2px 9px;
    border-radius: 10px;
    font-size: 0.68rem;
    font-weight: 700;
    letter-spacing: 0.8px;
    text-transform: uppercase;
    white-space: nowrap;
}
.badge-pass    { background:#003d20; color:#00C853; border:1px solid #00C85380; }
.badge-fail    { background:#3d0010; color:#FF1744; border:1px solid #FF174480; }
.badge-unknown { background:#3d2800; color:#FFA000; border:1px solid #FFA00080; }
.badge-manual  { background:#141430; color:#7c9aff; border:1px solid #7c9aff80; }

/* Component Pills */
.comp-pill {
    display: inline-block;
    padding: 1px 7px;
    border-radius: 8px;
    font-size: 0.65rem;
    font-weight: 600;
    letter-spacing: 0.3px;
    white-space: nowrap;
}
.comp-esxi       { background:#0d2137; color:#4d9fff; }
.comp-vcenter    { background:#1d0d37; color:#c47fff; }
.comp-vm         { background:#0d1d37; color:#4ddfff; }
.comp-network    { background:#0d3720; color:#4dffa0; }
.comp-vsan       { background:#37200d; color:#ffb04d; }
.comp-trustauth  { background:#2d1a00; color:#ffcc44; }

/* Control Row */
.ctrl-row {
    background: #13131e;
    border: 1px solid #1c1c2c;
    border-radius: 8px;
    padding: 10px 14px;
    margin: 5px 0;
    display: flex;
    align-items: center;
    gap: 12px;
    transition: border-color 0.15s;
}
.ctrl-row:hover  { border-color: #2a2a50; }
.ctrl-row.r-fail { border-left: 3px solid #FF1744; }
.ctrl-row.r-pass { border-left: 3px solid #00C853; }
.ctrl-row.r-unknown { border-left: 3px solid #FFA000; }
.ctrl-row.r-manual  { border-left: 3px solid #7c9aff; }
.ctrl-id    { font-family: monospace; font-size: 0.75rem; color: #8888aa; min-width: 130px; }
.ctrl-title { flex: 1; color: #dde0f0; font-size: 0.86rem; }
.ctrl-evid  { color: #55556f; font-size: 0.74rem; font-style: italic; max-width: 260px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }

/* Section header */
.sec-hdr {
    font-size: 0.7rem;
    font-weight: 700;
    letter-spacing: 2px;
    text-transform: uppercase;
    color: #C74634;
    padding: 10px 0 6px 0;
    border-bottom: 1px solid #2a1812;
    margin-bottom: 10px;
}

/* Sidebar label */
.sidebar-label {
    font-size: 0.68rem;
    text-transform: uppercase;
    letter-spacing: 1px;
    color: #C74634;
    margin-bottom: 2px;
}

/* Oracle accent bar */
.accent-bar {
    height: 3px;
    background: linear-gradient(90deg, #C74634 0%, #8B2E22 50%, transparent 100%);
    border-radius: 2px;
    margin: 0 0 14px 0;
}

/* Chat messages */
[data-testid="stChatMessage"] {
    background: #13131e !important;
    border: 1px solid #1c1c30 !important;
    border-radius: 8px !important;
    margin: 4px 0 !important;
}

/* Buttons */
.stButton > button {
    background: linear-gradient(135deg, #C74634 0%, #8B2E22 100%) !important;
    color: #fff !important;
    border: none !important;
    border-radius: 6px !important;
    font-weight: 600 !important;
    letter-spacing: 0.4px !important;
    transition: opacity 0.2s !important;
}
.stButton > button:hover { opacity: 0.82 !important; }

/* Fix / Confirm buttons */
.stButton > button[kind="secondary"] {
    background: linear-gradient(135deg, #1a3a2a 0%, #0d2018 100%) !important;
    border: 1px solid #00C85380 !important;
    color: #00C853 !important;
}

/* Inputs */
.stTextInput > div > div > input,
.stTextInput > div > div > input:focus {
    background: #16162a !important;
    border: 1px solid #2a2a50 !important;
    color: #e0e0f0 !important;
    border-radius: 6px !important;
}
.stTextInput > div > div > input:focus { border-color: #C74634 !important; }

/* Tab styling */
[data-testid="stTabs"] [role="tablist"] { border-bottom: 1px solid #2a2a40; }
[data-testid="stTabs"] [role="tab"]     { color: #888899 !important; font-weight: 500 !important; font-size: 0.85rem !important; }
[data-testid="stTabs"] [role="tab"][aria-selected="true"] { color: #C74634 !important; border-bottom: 2px solid #C74634 !important; }

/* Expander */
[data-testid="stExpander"] { background: #13131e; border: 1px solid #1c1c2c; border-radius: 8px; }

/* Misc */
h1, h2, h3, h4, h5 { color: #FFFFFF !important; }
p, li { color: #c8c8e0; }
.stMarkdown { color: #c8c8e0; }
code { background: #1a1a2e !important; color: #4ddfff !important; }
[data-testid="stMetricValue"] { color: #FFFFFF !important; }
</style>
"""

# ─── Data Class ──────────────────────────────────────────────────────────────
@dataclass
class ControlResult:
    control_id: str
    title: str
    component: str   # ESXi | vCenter | VM | Network | vSAN | TrustAuthority
    status: str      # PASS | FAIL | UNKNOWN | MANUAL
    evidence: str
    remediation_hint: str = ""


# ─── Control Definitions (real VMware SCG v8 IDs) ────────────────────────────
# ESXi advanced-option checks: (scg_id, title, option_key, operator, expected)
ESXI_ADV_CHECKS: List[Tuple] = [
    ("esxi-8.account-lockout",              "Account lock failures >= 5",          "Security.AccountLockFailures",                  ">=", 5),
    ("esxi-8.account-auto-unlock-time",     "Account unlock time >= 900s",         "Security.AccountUnlockTime",                    ">=", 900),
    ("esxi-8.shell-interactive-timeout",    "Shell interactive timeout <= 900s",   "UserVars.ESXiShellInteractiveTimeOut",           "<=", 900),
    ("esxi-8.shell-timeout",                "Shell timeout <= 600s",               "UserVars.ESXiShellTimeOut",                      "<=", 600),
    ("esxi-8.dcui-timeout",                 "DCUI timeout <= 600s",                "UserVars.DcuiTimeOut",                           "<=", 600),
    ("esxi-8.host-client-session-timeout",  "Host client session timeout <= 900s", "UserVars.HostClientSessionTimeout",              "<=", 900),
    ("esxi-8.account-password-history",     "Password history >= 5",               "Security.PasswordHistory",                      ">=", 5),
    ("esxi-8.network-bpdu",                 "Block guest BPDU",                    "Net.BlockGuestBPDU",                            "==", 1),
    ("esxi-8.network-dvfilter",             "DVFilter bind IP empty",              "Net.DVFilterBindIpAddress",                     "==", ""),
    ("esxi-8.logs-level",                   "Log level = info",                    "Config.HostAgent.log.level",                    "==", "info"),
    ("esxi-8.shell-warning",                "Suppress shell warning = 0",          "UserVars.SuppressShellWarning",                 "==", 0),
    ("esxi-8.transparent-page-sharing",     "Memory page sharing salting >= 2",    "Mem.ShareForceSalting",                         ">=", 2),
    ("esxi-8.memeagerzero",                 "Memory eager zero enabled",           "Mem.MemEagerZero",                              "==", 1),
    ("esxi-8.logs-audit-local",             "Audit record storage enabled",        "Syslog.global.auditRecord.storageEnable",       "==", "TRUE"),
    ("esxi-8.logs-remote-tls",              "Remote syslog TLS cert check",        "Syslog.global.certificate.checkSSLCerts",       "==", "TRUE"),
    ("esxi-8.hw-virtual-nic",               "BMC network interface disabled",      "Net.BMCNetworkEnable",                          "==", 0),
    ("esxi-8.deactivate-mob",               "Managed object browser disabled",     "Config.HostAgent.plugins.solo.enableMob",       "==", "False"),
    ("esxi-8.cpu-hyperthread-warning",      "Hyperthreading warning not suppressed","UserVars.SuppressHyperthreadWarning",           "==", 0),
    ("esxi-8.api-soap-timeout",             "SOAP session timeout <= 30 min",      "Config.HostAgent.vmacore.soap.sessionTimeout",  "<=", 30),
    # Additional SCG v8 advanced-option controls
    ("esxi-8.account-password-max-days",    "Password max age = 9999 days",        "Security.PasswordMaxDays",                      "==", 9999),
    ("esxi-8.account-password-policies",   "Password complexity configured",       "Security.PasswordQualityControl",               "!=", ""),
    ("esxi-8.annotations-welcomemessage",  "DCUI login banner configured",         "Annotations.WelcomeMessage",                    "!=", ""),
    ("esxi-8.etc-issue",                   "SSH login banner configured",          "Config.Etc.issue",                              "!=", ""),
    ("esxi-8.lockdown-dcui-access",        "DCUI access restricted to root",       "DCUI.Access",                                   "==", "root"),
    ("esxi-8.logs-audit-remote",           "Audit remote logging enabled",         "Syslog.global.auditRecord.remoteEnable",        "==", "TRUE"),
    ("esxi-8.logs-audit-local-capacity",   "Audit record capacity >= 100 MB",      "Syslog.global.auditRecord.storageCapacity",     ">=", 100),
    ("esxi-8.logs-level-global",           "Global syslog level = error",          "Syslog.global.logLevel",                        "==", "error"),
    ("esxi-8.logs-persistent",             "Persistent log location configured",   "Syslog.global.logDir",                          "!=", ""),
    ("esxi-8.logs-remote-tls-x509",        "Remote syslog strict x509 enabled",   "Syslog.global.certificate.strictX509Compliance","==", "TRUE"),
    ("esxi-8.tls-protocols",               "Weak TLS protocols disabled",          "UserVars.ESXiVPsDisabledProtocols",             "contains", "tlsv1.1"),
    ("esxi-8.logs-filter",                 "Log filter spec empty (filtering off)", "Syslog.global.logFilterSpec",                  "==",  ""),
]

# ESXi service checks: (scg_id, title, service_key, should_be_running)
ESXI_SVC_CHECKS: List[Tuple] = [
    ("esxi-8.deactivate-ssh",   "SSH service disabled",   "TSM-SSH", False),
    ("esxi-8.deactivate-shell", "ESXi Shell disabled",    "TSM",     False),
    ("esxi-8.timekeeping-services", "NTP (ntpd) enabled", "ntpd",    True),
    ("esxi-8.deactivate-cim",   "CIM server disabled",    "CIM",     False),
    ("esxi-8.deactivate-slp",   "SLP service disabled",   "slpd",    False),
    ("esxi-8.deactivate-snmp",  "SNMP service disabled",  "SNMP",    False),
]

# VM advanced-config checks: (scg_id, title, config_key, expected_value, op)
# op: eq_str | lte_int | gte_int
VM_CONFIG_CHECKS: List[Tuple] = [
    ("vm-8.deactivate-console-copy",             "Copy tools disabled",         "isolation.tools.copy.disable",       "true",    "eq_str"),
    ("vm-8.deactivate-console-paste",            "Paste tools disabled",        "isolation.tools.paste.disable",      "true",    "eq_str"),
    ("vm-8.deactivate-disk-shrinking-shrink",    "Disk shrink disabled",        "isolation.tools.diskShrink.disable", "true",    "eq_str"),
    ("vm-8.deactivate-disk-shrinking-wiper",     "Disk wiper disabled",         "isolation.tools.diskWiper.disable",  "true",    "eq_str"),
    ("vm-8.limit-setinfo-size",                  "Info msg size <= 1 MB",       "tools.setInfo.sizeLimit",            1048576,   "lte_int"),
    ("vm-8.deactivate-non-essential-3d-features","3D acceleration disabled",    "mks.enable3d",                       "false",   "eq_str"),
    ("vm-8.vmrc-lock",                           "Guest auto-lock enabled",     "tools.guest.desktop.autolock",       "true",    "eq_str"),
    ("vm-8.log-rotation-size",                   "VM log rotate size <= 2 MB",  "log.rotateSize",                     2048000,   "lte_int"),
    ("vm-8.log-retention",                       "VM log keep >= 10 files",     "log.keepOld",                        10,        "gte_int"),
    ("vm-8.limit-console-connections",           "Console max connections = 1", "RemoteDisplay.maxConnections",       1,         "lte_int"),
    ("vm-8.isolation-tools-dnd-deactivate",      "DnD tools disabled",          "isolation.tools.dnd.disable",        "true",    "eq_str"),
    ("vm-8.isolation-device-connectable-deactivate","Device connect disabled",  "isolation.device.connectable.disable","true",   "eq_str"),
    ("vm-8.restrict-host-info",                  "Host info restricted from VMs","tools.guestlib.enableHostInfo",     "false",   "eq_str"),
    ("vm-8.efi-boot-types",                      "EFI boot restricted to HDD",  "bios.bootDeviceClasses",            "allow:hd","eq_str"),
]

# vSwitch security policy checks: (scg_id, title, policy_attr, must_reject)
VSWITCH_SEC_CHECKS: List[Tuple] = [
    ("esxi-8.network-reject-promiscuous-mode-standardswitch", "vSwitch: promiscuous mode rejected", "allowPromiscuous", True),
    ("esxi-8.network-reject-forged-transmit-standardswitch",  "vSwitch: forged transmits rejected",  "forgedTransmits",  True),
    ("esxi-8.network-reject-mac-changes-standardswitch",      "vSwitch: MAC changes rejected",       "macChanges",       True),
]
PORTGROUP_SEC_CHECKS: List[Tuple] = [
    ("esxi-8.network-reject-promiscuous-mode-portgroup", "Port group: promiscuous mode rejected", "allowPromiscuous", True),
    ("esxi-8.network-reject-forged-transmit-portgroup",  "Port group: forged transmits rejected",  "forgedTransmits",  True),
    ("esxi-8.network-reject-mac-changes-portgroup",      "Port group: MAC changes rejected",       "macChanges",       True),
]

# Keyword → SCG ID for chat-based remediation intent detection
FIX_KEYWORDS: Dict[str, str] = {
    "ssh":          "esxi-8.deactivate-ssh",
    "shell":        "esxi-8.deactivate-shell",
    "ntp":          "esxi-8.timekeeping-services",
    "lockout":      "esxi-8.account-lockout",
    "unlock":       "esxi-8.account-auto-unlock-time",
    "bpdu":         "esxi-8.network-bpdu",
    "dvfilter":     "esxi-8.network-dvfilter",
    "log level":    "esxi-8.logs-level",
    "cim":          "esxi-8.deactivate-cim",
    "slp":          "esxi-8.deactivate-slp",
    "mob":          "esxi-8.deactivate-mob",
    "copy":         "vm-8.deactivate-console-copy",
    "paste":        "vm-8.deactivate-console-paste",
    "shrink":       "vm-8.deactivate-disk-shrinking-shrink",
    "wiper":        "vm-8.deactivate-disk-shrinking-wiper",
    "3d":           "vm-8.deactivate-non-essential-3d-features",
    "promiscuous":  "esxi-8.network-reject-promiscuous-mode-standardswitch",
    "forged":       "esxi-8.network-reject-forged-transmit-standardswitch",
    "mac change":   "esxi-8.network-reject-mac-changes-standardswitch",
}


# ─── vCenter / ESXi Utilities ────────────────────────────────────────────────
def connect_vcenter(host: str, user: str, password: str) -> vim.ServiceInstance:
    ctx = ssl._create_unverified_context()
    return connect.SmartConnect(host=host, user=user, pwd=password, sslContext=ctx)


def get_hosts(si: vim.ServiceInstance) -> List[vim.HostSystem]:
    view = si.content.viewManager.CreateContainerView(
        si.content.rootFolder, [vim.HostSystem], True
    )
    hosts = list(view.view)
    view.Destroy()
    return hosts


def get_all_vms(si: vim.ServiceInstance) -> List[vim.VirtualMachine]:
    view = si.content.viewManager.CreateContainerView(
        si.content.rootFolder, [vim.VirtualMachine], True
    )
    vms = list(view.view)
    view.Destroy()
    return vms


def get_advanced_option(host: vim.HostSystem, key: str) -> Optional[Any]:
    try:
        for opt in host.configManager.advancedOption.setting:
            if opt.key == key:
                return opt.value
    except Exception:
        pass
    return None


def get_vm_extra_config(vm: vim.VirtualMachine, key: str) -> Optional[str]:
    try:
        for opt in vm.config.extraConfig:
            if opt.key == key:
                return str(opt.value)
    except Exception:
        pass
    return None


def _summarize(ctrl_id: str, title: str, component: str,
               host_statuses: List[Tuple[str, str, str]],
               remediation_hint: str = "") -> ControlResult:
    if not host_statuses:
        return ControlResult(ctrl_id, title, component, "UNKNOWN", "No hosts found", remediation_hint)
    if any(s == "FAIL" for _, s, _ in host_statuses):
        fails = ", ".join(
            f"{n}({ev})" for n, s, ev in host_statuses if s == "FAIL"
        )
        return ControlResult(ctrl_id, title, component, "FAIL", fails, remediation_hint)
    if all(s == "UNKNOWN" for _, s, _ in host_statuses):
        return ControlResult(ctrl_id, title, component, "UNKNOWN", "Data unavailable", remediation_hint)
    return ControlResult(ctrl_id, title, component, "PASS", "All hosts compliant", remediation_hint)


def _compare(val: Any, op: str, expected: Any) -> bool:
    try:
        if op == ">=":       return int(val) >= int(expected)
        if op == "<=":       return int(val) <= int(expected)
        if op == "==":       return str(val).lower() == str(expected).lower()
        if op == "!=":       return str(val).lower() != str(expected).lower()
        if op == "contains": return str(expected).lower() in str(val).lower()
    except (ValueError, TypeError):
        pass
    return False


# ─── Check Functions ─────────────────────────────────────────────────────────
def check_esxi_advanced_options(hosts: List[vim.HostSystem],
                                checks: Optional[List[Tuple]] = None) -> List[ControlResult]:
    results = []
    for ctrl_id, title, key, op, expected in (checks or ESXI_ADV_CHECKS):
        statuses = []
        for h in hosts:
            val = get_advanced_option(h, key)
            if val is None:
                statuses.append((h.name, "UNKNOWN", f"{key} not found"))
            elif _compare(val, op, expected):
                statuses.append((h.name, "PASS", f"{key}={val}"))
            else:
                statuses.append((h.name, "FAIL", f"{key}={val} (need {op}{expected})"))
        hint = f"Set {key} {op} {expected} via ESXi advanced options"
        results.append(_summarize(ctrl_id, title, "ESXi", statuses, hint))
    return results


def check_esxi_services(hosts: List[vim.HostSystem]) -> List[ControlResult]:
    results = []
    for ctrl_id, title, svc_key, should_run in ESXI_SVC_CHECKS:
        statuses = []
        for h in hosts:
            svc_sys = getattr(h.configManager, "serviceSystem", None)
            if not svc_sys:
                statuses.append((h.name, "UNKNOWN", "Service system unavailable"))
                continue
            svc = next((s for s in svc_sys.serviceInfo.service if s.key == svc_key), None)
            if svc is None:
                statuses.append((h.name, "UNKNOWN", f"{svc_key} service not found"))
            elif svc.running == should_run:
                statuses.append((h.name, "PASS", f"{svc_key} running={svc.running}"))
            else:
                state = "running" if svc.running else "stopped"
                statuses.append((h.name, "FAIL", f"{svc_key} is {state}"))
        action = "Start" if should_run else "Stop"
        hint = f"{action} the {svc_key} service via ESXi serviceSystem API"
        results.append(_summarize(ctrl_id, title, "ESXi", statuses, hint))
    return results


def check_esxi_ntp_servers(hosts: List[vim.HostSystem]) -> List[ControlResult]:
    statuses = []
    for h in hosts:
        try:
            ntp_cfg = h.config.dateTimeInfo.ntpConfig
            if ntp_cfg and ntp_cfg.server:
                statuses.append((h.name, "PASS", f"NTP: {', '.join(ntp_cfg.server)}"))
            else:
                statuses.append((h.name, "FAIL", "No NTP servers configured"))
        except Exception:
            statuses.append((h.name, "UNKNOWN", "NTP config unavailable"))
    return [_summarize("esxi-8.timekeeping-sources", "NTP servers configured", "ESXi", statuses,
                       "Add NTP servers via host NTP configuration")]


def check_esxi_syslog(hosts: List[vim.HostSystem]) -> List[ControlResult]:
    statuses = []
    for h in hosts:
        val = get_advanced_option(h, "Syslog.global.logHost")
        if val is None or str(val).strip() == "":
            statuses.append((h.name, "FAIL", "Syslog.global.logHost not set"))
        else:
            statuses.append((h.name, "PASS", f"logHost={val}"))
    return [_summarize("esxi-8.logs-remote", "Remote syslog configured", "ESXi", statuses,
                       "Set Syslog.global.logHost to your syslog server")]


def check_esxi_lockdown(hosts: List[vim.HostSystem]) -> List[ControlResult]:
    statuses = []
    for h in hosts:
        try:
            mode = h.config.lockdownMode
            if mode in ("lockdownNormal", "lockdownStrict"):
                statuses.append((h.name, "PASS", f"lockdownMode={mode}"))
            else:
                statuses.append((h.name, "FAIL", f"lockdownMode={mode}"))
        except Exception:
            statuses.append((h.name, "UNKNOWN", "Lockdown mode unavailable"))
    return [_summarize("esxi-8.lockdown-mode", "Lockdown mode enabled", "ESXi", statuses,
                       "Enable lockdown mode via hostAccessManager.ChangeLockdownMode")]


def check_vcenter_password_policy(si: vim.ServiceInstance) -> List[ControlResult]:
    acct_mgr = getattr(si.content, "accountManager", None)
    policy   = getattr(acct_mgr, "passwordPolicy", None) if acct_mgr else None
    min_len  = getattr(policy, "minimumLength", None) if policy else None
    if min_len is None:
        return [ControlResult("vcenter-8.administration-sso-password-policy", "vCenter password min length >= 12",
                              "vCenter", "UNKNOWN",
                              "Password policy not accessible via API",
                              "Configure via vCenter SSO Administration")]
    status = "PASS" if min_len >= 12 else "FAIL"
    return [ControlResult("vcenter-8.administration-sso-password-policy", "vCenter password min length >= 12",
                          "vCenter", status, f"minLength={min_len}",
                          "Set password minimum length >= 12 in SSO password policy")]


def check_vcenter_session_timeout(si: vim.ServiceInstance) -> List[ControlResult]:
    sess_mgr = getattr(si.content, "sessionManager", None)
    timeout  = getattr(sess_mgr, "sessionTimeout", None) if sess_mgr else None
    if timeout is None:
        return [ControlResult("vcenter-8.administration-client-session-timeout", "Session idle timeout <= 1800s",
                              "vCenter", "UNKNOWN",
                              "Session timeout not accessible via API",
                              "Configure session timeout in vCenter settings")]
    status = "PASS" if timeout <= 1800 else "FAIL"
    return [ControlResult("vcenter-8.administration-client-session-timeout", "Session idle timeout <= 1800s",
                          "vCenter", status, f"sessionTimeout={timeout}s",
                          "Reduce session timeout to <= 1800 seconds")]


def check_vm_configs(vms: List[vim.VirtualMachine]) -> List[ControlResult]:
    results: Dict[str, List[Tuple[str, str, str]]] = {c[0]: [] for c in VM_CONFIG_CHECKS}
    meta: Dict[str, Tuple[str, str, str]] = {c[0]: (c[1], c[2], str(c[3])) for c in VM_CONFIG_CHECKS}
    ops: Dict[str, str] = {c[0]: c[4] for c in VM_CONFIG_CHECKS}

    for vm in vms:
        if vm.config is None:
            continue
        for ctrl_id, title, cfg_key, expected, op in VM_CONFIG_CHECKS:
            val = get_vm_extra_config(vm, cfg_key)
            if val is None:
                results[ctrl_id].append((vm.name, "UNKNOWN", f"{cfg_key} not set"))
            elif op == "eq_str" and val.lower() == str(expected).lower():
                results[ctrl_id].append((vm.name, "PASS", f"{cfg_key}={val}"))
            elif op == "lte_int" and int(val) <= int(expected):
                results[ctrl_id].append((vm.name, "PASS", f"{cfg_key}={val}"))
            elif op == "gte_int" and int(val) >= int(expected):
                results[ctrl_id].append((vm.name, "PASS", f"{cfg_key}={val}"))
            else:
                results[ctrl_id].append((vm.name, "FAIL", f"{cfg_key}={val} (need {expected})"))

    out = []
    for ctrl_id, title, cfg_key, expected, op in VM_CONFIG_CHECKS:
        hint = f"Set {cfg_key}={expected} in VM advanced configuration (extraConfig)"
        out.append(_summarize(ctrl_id, title, "VM", results[ctrl_id], hint))
    return out


def check_vswitch_security(hosts: List[vim.HostSystem]) -> List[ControlResult]:
    vs_statuses:  Dict[str, List[Tuple[str, str, str]]] = {c[0]: [] for c in VSWITCH_SEC_CHECKS}
    pg_statuses:  Dict[str, List[Tuple[str, str, str]]] = {c[0]: [] for c in PORTGROUP_SEC_CHECKS}

    for h in hosts:
        try:
            net_info = h.configManager.networkSystem.networkInfo
        except Exception:
            for c in VSWITCH_SEC_CHECKS:
                vs_statuses[c[0]].append((h.name, "UNKNOWN", "Network info unavailable"))
            continue

        # Standard vSwitches
        for vs in (net_info.vswitch or []):
            sec = getattr(getattr(vs.spec, "policy", None), "security", None)
            for ctrl_id, _, attr, must_reject in VSWITCH_SEC_CHECKS:
                if sec is None:
                    vs_statuses[ctrl_id].append((f"{h.name}/{vs.name}", "UNKNOWN", "No security policy"))
                    continue
                val = getattr(sec, attr, None)
                if val is None:
                    vs_statuses[ctrl_id].append((f"{h.name}/{vs.name}", "UNKNOWN", f"{attr} not set"))
                elif (must_reject and not val) or (not must_reject and val):
                    vs_statuses[ctrl_id].append((f"{h.name}/{vs.name}", "PASS", f"{attr}={val}"))
                else:
                    vs_statuses[ctrl_id].append((f"{h.name}/{vs.name}", "FAIL",
                                                 f"{attr}={val} (should be {'False' if must_reject else 'True'})"))

        # Port groups
        for pg in (net_info.portgroup or []):
            sec = getattr(getattr(pg.spec, "policy", None), "security", None)
            for ctrl_id, _, attr, must_reject in PORTGROUP_SEC_CHECKS:
                if sec is None:
                    pg_statuses[ctrl_id].append((f"{h.name}/{pg.spec.name}", "UNKNOWN", "No security policy"))
                    continue
                val = getattr(sec, attr, None)
                if val is None:
                    pg_statuses[ctrl_id].append((f"{h.name}/{pg.spec.name}", "UNKNOWN", f"{attr} not set"))
                elif (must_reject and not val) or (not must_reject and val):
                    pg_statuses[ctrl_id].append((f"{h.name}/{pg.spec.name}", "PASS", f"{attr}={val}"))
                else:
                    pg_statuses[ctrl_id].append((f"{h.name}/{pg.spec.name}", "FAIL",
                                                 f"{attr}={val} (should be {'False' if must_reject else 'True'})"))

    out = []
    for ctrl_id, title, attr, must_reject in VSWITCH_SEC_CHECKS:
        hint = f"Set vSwitch security policy {attr}=False via networkSystem API"
        out.append(_summarize(ctrl_id, title, "Network", vs_statuses[ctrl_id], hint))
    for ctrl_id, title, attr, must_reject in PORTGROUP_SEC_CHECKS:
        hint = f"Set port group security policy {attr}=False via networkSystem API"
        out.append(_summarize(ctrl_id, title, "Network", pg_statuses[ctrl_id], hint))
    return out


def check_esxi_supported(hosts: List[vim.HostSystem]) -> List[ControlResult]:
    statuses = []
    for h in hosts:
        try:
            v = h.config.product.version
            major = int(v.split(".")[0])
            build = h.config.product.build
            if major >= 8:
                statuses.append((h.name, "PASS", f"ESXi {v} build {build} (supported)"))
            else:
                statuses.append((h.name, "FAIL", f"ESXi {v} — End of General Support"))
        except Exception as exc:
            statuses.append((h.name, "UNKNOWN", str(exc)))
    return [_summarize("esxi-8.supported", "ESXi running supported version (>= 8.0)", "ESXi",
                       statuses, "Upgrade to ESXi 8.0 or later")]


def check_vcenter_version(si: vim.ServiceInstance) -> List[ControlResult]:
    try:
        about = si.content.about
        v = about.version
        major = int(v.split(".")[0])
        status = "PASS" if major >= 8 else "FAIL"
        evidence = f"vCenter {v} build {about.build}"
    except Exception as exc:
        status, evidence = "UNKNOWN", str(exc)
    return [ControlResult("vcenter-8.supported", "vCenter running supported version (>= 8.0)",
                          "vCenter", status, evidence, "Upgrade to vCenter Server 8.0 or later")]


def check_vcenter_sso_policy(si: vim.ServiceInstance) -> List[ControlResult]:
    """SSO lockout/password policy — not accessible via pyVmomi; returns MANUAL with UI hints."""
    controls = [
        ("vcenter-8.administration-sso-lockout-policy-max-attempts",
         "SSO: Account locks after <= 5 failed attempts",
         "Administration > Single Sign On > Configuration > Lockout Policy > Max Failures <= 5"),
        ("vcenter-8.administration-sso-lockout-policy-unlock-time",
         "SSO: Account unlocks after <= 900 seconds",
         "Administration > Single Sign On > Configuration > Lockout Policy > Unlock Time <= 900s"),
        ("vcenter-8.administration-sso-password-lifetime",
         "SSO: Password max lifetime <= 90 days",
         "Administration > Single Sign On > Configuration > Password Policy > Maximum Lifetime <= 90"),
        ("vcenter-8.administration-sso-password-reuse",
         "SSO: Password reuse restricted >= 5 previous",
         "Administration > Single Sign On > Configuration > Password Policy > Restrict Reuse >= 5"),
        ("vcenter-8.administration-failed-login-interval",
         "SSO: Failed login time interval configured",
         "Administration > Single Sign On > Configuration > Lockout Policy > Time Interval"),
        ("vcenter-8.administration-sso-groups",
         "SSO: Admin group separation configured",
         "Administration > Single Sign On > Users and Groups > verify group separation"),
    ]
    return [ControlResult(cid, title, "vCenter", "MANUAL",
                          "Requires manual verification in vCenter SSO UI", hint)
            for cid, title, hint in controls]


def check_vcenter_login_banner(si: vim.ServiceInstance) -> List[ControlResult]:
    """Check vCenter login banner — tries advanced settings, falls back to MANUAL."""
    out: List[ControlResult] = []

    def _get(key: str) -> Optional[str]:
        try:
            for opt in si.content.setting.setting:
                if opt.key == key:
                    return str(opt.value)
        except Exception:
            pass
        return None

    for ctrl_id, title, try_key, hint in [
        ("vcenter-8.administration-login-message-enable",
         "vCenter login banner enabled",
         "VirtualCenter.ShowLoginMessage",
         "Administration > Deployment > vCenter Server Settings > User Interface > Login Message"),
        ("vcenter-8.etc-issue",
         "vCenter login banner text configured",
         "VirtualCenter.LoginMessage",
         "Set login banner text in vCenter Server Settings > User Interface > Login Message"),
    ]:
        val = _get(try_key)
        if val is not None:
            ok = val.strip().lower() not in ("false", "0", "")
            out.append(ControlResult(ctrl_id, title, "vCenter",
                                     "PASS" if ok else "FAIL", f"{try_key}={val}", hint))
        else:
            out.append(ControlResult(ctrl_id, title, "vCenter", "MANUAL",
                                     "Not accessible via API — verify in vCenter UI", hint))
    return out


def check_vcenter_vami(si: vim.ServiceInstance) -> List[ControlResult]:
    """vCenter VAMI settings — require vCenter Appliance Management UI; returned as MANUAL."""
    controls = [
        ("vcenter-8.vami-access-ssh",
         "vCenter SSH service disabled",
         "vCenter Appliance Management > Access > Disable SSH"),
        ("vcenter-8.vami-syslog",
         "vCenter remote syslog server configured",
         "vCenter Appliance Management > Syslog > configure remote syslog"),
        ("vcenter-8.vami-time",
         "vCenter NTP time synchronisation configured",
         "vCenter Appliance Management > Time > configure NTP servers"),
        ("vcenter-8.vami-backup",
         "vCenter file-based backup configured",
         "vCenter Appliance Management > Backup > configure SFTP/FTP backup"),
        ("vcenter-8.vami-updates",
         "vCenter software updates applied",
         "vCenter Appliance Management > Update > check for and apply updates"),
        ("vcenter-8.vami-administration-password-expiration",
         "vCenter root password expiry configured",
         "vCenter Appliance Management > Administration > root password expiry"),
        ("vcenter-8.vami-firewall-restrict-access",
         "vCenter VAMI firewall restricts inbound access",
         "vCenter Appliance Management > Firewall > restrict by IP"),
        ("vcenter-8.administration-login-message-details",
         "vCenter login banner consent text configured",
         "Administration > Deployment > vCenter Server Settings > Login Message > consent checkbox"),
        ("vcenter-8.administration-login-message-text",
         "vCenter login banner text set",
         "Administration > Deployment > vCenter Server Settings > Login Message > banner text"),
        ("vcenter-8.fips-enable",
         "vCenter FIPS 140-2 cryptography enabled",
         "vCenter Appliance Management > Access > Enable FIPS (requires reboot)"),
        ("vcenter-8.tls-profile",
         "vCenter TLS profile set to NIST_2024",
         "Use vCenter TLS Reconfiguration utility: vecs-cli or TLS Reconfigure"),
    ]
    return [ControlResult(cid, title, "vCenter", "MANUAL",
                          "Requires manual verification in vCenter Appliance Management UI", hint)
            for cid, title, hint in controls]


def check_vcenter_dvswitch_security(si: vim.ServiceInstance) -> List[ControlResult]:
    """Check DVS/DVPortGroup security: MAC learning, VGT, NetFlow, CDP/LLDP, port overrides, reset."""
    try:
        dvs_view = si.content.viewManager.CreateContainerView(
            si.content.rootFolder, [vim.DistributedVirtualSwitch], True)
        dvs_list = list(dvs_view.view)
        dvs_view.Destroy()
        pg_view = si.content.viewManager.CreateContainerView(
            si.content.rootFolder, [vim.DistributedVirtualPortgroup], True)
        portgroups = list(pg_view.view)
        pg_view.Destroy()
    except Exception as exc:
        err = str(exc)
        return [ControlResult(cid, title, "Network", "UNKNOWN", f"Cannot access DVS: {err}", hint)
                for cid, title, hint in [
                    ("vcenter-8.network-mac-learning", "DVPortGroup MAC learning disabled",
                     "Disable MAC learning on all distributed portgroups"),
                    ("vcenter-8.network-vgt", "No VGT (VLAN 4095) on DVPortGroups",
                     "Remove VLAN 4095 from all distributed portgroups"),
                    ("vcenter-8.network-restrict-netflow-usage", "NetFlow restricted to authorised collector",
                     "Remove unauthorised NetFlow collector IPs from distributed switches"),
                    ("vcenter-8.network-restrict-discovery-protocol", "CDP/LLDP disabled on DVS",
                     "Set linkDiscoveryProtocolConfig.operation=none on all distributed switches"),
                    ("vcenter-8.network-reset-port", "DVPortGroup resets port at disconnect",
                     "Enable portConfigResetAtDisconnect on all distributed portgroups"),
                    ("vcenter-8.network-restrict-port-level-overrides", "No security overrides at port level",
                     "Disable security override permissions on distributed portgroup policy"),
                ]]

    def _pg_name(pg: Any) -> str:
        return getattr(getattr(pg, "config", None), "name", "Unknown")

    def _dvs_name(dvs: Any) -> str:
        return getattr(getattr(dvs, "config", None), "name", "Unknown")

    # ── MAC learning ─────────────────────────────────────────────────────────
    ml_st: List[Tuple[str, str, str]] = []
    for pg in portgroups:
        try:
            mm = getattr(pg.config.defaultPortConfig, "macManagementPolicy", None)
            ml = getattr(mm, "macLearningPolicy", None) if mm else None
            enabled = getattr(ml, "enabled", None) if ml else None
            if enabled is None:
                ml_st.append((_pg_name(pg), "UNKNOWN", "macLearningPolicy not accessible"))
            elif enabled:
                ml_st.append((_pg_name(pg), "FAIL", f"MAC learning enabled on {_pg_name(pg)}"))
            else:
                ml_st.append((_pg_name(pg), "PASS", "MAC learning disabled"))
        except Exception as exc:
            ml_st.append((_pg_name(pg), "UNKNOWN", str(exc)))
    if not portgroups:
        ml_st.append(("vCenter", "PASS", "No distributed portgroups"))

    # ── VGT (VLAN 4095) ──────────────────────────────────────────────────────
    vgt_st: List[Tuple[str, str, str]] = []
    for pg in portgroups:
        try:
            vlan = getattr(pg.config.defaultPortConfig, "vlan", None)
            vid  = getattr(vlan, "vlanId", None) if vlan else None
            if vid == 4095:
                vgt_st.append((_pg_name(pg), "FAIL", f"VLAN 4095 (VGT) on {_pg_name(pg)}"))
            elif vid is not None:
                vgt_st.append((_pg_name(pg), "PASS", f"VLAN={vid}"))
            else:
                vgt_st.append((_pg_name(pg), "UNKNOWN", "VLAN config not accessible"))
        except Exception as exc:
            vgt_st.append((_pg_name(pg), "UNKNOWN", str(exc)))
    if not portgroups:
        vgt_st.append(("vCenter", "PASS", "No distributed portgroups"))

    # ── NetFlow (IPFIX) ───────────────────────────────────────────────────────
    nf_st: List[Tuple[str, str, str]] = []
    for dvs in dvs_list:
        try:
            ipfix     = getattr(dvs.config, "ipfixConfig", None)
            collector = getattr(ipfix, "collectorIpAddress", None) if ipfix else None
            if collector:
                nf_st.append((_dvs_name(dvs), "FAIL", f"NetFlow collector: {collector}"))
            else:
                nf_st.append((_dvs_name(dvs), "PASS", "No NetFlow collector configured"))
        except Exception as exc:
            nf_st.append((_dvs_name(dvs), "UNKNOWN", str(exc)))
    if not dvs_list:
        nf_st.append(("vCenter", "PASS", "No distributed switches"))

    # ── CDP/LLDP Discovery protocol ──────────────────────────────────────────
    dp_st: List[Tuple[str, str, str]] = []
    for dvs in dvs_list:
        try:
            ldp       = getattr(dvs.config, "linkDiscoveryProtocolConfig", None)
            operation = getattr(ldp, "operation", None) if ldp else None
            protocol  = getattr(ldp, "protocol", None) if ldp else None
            if operation is None:
                dp_st.append((_dvs_name(dvs), "UNKNOWN", "linkDiscoveryProtocolConfig not accessible"))
            elif operation.lower() == "none":
                dp_st.append((_dvs_name(dvs), "PASS", "Discovery protocol operation=none"))
            else:
                dp_st.append((_dvs_name(dvs), "FAIL", f"Discovery {protocol}/{operation} active"))
        except Exception as exc:
            dp_st.append((_dvs_name(dvs), "UNKNOWN", str(exc)))
    if not dvs_list:
        dp_st.append(("vCenter", "PASS", "No distributed switches"))

    # ── Reset port at disconnect ──────────────────────────────────────────────
    rp_st: List[Tuple[str, str, str]] = []
    for pg in portgroups:
        try:
            policy = getattr(pg.config, "policy", None)
            reset  = getattr(policy, "portConfigResetAtDisconnect", None) if policy else None
            if reset is None:
                rp_st.append((_pg_name(pg), "UNKNOWN", "portConfigResetAtDisconnect not accessible"))
            elif reset:
                rp_st.append((_pg_name(pg), "PASS", "Reset port at disconnect enabled"))
            else:
                rp_st.append((_pg_name(pg), "FAIL", f"Reset disabled on {_pg_name(pg)}"))
        except Exception as exc:
            rp_st.append((_pg_name(pg), "UNKNOWN", str(exc)))
    if not portgroups:
        rp_st.append(("vCenter", "PASS", "No distributed portgroups"))

    # ── Port-level security overrides ────────────────────────────────────────
    po_st: List[Tuple[str, str, str]] = []
    for pg in portgroups:
        try:
            policy    = getattr(pg.config, "policy", None)
            overrides = getattr(policy, "allowPortConfigOverrides", None) if policy else None
            if overrides is None:
                po_st.append((_pg_name(pg), "UNKNOWN", "Override policy not accessible"))
            else:
                bad = [a for a in ("macChanges", "allowPromiscuous", "forgedTransmits")
                       if getattr(overrides, a, None) is True]
                if bad:
                    po_st.append((_pg_name(pg), "FAIL", f"Security overrides allowed: {', '.join(bad)}"))
                else:
                    po_st.append((_pg_name(pg), "PASS", "No security overrides permitted"))
        except Exception as exc:
            po_st.append((_pg_name(pg), "UNKNOWN", str(exc)))
    if not portgroups:
        po_st.append(("vCenter", "PASS", "No distributed portgroups"))

    return [
        _summarize("vcenter-8.network-mac-learning",
                   "DVPortGroup MAC learning disabled", "Network", ml_st,
                   "Disable macLearningPolicy on all distributed portgroups"),
        _summarize("vcenter-8.network-vgt",
                   "No VGT (VLAN 4095) on DVPortGroups", "Network", vgt_st,
                   "Remove VLAN 4095 from all distributed portgroups"),
        _summarize("vcenter-8.network-restrict-netflow-usage",
                   "NetFlow restricted to authorised collector", "Network", nf_st,
                   "Remove unauthorised NetFlow collector IPs from distributed switches"),
        _summarize("vcenter-8.network-restrict-discovery-protocol",
                   "CDP/LLDP disabled on distributed switches", "Network", dp_st,
                   "Set linkDiscoveryProtocolConfig.operation=none on all distributed switches"),
        _summarize("vcenter-8.network-reset-port",
                   "DVPortGroup resets port config at disconnect", "Network", rp_st,
                   "Set portConfigResetAtDisconnect=True on all distributed portgroups"),
        _summarize("vcenter-8.network-restrict-port-level-overrides",
                   "No security overrides at port level", "Network", po_st,
                   "Disable security override permissions on distributed portgroup policy"),
    ]


def check_vsan(si: vim.ServiceInstance) -> List[ControlResult]:
    """Check vSAN controls — PASS (N/A) if vSAN not configured, UNKNOWN if configured."""
    VSAN_CONTROLS = [
        ("vsan-8.data-at-rest",                   "vSAN data-at-rest encryption enabled",
         "vSAN Cluster > Configure > vSAN > Encryption > enable at-rest encryption"),
        ("vsan-8.data-in-transit",                "vSAN data-in-transit encryption enabled",
         "vSAN Cluster > Configure > vSAN > Services > enable in-transit encryption"),
        ("vsan-8.object-checksum",                "vSAN object checksum enabled",
         "vSAN Cluster > Configure > vSAN > Services > enable object checksum"),
        ("vsan-8.force-provisioning",             "vSAN force provisioning disabled",
         "vSAN Cluster > Configure > vSAN > Disk Management > disable force provisioning"),
        ("vsan-8.operations-reserve",             "vSAN operations reserve capacity set",
         "vSAN Cluster > Configure > vSAN > Disk Management > set operations reserve"),
        ("vsan-8.iscsi-mutual-chap",              "vSAN iSCSI mutual CHAP enabled",
         "vSAN iSCSI target > configure bidirectional CHAP"),
        ("vsan-8.file-services-access-control-nfs",  "vSAN NFS file services access controlled",
         "vSAN File Services > NFS shares > configure access control"),
        ("vsan-8.file-services-authentication-smb",  "vSAN SMB file services encrypted auth",
         "vSAN File Services > SMB shares > require encrypted authentication"),
    ]
    try:
        view     = si.content.viewManager.CreateContainerView(
            si.content.rootFolder, [vim.ClusterComputeResource], True)
        clusters = list(view.view)
        view.Destroy()
    except Exception as exc:
        return [ControlResult(cid, title, "vSAN", "UNKNOWN",
                              f"Cannot access cluster inventory: {exc}", hint)
                for cid, title, hint in VSAN_CONTROLS]

    vsan_on = any(
        getattr(getattr(getattr(c, "configurationEx", None), "vsanConfigEx", None), "enabled", False)
        for c in clusters
    )
    if not vsan_on:
        return [ControlResult(cid, title, "vSAN", "PASS",
                              "vSAN not configured (not applicable)", hint)
                for cid, title, hint in VSAN_CONTROLS]
    # vSAN is on — full verification needs the vSAN Management SDK
    return [ControlResult(cid, title, "vSAN", "UNKNOWN",
                          "vSAN configured — use vSAN Health Service to verify", hint)
            for cid, title, hint in VSAN_CONTROLS]


def check_vm_advanced(vms: List[vim.VirtualMachine]) -> List[ControlResult]:
    """Additional VM checks: dvFilter exposure, PCI passthrough, inter-VM TPS."""
    dvf_st: List[Tuple[str, str, str]] = []
    pci_st: List[Tuple[str, str, str]] = []
    tps_st: List[Tuple[str, str, str]] = []

    for vm in vms:
        cfg = getattr(vm, "config", None)
        if not cfg:
            continue
        n  = vm.name
        hw = getattr(cfg, "hardware", None)

        # PCI passthrough
        pci = [d for d in (getattr(hw, "device", []) or [])
               if isinstance(d, vim.vm.device.VirtualPCIPassthrough)]
        if pci:
            pci_st.append((n, "FAIL", f"{len(pci)} PCI passthrough device(s) found"))
        else:
            pci_st.append((n, "PASS", "No PCI passthrough devices"))

        # dvFilter binIpAddress
        dvf_val = get_vm_extra_config(vm, "dvfilter.binIpAddress")
        if dvf_val is None or dvf_val.strip() == "":
            dvf_st.append((n, "PASS", "dvfilter.binIpAddress not set"))
        else:
            dvf_st.append((n, "FAIL", f"dvfilter.binIpAddress={dvf_val}"))

        # Inter-VM TPS salting
        tps_val = get_vm_extra_config(vm, "sched.mem.pshare.salt")
        if tps_val is None:
            tps_st.append((n, "UNKNOWN", "sched.mem.pshare.salt not configured"))
        elif tps_val.strip():
            tps_st.append((n, "PASS", "Inter-VM TPS salt set"))
        else:
            tps_st.append((n, "FAIL", "sched.mem.pshare.salt empty — inter-VM TPS unrestricted"))

    return [
        _summarize("vm-8.dvfilter",
                   "VM dvFilter network API not exposed", "VM", dvf_st,
                   "Remove dvfilter.binIpAddress from VM advanced settings"),
        _summarize("vm-8.pci-passthrough",
                   "No unauthorised PCI passthrough devices", "VM", pci_st,
                   "Remove PCI passthrough devices if not required"),
        _summarize("vm-8.transparentpagesharing-inter-vm-enabled",
                   "Inter-VM transparent page sharing restricted", "VM", tps_st,
                   "Set sched.mem.pshare.salt to a unique value per VM"),
    ]


# ─── ESXi Direct-SSH Checks (paramiko) ───────────────────────────────────────
def _esxi_ssh_run(host_addr: str, user: str, password: str, port: int, cmd: str) -> Tuple[bool, str]:
    """SSH into ESXi host and run a single command. Returns (success, output)."""
    if not _PARAMIKO:
        return False, "paramiko not installed"
    try:
        client = _paramiko.SSHClient()
        client.set_missing_host_key_policy(_paramiko.AutoAddPolicy())
        client.connect(
            host_addr, port=port, username=user, password=password,
            timeout=15, look_for_keys=False, allow_agent=False,
        )
        _, stdout, _ = client.exec_command(cmd)
        out = stdout.read().decode(errors="replace").strip()
        client.close()
        return True, out
    except Exception as exc:
        return False, str(exc)


def _parse_sshd_config(text: str) -> Dict[str, str]:
    """Parse /etc/ssh/sshd_config into a key→value dict (lowercase keys)."""
    result: Dict[str, str] = {}
    for line in text.splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            parts = line.split(None, 1)
            if len(parts) == 2:
                result[parts[0].lower()] = parts[1].strip().lower()
    return result


def check_esxi_ssh_daemon(hosts: List[vim.HostSystem],
                          ssh_user: str, ssh_pass: str,
                          ssh_port: int = 22) -> List[ControlResult]:
    """Check /etc/ssh/sshd_config on each ESXi host via direct SSH."""
    SSH_CHECKS: List[Tuple] = [
        ("esxi-8.ssh-gateway-ports",            "SSH: GatewayPorts disabled",           "gatewayports",              "==",  "no"),
        ("esxi-8.ssh-host-based-auth",          "SSH: HostbasedAuthentication off",     "hostbasedauthentication",   "==",  "no"),
        ("esxi-8.ssh-idle-timeout-count",       "SSH: ClientAliveCountMax <= 3",        "clientalivecountmax",       "<=",  3),
        ("esxi-8.ssh-idle-timeout-interval",    "SSH: ClientAliveInterval <= 200",      "clientaliveinterval",       "<=",  200),
        ("esxi-8.ssh-login-banner",             "SSH: Login banner configured",         "banner",                    "!=",  ""),
        ("esxi-8.ssh-rhosts",                   "SSH: IgnoreRhosts enabled",            "ignorerhosts",              "==",  "yes"),
        ("esxi-8.ssh-stream-local-forwarding",  "SSH: StreamLocalForwarding disabled",  "allowstreamlocalforwarding","==",  "no"),
        ("esxi-8.ssh-tcp-forwarding",           "SSH: TCP forwarding disabled",         "allowtcpforwarding",        "==",  "no"),
        ("esxi-8.ssh-tunnels",                  "SSH: Tunnels disabled",                "permittunnel",              "==",  "no"),
        ("esxi-8.ssh-user-environment",         "SSH: PermitUserEnvironment off",       "permituserenvironment",     "==",  "no"),
    ]
    statuses: Dict[str, List[Tuple[str, str, str]]] = {c[0]: [] for c in SSH_CHECKS}

    for h in hosts:
        ok, output = _esxi_ssh_run(h.name, ssh_user, ssh_pass, ssh_port,
                                   "cat /etc/ssh/sshd_config 2>/dev/null")
        if not ok:
            for c in SSH_CHECKS:
                statuses[c[0]].append((h.name, "UNKNOWN", f"SSH error: {output[:80]}"))
            continue
        cfg = _parse_sshd_config(output)
        for ctrl_id, _, key, op, expected in SSH_CHECKS:
            val = cfg.get(key)
            if val is None:
                statuses[ctrl_id].append((h.name, "UNKNOWN", f"{key} not in sshd_config"))
            elif _compare(val, op, expected):
                statuses[ctrl_id].append((h.name, "PASS", f"{key}={val}"))
            else:
                statuses[ctrl_id].append((h.name, "FAIL",
                                          f"{key}={val} (expected {op} '{expected}')"))

    return [
        _summarize(ctrl_id, title, "ESXi", statuses[ctrl_id],
                   f"Set '{key} {expected}' in /etc/ssh/sshd_config on each ESXi host")
        for ctrl_id, title, key, op, expected in SSH_CHECKS
    ]


def check_esxi_account_shell(hosts: List[vim.HostSystem],
                              ssh_user: str, ssh_pass: str,
                              ssh_port: int = 22) -> List[ControlResult]:
    """Check dcui and vpxuser shell access via esxcli over SSH."""
    dcui_st: List[Tuple[str, str, str]] = []
    vpx_st:  List[Tuple[str, str, str]] = []

    for h in hosts:
        ok, out = _esxi_ssh_run(h.name, ssh_user, ssh_pass, ssh_port,
                                "esxcli system account list 2>/dev/null")
        if not ok:
            dcui_st.append((h.name, "UNKNOWN", f"SSH error: {out[:80]}"))
            vpx_st.append((h.name,  "UNKNOWN", f"SSH error: {out[:80]}"))
            continue
        for acct, st_list in [("dcui", dcui_st), ("vpxuser", vpx_st)]:
            lines = [l for l in out.splitlines() if l.strip().lower().startswith(acct)]
            if not lines:
                st_list.append((h.name, "UNKNOWN", f"Account '{acct}' not found"))
                continue
            parts = lines[0].split()
            shell = parts[-1].lower() if len(parts) >= 2 else "unknown"
            if shell == "false":
                st_list.append((h.name, "PASS", f"{acct} shellAccess=false"))
            else:
                st_list.append((h.name, "FAIL", f"{acct} shellAccess={shell}"))

    return [
        _summarize("esxi-8.account-dcui",    "dcui account shell access disabled",    "ESXi", dcui_st,
                   "esxcli system account set --id dcui --shell-access false"),
        _summarize("esxi-8.account-vpxuser", "vpxuser account shell access disabled", "ESXi", vpx_st,
                   "esxcli system account set --id vpxuser --shell-access false"),
    ]


def check_esxi_vib_acceptance(hosts: List[vim.HostSystem],
                               ssh_user: str, ssh_pass: str,
                               ssh_port: int = 22) -> List[ControlResult]:
    """Check VIB software acceptance level via esxcli over SSH."""
    statuses: List[Tuple[str, str, str]] = []
    ACCEPTABLE = {"vmwarecertified", "vmwareaccepted", "partnersupported"}

    for h in hosts:
        ok, out = _esxi_ssh_run(h.name, ssh_user, ssh_pass, ssh_port,
                                "esxcli software acceptance get 2>/dev/null")
        if not ok:
            statuses.append((h.name, "UNKNOWN", f"SSH error: {out[:80]}"))
            continue
        level = out.strip().lower()
        if level in ACCEPTABLE:
            statuses.append((h.name, "PASS", f"acceptanceLevel={out.strip()}"))
        elif "community" in level:
            statuses.append((h.name, "FAIL",
                             f"acceptanceLevel=CommunitySupported (too permissive — allows unsigned VIBs)"))
        else:
            statuses.append((h.name, "UNKNOWN", f"Unexpected output: {out[:60]}"))

    return [_summarize("esxi-8.vib-acceptance-level-supported",
                       "VIB acceptance level is PartnerSupported or above", "ESXi", statuses,
                       "esxcli software acceptance set --level PartnerSupported")]


def check_esxi_fips_ssh(hosts: List[vim.HostSystem],
                        ssh_user: str, ssh_pass: str,
                        ssh_port: int = 22) -> List[ControlResult]:
    """Check if FIPS mode is enabled for SSH on ESXi via esxcli."""
    statuses: List[Tuple[str, str, str]] = []
    for h in hosts:
        ok, out = _esxi_ssh_run(h.name, ssh_user, ssh_pass, ssh_port,
                                "esxcli system security fips140 ssh get 2>/dev/null")
        if not ok:
            statuses.append((h.name, "UNKNOWN", f"SSH error: {out[:80]}"))
            continue
        enabled = "true" in out.lower()
        if enabled:
            statuses.append((h.name, "PASS", "FIPS 140 SSH enabled"))
        else:
            statuses.append((h.name, "FAIL", f"FIPS 140 SSH disabled: {out[:60]}"))
    return [_summarize("esxi-8.ssh-fips", "SSH FIPS 140 mode enabled", "ESXi", statuses,
                       "esxcli system security fips140 ssh set --enable true")]


def check_esxi_tls_profile(hosts: List[vim.HostSystem],
                            ssh_user: str, ssh_pass: str,
                            ssh_port: int = 22) -> List[ControlResult]:
    """Check ESXi TLS profile via esxcli."""
    statuses: List[Tuple[str, str, str]] = []
    for h in hosts:
        ok, out = _esxi_ssh_run(h.name, ssh_user, ssh_pass, ssh_port,
                                "esxcli system tls reconfig get 2>/dev/null || "
                                "esxcli system tls reconfig current get 2>/dev/null")
        if not ok:
            statuses.append((h.name, "UNKNOWN", f"SSH error: {out[:80]}"))
            continue
        profile = "unknown"
        for line in out.splitlines():
            if "profile" in line.lower() or "nist" in line.lower():
                profile = line.strip()
                break
        nist = "nist" in out.lower()
        if nist:
            statuses.append((h.name, "PASS", f"TLS profile contains NIST: {profile}"))
        else:
            statuses.append((h.name, "FAIL", f"TLS profile not NIST_2024: {profile or out[:60]}"))
    return [_summarize("esxi-8.tls-profile", "TLS profile set to NIST_2024", "ESXi", statuses,
                       "esxcli system tls reconfig set --profile NIST_2024 (requires reboot)")]


def check_esxi_secureboot_enforcement(hosts: List[vim.HostSystem],
                                       ssh_user: str, ssh_pass: str,
                                       ssh_port: int = 22) -> List[ControlResult]:
    """Check TPM-based Secure Boot enforcement via esxcli."""
    statuses: List[Tuple[str, str, str]] = []
    for h in hosts:
        ok, out = _esxi_ssh_run(h.name, ssh_user, ssh_pass, ssh_port,
                                "esxcli system settings encryption get 2>/dev/null")
        if not ok:
            statuses.append((h.name, "UNKNOWN", f"SSH error: {out[:80]}"))
            continue
        enforced = "true" in out.lower() and "requir" in out.lower()
        if enforced:
            statuses.append((h.name, "PASS", "Secure Boot enforcement enabled"))
        else:
            statuses.append((h.name, "UNKNOWN", f"Cannot determine enforcement: {out[:80]}"))
    return [_summarize("esxi-8.secureboot-enforcement",
                       "TPM-based Secure Boot enforcement enabled", "ESXi", statuses,
                       "esxcli system settings encryption set --require-secure-boot=TRUE")]


def check_esxi_ssh_combined(hosts: List[vim.HostSystem],
                             ssh_user: str, ssh_pass: str,
                             ssh_port: int = 22) -> List[ControlResult]:
    """Run all ESXi SSH-based checks in one SSH session per host (efficient)."""
    out: List[ControlResult] = []
    out.extend(check_esxi_ssh_daemon(hosts, ssh_user, ssh_pass, ssh_port))
    out.extend(check_esxi_account_shell(hosts, ssh_user, ssh_pass, ssh_port))
    out.extend(check_esxi_vib_acceptance(hosts, ssh_user, ssh_pass, ssh_port))
    out.extend(check_esxi_fips_ssh(hosts, ssh_user, ssh_pass, ssh_port))
    out.extend(check_esxi_tls_profile(hosts, ssh_user, ssh_pass, ssh_port))
    out.extend(check_esxi_secureboot_enforcement(hosts, ssh_user, ssh_pass, ssh_port))
    return out


def check_vm_special(vms: List[vim.VirtualMachine]) -> List[ControlResult]:
    """Check VM config properties not in extraConfig (log-enable, encryption, device hygiene)."""
    log_st: List[Tuple[str, str, str]] = []
    ft_st:  List[Tuple[str, str, str]] = []
    vm_st:  List[Tuple[str, str, str]] = []
    dev_st: List[Tuple[str, str, str]] = []
    _UNWANTED = (
        vim.vm.device.VirtualFloppy,
        vim.vm.device.VirtualSerialPort,
        vim.vm.device.VirtualParallelPort,
    )
    for vm in vms:
        cfg = getattr(vm, "config", None)
        if not cfg:
            continue
        n = vm.name

        # vm-8.log-enable
        log_on = getattr(getattr(cfg, "flags", None), "enableLogging", None)
        if log_on is None:
            log_st.append((n, "UNKNOWN", "enableLogging not accessible"))
        elif log_on:
            log_st.append((n, "PASS", "enableLogging=True"))
        else:
            log_st.append((n, "FAIL", "enableLogging=False"))

        # vm-8.ft-encrypted
        ft = getattr(cfg, "ftEncryptionMode", None)
        if ft is None:
            ft_st.append((n, "UNKNOWN", "ftEncryptionMode not accessible"))
        elif str(ft).lower() == "ftencryptionrequired":
            ft_st.append((n, "PASS", f"ftEncryptionMode={ft}"))
        else:
            ft_st.append((n, "FAIL", f"ftEncryptionMode={ft} (need ftEncryptionRequired)"))

        # vm-8.vmotion-encrypted
        me = getattr(cfg, "migrateEncryption", None)
        if me is None:
            vm_st.append((n, "UNKNOWN", "migrateEncryption not accessible"))
        elif str(me).lower() == "required":
            vm_st.append((n, "PASS", f"migrateEncryption={me}"))
        else:
            vm_st.append((n, "FAIL", f"migrateEncryption={me} (need required)"))

        # vm-8.remove-unnecessary-devices
        hw = getattr(cfg, "hardware", None)
        bad = [type(d).__name__ for d in (getattr(hw, "device", []) or []) if isinstance(d, _UNWANTED)]
        if bad:
            dev_st.append((n, "FAIL", f"Found: {', '.join(bad)}"))
        else:
            dev_st.append((n, "PASS", "No floppy/serial/parallel devices"))

    return [
        _summarize("vm-8.log-enable", "VM logging enabled", "VM", log_st,
                   "Enable logging in VM advanced settings (flags.enableLogging=True)"),
        _summarize("vm-8.ft-encrypted", "Fault tolerance encryption required", "VM", ft_st,
                   "Set ftEncryptionMode=ftEncryptionRequired in VM config"),
        _summarize("vm-8.vmotion-encrypted", "vMotion encryption required", "VM", vm_st,
                   "Set migrateEncryption=required in VM config"),
        _summarize("vm-8.remove-unnecessary-devices", "No unnecessary hardware devices", "VM", dev_st,
                   "Remove floppy, serial, and parallel devices from VM hardware configuration"),
    ]


def check_esxi_secureboot(hosts: List[vim.HostSystem]) -> List[ControlResult]:
    statuses: List[Tuple[str, str, str]] = []
    for h in hosts:
        try:
            boot_opt = getattr(h.config, "bootOption", None) if h.config else None
            secure = getattr(boot_opt, "efiSecureBootEnabled", None) if boot_opt else None
            if secure is None:
                statuses.append((h.name, "UNKNOWN", "Secure Boot status not accessible via API"))
            elif secure:
                statuses.append((h.name, "PASS", "efiSecureBootEnabled=True"))
            else:
                statuses.append((h.name, "FAIL", "efiSecureBootEnabled=False"))
        except Exception as exc:
            statuses.append((h.name, "UNKNOWN", str(exc)))
    return [_summarize("esxi-8.secureboot", "Secure Boot enabled", "ESXi", statuses,
                       "Enable Secure Boot in ESXi host BIOS/UEFI settings")]


def check_esxi_firewall(hosts: List[vim.HostSystem]) -> List[ControlResult]:
    statuses: List[Tuple[str, str, str]] = []
    for h in hosts:
        try:
            fw_info = h.configManager.firewallSystem.firewallInfo
            dp = getattr(fw_info, "defaultPolicy", None)
            if dp is None:
                statuses.append((h.name, "UNKNOWN", "firewallInfo.defaultPolicy not accessible"))
                continue
            blocked = getattr(dp, "incomingBlocked", None)
            if blocked is None:
                statuses.append((h.name, "UNKNOWN", "incomingBlocked attribute not found"))
            elif blocked:
                statuses.append((h.name, "PASS", "Default incoming policy=block"))
            else:
                statuses.append((h.name, "FAIL", "Default incoming policy=allow (should block)"))
        except Exception as exc:
            statuses.append((h.name, "UNKNOWN", str(exc)))
    return [_summarize("esxi-8.firewall-incoming-default",
                       "Firewall default blocks incoming traffic", "ESXi", statuses,
                       "Enable ESXi firewall and set default incoming policy to block")]


def check_esxi_vlan_vgt(hosts: List[vim.HostSystem]) -> List[ControlResult]:
    statuses: List[Tuple[str, str, str]] = []
    for h in hosts:
        try:
            net_info = h.configManager.networkSystem.networkInfo
            vgt = [pg.spec.name for pg in (net_info.portgroup or [])
                   if getattr(pg.spec, "vlanId", 0) == 4095]
            if vgt:
                statuses.append((h.name, "FAIL", f"VLAN 4095 on portgroups: {', '.join(vgt)}"))
            else:
                statuses.append((h.name, "PASS", "No VLAN 4095 portgroups"))
        except Exception as exc:
            statuses.append((h.name, "UNKNOWN", str(exc)))
    return [_summarize("esxi-8.network-vgt",
                       "No Virtual Guest Tagging (VLAN 4095)", "ESXi", statuses,
                       "Remove VLAN 4095 from all portgroups to prevent VGT attacks")]


def check_esxi_lockdown_users(hosts: List[vim.HostSystem]) -> List[ControlResult]:
    statuses: List[Tuple[str, str, str]] = []
    for h in hosts:
        try:
            exceptions = h.configManager.hostAccessManager.QueryLockdownExceptions() or []
            if exceptions:
                statuses.append((h.name, "FAIL", f"Exception users: {', '.join(exceptions)}"))
            else:
                statuses.append((h.name, "PASS", "Lockdown exception list is empty"))
        except Exception as exc:
            statuses.append((h.name, "UNKNOWN", str(exc)))
    return [_summarize("esxi-8.lockdown-exception-users",
                       "Lockdown exception users list empty", "ESXi", statuses,
                       "Remove all users from the lockdown mode exception list")]


def check_vcenter_advanced_settings(si: vim.ServiceInstance) -> List[ControlResult]:
    """Check vCenter settings accessible via si.content.setting."""
    out: List[ControlResult] = []

    def _get(key: str) -> Optional[str]:
        try:
            for opt in si.content.setting.setting:
                if opt.key == key:
                    return str(opt.value)
        except Exception:
            pass
        return None

    checks = [
        ("vcenter-8.vpxuser-rotation",    "vpxuser password rotation <= 30 days",
         "VirtualCenter.VimPasswordExpirationInDays", "<=", 30,
         "Set VirtualCenter.VimPasswordExpirationInDays = 30"),
        ("vcenter-8.events-remote-logging", "vCenter event remote syslog enabled",
         "vpxd.event.syslog.enabled", "==", "true",
         "Set vpxd.event.syslog.enabled = true"),
        ("vcenter-8.logs-level-global",   "vCenter log level = info",
         "config.log.level", "==", "info",
         "Set config.log.level = info in vCenter advanced settings"),
        ("vcenter-8.events-database-retention", "Event database retention >= 30 days",
         "event.maxAge", ">=", 30,
         "Set event.maxAge >= 30 in vCenter Advanced Settings"),
    ]
    for ctrl_id, title, key, op, expected, hint in checks:
        val = _get(key)
        if val is None:
            out.append(ControlResult(ctrl_id, title, "vCenter", "UNKNOWN",
                                     f"{key} not accessible", hint))
        else:
            status = "PASS" if _compare(val, op, expected) else "FAIL"
            out.append(ControlResult(ctrl_id, title, "vCenter", status,
                                     f"{key}={val}", hint))
    return out


def check_vcenter_dvportgroup(si: vim.ServiceInstance) -> List[ControlResult]:
    """Check distributed virtual portgroup security policies."""
    pr_st: List[Tuple[str, str, str]] = []
    ft_st: List[Tuple[str, str, str]] = []
    mc_st: List[Tuple[str, str, str]] = []
    try:
        view = si.content.viewManager.CreateContainerView(
            si.content.rootFolder, [vim.DistributedVirtualPortgroup], True)
        portgroups = list(view.view)
        view.Destroy()
    except Exception as exc:
        err = str(exc)
        for lst in (pr_st, ft_st, mc_st):
            lst.append(("vCenter", "UNKNOWN", f"Cannot access dvPortGroups: {err}"))
        portgroups = []

    for pg in portgroups:
        try:
            pg_name = pg.config.name
            sec = pg.config.defaultPortConfig.securityPolicy

            def _sec_val(attr: str) -> Optional[bool]:
                return getattr(getattr(sec, attr, None), "value", None)

            ap = _sec_val("allowPromiscuous")
            pr_st.append((pg_name, "PASS" if ap is False else ("FAIL" if ap else "UNKNOWN"),
                          f"allowPromiscuous={ap}"))
            ft = _sec_val("forgedTransmits")
            ft_st.append((pg_name, "PASS" if ft is False else ("FAIL" if ft else "UNKNOWN"),
                          f"forgedTransmits={ft}"))
            mc = _sec_val("macChanges")
            mc_st.append((pg_name, "PASS" if mc is False else ("FAIL" if mc else "UNKNOWN"),
                          f"macChanges={mc}"))
        except Exception as exc:
            for lst in (pr_st, ft_st, mc_st):
                lst.append((getattr(getattr(pg, "config", None), "name", "Unknown"),
                            "UNKNOWN", str(exc)))

    if not portgroups and not pr_st:
        for lst in (pr_st, ft_st, mc_st):
            lst.append(("vCenter", "PASS", "No distributed portgroups configured"))

    return [
        _summarize("vcenter-8.network-reject-promiscuous-mode-dvportgroup",
                   "DVPortGroup: promiscuous mode rejected", "Network", pr_st,
                   "Set allowPromiscuous=False on all distributed portgroups"),
        _summarize("vcenter-8.network-reject-forged-transmit-dvportgroup",
                   "DVPortGroup: forged transmits rejected", "Network", ft_st,
                   "Set forgedTransmits=False on all distributed portgroups"),
        _summarize("vcenter-8.network-reject-mac-changes-dvportgroup",
                   "DVPortGroup: MAC changes rejected", "Network", mc_st,
                   "Set macChanges=False on all distributed portgroups"),
    ]


def run_scan_by_category(si: vim.ServiceInstance, category: str,
                         esxi_ssh_user: str = "", esxi_ssh_pass: str = "",
                         esxi_ssh_port: int = 22) -> List[ControlResult]:
    """Run only the checks belonging to the selected category."""
    hosts = get_hosts(si)
    results: List[ControlResult] = []
    _ssh = bool(esxi_ssh_user and esxi_ssh_pass and _PARAMIKO)

    IAM_KEYS = {
        "esxi-8.account-lockout", "esxi-8.account-auto-unlock-time",
        "esxi-8.account-password-history", "esxi-8.host-client-session-timeout",
        "esxi-8.api-soap-timeout", "esxi-8.account-password-max-days",
        "esxi-8.account-password-policies", "esxi-8.lockdown-dcui-access",
    }
    SVC_KEYS = {
        "esxi-8.shell-interactive-timeout", "esxi-8.shell-timeout",
        "esxi-8.dcui-timeout", "esxi-8.shell-warning", "esxi-8.deactivate-mob",
    }
    NET_KEYS = {
        "esxi-8.network-bpdu", "esxi-8.network-dvfilter", "esxi-8.hw-virtual-nic",
    }
    LOG_KEYS = {
        "esxi-8.logs-level", "esxi-8.logs-audit-local", "esxi-8.logs-remote-tls",
        "esxi-8.transparent-page-sharing", "esxi-8.memeagerzero",
        "esxi-8.cpu-hyperthread-warning", "esxi-8.logs-audit-remote",
        "esxi-8.logs-audit-local-capacity", "esxi-8.logs-level-global",
        "esxi-8.logs-persistent", "esxi-8.logs-remote-tls-x509",
        "esxi-8.tls-protocols", "esxi-8.annotations-welcomemessage",
        "esxi-8.etc-issue", "esxi-8.logs-filter",
    }

    if category in ("Identity & Access", "All"):
        iam_chks = [c for c in ESXI_ADV_CHECKS if c[0] in IAM_KEYS]
        results.extend(check_esxi_advanced_options(hosts, iam_chks))
        results.extend(check_esxi_lockdown(hosts))
        results.extend(check_esxi_lockdown_users(hosts))
        results.extend(check_vcenter_password_policy(si))
        results.extend(check_vcenter_session_timeout(si))
        results.extend(check_vcenter_sso_policy(si))
        results.extend(check_vcenter_login_banner(si))
        if _ssh:
            results.extend(check_esxi_account_shell(hosts, esxi_ssh_user, esxi_ssh_pass, esxi_ssh_port))

    if category in ("Services", "All"):
        results.extend(check_esxi_services(hosts))
        svc_chks = [c for c in ESXI_ADV_CHECKS if c[0] in SVC_KEYS]
        results.extend(check_esxi_advanced_options(hosts, svc_chks))
        results.extend(check_esxi_secureboot(hosts))
        results.extend(check_esxi_supported(hosts))
        results.extend(check_vcenter_version(si))
        results.extend(check_vcenter_vami(si))
        results.extend(check_vsan(si))
        if _ssh:
            results.extend(check_esxi_ssh_daemon(hosts, esxi_ssh_user, esxi_ssh_pass, esxi_ssh_port))
            results.extend(check_esxi_vib_acceptance(hosts, esxi_ssh_user, esxi_ssh_pass, esxi_ssh_port))
            results.extend(check_esxi_fips_ssh(hosts, esxi_ssh_user, esxi_ssh_pass, esxi_ssh_port))
            results.extend(check_esxi_tls_profile(hosts, esxi_ssh_user, esxi_ssh_pass, esxi_ssh_port))
            results.extend(check_esxi_secureboot_enforcement(hosts, esxi_ssh_user, esxi_ssh_pass, esxi_ssh_port))

    if category in ("Network", "All"):
        net_chks = [c for c in ESXI_ADV_CHECKS if c[0] in NET_KEYS]
        results.extend(check_esxi_advanced_options(hosts, net_chks))
        results.extend(check_vswitch_security(hosts))
        results.extend(check_esxi_firewall(hosts))
        results.extend(check_esxi_vlan_vgt(hosts))
        results.extend(check_vcenter_dvportgroup(si))
        results.extend(check_vcenter_dvswitch_security(si))

    if category in ("VM Security", "All"):
        vms = get_all_vms(si)
        results.extend(check_vm_configs(vms))
        results.extend(check_vm_special(vms))
        results.extend(check_vm_advanced(vms))

    if category in ("Logging & Audit", "All"):
        results.extend(check_esxi_syslog(hosts))
        results.extend(check_esxi_ntp_servers(hosts))
        log_chks = [c for c in ESXI_ADV_CHECKS if c[0] in LOG_KEYS]
        results.extend(check_esxi_advanced_options(hosts, log_chks))
        results.extend(check_vcenter_advanced_settings(si))

    # De-duplicate by control_id (keep first occurrence)
    seen: set = set()
    unique: List[ControlResult] = []
    for r in results:
        if r.control_id not in seen:
            seen.add(r.control_id)
            unique.append(r)
    return unique


def run_full_scan(si: vim.ServiceInstance,
                  esxi_ssh_user: str = "", esxi_ssh_pass: str = "",
                  esxi_ssh_port: int = 22) -> List[ControlResult]:
    hosts = get_hosts(si)
    vms   = get_all_vms(si)
    results: List[ControlResult] = []
    results.extend(check_esxi_syslog(hosts))
    results.extend(check_esxi_advanced_options(hosts))
    results.extend(check_esxi_services(hosts))
    results.extend(check_esxi_ntp_servers(hosts))
    results.extend(check_esxi_lockdown(hosts))
    results.extend(check_esxi_lockdown_users(hosts))
    results.extend(check_esxi_secureboot(hosts))
    results.extend(check_esxi_firewall(hosts))
    results.extend(check_esxi_vlan_vgt(hosts))
    results.extend(check_vcenter_password_policy(si))
    results.extend(check_vcenter_session_timeout(si))
    results.extend(check_vcenter_advanced_settings(si))
    results.extend(check_vcenter_dvportgroup(si))
    results.extend(check_vm_configs(vms))
    results.extend(check_vm_special(vms))
    results.extend(check_vm_advanced(vms))
    results.extend(check_vswitch_security(hosts))
    results.extend(check_esxi_supported(hosts))
    results.extend(check_vcenter_version(si))
    results.extend(check_vcenter_sso_policy(si))
    results.extend(check_vcenter_login_banner(si))
    results.extend(check_vcenter_vami(si))
    results.extend(check_vcenter_dvswitch_security(si))
    results.extend(check_vsan(si))
    if esxi_ssh_user and esxi_ssh_pass and _PARAMIKO:
        results.extend(check_esxi_ssh_combined(hosts, esxi_ssh_user, esxi_ssh_pass, esxi_ssh_port))
    return results


# ─── Remediation ─────────────────────────────────────────────────────────────
REMEDIATION_REGISTRY: Dict[str, Dict] = {}


def _reg(ctrl_id: str, description: str, fn: Callable) -> None:
    REMEDIATION_REGISTRY[ctrl_id] = {"description": description, "fn": fn}


def _remediate_adv_option(si: vim.ServiceInstance, key: str, value: Any) -> Tuple[bool, str]:
    hosts = get_hosts(si)
    errors = []
    for h in hosts:
        try:
            opt = vim.option.OptionValue(key=key, value=value)
            h.configManager.advancedOption.UpdateValues([opt])
        except Exception as exc:
            errors.append(f"{h.name}: {exc}")
    if errors:
        return False, "Errors: " + "; ".join(errors)
    return True, f"Set {key}={value} on {len(hosts)} host(s)"


def _remediate_service(si: vim.ServiceInstance, svc_key: str, should_run: bool) -> Tuple[bool, str]:
    hosts = get_hosts(si)
    errors = []
    for h in hosts:
        try:
            svc_sys = h.configManager.serviceSystem
            if should_run:
                svc_sys.StartService(id=svc_key)
            else:
                svc_sys.StopService(id=svc_key)
        except Exception as exc:
            errors.append(f"{h.name}: {exc}")
    if errors:
        return False, "Errors: " + "; ".join(errors)
    action = "started" if should_run else "stopped"
    return True, f"Service {svc_key} {action} on {len(hosts)} host(s)"


def _remediate_vm_config(si: vim.ServiceInstance, cfg_key: str, value: str) -> Tuple[bool, str]:
    vms = get_all_vms(si)
    errors = []
    for vm in vms:
        try:
            spec = vim.vm.ConfigSpec()
            spec.extraConfig = [vim.option.OptionValue(key=cfg_key, value=value)]
            vm.ReconfigVM_Task(spec)
        except Exception as exc:
            errors.append(f"{vm.name}: {exc}")
    if errors:
        return False, "Errors: " + "; ".join(errors)
    return True, f"Set {cfg_key}={value} on {len(vms)} VM(s)"


# Register remediations for automated controls
for _id, _title, _key, _op, _exp in ESXI_ADV_CHECKS:
    def _make_adv_fn(_k=_key, _e=_exp):
        def fn(si): return _remediate_adv_option(si, _k, _e)
        return fn
    _reg(_id, f"Set {_key} {_op} {_exp} on all ESXi hosts", _make_adv_fn())

for _id, _title, _svc, _run in ESXI_SVC_CHECKS:
    def _make_svc_fn(_s=_svc, _r=_run):
        def fn(si): return _remediate_service(si, _s, _r)
        return fn
    _reg(_id, f"{'Start' if _run else 'Stop'} {_svc} on all ESXi hosts", _make_svc_fn())

for _id, _title, _cfg, _val, _op in VM_CONFIG_CHECKS:
    def _make_vm_fn(_k=_cfg, _v=str(_val)):
        def fn(si): return _remediate_vm_config(si, _k, _v)
        return fn
    _reg(_id, f"Set {_cfg}={_val} on all VMs", _make_vm_fn())


def apply_remediation(si: vim.ServiceInstance, ctrl_id: str) -> Tuple[bool, str]:
    entry = REMEDIATION_REGISTRY.get(ctrl_id)
    if not entry:
        return False, f"No automated remediation available for {ctrl_id}"
    return entry["fn"](si)


# ─── Result Cache (file-based, survives server restarts) ────────────────────
CACHE_FILE = Path.home() / ".vsphere-scanner-cache.json"


def save_results_cache(results: List[ControlResult], host: str, category: str) -> None:
    """Save current scan; promotes existing current → previous for before/after comparison."""
    try:
        previous: Optional[Dict] = None
        if CACHE_FILE.exists():
            raw = json.loads(CACHE_FILE.read_text())
            if "current" in raw:
                previous = raw["current"]
            elif "results" in raw:          # migrate old flat format
                previous = raw

        current = {
            "host":      host,
            "category":  category,
            "timestamp": datetime.now().isoformat(timespec="seconds"),
            "results":   [asdict(r) for r in results],
        }
        payload: Dict = {"current": current}
        if previous and previous.get("results"):
            payload["previous"] = previous
        CACHE_FILE.write_text(json.dumps(payload, indent=2))
    except Exception:
        pass


def load_results_cache() -> Optional[Dict]:
    """Returns {'current': {...}, 'previous': {...}} or None."""
    try:
        if CACHE_FILE.exists():
            raw = json.loads(CACHE_FILE.read_text())
            if "current" in raw:
                return raw
            elif "results" in raw:          # old flat format
                return {"current": raw}
    except Exception:
        pass
    return None


# ─── OCI GenAI ───────────────────────────────────────────────────────────────
def get_genai_client() -> oci.generative_ai_inference.GenerativeAiInferenceClient:
    try:
        signer = oci.auth.signers.InstancePrincipalsSecurityTokenSigner()
        cfg    = {}
    except Exception:
        cfg    = oci.config.from_file()
        signer = None
    kwargs: Dict[str, Any] = {
        "config":           cfg,
        "service_endpoint": OCI_GENAI_ENDPOINT,
        "retry_strategy":   oci.retry.NoneRetryStrategy(),
        "timeout":          (10, 240),
    }
    if signer:
        kwargs["signer"] = signer
    return oci.generative_ai_inference.GenerativeAiInferenceClient(**kwargs)


def call_genai(prompt: str, temperature: float = 0.3, max_tokens: int = 800) -> str:
    client = get_genai_client()
    req = oci.generative_ai_inference.models.CohereChatRequest()
    req.message      = prompt
    req.max_tokens   = max_tokens
    req.temperature  = temperature
    req.frequency_penalty = 0
    req.top_p        = 0.75
    req.top_k        = 0
    req.safety_mode  = "CONTEXTUAL"

    detail = oci.generative_ai_inference.models.ChatDetails()
    detail.serving_mode = oci.generative_ai_inference.models.OnDemandServingMode(
        model_id=OCI_GENAI_MODEL_OCID
    )
    detail.chat_request  = req
    detail.compartment_id = OCI_COMPARTMENT_OCID

    resp = client.chat(detail)
    return resp.data.chat_response.chat_history[1].message


def generate_narrative(results: List[ControlResult]) -> str:
    passed  = sum(1 for r in results if r.status == "PASS")
    failed  = sum(1 for r in results if r.status == "FAIL")
    unknown = sum(1 for r in results if r.status == "UNKNOWN")
    fail_lines = "\n".join(
        f"- {r.control_id}: {r.title} | {r.evidence}"
        for r in results if r.status == "FAIL"
    ) or "None"
    prompt = (
        "You are a vSphere security hardening expert for an Oracle Cloud Infrastructure SOC. "
        "Provide a concise executive summary (3-4 sentences) and prioritized remediation actions "
        "for the failing controls. Be direct and technical.\n\n"
        f"Scan results: {len(results)} controls | {passed} PASS | {failed} FAIL | {unknown} UNKNOWN\n"
        f"Failing controls:\n{fail_lines}"
    )
    return call_genai(prompt, temperature=0.2, max_tokens=700)


# ─── UI Helpers ──────────────────────────────────────────────────────────────
def load_logo_b64() -> Optional[str]:
    logo_path = ASSETS_DIR / "oracle_logo.png"
    if logo_path.exists():
        return base64.b64encode(logo_path.read_bytes()).decode()
    return None


def render_header(logo_b64: Optional[str]) -> None:
    logo_html = (
        f'<img src="data:image/png;base64,{logo_b64}" style="height:42px;" alt="Oracle"/>'
        if logo_b64 else
        '<span style="color:#C74634;font-size:1.4rem;font-weight:800;letter-spacing:1px;">ORACLE</span>'
    )
    st.markdown(f"""
    <div class="oracle-header">
        {logo_html}
        <div class="oracle-header-title">
            <div class="oracle-title">vSphere Security Hardening Scanner</div>
            <div class="oracle-subtitle">Oracle Cloud Infrastructure &nbsp;|&nbsp; Enterprise SOC Automation</div>
        </div>
    </div>
    """, unsafe_allow_html=True)


def render_metrics(results: List[ControlResult]) -> None:
    total   = len(results)
    passed  = sum(1 for r in results if r.status == "PASS")
    failed  = sum(1 for r in results if r.status == "FAIL")
    unknown = sum(1 for r in results if r.status == "UNKNOWN")
    manual  = sum(1 for r in results if r.status == "MANUAL")
    pct     = int(passed / total * 100) if total else 0
    st.markdown(f"""
    <div class="metric-grid">
        <div class="metric-card">
            <div class="metric-value mv-total">{total}</div>
            <div class="metric-label">Controls Scanned</div>
        </div>
        <div class="metric-card">
            <div class="metric-value mv-pass">{passed}</div>
            <div class="metric-label">Passed</div>
        </div>
        <div class="metric-card">
            <div class="metric-value mv-fail">{failed}</div>
            <div class="metric-label">Failed</div>
        </div>
        <div class="metric-card">
            <div class="metric-value mv-unknown">{unknown}</div>
            <div class="metric-label">Unknown</div>
        </div>
        <div class="metric-card">
            <div class="metric-value mv-pass">{pct}%</div>
            <div class="metric-label">Compliance Score</div>
        </div>
    </div>
    """, unsafe_allow_html=True)


COMP_CLASS = {
    "ESXi": "comp-esxi", "vCenter": "comp-vcenter",
    "VM": "comp-vm", "Network": "comp-network",
    "vSAN": "comp-vsan", "TrustAuthority": "comp-trustauth",
}
STATUS_BADGE = {
    "PASS":    "badge-pass",
    "FAIL":    "badge-fail",
    "UNKNOWN": "badge-unknown",
    "MANUAL":  "badge-manual",
}


def render_result_rows(results: List[ControlResult], show_fix: bool = True,
                       key_prefix: str = "") -> None:
    for i, r in enumerate(results):
        badge_cls = STATUS_BADGE.get(r.status, "badge-unknown")
        comp_cls  = COMP_CLASS.get(r.component, "comp-esxi")
        row_cls   = f"r-{r.status.lower()}"
        btn_key   = f"fix_{key_prefix}_{i}_{r.control_id}"

        col_row, col_fix = st.columns([10, 1]) if show_fix and r.status == "FAIL" else (st.container(), None)
        with col_row:
            st.markdown(f"""
            <div class="ctrl-row {row_cls}">
                <span class="ctrl-id">{r.control_id}</span>
                <span class="comp-pill {comp_cls}">{r.component}</span>
                <span class="ctrl-title">{r.title}</span>
                <span class="ctrl-evid">{r.evidence}</span>
                <span class="badge {badge_cls}">{r.status}</span>
            </div>
            """, unsafe_allow_html=True)
        if col_fix is not None and r.control_id in REMEDIATION_REGISTRY:
            with col_fix:
                if st.button("Fix", key=btn_key):
                    st.session_state.pending_remediation = r.control_id


def _detect_fix_intent(text: str) -> Optional[str]:
    lower = text.lower()
    if not any(w in lower for w in ("fix", "remediat", "disable", "enable", "stop", "start")):
        return None
    for kw, ctrl_id in FIX_KEYWORDS.items():
        if kw in lower and ctrl_id in REMEDIATION_REGISTRY:
            return ctrl_id
    ids = re.findall(r'\b(ESXI-8-\d+|VMCH-8-\d+|NET-8-\d+|VCENTER-8-\d+)\b', text.upper())
    for cid in ids:
        if cid in REMEDIATION_REGISTRY:
            return cid
    return None


# ─── PDF Report Generation ────────────────────────────────────────────────────
def generate_pdf_report(
    results: List[ControlResult],
    previous_results: Optional[List[ControlResult]] = None,
    host: str = "",
    timestamp: str = "",
    narrative: str = "",
) -> bytes:
    if not _REPORTLAB:
        raise RuntimeError("reportlab is not installed on this server.")

    buf = BytesIO()
    doc = SimpleDocTemplate(
        buf, pagesize=A4,
        topMargin=1.5*cm, bottomMargin=1.5*cm,
        leftMargin=2*cm, rightMargin=2*cm,
    )
    ORA   = rl_colors.HexColor("#C74634")
    GRN   = rl_colors.HexColor("#00C853")
    RED   = rl_colors.HexColor("#FF1744")
    AMB   = rl_colors.HexColor("#FFA000")
    LGREY = rl_colors.HexColor("#f4f4f4")
    DGREY = rl_colors.HexColor("#555555")

    SS = getSampleStyleSheet()
    s_h1   = ParagraphStyle("h1",  parent=SS["Heading1"],  textColor=ORA,   fontSize=18, spaceAfter=4)
    s_h2   = ParagraphStyle("h2",  parent=SS["Heading2"],  textColor=ORA,   fontSize=11, spaceBefore=10, spaceAfter=4)
    s_body = ParagraphStyle("body",parent=SS["Normal"],     textColor=DGREY, fontSize=8)
    s_sm   = ParagraphStyle("sm",  parent=SS["Normal"],     textColor=DGREY, fontSize=7)
    s_foot = ParagraphStyle("ft",  parent=SS["Normal"],     textColor=rl_colors.HexColor("#aaaaaa"), fontSize=7, alignment=1)

    story = []

    # ── Header ────────────────────────────────────────────────────────────────
    story.append(Paragraph("Oracle Cloud Infrastructure", s_sm))
    story.append(Paragraph("vSphere Security Hardening Scanner", s_h1))
    story.append(Paragraph("SOC Compliance Report — VMware SCG v8", s_body))
    story.append(HRFlowable(width="100%", color=ORA, thickness=2, spaceAfter=6))

    meta = [
        ["vCenter Host:", host or "N/A"],
        ["Scan Time:",    timestamp or "N/A"],
        ["Report Date:",  datetime.now().strftime("%Y-%m-%d %H:%M")],
    ]
    mt = Table(meta, colWidths=[3.5*cm, 13*cm])
    mt.setStyle(TableStyle([
        ("FONTSIZE",  (0,0), (-1,-1), 8),
        ("TEXTCOLOR", (0,0), (0,-1), ORA),
        ("FONTNAME",  (0,0), (0,-1), "Helvetica-Bold"),
    ]))
    story.append(mt)
    story.append(Spacer(1, 0.4*cm))

    # ── Compliance Scorecard ──────────────────────────────────────────────────
    total   = len(results)
    passed  = sum(1 for r in results if r.status == "PASS")
    failed  = sum(1 for r in results if r.status == "FAIL")
    unknown = sum(1 for r in results if r.status == "UNKNOWN")
    pct     = int(passed / total * 100) if total else 0
    score_color = GRN if pct >= 80 else (AMB if pct >= 50 else RED)

    sc_data = [
        ["Controls Scanned", "Passed", "Failed", "Unknown", "Compliance Score"],
        [str(total), str(passed), str(failed), str(unknown), f"{pct}%"],
    ]
    sc = Table(sc_data, colWidths=[3.5*cm]*5)
    sc.setStyle(TableStyle([
        ("BACKGROUND", (0,0), (-1,0), ORA),
        ("TEXTCOLOR",  (0,0), (-1,0), rl_colors.white),
        ("FONTNAME",   (0,0), (-1,0), "Helvetica-Bold"),
        ("ALIGN",      (0,0), (-1,-1), "CENTER"),
        ("FONTSIZE",   (0,0), (-1,-1), 9),
        ("FONTNAME",   (0,1), (-1,1), "Helvetica-Bold"),
        ("FONTSIZE",   (0,1), (-1,1), 14),
        ("TEXTCOLOR",  (1,1), (1,1), GRN),
        ("TEXTCOLOR",  (2,1), (2,1), RED),
        ("TEXTCOLOR",  (3,1), (3,1), AMB),
        ("TEXTCOLOR",  (4,1), (4,1), score_color),
        ("BOX",        (0,0), (-1,-1), 1, rl_colors.HexColor("#cccccc")),
        ("GRID",       (0,0), (-1,-1), 0.5, rl_colors.HexColor("#dddddd")),
        ("ROWBACKGROUNDS", (0,1), (-1,1), [LGREY]),
    ]))
    story.append(sc)
    story.append(Spacer(1, 0.3*cm))

    # ── AI Executive Summary ──────────────────────────────────────────────────
    if narrative:
        story.append(Paragraph("Executive Summary", s_h2))
        story.append(Paragraph(narrative.replace("\n", "<br/>"), s_body))
        story.append(Spacer(1, 0.3*cm))

    # ── Before / After Comparison ─────────────────────────────────────────────
    if previous_results:
        story.append(Paragraph("Remediation Progress — Before vs After", s_h2))
        prev_map = {r.control_id: r for r in previous_results}
        changed = [
            (r.control_id, r.title, prev_map[r.control_id].status, r.status)
            for r in results if r.control_id in prev_map
            and prev_map[r.control_id].status != r.status
        ]
        if changed:
            cmp_data = [["Control ID", "Title", "Before", "After"]]
            for cid, title, before, after in changed:
                cmp_data.append([cid, Paragraph(title[:60], s_sm), before, after])
            row_styles = [
                ("BACKGROUND", (0,0), (-1,0), ORA),
                ("TEXTCOLOR",  (0,0), (-1,0), rl_colors.white),
                ("FONTNAME",   (0,0), (-1,0), "Helvetica-Bold"),
                ("FONTSIZE",   (0,0), (-1,-1), 8),
                ("GRID",       (0,0), (-1,-1), 0.5, rl_colors.HexColor("#cccccc")),
                ("ROWBACKGROUNDS", (0,1), (-1,-1), [rl_colors.white, LGREY]),
                ("VALIGN",     (0,0), (-1,-1), "TOP"),
            ]
            for i, (_, _, before, after) in enumerate(changed, 1):
                b_col = GRN if before == "PASS" else (RED if before == "FAIL" else AMB)
                a_col = GRN if after == "PASS"  else (RED if after == "FAIL"  else AMB)
                row_styles += [
                    ("TEXTCOLOR", (2,i), (2,i), b_col),
                    ("TEXTCOLOR", (3,i), (3,i), a_col),
                    ("FONTNAME",  (3,i), (3,i), "Helvetica-Bold"),
                ]
            ct = Table(cmp_data, colWidths=[4.5*cm, 8*cm, 2*cm, 2*cm])
            ct.setStyle(TableStyle(row_styles))
            story.append(ct)
            improved = sum(1 for _,_,b,a in changed if b=="FAIL" and a=="PASS")
            regressed = sum(1 for _,_,b,a in changed if b=="PASS" and a=="FAIL")
            story.append(Spacer(1, 0.15*cm))
            story.append(Paragraph(
                f"Changes: {len(changed)} total — "
                f"<font color='#00C853'>{improved} improved</font>, "
                f"<font color='#FF1744'>{regressed} regressed</font>",
                s_body))
        else:
            story.append(Paragraph("No status changes detected between scans.", s_body))
        story.append(Spacer(1, 0.3*cm))

    # ── Failing Controls Detail ───────────────────────────────────────────────
    fails = [r for r in results if r.status == "FAIL"]
    if fails:
        story.append(Paragraph(f"Failing Controls ({len(fails)})", s_h2))
        fd = [["Control ID", "Comp", "Title", "Evidence", "Remediation Hint"]]
        for r in fails:
            fd.append([
                Paragraph(r.control_id, s_sm),
                r.component,
                Paragraph(r.title[:55], s_sm),
                Paragraph(r.evidence[:70], s_sm),
                Paragraph(r.remediation_hint[:70], s_sm),
            ])
        ft = Table(fd, colWidths=[3.8*cm, 1.5*cm, 3.8*cm, 3.5*cm, 3.8*cm])
        ft.setStyle(TableStyle([
            ("BACKGROUND", (0,0), (-1,0), RED),
            ("TEXTCOLOR",  (0,0), (-1,0), rl_colors.white),
            ("FONTNAME",   (0,0), (-1,0), "Helvetica-Bold"),
            ("FONTSIZE",   (0,0), (-1,-1), 8),
            ("GRID",       (0,0), (-1,-1), 0.5, rl_colors.HexColor("#cccccc")),
            ("ROWBACKGROUNDS", (0,1), (-1,-1), [rl_colors.white, rl_colors.HexColor("#fff0f0")]),
            ("VALIGN",     (0,0), (-1,-1), "TOP"),
        ]))
        story.append(ft)
        story.append(Spacer(1, 0.3*cm))

    # ── Full Results Summary ──────────────────────────────────────────────────
    story.append(Paragraph("Full Results Summary", s_h2))
    status_color_map = {"PASS": GRN, "FAIL": RED, "UNKNOWN": AMB, "MANUAL": rl_colors.HexColor("#7c9aff")}
    ad = [["Control ID", "Component", "Title", "Status"]]
    row_st = [
        ("BACKGROUND", (0,0), (-1,0), ORA),
        ("TEXTCOLOR",  (0,0), (-1,0), rl_colors.white),
        ("FONTNAME",   (0,0), (-1,0), "Helvetica-Bold"),
        ("FONTSIZE",   (0,0), (-1,-1), 8),
        ("GRID",       (0,0), (-1,-1), 0.5, rl_colors.HexColor("#dddddd")),
        ("ROWBACKGROUNDS", (0,1), (-1,-1), [rl_colors.white, LGREY]),
        ("VALIGN",     (0,0), (-1,-1), "TOP"),
    ]
    sorted_results = sorted(results, key=lambda r: (r.status != "FAIL", r.component, r.control_id))
    for i, r in enumerate(sorted_results, 1):
        ad.append([Paragraph(r.control_id, s_sm), r.component, Paragraph(r.title[:60], s_sm), r.status])
        row_st.append(("TEXTCOLOR", (3,i), (3,i), status_color_map.get(r.status, AMB)))
        row_st.append(("FONTNAME",  (3,i), (3,i), "Helvetica-Bold"))
    at = Table(ad, colWidths=[4.5*cm, 2*cm, 8.5*cm, 1.5*cm])
    at.setStyle(TableStyle(row_st))
    story.append(at)

    # ── Footer ────────────────────────────────────────────────────────────────
    story.append(Spacer(1, 0.5*cm))
    story.append(HRFlowable(width="100%", color=ORA, thickness=1))
    story.append(Paragraph(
        "Oracle Cloud Infrastructure | vSphere SOC Automation | VMware SCG v8 | OCI GenAI",
        s_foot))

    doc.build(story)
    return buf.getvalue()


# ─── Main Streamlit App ───────────────────────────────────────────────────────
def main() -> None:
    st.set_page_config(
        page_title="vSphere SOC Scanner | Oracle",
        page_icon="🛡️",
        layout="wide",
        initial_sidebar_state="expanded",
    )
    st.markdown(ENTERPRISE_CSS, unsafe_allow_html=True)

    # ── Session state init (load from file cache if session is fresh) ─────────
    _defaults = {
        "last_results":         None,
        "previous_results":     None,
        "scan_narrative":       "",
        "chat_history":         [],
        "vcenter_host":         "",
        "vcenter_user":         "",
        "pending_remediation":  None,
        "last_scan_ts":         "",
        "last_scan_category":   "All",
        "prev_scan_ts":         "",
    }
    for k, v in _defaults.items():
        if k not in st.session_state:
            st.session_state[k] = v

    # Restore last results from disk cache if session is empty (e.g. server restart)
    if st.session_state.last_results is None:
        cached = load_results_cache()
        if cached:
            cur = cached.get("current", {})
            st.session_state.last_results       = cur.get("results")
            st.session_state.last_scan_ts       = cur.get("timestamp", "")
            st.session_state.last_scan_category = cur.get("category", "All")
            st.session_state.vcenter_host       = cur.get("host", "")
            prev = cached.get("previous")
            if prev and prev.get("results"):
                st.session_state.previous_results = prev.get("results")
                st.session_state.prev_scan_ts     = prev.get("timestamp", "")

    # ── Logo + Header ─────────────────────────────────────────────────────────
    logo_b64 = load_logo_b64()
    render_header(logo_b64)

    SCAN_CATEGORIES = [
        "All",
        "Identity & Access",
        "Network",
        "Services",
        "VM Security",
        "Logging & Audit",
    ]

    # ── Sidebar ───────────────────────────────────────────────────────────────
    with st.sidebar:
        if logo_b64:
            st.markdown(
                f'<div style="text-align:center;padding:16px 8px 12px 8px;">'
                f'<img src="data:image/png;base64,{logo_b64}" style="height:64px;max-width:100%;"/></div>',
                unsafe_allow_html=True,
            )
        st.markdown('<div class="accent-bar"></div>', unsafe_allow_html=True)
        st.markdown('<p class="sidebar-label">vCenter Connection</p>', unsafe_allow_html=True)
        host     = st.text_input("Host / IP", placeholder="vcenter.example.local",
                                 value=st.session_state.vcenter_host)
        user     = st.text_input("Username", placeholder="administrator@vsphere.local",
                                 value=st.session_state.vcenter_user)
        password = st.text_input("Password", type="password")

        st.markdown('<p class="sidebar-label" style="margin-top:12px;">Scan Category</p>',
                    unsafe_allow_html=True)
        selected_cat = st.radio(
            "category",
            SCAN_CATEGORIES,
            label_visibility="collapsed",
        )
        run_clicked = st.button(
            f"Run {selected_cat} Scan",
            use_container_width=True,
        )

        st.markdown("---")
        if st.session_state.last_results:
            results_preview = [ControlResult(**r) for r in st.session_state.last_results]
            failed_count = sum(1 for r in results_preview if r.status == "FAIL")
            st.markdown('<p class="sidebar-label">Last Scan</p>', unsafe_allow_html=True)
            if st.session_state.last_scan_ts:
                st.caption(f"Time: {st.session_state.last_scan_ts}")
            cat_lbl = st.session_state.last_scan_category
            st.caption(f"Category: {cat_lbl}")
            st.caption(
                f"FAIL: {failed_count}  |  "
                f"PASS: {sum(1 for r in results_preview if r.status=='PASS')}"
            )
            if st.button("Clear Results", use_container_width=True):
                st.session_state.last_results = None
                st.session_state.scan_narrative = ""
                try:
                    CACHE_FILE.unlink(missing_ok=True)
                except Exception:
                    pass
                st.rerun()

    # ── Run scan ──────────────────────────────────────────────────────────────
    if run_clicked:
        if not host or not user or not password:
            st.warning("Please provide vCenter host, username, and password.")
        else:
            # Promote current → previous before overwriting
            if st.session_state.last_results:
                st.session_state.previous_results = st.session_state.last_results
                st.session_state.prev_scan_ts     = st.session_state.last_scan_ts
            st.session_state.vcenter_host       = host
            st.session_state.vcenter_user       = user
            st.session_state.last_scan_category = selected_cat
            prog = st.progress(0, text=f"Connecting to vCenter — scanning: {selected_cat}…")
            try:
                si = connect_vcenter(host, user, password)
                prog.progress(15, text="Connected. Running checks…")
                if selected_cat == "All":
                    scan_results = run_full_scan(si)
                else:
                    scan_results = run_scan_by_category(si, selected_cat)
                prog.progress(80, text="Generating AI summary…")
                # Merge with existing results from other categories if partial scan
                if selected_cat != "All" and st.session_state.last_results:
                    existing = {r["control_id"]: r for r in st.session_state.last_results}
                    for r in scan_results:
                        existing[r.control_id] = asdict(r)
                    merged = list(existing.values())
                else:
                    merged = [asdict(r) for r in scan_results]
                st.session_state.last_results = merged
                st.session_state.last_scan_ts = datetime.now().strftime("%Y-%m-%d %H:%M")
                save_results_cache(
                    [ControlResult(**r) for r in merged], host, selected_cat
                )
                try:
                    narrative = generate_narrative(scan_results)
                    st.session_state.scan_narrative = narrative
                except Exception as exc:
                    st.session_state.scan_narrative = (
                        f"GenAI summary unavailable: {exc}\n\n"
                        f"Scan complete: {len(scan_results)} controls checked "
                        f"({selected_cat}), "
                        f"{sum(1 for r in scan_results if r.status=='FAIL')} failures."
                    )
                prog.progress(100, text="Scan complete.")
                prog.empty()
                st.rerun()
            except Exception as exc:
                prog.empty()
                st.error(f"Connection failed: {exc}")

    # ── Load stored results ───────────────────────────────────────────────────
    results: Optional[List[ControlResult]] = None
    if st.session_state.last_results:
        results = [ControlResult(**r) for r in st.session_state.last_results]

    # ── Load CSV control catalog (graceful - no st.stop) ─────────────────────
    df_catalog: Optional[pd.DataFrame] = None
    if CSV_PATH.exists():
        try:
            df_catalog = pd.read_csv(CSV_PATH, encoding="utf-8-sig")
            # Normalize component names (strip "VMware " prefix)
            if "Component" in df_catalog.columns:
                df_catalog["Component"] = df_catalog["Component"].str.replace("VMware ", "", regex=False)
        except Exception:
            pass

    # ── Main content ──────────────────────────────────────────────────────────
    if results:
        render_metrics(results)

        # ── PDF Download ──────────────────────────────────────────────────────
        prev_results_obj = (
            [ControlResult(**r) for r in st.session_state.previous_results]
            if st.session_state.previous_results else None
        )
        _pdf_col, _ts_col = st.columns([2, 6])
        with _pdf_col:
            if _REPORTLAB:
                try:
                    pdf_bytes = generate_pdf_report(
                        results,
                        previous_results=prev_results_obj,
                        host=st.session_state.vcenter_host,
                        timestamp=st.session_state.last_scan_ts,
                        narrative=st.session_state.scan_narrative,
                    )
                    st.download_button(
                        label="Download PDF Report",
                        data=pdf_bytes,
                        file_name=f"vsphere-soc-report-{datetime.now().strftime('%Y%m%d-%H%M')}.pdf",
                        mime="application/pdf",
                        use_container_width=True,
                    )
                except Exception as _pdf_err:
                    st.warning(f"PDF generation error: {_pdf_err}")
            else:
                st.info("Install reportlab on server to enable PDF export.")
        with _ts_col:
            if prev_results_obj:
                prev_fail = sum(1 for r in prev_results_obj if r.status == "FAIL")
                curr_fail = sum(1 for r in results if r.status == "FAIL")
                delta = curr_fail - prev_fail
                delta_str = f"{'▼' if delta < 0 else '▲' if delta > 0 else '='} {abs(delta)} failures vs previous scan ({st.session_state.prev_scan_ts})"
                color = "#00C853" if delta < 0 else ("#FF1744" if delta > 0 else "#FFA000")
                st.markdown(
                    f'<div style="padding:8px 0;font-size:0.82rem;color:{color};">{delta_str}</div>',
                    unsafe_allow_html=True,
                )

        # ── Pending remediation confirmation ──────────────────────────────────
        if st.session_state.pending_remediation:
            ctrl_id = st.session_state.pending_remediation
            entry   = REMEDIATION_REGISTRY.get(ctrl_id, {})
            with st.container():
                st.markdown(f"""
                <div style="background:#1a1200;border:1px solid #FFA000;border-radius:8px;
                            padding:14px 18px;margin:8px 0;">
                    <span style="color:#FFA000;font-weight:700;">Confirm Remediation</span><br/>
                    <span style="color:#e0d0a0;font-size:0.9rem;">
                        <code>{ctrl_id}</code> — {entry.get('description','Execute automated fix')}
                    </span>
                </div>
                """, unsafe_allow_html=True)
                # Password always required before applying — never stored in session state
                rem_pass = st.text_input(
                    f"vCenter password for {st.session_state.vcenter_user or 'user'} to confirm fix",
                    type="password", key="_rem_pass",
                )
                c1, c2, _ = st.columns([1.5, 1.5, 5])
                with c1:
                    if st.button("Confirm & Apply Fix", key="confirm_rem"):
                        if not rem_pass:
                            st.error("Enter vCenter password to apply the fix.")
                        else:
                            try:
                                si = connect_vcenter(
                                    st.session_state.vcenter_host,
                                    st.session_state.vcenter_user,
                                    rem_pass,
                                )
                                ok, msg = apply_remediation(si, ctrl_id)
                                if ok:
                                    st.success(f"Fix applied: {msg} — rescanning to verify…")
                                    st.session_state.chat_history.append({
                                        "role": "assistant",
                                        "content": f"Remediation applied for **{ctrl_id}**: {msg}"
                                    })
                                    st.session_state.pending_remediation = None
                                    # Auto-rescan to verify the fix took effect
                                    try:
                                        _cat = st.session_state.last_scan_category
                                        if _cat == "All":
                                            _new = run_full_scan(si)
                                        else:
                                            _new = run_scan_by_category(si, _cat)
                                        # Merge with existing results
                                        _existing = {r["control_id"]: r
                                                     for r in st.session_state.last_results}
                                        for _r in _new:
                                            _existing[_r.control_id] = asdict(_r)
                                        st.session_state.last_results = list(_existing.values())
                                        save_results_cache(
                                            [ControlResult(**r) for r in st.session_state.last_results],
                                            st.session_state.vcenter_host, _cat,
                                        )
                                        st.session_state.last_scan_ts = datetime.now().strftime("%Y-%m-%d %H:%M")
                                    except Exception as _re:
                                        st.warning(f"Auto-rescan failed: {_re}. Run scan manually to verify.")
                                    st.rerun()
                                else:
                                    st.error(f"Remediation failed: {msg}")
                            except Exception as exc:
                                st.error(f"Connection failed — check password: {exc}")
                with c2:
                    if st.button("Cancel", key="cancel_rem"):
                        st.session_state.pending_remediation = None
                        st.rerun()

        # ── Tabs ──────────────────────────────────────────────────────────────
        tab_overview, tab_iam, tab_net, tab_services, tab_vm, tab_logging, tab_catalog = st.tabs(
            ["Overview", "Identity & Access", "Network",
             "Services", "VM Security", "Logging", "Full Catalog (156)"]
        )

        # Category → control IDs mapping (for display grouping)
        CAT_MAP: Dict[str, List[str]] = {
            "Identity & Access": [
                "esxi-8.account-lockout", "esxi-8.account-auto-unlock-time",
                "esxi-8.account-password-history", "esxi-8.host-client-session-timeout",
                "esxi-8.api-soap-timeout", "esxi-8.lockdown-mode",
                "esxi-8.account-password-max-days", "esxi-8.account-password-policies",
                "esxi-8.lockdown-dcui-access", "esxi-8.lockdown-exception-users",
                "esxi-8.account-dcui", "esxi-8.account-vpxuser",
                "vcenter-8.administration-sso-password-policy",
                "vcenter-8.administration-client-session-timeout",
                "vcenter-8.administration-sso-lockout-policy-max-attempts",
                "vcenter-8.administration-sso-lockout-policy-unlock-time",
                "vcenter-8.administration-sso-password-lifetime",
                "vcenter-8.administration-sso-password-reuse",
                "vcenter-8.administration-failed-login-interval",
                "vcenter-8.administration-sso-groups",
                "vcenter-8.administration-login-message-enable",
                "vcenter-8.etc-issue",
                "vcenter-8.administration-login-message-details",
                "vcenter-8.administration-login-message-text",
            ],
            "Network": [
                "esxi-8.network-bpdu", "esxi-8.network-dvfilter", "esxi-8.hw-virtual-nic",
                "esxi-8.network-reject-promiscuous-mode-standardswitch",
                "esxi-8.network-reject-forged-transmit-standardswitch",
                "esxi-8.network-reject-mac-changes-standardswitch",
                "esxi-8.network-reject-promiscuous-mode-portgroup",
                "esxi-8.network-reject-forged-transmit-portgroup",
                "esxi-8.network-reject-mac-changes-portgroup",
                "esxi-8.firewall-incoming-default", "esxi-8.network-vgt",
                "vcenter-8.network-reject-promiscuous-mode-dvportgroup",
                "vcenter-8.network-reject-forged-transmit-dvportgroup",
                "vcenter-8.network-reject-mac-changes-dvportgroup",
                "vcenter-8.network-mac-learning",
                "vcenter-8.network-vgt",
                "vcenter-8.network-restrict-netflow-usage",
                "vcenter-8.network-restrict-discovery-protocol",
                "vcenter-8.network-reset-port",
                "vcenter-8.network-restrict-port-level-overrides",
            ],
            "Services": [
                "esxi-8.deactivate-ssh", "esxi-8.deactivate-shell",
                "esxi-8.shell-interactive-timeout", "esxi-8.shell-timeout",
                "esxi-8.dcui-timeout", "esxi-8.deactivate-cim",
                "esxi-8.deactivate-slp", "esxi-8.deactivate-mob",
                "esxi-8.shell-warning", "esxi-8.timekeeping-services",
                "esxi-8.timekeeping-sources",
                "esxi-8.deactivate-snmp", "esxi-8.secureboot",
                # SSH daemon / esxcli checks (require ESXi SSH creds)
                "esxi-8.ssh-gateway-ports", "esxi-8.ssh-host-based-auth",
                "esxi-8.ssh-idle-timeout-count", "esxi-8.ssh-idle-timeout-interval",
                "esxi-8.ssh-login-banner", "esxi-8.ssh-rhosts",
                "esxi-8.ssh-stream-local-forwarding", "esxi-8.ssh-tcp-forwarding",
                "esxi-8.ssh-tunnels", "esxi-8.ssh-user-environment",
                "esxi-8.vib-acceptance-level-supported",
                "esxi-8.ssh-fips", "esxi-8.tls-profile", "esxi-8.secureboot-enforcement",
                "esxi-8.supported",
                "vcenter-8.supported",
                "vcenter-8.vami-access-ssh",
                "vcenter-8.vami-time",
                "vcenter-8.vami-backup",
                "vcenter-8.vami-updates",
                "vcenter-8.vami-administration-password-expiration",
                "vcenter-8.vami-firewall-restrict-access",
                "vcenter-8.fips-enable",
                "vcenter-8.tls-profile",
                "vsan-8.data-at-rest",
                "vsan-8.data-in-transit",
                "vsan-8.object-checksum",
                "vsan-8.force-provisioning",
                "vsan-8.operations-reserve",
                "vsan-8.iscsi-mutual-chap",
                "vsan-8.file-services-access-control-nfs",
                "vsan-8.file-services-authentication-smb",
            ],
            "VM Security": [c[0] for c in VM_CONFIG_CHECKS] + [
                "vm-8.log-enable", "vm-8.ft-encrypted",
                "vm-8.vmotion-encrypted", "vm-8.remove-unnecessary-devices",
                "vm-8.dvfilter",
                "vm-8.pci-passthrough",
                "vm-8.transparentpagesharing-inter-vm-enabled",
            ],
            "Logging": [
                "esxi-8.logs-level", "esxi-8.logs-remote", "esxi-8.logs-audit-local",
                "esxi-8.logs-remote-tls", "esxi-8.transparent-page-sharing",
                "esxi-8.memeagerzero", "esxi-8.cpu-hyperthread-warning",
                "esxi-8.logs-audit-remote", "esxi-8.logs-audit-local-capacity",
                "esxi-8.logs-level-global", "esxi-8.logs-persistent",
                "esxi-8.logs-remote-tls-x509", "esxi-8.tls-protocols",
                "esxi-8.annotations-welcomemessage", "esxi-8.etc-issue",
                "esxi-8.logs-filter",
                "vcenter-8.events-remote-logging", "vcenter-8.logs-level-global",
                "vcenter-8.vpxuser-rotation",
                "vcenter-8.events-database-retention",
                "vcenter-8.vami-syslog",
            ],
        }

        def _cat_results(cat_name: str) -> List[ControlResult]:
            ids = set(CAT_MAP.get(cat_name, []))
            return [r for r in results if r.control_id in ids]

        def _render_cat(cat_name: str, component_filter: Optional[str] = None,
                        key_prefix: str = "") -> None:
            cat_r = _cat_results(cat_name) if component_filter is None else \
                    [r for r in results if r.component == component_filter]
            if not cat_r:
                st.info("No checks in this category from the last scan.")
                return
            for status in ("FAIL", "UNKNOWN", "PASS"):
                grp = [r for r in cat_r if r.status == status]
                if grp:
                    label = {"FAIL": "Failing", "UNKNOWN": "Unknown / Not Checked",
                             "PASS": "Passing"}[status]
                    st.markdown(f'<p class="sec-hdr">{label}</p>', unsafe_allow_html=True)
                    render_result_rows(grp, key_prefix=f"{key_prefix}_{status.lower()}")

        with tab_overview:
            if st.session_state.scan_narrative:
                st.markdown('<p class="sec-hdr">AI Executive Summary</p>', unsafe_allow_html=True)
                st.info(st.session_state.scan_narrative)
            st.markdown('<p class="sec-hdr">All Failing Controls</p>', unsafe_allow_html=True)
            fails = [r for r in results if r.status == "FAIL"]
            if fails:
                render_result_rows(fails, key_prefix="ov")
            else:
                st.success("No failing controls found across all scanned checks.")

        with tab_iam:
            st.markdown('<p class="sec-hdr">Identity & Access — Passwords, Lockout, Sessions</p>',
                        unsafe_allow_html=True)
            _render_cat("Identity & Access", key_prefix="iam")
            # Also show vCenter checks
            vc_r = [r for r in results if r.component == "vCenter"]
            if vc_r:
                st.markdown('<p class="sec-hdr">vCenter Server</p>', unsafe_allow_html=True)
                render_result_rows(vc_r, key_prefix="iam_vc")

        with tab_net:
            st.markdown('<p class="sec-hdr">Network Security — vSwitch, BPDU, Port Groups</p>',
                        unsafe_allow_html=True)
            _render_cat("Network", key_prefix="net")

        with tab_services:
            st.markdown('<p class="sec-hdr">Attack Surface Reduction — Services & Interfaces</p>',
                        unsafe_allow_html=True)
            _render_cat("Services", key_prefix="svc")

        with tab_vm:
            st.markdown('<p class="sec-hdr">Virtual Machine Security Controls</p>',
                        unsafe_allow_html=True)
            _render_cat("VM Security", key_prefix="vm")

        with tab_logging:
            st.markdown('<p class="sec-hdr">Logging, Audit & System Hardening</p>',
                        unsafe_allow_html=True)
            _render_cat("Logging", key_prefix="log")

        with tab_catalog:
            st.markdown('<p class="sec-hdr">VMware SCG v8 — Full Control Catalog</p>',
                        unsafe_allow_html=True)
            if df_catalog is not None:
                scanned_ids = {r.control_id for r in results}
                c1, c2 = st.columns([2, 2])
                with c1:
                    comp_filter = st.selectbox(
                        "Component",
                        ["All"] + sorted(df_catalog["Component"].dropna().unique().tolist()),
                        key="cat_comp"
                    )
                with c2:
                    status_filter = st.selectbox(
                        "Status",
                        ["All", "Scanned (PASS)", "Scanned (FAIL)", "Not Yet Scanned"],
                        key="cat_status"
                    )
                show_df = df_catalog if comp_filter == "All" else \
                    df_catalog[df_catalog["Component"] == comp_filter]
                total_shown = 0
                for _, row in show_df.iterrows():
                    scg_id = row.get("SCG ID", "")
                    res = next((r for r in results if r.control_id == scg_id), None)
                    if res:
                        badge_cls = STATUS_BADGE.get(res.status, "badge-unknown")
                        badge_txt = res.status
                        if status_filter == "Not Yet Scanned":
                            continue
                        if status_filter == "Scanned (PASS)" and res.status != "PASS":
                            continue
                        if status_filter == "Scanned (FAIL)" and res.status != "FAIL":
                            continue
                    else:
                        badge_cls = "badge-manual"
                        badge_txt = "NOT SCANNED"
                        if status_filter in ("Scanned (PASS)", "Scanned (FAIL)"):
                            continue
                    comp = str(row.get("Component", "ESXi"))
                    comp_cls = COMP_CLASS.get(comp, "comp-esxi")
                    title = str(row.get("Description/Title", ""))[:90]
                    priority = str(row.get("Implementation Priority", "")).split("\n")[0]
                    powercli = str(row.get("PowerCLI Command Assessment", ""))[:60]
                    st.markdown(f"""
                    <div class="ctrl-row">
                        <span class="ctrl-id">{scg_id}</span>
                        <span class="comp-pill {comp_cls}">{comp}</span>
                        <span class="ctrl-title">{title}</span>
                        <span class="ctrl-evid" title="{powercli}">{priority}</span>
                        <span class="badge {badge_cls}">{badge_txt}</span>
                    </div>
                    """, unsafe_allow_html=True)
                    total_shown += 1
                st.caption(f"Showing {total_shown} of {len(df_catalog)} controls")
            else:
                st.warning(f"Control catalog CSV not found at `{CSV_PATH}`.")

    else:
        # ── Welcome / No-scan state ───────────────────────────────────────────
        st.markdown('<div class="accent-bar"></div>', unsafe_allow_html=True)
        col1, col2, col3 = st.columns(3)
        with col1:
            st.markdown("""
            <div class="metric-card" style="text-align:left;padding:20px;">
                <div style="color:#C74634;font-size:0.65rem;font-weight:700;letter-spacing:2px;text-transform:uppercase;margin-bottom:8px;">SOC Automation</div>
                <div style="color:#e0e0f0;font-weight:600;margin:0 0 4px 0;">Automated SOC Scanning</div>
                <div style="color:#666688;font-size:0.82rem;">
                    Checks ESXi hosts, vCenter, VMs and network against the
                    VMware vSphere 8 Security Configuration Guide.
                </div>
            </div>
            """, unsafe_allow_html=True)
        with col2:
            st.markdown("""
            <div class="metric-card" style="text-align:left;padding:20px;">
                <div style="color:#C74634;font-size:0.65rem;font-weight:700;letter-spacing:2px;text-transform:uppercase;margin-bottom:8px;">Remediation</div>
                <div style="color:#e0e0f0;font-weight:600;margin:0 0 4px 0;">One-Click Remediation</div>
                <div style="color:#666688;font-size:0.82rem;">
                    Apply automated fixes for failing controls directly from the dashboard,
                    with confirmation before any changes are made.
                </div>
            </div>
            """, unsafe_allow_html=True)
        with col3:
            st.markdown("""
            <div class="metric-card" style="text-align:left;padding:20px;">
                <div style="color:#C74634;font-size:0.65rem;font-weight:700;letter-spacing:2px;text-transform:uppercase;margin-bottom:8px;">OCI GenAI</div>
                <div style="color:#e0e0f0;font-weight:600;margin:0 0 4px 0;">AI Security Assistant</div>
                <div style="color:#666688;font-size:0.82rem;">
                    Powered by OCI GenAI — ask questions about findings,
                    request remediation guidance, or trigger automated fixes.
                </div>
            </div>
            """, unsafe_allow_html=True)

        st.markdown("""
        <div style="text-align:center;padding:32px 0 16px 0;color:#555577;font-size:0.9rem;">
            Enter vCenter credentials in the sidebar and click <strong style="color:#C74634;">
            Run Security Scan</strong> to begin.
        </div>
        """, unsafe_allow_html=True)

    # ─── CHAT INTERFACE — always rendered outside any conditional ─────────────
    st.markdown('<div class="accent-bar" style="margin-top:24px;"></div>', unsafe_allow_html=True)
    st.markdown('<p class="sec-hdr">GenAI Security Assistant</p>', unsafe_allow_html=True)

    for msg in st.session_state.chat_history:
        with st.chat_message(msg["role"]):
            st.markdown(msg["content"])

    if question := st.chat_input("Ask about controls, request remediation, or get fix guidance…"):
        st.session_state.chat_history.append({"role": "user", "content": question})
        with st.chat_message("user"):
            st.markdown(question)

        # Build scan context
        if results:
            fails = [r for r in results if r.status == "FAIL"]
            scan_ctx = (
                f"Scan results: {len(results)} controls | "
                f"{sum(1 for r in results if r.status=='PASS')} PASS | "
                f"{len(fails)} FAIL | "
                f"{sum(1 for r in results if r.status=='UNKNOWN')} UNKNOWN\n"
            )
            if fails:
                scan_ctx += "Failing controls:\n" + "\n".join(
                    f"- {r.control_id}: {r.title} | Evidence: {r.evidence} | Fix: {r.remediation_hint}"
                    for r in fails[:25]
                )
        else:
            scan_ctx = "No scan has been run yet. Ask the user to run a scan first."

        prompt = (
            "You are an expert vSphere 8 security hardening engineer for an Oracle Cloud "
            "Infrastructure SOC. Respond concisely and technically. "
            "If asked to fix or remediate a control, acknowledge the request and state the "
            "exact control ID (format ESXI-8-XXXXXX, VMCH-8-XXXXXX, NET-8-XXXXXX, VCENTER-8-XXXXXX) "
            "that should be fixed. The user can click the Fix button next to that control in the UI.\n\n"
            f"Current scan context:\n{scan_ctx}\n\n"
            f"User: {question}"
        )

        with st.chat_message("assistant"):
            with st.spinner("Analyzing with OCI GenAI…"):
                try:
                    answer = call_genai(prompt, temperature=0.2, max_tokens=600)
                    st.markdown(answer)
                    st.session_state.chat_history.append({"role": "assistant", "content": answer})

                    # Auto-detect fix intent from user question
                    ctrl_id = _detect_fix_intent(question)
                    if ctrl_id and results and any(r.control_id == ctrl_id and r.status == "FAIL"
                                                    for r in results):
                        reg = REMEDIATION_REGISTRY.get(ctrl_id, {})
                        st.info(
                            f"Automated fix available for **{ctrl_id}**. "
                            f"Scroll up and click the **Fix** button next to that control, "
                            f"or I can set it as pending confirmation now."
                        )
                        if st.button(f"Queue fix for {ctrl_id}", key=f"chat_fix_{ctrl_id}"):
                            st.session_state.pending_remediation = ctrl_id
                            st.rerun()
                except Exception as exc:
                    err_msg = (
                        f"OCI GenAI unavailable: `{exc}`\n\n"
                        f"**Tip:** Ensure the app is running on an OCI instance with Instance Principal "
                        f"permissions, or configure `~/.oci/config` for local development."
                    )
                    st.warning(err_msg)
                    st.session_state.chat_history.append({"role": "assistant", "content": err_msg})

    st.markdown(
        '<div style="text-align:center;padding:16px 0 4px 0;color:#333350;font-size:0.7rem;">'
        'Oracle Cloud Infrastructure &nbsp;|&nbsp; vSphere SOC Automation &nbsp;|&nbsp; '
        'VMware SCG v8 Compliance &nbsp;|&nbsp; Powered by OCI GenAI'
        '</div>',
        unsafe_allow_html=True,
    )


if __name__ == "__main__":
    main()
