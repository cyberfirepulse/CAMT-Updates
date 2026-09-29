from projectmanager.i18n import tr as _tr, get_language as _get_language
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
from tkinter import simpledialog
from tkinter.scrolledtext import ScrolledText

import subprocess
import shlex
import re
import math
import shutil
import sys
import json
import os
import tempfile
import webbrowser
import socket
import xml.etree.ElementTree as ET
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
import ipaddress
import threading
import queue
import time
# Scapy wordt gebruikt voor optionele L2 discovery. De volledige CAMT-build bundelt
# dit pakket; de fallback houdt de kaart bruikbaar als een distributie beschadigd is.
try:
    import scapy  # noqa: F401
    SCAPY_AVAILABLE = True
except Exception:
    scapy = None
    SCAPY_AVAILABLE = False


try:
    from projectmanager.core.shared import get_app_home_dir
except Exception:
    get_app_home_dir = None

try:
    from projectmanager.ui.device_icons import draw_device_icon
except Exception:
    draw_device_icon = None


try:
    from projectmanager.offline_intelligence.database import OfflineIntelligenceDatabase
except Exception:
    OfflineIntelligenceDatabase = None


if os.name == "nt":  # alleen op Windows
    _real_run = subprocess.run

    def run_no_console(*args, **kwargs):
        # Zorg dat CREATE_NO_WINDOW wordt gezet
        kwargs.setdefault("creationflags", 0)
        kwargs["creationflags"] |= subprocess.CREATE_NO_WINDOW

        return _real_run(*args, **kwargs)

    subprocess.run = run_no_console

if os.name == "nt":
    _real_popen = subprocess.Popen

    def popen_no_console(*args, **kwargs):
        kwargs.setdefault("creationflags", 0)
        kwargs["creationflags"] |= subprocess.CREATE_NO_WINDOW
        return _real_popen(*args, **kwargs)

    subprocess.Popen = popen_no_console

def run_hidden(cmd, **kwargs):
    """Run a subprocess without opening a console on Windows.

    The Network Digital Twin is hybrid Windows/Linux. STARTUPINFO only exists
    on Windows, so it must never be constructed on Linux/macOS. No command is
    executed while this module is imported.
    """
    kwargs.setdefault("stdout", subprocess.PIPE)
    kwargs.setdefault("stderr", subprocess.PIPE)
    kwargs.setdefault("text", True)
    if os.name == "nt":
        startupinfo = subprocess.STARTUPINFO()
        startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
        kwargs.setdefault("startupinfo", startupinfo)
        kwargs.setdefault("creationflags", 0)
        kwargs["creationflags"] |= getattr(subprocess, "CREATE_NO_WINDOW", 0)
    return subprocess.run(cmd, **kwargs)

def _apply_camt_window_icon(window):
    """Apply the CAMT shield icon to Network Digital Twin/NetMap windows.

    The icon is shipped as runtime data in frozen builds. Source mode also
    checks the CAMT project root. Failure is deliberately non-fatal.
    """
    candidates = []
    try:
        meipass = getattr(sys, "_MEIPASS", None)
        if meipass:
            candidates.append(Path(meipass) / "CAMT.ico")
    except Exception:
        pass
    try:
        candidates.append(Path(__file__).resolve().parents[2] / "CAMT.ico")
    except Exception:
        pass
    try:
        candidates.append(Path(sys.executable).resolve().parent / "CAMT.ico")
    except Exception:
        pass
    for candidate in candidates:
        try:
            if candidate.is_file():
                window.iconbitmap(default=str(candidate))
                return str(candidate)
        except Exception:
            continue
    return None


# --- Optionele L2 discovery (CDP/LLDP/MNDP) met Scapy ---
try:
    from scapy.all import sniff, Ether, UDP
    SCAPY_AVAILABLE = True
except Exception as e:
    print("Scapy not available for L2 discovery:", e)
    SCAPY_AVAILABLE = False
    sniff = None
    Ether = None
    UDP = None

try:
    import requests
    REQUESTS_AVAILABLE = True
except Exception as e:
    print("Requests not available for online CVE lookup:", e)
    requests = None
    REQUESTS_AVAILABLE = False

def fetch_cves_online(service_name):
    if not REQUESTS_AVAILABLE or requests is None:
        return []
    url = f"https://cve.circl.lu/api/search/{service_name}"
    try:
        r = requests.get(url, timeout=10)
        if r.status_code != 200:
            return []
        data = r.json()
    except Exception:
        return []
    # Bestaande parser/consument bepaalt de uiteindelijke normalisatie.
    return data if isinstance(data, list) else data


CVE_DB_PATH = "cve_db.json"
CVE_DB = {}

def load_cve_db():
    global CVE_DB
    try:
        if os.path.exists(CVE_DB_PATH):
            with open(CVE_DB_PATH, "r", encoding="utf-8") as f:
                CVE_DB = json.load(f)
        else:
            CVE_DB = {}
    except Exception as e:
        print("Error loading CVE DB:", e)
        CVE_DB = {}


# ============================================
#  Interactieve Help / Documentatie
#  (kan later uit extern JSON-bestand komen)
# ============================================




# === OSINT Classroom Theme constants ===
ROUTER_COLOR = "#cfe8ff"       # ijsblauw (router / internet edge)
SWITCH_COLOR = "#e8d7ff"       # pastel paars (L2 / LAN)
SERVER_COLOR = "#ffe8cc"       # pastel oranje (servers / infra)
CLIENT_COLOR = "#ddffe8"       # pastel groen (workstations)
IOT_COLOR = "#d7fff6"          # pastel turquoise (IoT / BYOD)
PRINTER_COLOR = "#ffd7e3"      # pastel roze (printers)
STORAGE_COLOR = "#ffe8cc"      # zelfde als server

HOST_LINK_COLOR = "#cccccc"    # gewone host-links (LAN)
ROUTER_LINK_COLOR = "#b38cff"  # router→switch links (uplink / WAN)
HIGHLIGHT_COLOR = "#ff4f4f"    # highlight op rechtsklik (“attack path”)



# === Demo CVE / vulnerability signatures ===
# LET OP: dit is puur een EDUCA-TIEVE DEMO, geen echte scanner!
VULN_SIGNATURES = [
    {
        "id": "CVE-2017-0144",
        "label": "SMBv1 EternalBlue (demo)",
        "risk": "Critical",
        "match_any": ["445/tcp"],
        "summary": "Ongepatchte SMBv1 file sharing dienst kan kwetsbaar zijn voor wormbare exploits."
    },
    {
        "id": "CVE-2019-0708",
        "label": "RDP BlueKeep (demo)",
        "risk": "Critical",
        "match_any": ["3389/tcp"],
        "summary": "Ongepatchte RDP-dienst op oudere Windows systemen (remote code execution)."
    },
    {
        "id": "CVE-2014-0160",
        "label": "Heartbleed (demo)",
        "risk": "High",
        "match_any": ["443/tcp"],
        "summary": "Oude TLS/SSL implementaties kunnen geheugendata lekken (Heartbleed)."
    },
    {
        "id": "CVE-2021-41773",
        "label": "Apache Path Traversal (demo)",
        "risk": "High",
        "match_any": ["80/tcp", "8080/tcp"],
        "summary": "Kwetsbare HTTP servers met path traversal / mogelijke RCE."
    },
    {
        "id": "TELNET-LEGACY",
        "label": "Onversleutelde Telnet (demo)",
        "risk": "Medium",
        "match_any": ["23/tcp"],
        "summary": "Beheer via Telnet is onversleuteld en makkelijk af te luisteren."
    },
    {
        "id": "SSH-WEAK",
        "label": "Legacy SSH (demo)",
        "risk": "Low",
        "match_any": ["22/tcp"],
        "summary": "Oude of slecht geconfigureerde SSH-servers kunnen zwakke crypto gebruiken."
    },
    {
        "id": "LSM",
        "label": "LSM service",
        "risk": "medium",
        "match_any": ["139/udp"],
        "summary": " A recent (2025) vulnerability in the Local Session Manager (LSM) service was found to be remotely exploitable if ports 139 or 445 were open."
    },
]

def _help_json_candidates(path=None):
    here=Path(__file__).resolve()
    lang = "en" if str(_get_language()).lower().startswith("en") else "nl"
    filename = f"help_content.{lang}.json"
    candidates=[]
    if path:
        supplied=Path(path)
        if supplied.name == "help_content.json":
            supplied = supplied.with_name(filename)
        candidates.append(supplied)
    candidates.extend([
        here.with_name(filename),
        here.parent / filename,
        here.parents[2] / filename if len(here.parents)>2 else here.parent / filename,
    ])
    return candidates

def load_help_topics(path=None):
    for candidate in _help_json_candidates(path):
        try:
            if candidate.is_file():
                with candidate.open("r",encoding="utf-8") as f:
                    data=json.load(f)
                if isinstance(data,dict):
                    return data
        except Exception as e:
            print(_tr("netmap.help.load_error", default="Could not load help content from {path}: {error}", path=candidate, error=e))
    return {
        "network_mapper":{
            "title":"Network Mapper",
            "text":[
                "Network Mapper ondersteunt Windows en Linux.",
                "Windows: actieve native host discovery en ARP-verrijking.",
                "Linux: netdiscover indien beschikbaar, met ARP fallback.",
                "Na discovery kunnen gevonden hosts via service/version en Vulnerability Analysis worden verrijkt."
            ]
        }
    }


NETMAP_ASSET_CATALOG = [('IT & Systems', 'workstation', 'PC / Workstation', 'IT', 'Digital'), ('IT & Systems', 'laptop', 'Laptop', 'IT', 'Digital'), ('IT & Systems', 'server', 'Server', 'IT', 'Digital'), ('IT & Systems', 'historian', 'Historian / Database', 'IT/OT', 'Digital'), ('IT & Systems', 'storage', 'NAS / Storage', 'IT', 'Digital'), ('IT & Systems', 'printer', 'Printer', 'IT', 'Digital'), ('Smart / IoT', 'smartphone', 'Smartphone', 'Smart/IoT', 'Digital'), ('Smart / IoT', 'tablet', 'Tablet', 'Smart/IoT', 'Digital'), ('Smart / IoT', 'smartwatch', 'Smartwatch', 'Smart/IoT', 'Cyber-Physical'), ('Smart / IoT', 'earbuds', 'Earbuds / Headset', 'Smart/IoT', 'Cyber-Physical'), ('Smart / IoT', 'smart_speaker', 'Smart Speaker', 'Smart/IoT', 'Cyber-Physical'), ('Smart / IoT', 'smart_tv', 'Smart TV / Display', 'Smart/IoT', 'Cyber-Physical'), ('Smart / IoT', 'iot', 'Generic IoT Device', 'Smart/IoT', 'Cyber-Physical'), ('Smart / IoT', 'camera', 'Camera / CCTV', 'Smart/IoT', 'Cyber-Physical'), ('Network & Security', 'firewall', 'Firewall', 'Network/Security', 'Digital'), ('Network & Security', 'router', 'Router', 'Network/Security', 'Digital'), ('Network & Security', 'switch', 'Switch', 'Network/Security', 'Digital'), ('Network & Security', 'gateway', 'Industrial Gateway', 'Network/Security', 'Digital'), ('Network & Security', 'access_point', 'Wireless AP', 'Network/Security', 'Digital'), ('Network & Security', 'vpn_gateway', 'VPN Gateway', 'Network/Security', 'Digital'), ('Network & Security', 'cellular_gateway', 'Cellular / 5G Gateway', 'Network/Security', 'Digital'), ('Network & Security', 'satellite_gps', 'Satellite / GPS', 'Network/Security', 'Cyber-Physical'), ('Network & Security', 'radio_link', 'Radio Link', 'Network/Security', 'Cyber-Physical'), ('Network & Security', 'load_balancer', 'Load Balancer', 'Network/Security', 'Digital'), ('Network & Security', 'cloud', 'Cloud / Internet', 'External', 'Digital'), ('OT / ICS Control', 'plc', 'PLC', 'OT/ICS', 'Control'), ('OT / ICS Control', 'rtu', 'RTU', 'OT/ICS', 'Control'), ('OT / ICS Control', 'ied', 'IED', 'OT/ICS', 'Control'), ('OT / ICS Control', 'relay', 'Protection Relay', 'OT/ICS', 'Control'), ('OT / ICS Control', 'hmi', 'HMI', 'OT/ICS', 'Control'), ('OT / ICS Control', 'scada_server', 'SCADA Server', 'OT/ICS', 'Control'), ('OT / ICS Control', 'engineering_station', 'Engineering Workstation', 'OT/ICS', 'Control'), ('OT / ICS Control', 'sensor', 'Sensor / Meter', 'OT/ICS', 'Field'), ('OT / ICS Control', 'actuator', 'Actuator', 'OT/ICS', 'Field'), ('OT / ICS Control', 'vfd', 'Variable Frequency Drive', 'OT/ICS', 'Control'), ('OT / ICS Control', 'motor', 'Industrial Motor', 'OT/ICS', 'Physical'), ('OT / ICS Control', 'pump', 'Pump', 'OT/ICS', 'Physical'), ('OT / ICS Control', 'valve', 'Valve', 'OT/ICS', 'Physical'), ('Energy', 'wind_turbine', 'Wind Turbine', 'Energy', 'Physical'), ('Energy', 'wind_farm', 'Wind Farm', 'Energy', 'Physical'), ('Energy', 'solar_array', 'Solar Array', 'Energy', 'Physical'), ('Energy', 'inverter', 'Solar / Power Inverter', 'Energy', 'Control'), ('Energy', 'transformer', 'Transformer', 'Energy', 'Physical'), ('Energy', 'substation', 'Electrical Substation', 'Energy', 'Physical'), ('Energy', 'generator', 'Generator', 'Energy', 'Physical'), ('Energy', 'bess', 'Battery / BESS', 'Energy', 'Cyber-Physical'), ('Energy', 'grid_meter', 'Grid / Smart Meter', 'Energy', 'Field'), ('Energy', 'hydro_turbine', 'Hydro Turbine', 'Energy', 'Physical'), ('Energy', 'hydro_plant', 'Hydroelectric Plant', 'Energy', 'Physical'), ('Energy', 'ev_charger', 'EV Charger', 'Energy', 'Cyber-Physical'), ('Roads & Traffic', 'traffic_light', 'Traffic Light', 'Traffic/Transport', 'Physical'), ('Roads & Traffic', 'traffic_controller', 'Traffic Controller', 'Traffic/Transport', 'Control'), ('Roads & Traffic', 'matrix_sign', 'Matrix / Variable Message Sign', 'Traffic/Transport', 'Cyber-Physical'), ('Roads & Traffic', 'roadside_unit', 'Roadside Unit / ITS', 'Traffic/Transport', 'Cyber-Physical'), ('Roads & Traffic', 'traffic_control_centre', 'Traffic Control Centre', 'Traffic/Transport', 'Facility'), ('Roads & Traffic', 'tunnel', 'Road Tunnel', 'Traffic/Transport', 'Physical'), ('Rail', 'railway_signal', 'Railway Signal', 'Rail', 'Physical'), ('Rail', 'level_crossing', 'Level Crossing', 'Rail', 'Cyber-Physical'), ('Water & Civil', 'bridge', 'Bridge', 'Water/Civil', 'Physical'), ('Water & Civil', 'movable_bridge', 'Movable Bridge', 'Water/Civil', 'Cyber-Physical'), ('Water & Civil', 'lock', 'Lock / Sluis', 'Water/Civil', 'Cyber-Physical'), ('Water & Civil', 'dam', 'Dam', 'Water/Civil', 'Physical'), ('Water & Civil', 'dike', 'Dike / Levee', 'Water/Civil', 'Physical'), ('Water & Civil', 'pumping_station', 'Pumping Station', 'Water/Civil', 'Facility'), ('Water & Civil', 'water_treatment', 'Water Treatment Plant', 'Water/Civil', 'Facility'), ('Water & Civil', 'reservoir', 'Reservoir', 'Water/Civil', 'Physical'), ('Water & Civil', 'sluice_gate', 'Sluice Gate', 'Water/Civil', 'Cyber-Physical'), ('Industrial', 'conveyor', 'Conveyor', 'Industrial', 'Physical'), ('Industrial', 'robot', 'Industrial Robot', 'Industrial', 'Cyber-Physical'), ('Industrial', 'production_line', 'Production Line', 'Industrial', 'Physical'), ('Industrial', 'tank', 'Process Tank', 'Industrial', 'Physical'), ('Industrial', 'boiler', 'Boiler', 'Industrial', 'Physical'), ('Industrial', 'compressor', 'Compressor', 'Industrial', 'Physical'), ('Industrial', 'crane', 'Crane', 'Industrial', 'Cyber-Physical'), ('Industrial', 'hvac', 'HVAC / Climate System', 'Industrial/Facility', 'Cyber-Physical'), ('Facilities', 'building', 'Building / Site', 'Facility', 'Physical'), ('Facilities', 'control_room', 'Control Room', 'Facility', 'Physical'), ('Facilities', 'data_center', 'Data Centre', 'Facility', 'Physical'), ('Facilities', 'access_control', 'Access Control', 'Facility/Security', 'Cyber-Physical'), ('Facilities', 'badge_reader', 'Badge Reader', 'Facility/Security', 'Cyber-Physical'), ('Facilities', 'fire_alarm', 'Fire Alarm', 'Facility/Safety', 'Cyber-Physical'), ('Facilities', 'ups', 'UPS / Power Backup', 'Facility/Energy', 'Cyber-Physical')]

class Device:
    def __init__(self, ip, mac, hostname, dev_type="client", note="", ports_summary="", pos_x=None, pos_y=None,
                 services=None, vulnerabilities=None, is_gateway=False, online_status="unknown",
                 asset_id="", zone="", layer="", criticality="", crown_jewel=False, controller_id=""):
        self.ip = ip
        self.mac = mac
        self.hostname = hostname
        self.dev_type = dev_type
        self.note = note  # vrije tekst
        self.ports_summary = ports_summary  # korte samenvatting van open poorten
        # logische positie op de kaart (voor locked layout)
        self.pos_x = pos_x
        self.pos_y = pos_y
        self.services = list(services or [])
        self.vulnerabilities = list(vulnerabilities or [])
        self.is_gateway = bool(is_gateway)
        self.online_status = str(online_status or "unknown")
        # Cyber-physical metadata used by CAMT visualisation/scenario topologies.
        self.asset_id = str(asset_id or ip or hostname or "")
        self.zone = str(zone or "")
        self.layer = str(layer or "")
        self.criticality = str(criticality or "")
        self.crown_jewel = bool(crown_jewel)
        self.controller_id = str(controller_id or "")


    def to_dict(self):
        return {
            "ip": self.ip,
            "mac": self.mac,
            "hostname": self.hostname,
            "dev_type": self.dev_type,
            "note": self.note,
            "ports_summary": self.ports_summary,
            "pos_x": self.pos_x,
            "pos_y": self.pos_y,
            "services": self.services,
            "vulnerabilities": self.vulnerabilities,
            "is_gateway": self.is_gateway,
            "online_status": self.online_status,
            "asset_id": self.asset_id,
            "zone": self.zone,
            "layer": self.layer,
            "criticality": self.criticality,
            "crown_jewel": self.crown_jewel,
            "controller_id": self.controller_id,
        }

    @staticmethod
    def from_dict(d):
        # Accept native NetMap device rows AND CAMT cyber-physical asset rows.
        return Device(
            ip=d.get("ip", ""),
            mac=d.get("mac", ""),
            hostname=d.get("hostname") or d.get("name", ""),
            dev_type=d.get("dev_type") or d.get("type", "client"),
            note=d.get("note") or d.get("description", ""),
            ports_summary=d.get("ports_summary", ""),
            pos_x=d.get("pos_x", d.get("x")),
            pos_y=d.get("pos_y", d.get("y")),
            services=d.get("services", []),
            vulnerabilities=d.get("vulnerabilities", []),
            is_gateway=d.get("is_gateway", False) or str(d.get("type", "")).lower() in {"gateway", "router", "gateway/router"},
            online_status=d.get("online_status", "unknown"),
            asset_id=d.get("asset_id") or d.get("id", ""),
            zone=d.get("zone", ""),
            layer=d.get("layer", ""),
            criticality=d.get("criticality", ""),
            crown_jewel=d.get("crown_jewel", False),
            controller_id=d.get("controller_id", ""),
        )
class HelpDialog(tk.Toplevel):
    def __init__(self, master, help_topics: dict):
        super().__init__(master)
        self.title(_tr('ui.source.help.c47ae153'))
        self.geometry("800x500")
        self.transient(master)
        self.help_topics = help_topics

        # Layout
        self.columnconfigure(1, weight=1)
        self.rowconfigure(0, weight=1)

        # Topic list
        left_frame = ttk.Frame(self)
        left_frame.grid(row=0, column=0, sticky="nsw", padx=5, pady=5)

        ttk.Label(left_frame, text=_tr('ui.source.topics.07e4f9c2')).pack(anchor="w")
        self.topic_list = tk.Listbox(left_frame, height=20)
        self.topic_list.pack(fill="y", expand=False)

        # Mapping tussen listbox index en topic_id
        self.topic_ids = []

        for topic_id, meta in self.help_topics.items():
            title = meta.get("title", topic_id)
            self.topic_ids.append(topic_id)
            self.topic_list.insert("end", title)

        self.topic_list.bind("<<ListboxSelect>>", self.on_topic_select)

        # Text area
        right_frame = ttk.Frame(self)
        right_frame.grid(row=0, column=1, sticky="nsew", padx=5, pady=5)
        right_frame.rowconfigure(0, weight=1)
        right_frame.columnconfigure(0, weight=1)

        self.text_widget = tk.Text(right_frame, wrap="word")
        self.text_widget.grid(row=0, column=0, sticky="nsew")

        scroll = ttk.Scrollbar(right_frame, orient="vertical", command=self.text_widget.yview)
        scroll.grid(row=0, column=1, sticky="ns")
        self.text_widget.configure(yscrollcommand=scroll.set)

        btn_frame = ttk.Frame(self)
        btn_frame.grid(row=1, column=0, columnspan=2, sticky="e", padx=5, pady=5)
        ttk.Button(btn_frame, text=_tr('ui.source.close.bbfa773e'), command=self.destroy).pack()

        # Eerste topic selecteren (optioneel)
        if self.topic_ids:
            self.topic_list.selection_set(0)
            self.on_topic_select(None)

    def on_topic_select(self, event):
        selection = self.topic_list.curselection()
        if not selection:
            return
        idx = selection[0]
        topic_id = self.topic_ids[idx]
        topic = self.help_topics.get(topic_id, {})

        title = topic.get("title", topic_id)
        text_lines = topic.get("text", [])
        if isinstance(text_lines, str):
            body = text_lines
        else:
            body = "\n".join(text_lines)

        self.text_widget.configure(state="normal")
        self.text_widget.delete("1.0", "end")
        self.text_widget.insert("1.0", title + "\n" + "=" * len(title) + "\n\n" + body)
        self.text_widget.configure(state="disabled")


class NetworkMapGUI:

    # Keep Network Mapper dialogs owned by the Network Mapper Toplevel.
    # Without an explicit parent tkinter can attach a messagebox to CAMT's
    # application root, which brings the main GUI to the foreground.
    def _mb_info(self, title, message, **kwargs):
        kwargs.setdefault("parent", self.root)
        return messagebox.showinfo(title, message, **kwargs)

    def _mb_warning(self, title, message, **kwargs):
        kwargs.setdefault("parent", self.root)
        return messagebox.showwarning(title, message, **kwargs)

    def _mb_error(self, title, message, **kwargs):
        kwargs.setdefault("parent", self.root)
        return messagebox.showerror(title, message, **kwargs)

    def _mb_askyesno(self, title, message, **kwargs):
        kwargs.setdefault("parent", self.root)
        return messagebox.askyesno(title, message, **kwargs)

    def __init__(self, root):
        self.root = root
        self.root.title(_tr('ui.source.team.network.mapper.interactive.63aeb871'))
        # Preferred size remains generous on desktops, but never exceeds the
        # usable laptop work area. The suite-level window manager performs a
        # second clamp after widget creation (including the Windows taskbar).
        try:
            _sw=max(800,int(self.root.winfo_screenwidth()))
            _sh=max(600,int(self.root.winfo_screenheight()))
            _w=min(1480,max(760,_sw-36))
            _h=min(900,max(560,_sh-96))
            self.root.geometry(f"{_w}x{_h}")
            self.root.minsize(min(900,_w),min(560,_h))
        except Exception:
            self.root.geometry("1100x700")
            self.root.minsize(760,560)
        _apply_camt_window_icon(self.root)

        self.devices = []
        self.relationships = []
        self.scan_stop_event = threading.Event()
        self.scan_worker = None
        self.scan_started_at = 0.0
        self.scan_total = 0
        self.scan_done = 0
        self.scan_found = 0
        self.live_discovered = {}
        self.live_render_pending = False
        self.live_host_queue = queue.Queue()
        self.live_queue_polling = False
        self.enrichment_queue = queue.Queue()
        self.enrichment_worker = None
        self.gateway_ip = ""
        self.service_scan_queue = queue.Queue()
        self.service_scan_worker = None
        self.service_scan_stop_event = threading.Event()
        self.l2_discovered_neighbors = []  # lijst van (proto, mac, ip, desc)
        self.vuln_findings = {}

        # Scan Wizard / routed discovery state.  Kept separate from the classic
        # local scanner so existing Windows/Linux discovery remains intact.
        self.scan_context = {"mode": "local", "route": {}, "jump_host": {}}
        self.topology_search_var = tk.StringVar(value="")
        self.topology_relation_filter_var = tk.StringVar(value="All")
        self.topology_subnet_groups_var = tk.BooleanVar(value=True)
        self._pan_anchor = None
        # Network Visualisation parity controls
        self.topology_tool = "select"
        self.topology_connect_source = None
        self.topology_selected_device = None
        self.topology_layout_var = tk.StringVar(value="Hierarchical")
        self.topology_layer_var = tk.StringVar(value="All")
        self.topology_show_grid_var = tk.BooleanVar(value=False)
        self.topology_snap_grid_var = tk.BooleanVar(value=False)
        self.topology_show_zones_var = tk.BooleanVar(value=True)

        self.zoom = 1.0  # zoomfactor (we schalen coördinaten zelf)
        self.help_topics = load_help_topics()
        self.help_content = self.load_help_content()


        # Portscan-opties (protocol + poorten)
        self.scan_proto_var = tk.StringVar(value=_tr('ui.source.tcp.6ce375e3'))
        self.scan_ports_var = tk.StringVar(value=_tr('ui.source.top.20.df021aaa'))
        self.scan_optimized_var = tk.BooleanVar(value=False)
        self.scan_nmap_params_var = tk.StringVar(value="")
        
                # --- NIEUW: annotaties / commentaar-vakjes op de kaart ---
        self.annotations = []      # lijst dicts {"x","y","text","color","shape"}
        self.annotation_mode = False  # True = volgende klik plaatst een note
        
                # Zones (DMZ / Extranet / Intranet) als achtergrondvlakken
        self.zones = []             # lijst dicts {"x0","y0","x1","y1","label","color"}
        self.zone_mode = False      # True = we zijn bezig met een zone tekenen
        self.zone_temp_start = None # eerste hoek van de rechthoek
        self.zone_place_mode = False
        self.pending_zone = None

        self.zone_start = None       # eerste hoekpunt (logische coords)

        self.zone_label_var = tk.StringVar(value=_tr('ui.source.dmz.138a224d'))
        self.zone_type_var = tk.StringVar(value=_tr('ui.source.dmz.e0642f18'))
        
        
        # Interface-keuze voor discovery
        self.iface_var = tk.StringVar(value=_tr('ui.source.auto.0d612c12'))
        self.interfaces = self.detect_interfaces()

        # Huidig bestand (voor Opslaan/Opslaan als)
        self.current_file = None
        load_cve_db()

        # Mapping van canvas items naar object info
        self.canvas_item_map = {}

        # Mapping device -> canvas items (voor slepen)
        self.device_canvas_items = {}  # {device_obj: {"oval": id, "icon": id, "label": id, "link": id}}

        # Sleep-state
        self.drag_device = None
        self.drag_last_x = 0
        self.drag_last_y = 0

        # Laatste traceroute-resultaat (voor overlay)
        self.last_traceroute = None  # {"target": str, "hops": [ {hop, ip, rtt_ms}, ... ]}

        self.create_menu()
        self.create_widgets()
                # Mapping device -> canvas items (voor slepen)
        self.device_canvas_items = {}  # {device_obj: {...}}

        # NIEUW: Mapping annotation -> canvas items
        self.annotation_canvas_items = {}  # {id(ann): {"box": id, "text": id}}

        # Sleep-state
        self.drag_device = None
        self.drag_annotation = None   # NIEUW
        self.drag_last_x = 0
        self.drag_last_y = 0



    def load_help_content(self):
        """Load language-specific NetMap help content with a localized fallback."""
        try:
            lang = "en" if str(_get_language()).lower().startswith("en") else "nl"
            base_dir = os.path.dirname(os.path.abspath(__file__))
            help_path = os.path.join(base_dir, f"help_content.{lang}.json")
            with open(help_path, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception as e:
            print(_tr("netmap.help.load_error_short", default="Could not load NetMap help content: {error}", error=e))
            return {
                "intro": {
                    "title": _tr("netmap.help.unavailable.title", default="Help unavailable"),
                    "text": [
                        _tr("netmap.help.unavailable.file", default="The language-specific NetMap help file could not be loaded."),
                        _tr("netmap.help.unavailable.check", default="Check whether the help resources are installed with this application.")
                    ]
                }
            }


        
    def find_cves_for_device(self, dev):
        """Use the shared SQLite correlator and normalize NetMap/Nmap service shapes."""
        services=[]
        for svc in list(getattr(dev,"services",[]) or []):
            if not isinstance(svc,dict): continue
            product=str(svc.get("product") or "").strip()
            vendor=str(svc.get("vendor") or "").strip()
            version=str(svc.get("version") or "").strip()
            extra=str(svc.get("extrainfo") or svc.get("extra_info") or "").strip()
            pv=str(svc.get("product_version") or "").strip()
            if not pv: pv=" ".join(x for x in (vendor,product,version,extra) if x).strip()
            services.append({"port":int(svc.get("port") or 0),
                "protocol":str(svc.get("protocol") or "tcp").lower(),
                "service":str(svc.get("service") or svc.get("name") or "").strip(),
                "product_version":pv})
        # ports_summary is also used as enrichment, not only as an empty-list fallback.
        for part in [p.strip() for p in str(getattr(dev,"ports_summary","") or "").split(",") if p.strip()]:
            m=re.match(r"(\d+)/(tcp|udp)\s+(\S+)(?:\s+(.*))?$",part)
            if not m: continue
            key=(int(m.group(1)),m.group(2))
            pv=(m.group(4) or "").strip()
            existing=next((x for x in services if (x["port"],x["protocol"])==key),None)
            if existing:
                if not existing["service"]: existing["service"]=m.group(3)
                if not existing["product_version"] and pv: existing["product_version"]=pv
            else:
                services.append({"port":key[0],"protocol":key[1],"service":m.group(3),"product_version":pv})
        db=self._vulnerability_db()
        return db.match_network_vulnerabilities(services) if db is not None and services else []


    def show_cves_for_selected(self):
        item_id = self.device_tree.focus()
        if not item_id:
            self._mb_warning(_tr('ui.source.cve.lookup.3195b1b0'), _tr('ui.source.selecteer.eerst.een.host.in.de.lijst.dd0ab7f9'))
            return

        try:
            index = int(item_id)
        except ValueError:
            self._mb_warning(_tr('ui.source.cve.lookup.3195b1b0'), _tr('ui.source.ongeldige.selectie.8dc38453'))
            return

        if index < 0 or index >= len(self.devices):
            self._mb_warning(_tr('ui.source.cve.lookup.3195b1b0'), _tr('ui.source.ongeldige.selectie.8dc38453'))
            return

        dev = self.devices[index]
        findings = self.find_cves_for_device(dev)

        if not findings:
            self._mb_info(
                _tr('ui.source.cve.lookup.3195b1b0'),
                _tr('ui.source.geen.cve.matches.gevonden.voor.p0.op.basis.van.5d37e1fb',p0=dev.ip)
            )
            return

        lines = []
        lines.append(f"CVE-matches voor host {dev.ip}:")
        lines.append("")
        for cve in findings:
            lines.append(f"- {cve.get('id','-')} — {cve.get('label','')}")
            lines.append(f"  Status: {cve.get('correlation_state','candidate')}")
            lines.append(f"  Confidence: {cve.get('confidence',0)}%")
            lines.append(f"  Evidence: {cve.get('evidence','-')}")
            if cve.get("risk"): lines.append(f"  Severity: {cve['risk']}")
            if cve.get("reason"): lines.append(f"  Reden: {cve['reason']}")
            lines.append("")
        self._mb_info(_tr('ui.source.cve.lookup.local.db.b7fc2528'), "\n".join(lines))

        

    # ------------- MENUBALK (Bestand + Discover + Tools) ----------------
    def create_menu(self):
        menubar = tk.Menu(self.root)

        # --- Bestand ---
        file_menu = tk.Menu(menubar, tearoff=0)
        file_menu.add_command(label=_tr('ui.source.nieuw.8762a532'), command=self.file_new)
        file_menu.add_command(label=_tr('ui.source.openen.f00cfa12'), command=self.file_open)
        file_menu.add_separator()
        file_menu.add_command(label=_tr('ui.source.opslaan.2b030208'), command=self.file_save)
        file_menu.add_command(label=_tr('ui.source.opslaan.als.801b04c4'), command=self.file_save_as)
        file_menu.add_separator()
        file_menu.add_command(label=_tr('ui.source.afdrukken.af156033'), command=self.file_print)
        file_menu.add_command(label=_tr('ui.source.verzenden.747a6213'), command=self.file_send)
        file_menu.add_separator()
        file_menu.add_command(label=_tr('ui.source.afsluiten.d4ecbb98'), command=self.root.quit)
        menubar.add_cascade(label=_tr('ui.source.bestand.6e8cf3e6'), menu=file_menu)

        # --- Discover / analyse-flow ---
        discover_menu = tk.Menu(menubar, tearoff=0)
        discover_menu.add_command(label='Guided Network Analysis', command=self.open_guided_network_analysis)
        discover_menu.add_separator()
        discover_menu.add_command(label=_tr('ui.source.1.scan.network.hybride.4251ccb1'), command=self.open_scan_wizard)
        discover_menu.add_command(label=_tr('ui.source.2.scan.gevonden.hosts.service.version.a19d07d9'), command=self.scan_discovered_hosts)
        discover_menu.add_command(label=_tr('ui.source.3.vulnerability.analysis.14e38ea4'), command=self.run_vulnerability_analysis)
        discover_menu.add_command(label=_tr('ui.source.4.analyse.advies.9615ae8a'), command=self.run_analysis_advice)
        discover_menu.add_separator()
        discover_menu.add_command(label=_tr('ui.source.detecteer.cdp.neighbor.ab94366e'), command=self.detect_cdp_neighbor)
        discover_menu.add_command(label=_tr('ui.source.layer.2.discovery.cdp.lldp.mndp.50f9dee9'), command=self.run_l2_discovery)
        menubar.add_cascade(label=_tr('ui.source.discover.4827ea22'), menu=discover_menu)

        # --- Tools (Traceroute) ---
    
        
        tools_menu = tk.Menu(menubar, tearoff=0)
        tools_menu.add_command(
            label=_tr('ui.source.traceroute.visualiseren.642b8acc'),
            command=self.trace_route_dialog
        )
        tools_menu.add_command(
            label=_tr('ui.source.markeer.geselecteerde.host.als.compromised.7e3f4dba'),
            command=self.mark_compromised_selected
        )
        tools_menu.add_separator()
        tools_menu.add_command(
            label=_tr('ui.source.export.topology.json.213a088c'),
            command=self.export_topology_json
        )
        
        tools_menu.add_command(
            label=_tr('ui.source.vulnerability.analysis.6f65111e'),
            command=self.run_vulnerability_analysis
        )
        tools_menu.add_command(
            label=_tr('ui.source.pcap.network.map.3e2ccd53'),
            command=self.import_pcap_dialog   # << NIEUW
        )
        menubar.add_cascade(label=_tr('ui.source.tools.4fa8cc86'), menu=tools_menu)
        zones_menu = tk.Menu(menubar, tearoff=0)
        zones_menu.add_command(label=_tr('ui.source.add.zone.a3f3ba14'), command=self.add_zone)


        # --- Zones (DMZ / Intranet / Extranet / Guest) ---
        
        zones_menu = tk.Menu(menubar, tearoff=0)
        zones_menu.add_command(
            label=_tr('ui.source.nieuwe.zone.klik.twee.punten.c8bb5cd1'),
            command=self.start_zone_mode
        )
        zones_menu.add_command(
            label=_tr('ui.source.alle.zones.wissen.d79321dc'),
            command=self.clear_zones
        )
        menubar.add_cascade(label=_tr('ui.source.zones.182e2eb7'), menu=zones_menu)

        # --- Help ---
        help_menu = tk.Menu(menubar, tearoff=0)
        help_menu.add_command(label=_tr('ui.source.help.topics.d5de1e52'), command=self.show_help_window)
        help_menu.add_separator()
        help_menu.add_command(label=_tr('ui.source.about.6b21fb79'), command=self.show_about)
        menubar.add_cascade(label=_tr('ui.source.help.c47ae153'), menu=help_menu)

        self.root.config(menu=menubar)

        # F1 = help
        self.root.bind("<F1>", lambda e: self.show_help_window())




    # ============================================
    #  Interactief help-venster
    # ============================================
    
    
    def show_help_dialog(self):
        if not getattr(self, "help_topics", None):
            self._mb_warning(
                _tr('ui.source.help.c47ae153'),
                _tr('ui.source.no.help.topics.loaded.check.help.content.json.199ff1d7')
            )
            return
        HelpDialog(self.root, self.help_topics)

    def show_about(self):
        self._mb_info(
            _tr('ui.source.about.6b21fb79'),
            _tr('ui.source.network.mapper.educational.tool.for.visualisin.506cfbc8')
        )

    

    def show_help_window(self):
        """
        Toon een helpvenster met:
        - links: Treeview met topics + zoekveld + scrollbar
        - rechts: ScrolledText met inhoud + kopieerknop
        """
        win = tk.Toplevel(self.root)
        win.title(_tr('ui.source.help.network.mapper.bb945fa8'))
        win.geometry("900x600")
        win.transient(self.root)

        # Hoofd container: horizontale PanedWindow
        paned = ttk.PanedWindow(win, orient="horizontal")
        paned.pack(fill="both", expand=True)

        # === LINKER PANE: zoekveld + topics (Treeview) ===
        left_frame = ttk.Frame(paned)
        paned.add(left_frame, weight=1)

        # Zoekbalk bovenaan
        search_frame = ttk.Frame(left_frame)
        search_frame.pack(side="top", fill="x", padx=5, pady=5)

        ttk.Label(search_frame, text=_tr('ui.source.zoek.in.help.ea021645')).pack(side="left")
        self.help_search_var = tk.StringVar()
        search_entry = ttk.Entry(search_frame, textvariable=self.help_search_var, width=20)
        search_entry.pack(side="left", padx=(5, 5))

        search_btn = ttk.Button(search_frame, text=_tr('ui.source.zoek.2f4d969b'), command=self.search_help)
        search_btn.pack(side="left")

        reset_btn = ttk.Button(search_frame, text=_tr('ui.source.reset.44c57abd'), command=self.reset_help_search)
        reset_btn.pack(side="left", padx=(5, 0))

        # Treeview + scrollbar in eigen frame
        tree_frame = ttk.Frame(left_frame)
        tree_frame.pack(side="top", fill="both", expand=True)

        tree_scroll = ttk.Scrollbar(tree_frame, orient="vertical")
        self.help_tree = ttk.Treeview(
            tree_frame,
            columns=("id",),
            show="tree",
            yscrollcommand=tree_scroll.set
        )
        tree_scroll.config(command=self.help_tree.yview)

        self.help_tree.pack(side="left", fill="both", expand=True)
        tree_scroll.pack(side="right", fill="y")

        # === RECHTER PANE: kopieerknop + ScrolledText ===
        right_frame = ttk.Frame(paned)
        paned.add(right_frame, weight=3)

        ctrl_frame = ttk.Frame(right_frame)
        ctrl_frame.pack(side="top", fill="x", padx=5, pady=5)

        def copy_help_to_clipboard():
            text = self.help_text.get("1.0", "end").strip()
            if not text:
                self._mb_info(_tr('ui.source.kopi.ren.6ebc5343'), _tr('ui.source.er.is.geen.tekst.om.te.kopi.ren.c8d03070'))
                return
            # klembord van de hoofd-root gebruiken
            self.root.clipboard_clear()
            self.root.clipboard_append(text)
            self._mb_info(_tr('ui.source.kopi.ren.6ebc5343'), _tr('ui.source.huidig.help.onderwerp.is.gekopieerd.naar.het.k.ea1f9ed6'))

        copy_btn = ttk.Button(ctrl_frame, text=_tr('ui.source.kopieer.tekst.e7965603'), command=copy_help_to_clipboard)
        copy_btn.pack(side="left")

        self.help_text = ScrolledText(right_frame, wrap="word")
        self.help_text.pack(side="top", fill="both", expand=True)
        self.help_text.configure(state="disabled")

        # Help-content vullen in de Treeview
        # we hangen het id (key) in 'values', zodat we later weten welke sectie gekozen is
        self.help_topic_ids = {}  # item_id -> key in help_content
        for key, section in self.help_content.items():
            title = section.get("title", key)
            item_id = self.help_tree.insert("", "end", text=title, values=(key,))
            self.help_topic_ids[item_id] = key

        # Selectie-event binden
        self.help_tree.bind("<<TreeviewSelect>>", self.on_help_topic_selected)

        # Enter in zoekveld triggert ook zoeken
        search_entry.bind("<Return>", lambda e: self.search_help())

        # Standaard eerste item tonen
        first_item = self.help_tree.get_children()
        if first_item:
            self.help_tree.selection_set(first_item[0])
            self.help_tree.focus(first_item[0])
            self._display_help_topic_by_item(first_item[0])


    def _help_build_tree(self, filtered_ids=None):
        """Vult de treeview met HELP_TOPICS. filtered_ids = optioneel set met ids."""
        self.help_tree.delete(*self.help_tree.get_children())

        def add_node(topic_id, parent=""):
            topic = HELP_TOPICS.get(topic_id)
            if not topic:
                return
            if filtered_ids is not None and topic_id not in filtered_ids:
                return
            node = self.help_tree.insert(parent, "end", iid=topic_id, text=topic["title"])
            for child_id in topic.get("children", []):
                add_node(child_id, node)

        add_node("intro")

    def on_help_topic_selected(self, event):
        sel = self.help_tree.selection()
        if not sel:
            return
        item_id = sel[0]
        self._display_help_topic_by_item(item_id)


    def _display_help_topic_by_item(self, item_id):
        key = self.help_topic_ids.get(item_id)
        if not key:
            return
        section = self.help_content.get(key, {})
        title = section.get("title", key)
        lines = section.get("text", [])

        self.help_text.configure(state="normal")
        self.help_text.delete("1.0", "end")

        self.help_text.insert("end", title + "\n", ("title",))
        self.help_text.insert("end", "=" * len(title) + "\n\n")

        for line in lines:
            self.help_text.insert("end", line + "\n")

        self.help_text.tag_config("title", font=("Arial", 14, "bold"))

        # Eerst oude highlights wissen
        self.help_text.tag_delete("search_match")
        self.help_text.tag_config("search_match", background="yellow")

        # Als er een zoekterm actief is, highlight die
        if hasattr(self, "help_search_var"):
            query = (self.help_search_var.get() or "").strip()
            if query:
                self._highlight_help_search(query)

        self.help_text.configure(state="disabled")
    def _highlight_help_search(self, query: str):
        """Highlight alle voorkomens van 'query' in het help-tekstveld."""
        self.help_text.tag_remove("search_match", "1.0", "end")
        if not query:
            return

        q = query.lower()
        start = "1.0"
        while True:
            pos = self.help_text.search(q, start, stopindex="end", nocase=True)
            if not pos:
                break
            end_pos = f"{pos}+{len(q)}c"
            self.help_text.tag_add("search_match", pos, end_pos)
            start = end_pos

    def search_help(self):
        """Filter de help-secties op basis van de zoekterm en highlight in de tekst."""
        if not hasattr(self, "help_tree"):
            return

        query = (self.help_search_var.get() or "").strip().lower()
        # Als leeg → reset
        if not query:
            self.reset_help_search()
            return

        # Tree leegmaken
        for item in self.help_tree.get_children():
            self.help_tree.delete(item)
        self.help_topic_ids.clear()

        matches = []

        # Filter op titel + tekst
        for key, section in self.help_content.items():
            title = section.get("title", key)
            text_lines = section.get("text", [])
            full_text = (title + "\n" + "\n".join(text_lines)).lower()

            if query in full_text:
                item_id = self.help_tree.insert("", "end", text=title, values=(key,))
                self.help_topic_ids[item_id] = key
                matches.append(item_id)

        # Niets gevonden?
        if not matches:
            # 1 dummy item
            dummy_id = self.help_tree.insert("", "end", text=_tr('ui.source.geen.resultaten.0765426a'), values=("",))
            self.help_topic_ids[dummy_id] = None
            self.help_text.configure(state="normal")
            self.help_text.delete("1.0", "end")
            self.help_text.insert(
                "end",
                _tr('ui.source.geen.help.onderwerpen.gevonden.die.p0.bevatten.afe5b158',p0=query)
            )
            self.help_text.configure(state="disabled")
            return

        # Eerste match tonen
        self.help_tree.selection_set(matches[0])
        self.help_tree.focus(matches[0])
        self._display_help_topic_by_item(matches[0])

    def reset_help_search(self):
        """Originele lijst met alle help-secties herstellen en zoekterm leegmaken."""
        if hasattr(self, "help_search_var"):
            self.help_search_var.set("")

        if not hasattr(self, "help_tree"):
            return

        # Tree leegmaken
        for item in self.help_tree.get_children():
            self.help_tree.delete(item)
        self.help_topic_ids.clear()

        # Opnieuw vullen met alle secties
        for key, section in self.help_content.items():
            title = section.get("title", key)
            item_id = self.help_tree.insert("", "end", text=title, values=(key,))
            self.help_topic_ids[item_id] = key

        # Eerste item weer tonen
        first_item = self.help_tree.get_children()
        if first_item:
            self.help_tree.selection_set(first_item[0])
            self.help_tree.focus(first_item[0])
            self._display_help_topic_by_item(first_item[0])


    def _select_help_topic(self, topic_id):
        """
        Programmatic selectie (F1, zoekfunctie enz.).
        Zet de selectie in de tree en toon de tekst,
        maar wordt NIET door de Treeview zelf aangeroepen.
        """
        try:
            self.help_tree.selection_set(topic_id)
            self.help_tree.see(topic_id)
        except Exception:
            pass
        self._show_help_topic_text(topic_id)

    def _show_help_topic_text(self, topic_id):
        """
        Hulp-functie die alleen de tekst in het rechtervlak bijwerkt.
        Dit voorkomt dat we in een selectie-callback-lus terechtkomen.
        """
        topic = HELP_TOPICS.get(topic_id)
        if not topic:
            return

        text = topic.get("text", "")

        self.help_text.config(state="normal")
        self.help_text.delete("1.0", "end")
        self.help_text.insert("1.0", text)
        self.help_text.config(state="disabled")
        self.help_text.yview_moveto(0.0)


    def _help_apply_search(self):
        """
        Zoek in titel en tekst; toon alleen matching topics in de boom.
        """
        term = (self.help_search_var.get() or "").strip().lower()
        if not term:
            self._help_reset_search()
            return

        matches = set()
        for tid, data in HELP_TOPICS.items():
            title = data.get("title", "").lower()
            text = data.get("text", "").lower()
            if term in title or term in text:
                matches.add(tid)
                # ook parent 'intro' meenemen zodat boomstructuur zichtbaar blijft
                matches.add("intro")

        self._help_build_tree(filtered_ids=matches)

        # automatisch eerste match tonen
        for tid in matches:
            if tid != "intro":
                self._select_help_topic(tid)
                break

    def _help_reset_search(self):
        self.help_search_var.set("")
        self._help_build_tree()
        self._select_help_topic("intro")


    def mark_compromised_selected(self):
        item_id = self.device_tree.focus()
        if not item_id:
            self._mb_warning(_tr('ui.source.no.selection.915cf89a'), _tr('ui.source.selecteer.eerst.een.host.in.de.devicelijst.ca83978f'))
            return

        try:
            index = int(item_id)
        except ValueError:
            self._mb_warning(_tr('ui.source.error.7f2f6a15'), _tr('ui.source.ongeldige.selectie.8dc38453'))
            return

        if index < 0 or index >= len(self.devices):
            self._mb_warning(_tr('ui.source.error.7f2f6a15'), _tr('ui.source.ongeldige.selectie.8dc38453'))
            return

        dev = self.devices[index]
        dev.dev_type = "compromised"
        extra = "\n[Marked as COMPROMISED in Blue Team demo]"
        if dev.note:
            if "compromised" not in dev.note.lower():
                dev.note += extra
        else:
            dev.note = extra.strip()

        self.update_device_table()
        self.draw_network_map()
        self.status_label.config(text=_tr('ui.source.host.p0.gemarkeerd.als.compromised.a4d776de',p0=dev.ip))


    # ------------- VULNERABILITY / CVE OVERLAY (DEMO) ----------------
    def _match_vulns_for_device(self, dev):
        """
        Kijk naar dev.ports_summary en match tegen VULN_SIGNATURES.
        Dit is een EDU-demo: het zegt alleen 'mogelijk kwetsbaar'.
        """
        results = []
        ports = (dev.ports_summary or "").lower()
        if not ports:
            return results

        for sig in VULN_SIGNATURES:
            for term in sig.get("match_any", []):
                if term.lower() in ports:
                    results.append(sig)
                    break  # zelfde signature niet dubbel toevoegen

        return results

    def run_vulnerability_overlay(self):
        """
        Loop alle devices langs, match demo-CVE's op basis van poorten
        en teken een overlay op de kaart (rode rand + ⚠-icoon + label).
        """
        if not self.devices:
            self._mb_info(_tr('ui.source.cve.overlay.demo.1199569a'), _tr('ui.source.geen.devices.om.te.analyseren.0c519a0e'))
            return

        self.vuln_findings.clear()
        total_matches = 0

        for dev in self.devices:
            matches = self._match_vulns_for_device(dev)
            if matches:
                self.vuln_findings[dev] = matches
                total_matches += len(matches)

        # Kaart opnieuw tekenen zodat de visuele overlay zichtbaar wordt
        self.draw_network_map()

        if total_matches == 0:
            self._mb_info(
                _tr('ui.source.cve.overlay.demo.1199569a'),
                _tr('ui.source.geen.demo.cve.matches.gevonden.tip.voer.eerst..8b93083d')
            )
            return

        # Kort tekstueel rapport in popup + log-tab
        lines = []
        lines.append(_tr('ui.source.demo.cve.overlay.lokaal.gegenereerd.geen.live..b8495da5'))
        lines.append("=" * 60)
        for dev, matches in self.vuln_findings.items():
            lines.append(_tr('ui.source.p0.p1.7fe766f6',p0=dev.ip,p1=dev.hostname or 'geen hostname'))
            for m in matches:
                lines.append(f"  - {m['id']} [{m['risk']}]: {m['label']}")
            lines.append("")
        report = "\n".join(lines)

        # Als je de traceroute-logtab hebt, gebruik die ook als 'security log'
        if hasattr(self, "append_traceroute_log"):
            self.append_traceroute_log(report)

        self._mb_info(
            _tr('ui.source.cve.overlay.demo.1199569a'),
            _tr('ui.source.demo.overlay.voltooid.devices.met.matches.p0.t.8c0cdeee',p0=len(self.vuln_findings),p1=total_matches)
        )



    def detect_cdp_neighbor(self):
        """Placeholder voor CDP-detectie."""
        self._mb_info(
            _tr('ui.source.cdp.detectie.52f5c8be'),
            _tr('ui.source.cdp.detectie.is.in.deze.build.nog.niet.actief..72db817d')
        )

    # =========================================================
    #  L2 DISCOVERY: CDP / LLDP / MNDP (MikroTik)
    # =========================================================
    def run_l2_discovery(self):
        """
        Start een korte L2-discovery (CDP, LLDP, MNDP) via Scapy-sniff.
        Resultaat: nieuwe 'l2-neighbor' devices in de lijst + map.
        """
        if sniff is None or Ether is None:
            self._mb_error(
                _tr('ui.source.l2.discovery.485526e2'),
                _tr('ui.source.scapy.npcap.zijn.niet.beschikbaar.installeer.s.cb254177')
            )
            return

        # Simpele vraag: hoe lang sniffen?
        duration = simpledialog.askinteger(
            _tr('ui.source.l2.discovery.485526e2'),
            _tr('ui.source.hoeveel.seconden.wil.je.sniffen.op.l2.typisch..357bfbf1'),
            parent=self.root,
            minvalue=3,
            maxvalue=60
        )
        if not duration:
            return

        self.status_label.config(text=_tr('ui.source.l2.discovery.gestart.p0.s.49427b39',p0=duration))
        self.root.update_idletasks()

        # Bepaal interface (optioneel; als je self.iface_var hebt)
        iface = None
        try:
            if hasattr(self, "iface_var"):
                val = (self.iface_var.get() or "").strip()
                if val and val.lower() != "auto":
                    detail=self._selected_interface_detail(val)
                    iface=(detail or {}).get("name") or val
        except Exception:
            iface = None

        # We snuffelen in een aparte thread zodat de GUI niet blokkeert
        t = threading.Thread(
            target=self._l2_sniff_worker,
            args=(duration, iface),
            daemon=True
        )
        t.start()

    def _l2_sniff_worker(self, duration, iface):
        """
        Background-thread die Scapy-sniff draait en pakketten
        terug geeft aan _l2_sniff_callback.
        """
        seen = []  # lokale lijst; later terug naar GUI-thread

        def _callback(pkt):
            try:
                info = self._l2_sniff_callback(pkt)
                if info is not None:
                    seen.append(info)
            except Exception as e:
                # Geen crash als parsing faalt
                print("L2 sniff callback error:", e)

        kwargs = dict(prn=_callback, store=False, timeout=duration)
        if iface:
            kwargs["iface"] = iface

        try:
            sniff(**kwargs)
        except Exception as e:
            self.root.after(
                0,
                lambda: self._mb_error(
                    _tr('ui.source.l2.discovery.485526e2'),
                    _tr('ui.source.sniffing.faalde.p0.controleer.of.je.npcap.hebt.82814346',p0=e)
                )
            )
            self.root.after(0, lambda: self.status_label.config(text=_tr('ui.source.l2.discovery.mislukt.49102c3c')))
            return

        # Terug naar GUI-thread om devices toe te voegen
        self.root.after(0, self._l2_sniff_done, seen)

    def _l2_sniff_callback(self, pkt):
        """
        Herken CDP/LLDP/MNDP-pakketten.
        Returnt een tuple (proto, mac, ip, desc) of None.
        """
        if Ether not in pkt:
            return None
        eth = pkt[Ether]
        dst = eth.dst.lower()
        src_mac = eth.src.lower()

        raw_bytes = bytes(pkt.payload)
        raw_text = ""
        try:
            raw_text = raw_bytes.decode(errors="ignore")
        except Exception:
            pass

        # --- CDP: Cisco Discovery Protocol ---
        # MAC 01:00:0c:cc:cc:cc
        if dst == "01:00:0c:cc:cc:cc":
            ip = self._extract_ip_from_text(raw_text)
            desc = "CDP neighbor"
            if "Cisco" in raw_text:
                desc += " (Cisco)"
            return ("CDP", src_mac, ip, desc)

        # --- LLDP: IEEE 802.1AB ---
        # Ethertype 0x88cc
        if eth.type == 0x88cc:
            ip = self._extract_ip_from_text(raw_text)
            # probeer een system name te vinden
            name = self._extract_lldp_name(raw_text)
            desc = f"LLDP neighbor: {name}" if name else "LLDP neighbor"
            return ("LLDP", src_mac, ip, desc)

        # --- MNDP: MikroTik Neighbor Discovery Protocol ---
        # UDP/5678
        if UDP in pkt and pkt[UDP].dport == 5678:
            ip = self._extract_ip_from_text(raw_text)
            # mikrotik zendt vaak 'MikroTik' + board-name etc.
            if "MikroTik" in raw_text:
                desc = "MNDP neighbor (MikroTik)"
            else:
                desc = "MNDP neighbor"
            return ("MNDP", src_mac, ip, desc)

        return None

    def _extract_ip_from_text(self, text):
        """
        Zoekt eerste IPv4-adres in een tekst.
        """
        if not text:
            return ""
        m = re.search(r"(\d+\.\d+\.\d+\.\d+)", text)
        return m.group(1) if m else ""

    def _extract_lldp_name(self, text):
        """
        Heel simpele heuristiek om een LLDP system-name te vinden.
        In echte setups staat vaak een hostname in plain text.
        """
        if not text:
            return ""
        # Neem een leesbare 'woordachtige' substring
        candidates = [line.strip() for line in text.splitlines() if 3 < len(line.strip()) < 40]
        # filter rare binaire rommel eruit
        candidates = [c for c in candidates if any(ch.isalpha() for ch in c)]
        return candidates[0] if candidates else ""

    def _l2_sniff_done(self, seen):
        """
        Loopt over alle gevonden neighbors en voegt ze toe aan self.devices.
        """
        if not seen:
            self.status_label.config(text=_tr('ui.source.l2.discovery.voltooid.geen.neighbors.gevonden.3d378444'))
            return

        added = 0
        for proto, mac, ip, desc in seen:
            added += self._register_l2_neighbor(proto, mac, ip, desc)

        self.update_device_table()
        self.draw_network_map()

        self.status_label.config(
            text=_tr('ui.source.l2.discovery.p0.pakketten.herkend.p1.nieuwe.ne.763900c1',p0=len(seen),p1=added)
        )

    def _register_l2_neighbor(self, proto, mac, ip, desc):
        """
        Zorgt dat er een Device bestaat voor deze neighbor.
        Retourneert 1 als er een nieuw device is aangemaakt, anders 0.
        """
        mac = (mac or "").lower()
        if not mac:
            return 0

        # Bestaat er al een device met deze MAC?
        for d in self.devices:
            if d.mac.lower() == mac:
                # note aanvullen
                extra = f"\n{proto} neighbor gezien"
                if desc:
                    extra += f": {desc}"
                if ip and ip not in (d.ip or ""):
                    extra += f" (IP hint: {ip})"
                if extra.strip() not in (d.note or ""):
                    d.note = (d.note or "") + extra
                return 0

        # Nieuw device
        hostname = desc or f"{proto} neighbor"
        note = f"{proto} discovered neighbor"
        if desc:
            note += f": {desc}"
        if ip:
            note += f"\nIP hint: {ip}"

        dev = Device(
            ip=ip or "",
            mac=mac,
            hostname=hostname,
            dev_type="l2-neighbor",
            note=note
        )
        self.devices.append(dev)

        if hasattr(self, "l2_discovered_neighbors"):
            self.l2_discovered_neighbors.append((proto, mac, ip, desc))

        return 1


    def detect_interfaces(self):
        """Detect active IPv4 interfaces and retain prefix/network metadata (Windows/Linux)."""
        interfaces=[]
        self.interface_details=[]
        creationflags=getattr(subprocess,"CREATE_NO_WINDOW",0)

        def add(name, ip, prefix=None):
            if not name or not ip or str(ip).startswith("127."):
                return
            try:
                addr=ipaddress.ip_address(str(ip))
                if addr.version != 4:
                    return
                pfx=int(prefix) if prefix is not None else None
                network=str(ipaddress.ip_network(f"{ip}/{pfx}",strict=False)) if pfx is not None else ""
            except Exception:
                return
            key=(str(name),str(ip))
            if key not in interfaces:
                interfaces.append(key)
                self.interface_details.append({"name":str(name),"ip":str(ip),"prefix":pfx,"network":network})

        try:
            if sys.platform.startswith("win"):
                # CIM/PowerShell is used first because WMIC is removed on current Windows 11 builds.
                ps=shutil.which("powershell") or shutil.which("powershell.exe")
                if ps:
                    cmd=("Get-NetIPConfiguration | ForEach-Object { $a=$_; "
                         "$a.IPv4Address | ForEach-Object { [PSCustomObject]@{"
                         "Name=$a.InterfaceAlias; IP=$_.IPAddress; Prefix=$_.PrefixLength} } } | ConvertTo-Json -Compress")
                    cp=subprocess.run([ps,"-NoProfile","-NonInteractive","-Command",cmd],capture_output=True,text=True,
                                      errors="ignore",creationflags=creationflags,timeout=10)
                    if cp.returncode==0 and cp.stdout.strip():
                        data=json.loads(cp.stdout)
                        if isinstance(data,dict): data=[data]
                        for item in data or []:
                            add(item.get("Name"),item.get("IP"),item.get("Prefix"))

                # Fallback: route table still gives interface IPv4 + directly connected network.
                if not interfaces:
                    for r in self._detect_routes():
                        if r.get("gateway")!="On-link" or r.get("network")=="0.0.0.0/0":
                            continue
                        ip=r.get("interface","")
                        try: pfx=ipaddress.ip_network(r["network"],strict=False).prefixlen
                        except Exception: pfx=None
                        add(f"Interface {ip}",ip,pfx)
            else:
                cp=subprocess.run(["ip","-o","-4","addr","show"],capture_output=True,text=True,errors="ignore",timeout=8)
                for line in cp.stdout.splitlines():
                    parts=line.split()
                    if len(parts)>=4 and parts[2]=="inet":
                        name=parts[1].split("@",1)[0]; cidr=parts[3]
                        ip,prefix=cidr.split("/",1)
                        add(name,ip,prefix)
        except Exception as exc:
            print("Interface detect error:",exc)
        return interfaces

    def _interface_display_values(self):
        values=["auto"]
        for d in getattr(self,"interface_details",[]):
            suffix=f"{d['ip']}/{d['prefix']}" if d.get('prefix') is not None else d['ip']
            if d.get("network"):
                suffix += f"  ->  {d['network']}"
            values.append(f"{d['name']}  ({suffix})")
        if len(values)==1:
            for name,ip in getattr(self,"interfaces",[]):
                values.append(f"{name} ({ip})" if ip else name)
        return values

    def _selected_interface_detail(self, value=None):
        value=(value if value is not None else self.iface_var.get() or "").strip()
        if not value or value.lower()=="auto": return None
        for d in getattr(self,"interface_details",[]):
            if value==d.get("name") or value.startswith(d.get("name","")+"  ("):
                return d
        m=re.search(r"\((\d+\.\d+\.\d+\.\d+)(?:/\d+)?",value)
        if m:
            ip=m.group(1)
            for d in getattr(self,"interface_details",[]):
                if d.get("ip")==ip: return d
            return {"name":value.split("(",1)[0].strip(),"ip":ip,"prefix":None,"network":""}
        return {"name":value.split("(",1)[0].strip(),"ip":"","prefix":None,"network":""}

    def _on_interface_selected(self, event=None):
        d=self._selected_interface_detail()
        if d and d.get("network"):
            self.range_var.set(d["network"])
            self.status_label.config(text=f"Interface selected: {d['name']} - {d['ip']}/{d['prefix']} - network {d['network']}")

    def refresh_interface_list(self):
        current=self.iface_var.get()
        self.interfaces=self.detect_interfaces()
        values=self._interface_display_values()
        if hasattr(self,"iface_combo"):
            self.iface_combo.configure(values=values)
        if current in values:
            self.iface_var.set(current)
        elif len(values)>1:
            self.iface_var.set(values[1]); self._on_interface_selected()
        else:
            self.iface_var.set("auto")
        return values

    def build_topology_from_pcap(self, filepath):
        """
        Parseer een PCAP/PCAPNG met scapy en bouw een lijst Device-objecten.
        - ARP: IP <-> MAC
        - IP-verkeer: extra IP's
        - DHCP: DHCP-servers herkennen
        - LLDP (optioneel): switch/router-informatie als notities
        """
        try:
            from scapy.all import rdpcap, ARP, IP, Ether, BOOTP, DHCP
            try:
                # LLDP is optioneel – als niet aanwezig, slaan we LLDP gewoon over
                from scapy.layers.l2 import (
                    LLDPDU,
                    LLDPDUChassisID,
                    LLDPDUPortID,
                    LLDPDUSystemName,
                )
                HAVE_LLDP = True
            except Exception:
                HAVE_LLDP = False
        except ImportError:
            # Wordt door de caller (import_pcap_dialog) opgevangen als ImportError
            raise

        pkts = rdpcap(filepath)

        # --- ARP & IP verzamelen ---
        ip_to_mac = {}    # "192.168.1.10" -> "aa:bb:cc:dd:ee:ff"
        seen_ips = set()

        for p in pkts:
            # ARP
            if p.haslayer(ARP):
                a = p[ARP]
                if a.psrc and a.hwsrc:
                    ip_to_mac[a.psrc] = a.hwsrc.lower()
                    seen_ips.add(a.psrc)
                if a.pdst:
                    seen_ips.add(a.pdst)

            # IP-laag
            if p.haslayer(IP):
                ip_layer = p[IP]
                if ip_layer.src:
                    seen_ips.add(ip_layer.src)
                if ip_layer.dst:
                    seen_ips.add(ip_layer.dst)

        # --- DHCP-informatie (DHCP servers zoeken) ---
        dhcp_servers = set()
        for p in pkts:
            if p.haslayer(BOOTP) and p.haslayer(DHCP):
                bootp = p[BOOTP]
                dhcp = p[DHCP]
                # DHCP options naar dict
                opts = {}
                for opt in dhcp.options:
                    if isinstance(opt, tuple) and len(opt) == 2:
                        k, v = opt
                        opts[k] = v

                mtype = opts.get("message-type", None)
                # bytes -> string
                if isinstance(mtype, bytes):
                    try:
                        mtype = mtype.decode(errors="ignore")
                    except Exception:
                        pass

                # OFFER/ACK → we kunnen hier vaak de server herkennen
                if mtype in ("offer", "ack", 2, 5):
                    # server-ip kan in siaddr zitten of in IP.src
                    server_ip = None
                    if getattr(bootp, "siaddr", None):
                        server_ip = bootp.siaddr
                    elif p.haslayer(IP):
                        server_ip = p[IP].src

                    if server_ip:
                        dhcp_servers.add(server_ip)

        # --- LLDP-informatie (optioneel) ---
        lldp_neighbors = []  # lijst van dicts: {"chassis", "port", "sysname"}
        if HAVE_LLDP:
            for p in pkts:
                if p.haslayer(LLDPDU):
                    chassis = None
                    port = None
                    sysname = None

                    if p.haslayer(LLDPDUChassisID):
                        chassis = getattr(p[LLDPDUChassisID], "id", None)
                    if p.haslayer(LLDPDUPortID):
                        port = getattr(p[LLDPDUPortID], "id", None)
                    if p.haslayer(LLDPDUSystemName):
                        s = getattr(p[LLDPDUSystemName], "system_name", None)
                        if isinstance(s, bytes):
                            try:
                                sysname = s.decode(errors="ignore")
                            except Exception:
                                sysname = str(s)
                        else:
                            sysname = s

                    # chassis-id kan bytes zijn (MAC); maak er een nette string van als mogelijk
                    chassis_str = None
                    if isinstance(chassis, bytes) and len(chassis) in (6, 8):
                        chassis_str = ":".join(f"{b:02x}" for b in chassis)
                    elif isinstance(chassis, str):
                        chassis_str = chassis

                    lldp_neighbors.append({
                        "chassis": chassis_str,
                        "port": port,
                        "sysname": sysname,
                    })

        # --- Devices bouwen ---
        devices = []
        seen_dev_ips = set()

        def is_private(ip):
            # simpele check voor RFC1918 (didactisch genoeg)
            try:
                parts = [int(x) for x in ip.split(".")]
                if len(parts) != 4:
                    return False
                if parts[0] == 10:
                    return True
                if parts[0] == 172 and 16 <= parts[1] <= 31:
                    return True
                if parts[0] == 192 and parts[1] == 168:
                    return True
                return False
            except Exception:
                return False

        for ip in sorted(
            seen_ips,
            key=lambda s: tuple(int(x) for x in s.split(".")) if s.count(".") == 3 else (999,)
        ):
            mac = ip_to_mac.get(ip, "")
            hostname = ""  # kun je later via PTR lookup resolven
            dev_type = self.classify_device(hostname, ip, mac)

            if ip in seen_dev_ips:
                continue
            seen_dev_ips.add(ip)

            note_lines = ["Imported from PCAP capture"]

            # DHCP-server?
            if ip in dhcp_servers:
                note_lines.append("DHCP server detected (from PCAP).")
                # didactisch: maak 'm duidelijk als infra/server
                if dev_type == "client":
                    dev_type = "server"

            # LLDP koppelen: als chassis-id matcht met MAC -> extra notities
            if mac:
                for n in lldp_neighbors:
                    ch = n.get("chassis")
                    if not ch:
                        continue
                    if ch.lower() == mac.lower():
                        sysname = n.get("sysname") or "unknown"
                        port = n.get("port") or "unknown-port"
                        note_lines.append(f"LLDP: seen as '{sysname}' on port {port}.")

            dev = Device(
                ip=ip,
                mac=mac,
                hostname=hostname,
                dev_type=dev_type,
                note="\n".join(note_lines)
            )
            devices.append(dev)

        # BONUS: als we LLDP-neighbors hebben die we niet konden koppelen
        # aan een MAC in ip_to_mac, kunnen we ze als 'infra' node toevoegen.
        for n in lldp_neighbors:
            ch = n.get("chassis")
            if not ch:
                continue
            # Staat dit chassis-MAC al als device?
            if any(d.mac.lower() == ch.lower() for d in devices if d.mac):
                continue
            # Voeg een 'switch / infra' device toe zonder IP
            sysname = n.get("sysname") or "LLDP-device"
            port = n.get("port") or "unknown-port"
            note = f"LLDP-only device: {sysname}, port {port} (no IP observed in capture)."
            dev = Device(
                ip="",  # geen IP; komt dan in 'unknown' subnet
                mac=ch.lower(),
                hostname=sysname,
                dev_type="server",  # of 'storage'/'iot' – maar server geeft duidelijk infra-icoon
                note=note
            )
            devices.append(dev)

        return devices


    def build_topology_from_pcap(self, filepath):
        """
        Parseer een PCAP/PCAPNG met scapy en bouw een lijst Device-objecten.
        - ARP: IP <-> MAC
        - IP-verkeer: extra IP's
        - DHCP: DHCP-servers herkennen
        - LLDP (optioneel): switch/router-informatie als notities
        """
        try:
            from scapy.all import rdpcap, ARP, IP, Ether, BOOTP, DHCP
            try:
                # LLDP is optioneel – als niet aanwezig, slaan we LLDP gewoon over
                from scapy.layers.l2 import (
                    LLDPDU,
                    LLDPDUChassisID,
                    LLDPDUPortID,
                    LLDPDUSystemName,
                )
                HAVE_LLDP = True
            except Exception:
                HAVE_LLDP = False
        except ImportError:
            # Wordt door de caller (import_pcap_dialog) opgevangen als ImportError
            raise

        pkts = rdpcap(filepath)

        # --- ARP & IP verzamelen ---
        ip_to_mac = {}    # "192.168.1.10" -> "aa:bb:cc:dd:ee:ff"
        seen_ips = set()

        for p in pkts:
            # ARP
            if p.haslayer(ARP):
                a = p[ARP]
                if a.psrc and a.hwsrc:
                    ip_to_mac[a.psrc] = a.hwsrc.lower()
                    seen_ips.add(a.psrc)
                if a.pdst:
                    seen_ips.add(a.pdst)

            # IP-laag
            if p.haslayer(IP):
                ip_layer = p[IP]
                if ip_layer.src:
                    seen_ips.add(ip_layer.src)
                if ip_layer.dst:
                    seen_ips.add(ip_layer.dst)

        # --- DHCP-informatie (DHCP servers zoeken) ---
        dhcp_servers = set()
        for p in pkts:
            if p.haslayer(BOOTP) and p.haslayer(DHCP):
                bootp = p[BOOTP]
                dhcp = p[DHCP]
                # DHCP options naar dict
                opts = {}
                for opt in dhcp.options:
                    if isinstance(opt, tuple) and len(opt) == 2:
                        k, v = opt
                        opts[k] = v

                mtype = opts.get("message-type", None)
                # bytes -> string
                if isinstance(mtype, bytes):
                    try:
                        mtype = mtype.decode(errors="ignore")
                    except Exception:
                        pass

                # OFFER/ACK → we kunnen hier vaak de server herkennen
                if mtype in ("offer", "ack", 2, 5):
                    # server-ip kan in siaddr zitten of in IP.src
                    server_ip = None
                    if getattr(bootp, "siaddr", None):
                        server_ip = bootp.siaddr
                    elif p.haslayer(IP):
                        server_ip = p[IP].src

                    if server_ip:
                        dhcp_servers.add(server_ip)

        # --- LLDP-informatie (optioneel) ---
        lldp_neighbors = []  # lijst van dicts: {"chassis", "port", "sysname"}
        if HAVE_LLDP:
            for p in pkts:
                if p.haslayer(LLDPDU):
                    chassis = None
                    port = None
                    sysname = None

                    if p.haslayer(LLDPDUChassisID):
                        chassis = getattr(p[LLDPDUChassisID], "id", None)
                    if p.haslayer(LLDPDUPortID):
                        port = getattr(p[LLDPDUPortID], "id", None)
                    if p.haslayer(LLDPDUSystemName):
                        s = getattr(p[LLDPDUSystemName], "system_name", None)
                        if isinstance(s, bytes):
                            try:
                                sysname = s.decode(errors="ignore")
                            except Exception:
                                sysname = str(s)
                        else:
                            sysname = s

                    # chassis-id kan bytes zijn (MAC); maak er een nette string van als mogelijk
                    chassis_str = None
                    if isinstance(chassis, bytes) and len(chassis) in (6, 8):
                        chassis_str = ":".join(f"{b:02x}" for b in chassis)
                    elif isinstance(chassis, str):
                        chassis_str = chassis

                    lldp_neighbors.append({
                        "chassis": chassis_str,
                        "port": port,
                        "sysname": sysname,
                    })

        # --- Devices bouwen ---
        devices = []
        seen_dev_ips = set()

        def is_private(ip):
            # simpele check voor RFC1918 (didactisch genoeg)
            try:
                parts = [int(x) for x in ip.split(".")]
                if len(parts) != 4:
                    return False
                if parts[0] == 10:
                    return True
                if parts[0] == 172 and 16 <= parts[1] <= 31:
                    return True
                if parts[0] == 192 and parts[1] == 168:
                    return True
                return False
            except Exception:
                return False

        for ip in sorted(
            seen_ips,
            key=lambda s: tuple(int(x) for x in s.split(".")) if s.count(".") == 3 else (999,)
        ):
            mac = ip_to_mac.get(ip, "")
            hostname = ""  # kun je later via PTR lookup resolven
            dev_type = self.classify_device(hostname, ip, mac)

            if ip in seen_dev_ips:
                continue
            seen_dev_ips.add(ip)

            note_lines = ["Imported from PCAP capture"]

            # DHCP-server?
            if ip in dhcp_servers:
                note_lines.append("DHCP server detected (from PCAP).")
                # didactisch: maak 'm duidelijk als infra/server
                if dev_type == "client":
                    dev_type = "server"

            # LLDP koppelen: als chassis-id matcht met MAC -> extra notities
            if mac:
                for n in lldp_neighbors:
                    ch = n.get("chassis")
                    if not ch:
                        continue
                    if ch.lower() == mac.lower():
                        sysname = n.get("sysname") or "unknown"
                        port = n.get("port") or "unknown-port"
                        note_lines.append(f"LLDP: seen as '{sysname}' on port {port}.")

            dev = Device(
                ip=ip,
                mac=mac,
                hostname=hostname,
                dev_type=dev_type,
                note="\n".join(note_lines)
            )
            devices.append(dev)

        # BONUS: als we LLDP-neighbors hebben die we niet konden koppelen
        # aan een MAC in ip_to_mac, kunnen we ze als 'infra' node toevoegen.
        for n in lldp_neighbors:
            ch = n.get("chassis")
            if not ch:
                continue
            # Staat dit chassis-MAC al als device?
            if any(d.mac.lower() == ch.lower() for d in devices if d.mac):
                continue
            # Voeg een 'switch / infra' device toe zonder IP
            sysname = n.get("sysname") or "LLDP-device"
            port = n.get("port") or "unknown-port"
            note = f"LLDP-only device: {sysname}, port {port} (no IP observed in capture)."
            dev = Device(
                ip="",  # geen IP; komt dan in 'unknown' subnet
                mac=ch.lower(),
                hostname=sysname,
                dev_type="server",  # of 'storage'/'iot' – maar server geeft duidelijk infra-icoon
                note=note
            )
            devices.append(dev)

        return devices


    def import_pcap_dialog(self):
        """
        Kies een PCAP/PCAPNG bestand en bouw een topology op basis van ARP/IP/DHCP/LLDP uit de capture.
        Daarna: vraag of we 'm meteen als JSON-topology willen opslaan.
        """
        filename = filedialog.askopenfilename(
            title=_tr('ui.source.pcap.importeren.voor.network.map.6afd5764'),
            filetypes=[
                (_tr('ui.source.pcap.files.087583f7'), "*.pcap"),
                (_tr('ui.source.pcap.ng.files.92849252'), "*.pcapng"),
                (_tr('ui.source.all.files.f7857dcc'), "*.*"),
            ]
        )
        if not filename:
            return

        try:
            devices = self.build_topology_from_pcap(filename)
        except ImportError:
            self._mb_error(
                _tr('ui.source.pcap.import.453b9767'),
                _tr('ui.source.de.scapy.runtimecomponent.is.niet.beschikbaar..19e24df5')
            )
            return
        except Exception as e:
            self._mb_error(
                _tr('ui.source.pcap.import.453b9767'),
                _tr('ui.source.fout.bij.uitlezen.van.pcap.p0.8bdb6663',p0=e)
            )
            return

        if not devices:
            self._mb_info(
                _tr('ui.source.pcap.import.453b9767'),
                _tr('ui.source.er.zijn.geen.bruikbare.hosts.gevonden.in.dit.p.bda4c233')
            )
            return

        # Als we hier zijn: lijst Device-objecten teruggekregen
        self.devices = devices
        self.last_traceroute = None
        self.update_device_table()
        self.reset_zoom()
        self.status_label.config(
            text=_tr('ui.source.pcap.import.p0.hosts.uit.capture.geladen.3cd6476b',p0=len(self.devices))
        )

        # BONUS: vraag of we de kaart direct als JSON willen bewaren
        if self._mb_askyesno(
            _tr('ui.source.pcap.import.voltooid.eb23546a'),
            _tr('ui.source.de.topology.is.uit.de.pcap.opgebouwd.wil.je.de.bff89b20')
        ):
            # we gebruiken je bestaande save-logica
            self.file_save_as()


    # ------------- TRACEROUTE FUNCTIES ----------------
    def trace_route_dialog(self):
        """
        Vraagt om een target, draait een systeem-traceroute,
        toont de hops én voegt ze toe aan de topology als 'transit' nodes.
        """
        target = simpledialog.askstring(
            _tr('ui.source.traceroute.5853439a'),
            _tr('ui.source.voer.een.hostnaam.of.ip.adres.in.voor.tracerou.220005cc'),
            parent=self.root
        )
        if not target:
            return

        self.status_label.config(text=_tr('ui.source.start.traceroute.naar.p0.5f90deff',p0=target))
        self.root.update_idletasks()

        def run_traceroute():
            try:
                # Windows vs. *nix
                if sys.platform.startswith("win"):
                    cmd = ["tracert", target]
                else:
                    # -n = geen DNS lookup → sneller & makkelijker te parsen
                    cmd = ["traceroute", "-n", target]

                proc = subprocess.Popen(
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True
                )
                stdout, stderr = proc.communicate()

                hops = self._parse_traceroute_output(stdout)

                # Terug naar GUI-thread om UI te updaten
                self.root.after(0, self._after_traceroute, target, stdout, stderr, hops)

            except subprocess.TimeoutExpired:
                self.root.after(
                    0,
                    lambda: self._mb_error(
                        _tr('ui.source.traceroute.5853439a'),
                        _tr('ui.source.traceroute.naar.p0.duurde.te.lang.en.is.afgebr.1df9afd8',p0=target)
                    )
                )
                self.root.after(0, lambda: self.status_label.config(text=_tr('ui.source.traceroute.timeout.f199f2d4')))
            except Exception as e:
                self.root.after(
                    0,
                    lambda: self._mb_error(_tr('ui.source.traceroute.fout.d7aa5a97'), str(e))
                )
                self.root.after(0, lambda: self.status_label.config(text=_tr('ui.source.traceroute.fout.37354aba')))

        t = threading.Thread(target=run_traceroute, daemon=True)
        t.start()

    def _parse_traceroute_output(self, stdout: str):
        """
        Parseert de tekstuitvoer van tracert/traceroute en geeft een lijst
        terug van dicts: {"hop": nummer, "ip": "x.x.x.x"}.
        Werkt voor typische Windows 'tracert' en Linux 'traceroute -n' output.
        """
        hops = []
        for line in stdout.splitlines():
            line = line.strip()
            if not line:
                continue

            # Zoek hop-nummer
            m_hop = re.match(r"^(\d+)\s+", line)
            if not m_hop:
                continue
            hop_no = int(m_hop.group(1))

            # 1) Probeer [x.x.x.x] (Windows: hostname [IP])
            m_ip_br = re.search(r"\[([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)\]", line)
            if m_ip_br:
                ip = m_ip_br.group(1)
            else:
                # 2) Laatste IP op de regel (Linux: traceroute -n)
                m_ip_end = re.findall(r"([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)", line)
                if m_ip_end:
                    ip = m_ip_end[-1]
                else:
                    ip = None

            if ip:
                hops.append({"hop": hop_no, "ip": ip})

        return hops

    def _after_traceroute(self, target, stdout, stderr, hops):
        """
        UI-update nadat traceroute klaar is (draait in GUI-thread).
        Logt alles in de 'Traceroute log' tab en voegt hops toe aan de topology.
        """
        lines = []
        lines.append("=" * 60)
        lines.append(_tr('ui.source.traceroute.naar.p0.is.voltooid.d9d27711',p0=target))
        lines.append("")

        if hops:
            lines.append(_tr('ui.source.gevonden.hops.2af0afbd'))
            for h in hops:
                lines.append(f"  {h['hop']:2d}: {h['ip']}")
        else:
            lines.append(_tr('ui.source.geen.hops.gevonden.in.de.output.6b6effa0'))

        lines.append("")
        lines.append("Ruwe traceroute-uitvoer:")
        lines.append("-" * 60)
        if stdout.strip():
            lines.extend(stdout.splitlines())
        else:
            lines.append(_tr('ui.source.geen.stdout.7cbedabe'))

        if stderr.strip():
            lines.append("")
            lines.append("stderr:")
            lines.append("-" * 60)
            lines.extend(stderr.splitlines())

        log_text = "\n".join(lines) + "\n"
        self.append_traceroute_log(log_text)

        # Bewaar traceroute-info voor export / hertekenen
        self.last_traceroute = {"target": target, "hops": hops}


        # Hops toevoegen als transit-nodes
        if hops:
            self.add_traceroute_hops_to_devices(hops, target)

        # Statusbalk & optioneel korte popup
        self.status_label.config(text=_tr('ui.source.traceroute.naar.p0.voltooid.zie.tab.traceroute.4169e3de',p0=target))
        # Eventueel een héél kleine info-popup:
        # self._mb_info("Traceroute", f"Traceroute naar {target} voltooid.\nZie tab 'Traceroute log'.")



    def _perform_traceroute_system(self, target):
        """Voer tracert/traceroute uit en parseer hops → lijst met dicts."""
        try:
            if sys.platform.startswith("win"):
                cmd = ["tracert", target]
            else:
                cmd = ["traceroute", target]

            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            stdout, stderr = proc.communicate()
        except subprocess.TimeoutExpired:
            self.root.after(
                0,
                lambda: self._mb_error(
                    _tr('ui.source.traceroute.5853439a'),
                    _tr('ui.source.traceroute.naar.p0.duurde.te.lang.en.is.afgebr.1df9afd8',p0=target)
                )
            )
            return []
        except Exception as e:
            self.root.after(
                0,
                lambda: self._mb_error(_tr('ui.source.traceroute.fout.d7aa5a97'), str(e))
            )
            return []

        hops = []

        # Windows tracert voorbeeld:
        #  1     6 ms     7 ms     8 ms  10.201.8.1
        #  5     *        *        *     Request timed out.
        lines = stdout.splitlines()
        for line in lines:
            raw = line
            line = line.strip()
            if not line:
                continue

            # Windows-achtige regel: begint met hop-nummer
            m = re.match(r"^(\d+)\s+(.+)$", line)
            if m:
                hop_no = int(m.group(1))
                rest = m.group(2)

                # timeout
                if "Request timed out" in rest or rest.strip().startswith("*"):
                    hops.append({"hop": hop_no, "ip": "*", "rtt_ms": None})
                    continue

                # IP vinden
                ip_match = re.search(r"(\d+\.\d+\.\d+\.\d+)", rest)
                ip = ip_match.group(1) if ip_match else None

                # ms-waarden zoeken
                rtts = []
                for tok in rest.split():
                    if "ms" in tok:
                        tok2 = tok.replace("<", "").replace("ms", "")
                        try:
                            rtts.append(float(tok2))
                        except ValueError:
                            pass
                avg = sum(rtts) / len(rtts) if rtts else None

                if ip:
                    hops.append({"hop": hop_no, "ip": ip, "rtt_ms": avg})
                else:
                    # fallback: geen IP gevonden
                    hops.append({"hop": hop_no, "ip": rest.strip(), "rtt_ms": avg})
                continue

            # Simpele Unix-style traceroute parse (niet perfect, maar beter dan niets):
            # 1  host (1.2.3.4)  6.123 ms  7.456 ms  8.789 ms
            mu = re.match(r"^(\d+)\s+(\S+)\s+\((\d+\.\d+\.\d+\.\d+)\)\s+(.+)$", line)
            if mu:
                hop_no = int(mu.group(1))
                ip = mu.group(3)
                rtts = []
                for tok in mu.group(4).split():
                    if tok.endswith("ms"):
                        try:
                            rtts.append(float(tok.replace("ms", "")))
                        except ValueError:
                            pass
                avg = sum(rtts) / len(rtts) if rtts else None
                hops.append({"hop": hop_no, "ip": ip, "rtt_ms": avg})

        return hops

    def _draw_traceroute_overlay(self, router_positions):
        """Teken een verticale keten met hops boven de eerste router (OSINT stijl)."""
        if not self.last_traceroute:
            return
        hops = [h for h in self.last_traceroute.get("hops", []) if h.get("ip")]
        if not hops or not router_positions:
            return

        # Neem de eerste router als anker
        rx0, ry0, dev = router_positions[0]
        anchor_x = rx0 * self.zoom
        router_radius = 25 * self.zoom

        # startpunt net boven de router
        prev_x = anchor_x
        prev_y = (ry0 * self.zoom) - router_radius

        # eerste hop iets boven de router
        start_y = prev_y - 30 * self.zoom
        step = 40 * self.zoom

        for idx, hop in enumerate(hops, start=1):
            hy = start_y - (idx - 1) * step
            hx = anchor_x

            rtt = hop.get("rtt_ms")
            ip = hop.get("ip")

            if rtt is None or ip == "*":
                color = "#e63946"   # rood voor timeout
                emoji = "❌"
            elif rtt < 10:
                color = "#d9ffdb"  # zacht groen
                emoji = "⚡"
            elif rtt < 30:
                color = "#fffac8"  # geel
                emoji = "🟢"
            elif rtt < 70:
                color = "#ffe5b4"  # oranje
                emoji = "🟡"
            elif rtt < 150:
                color = "#ffc4c4"  # licht rood
                emoji = "🟠"
            else:
                color = "#ff7b7b"  # fel rood
                emoji = "🔴"

            hr = 12 * self.zoom
            node_id = self.map_canvas.create_oval(
                hx - hr, hy - hr,
                hx + hr, hy + hr,
                fill=color, outline="black"
            )
            icon_id = self.map_canvas.create_text(
                hx, hy,
                text="🌐" if ip != "*" else "❌",
                font=("Arial", int(11 * self.zoom))
            )

            self.canvas_item_map[node_id] = {"kind": "tr_hop", "hop": hop}
            self.canvas_item_map[icon_id] = {"kind": "tr_hop", "hop": hop}

            # lijn van vorige punt naar deze hop
            line_id = self.map_canvas.create_line(
                prev_x, prev_y,
                hx, hy,
                fill=ROUTER_LINK_COLOR,
                width=2,
                smooth=True
            )
            self.canvas_item_map[line_id] = {"kind": "link", "orig_color": ROUTER_LINK_COLOR}

            prev_x, prev_y = hx, hy

        # label bovenaan
        label_y = start_y - (len(hops)) * step
        self.map_canvas.create_text(
            anchor_x,
            label_y,
            text=_tr('ui.source.traceroute.to.p0.985a9cd1',p0=self.last_traceroute.get('target', '')),
            font=("Arial", int(9 * self.zoom)),
            fill="#444444"
        )

    # ------------- BESTAND-ACTIES ----------------
    def get_topology_dict(self):
        device_rows=[]
        db=self._vulnerability_db()
        for dev in self.devices:
            row=dev.to_dict()
            try: row["vulnerabilities"]=self.find_cves_for_device(dev)
            except Exception: row["vulnerabilities"]=list(getattr(dev,"vulnerabilities",[]) or [])
            try: row["exposures"]=db.analyze_service_exposures(list(getattr(dev,"services",[]) or [])) if db is not None else []
            except Exception: row["exposures"]=[]
            device_rows.append(row)
        topo = {
            "schema":"CAMT.NetMap.FullObservation.1",
            "generated_at":time.strftime("%Y-%m-%dT%H:%M:%S"),
            "range": self.range_var.get(),
            "devices": device_rows,
            "relationships": list(getattr(self, "relationships", []) or []),
            "annotations": self.annotations,
            "zones": self.zones,
        }
        if getattr(self, "last_traceroute", None):
            topo["traceroute"] = self.last_traceroute
        return topo



    def load_topology_dict(self, data):
        if not isinstance(data, dict):
            raise ValueError("Topologiebestand moet een JSON-object bevatten.")
        # Accept direct NetMap topology, CAMT cyber-physical topology and common wrappers.
        for key in ("topology","netmap","network_map","data"):
            wrapped=data.get(key)
            if isinstance(wrapped,dict) and (isinstance(wrapped.get("devices"),list) or isinstance(wrapped.get("assets"),list)):
                data=wrapped
                break
        rows=data.get("devices")
        if not isinstance(rows,list):
            rows=data.get("assets")
        if not isinstance(rows,list):
            raise ValueError("Geen geldige NetMap/CAMT-topologie: veld 'devices' of 'assets' ontbreekt.")
        self.devices = [Device.from_dict(x) for x in rows if isinstance(x,dict)]
        self.relationships = [dict(x) for x in (data.get("relationships") or data.get("relations") or []) if isinstance(x,dict)]
        self.annotations = data.get("annotations", [])
        self.zones = []
        for z in data.get("zones", []) or []:
            if not isinstance(z,dict):
                continue
            nz=dict(z)
            # Support both schemas used by earlier CAMT/NetMap builds:
            #   x1,y1,x2,y2   and   x0,y0,x1,y1
            if "x2" not in nz and "x0" in nz and "x1" in nz:
                nz["x2"]=nz["x1"]
                nz["x1"]=nz["x0"]
            if "y2" not in nz and "y0" in nz and "y1" in nz:
                nz["y2"]=nz["y1"]
                nz["y1"]=nz["y0"]
            if all(k in nz for k in ("x1","y1","x2","y2")):
                if not nz.get("name") and nz.get("label"):
                    nz["name"]=nz["label"]
                if not nz.get("label") and nz.get("name"):
                    nz["label"]=nz["name"]
                self.zones.append(nz)

        ip_range = data.get("range")
        if ip_range:
            self.range_var.set(ip_range)

        # Traceroute info (optioneel)
        self.last_traceroute = data.get("traceroute")
        self.last_traceroute_hops = []
        if self.last_traceroute and "hops" in self.last_traceroute:
            for h in self.last_traceroute["hops"]:
                ip = h.get("ip")
                if not ip:
                    continue
                dev = next((d for d in self.devices if d.ip == ip), None)
                if dev:
                    self.last_traceroute_hops.append((h.get("hop", 0), dev))

        self.update_device_table()
        self.reset_zoom()
        self.status_label.config(
            text=_tr('ui.source.loaded.topology.with.p0.devices.p1.relationshi.e8512fe7',p0=len(self.devices),p1=len(self.relationships),p2=len(self.annotations))
        )


    def file_new(self):
        if self.devices:
            if not self._mb_askyesno(_tr('ui.source.nieuw.8762a532'), _tr('ui.source.huidige.topologie.verwerpen.en.nieuw.beginnen.a737a401')):
                return
        self.devices = []
        self.relationships = []
        self.current_file = None
        self.last_traceroute = None
        self.update_device_table()
        self.map_canvas.delete("all")
        self.status_label.config(text=_tr('ui.source.new.empty.topology.a21d918e'))
        self.range_var.set("192.168.1.0/24")

    def file_open(self):
        filename = filedialog.askopenfilename(
            title=_tr('ui.source.open.topology.file.1e0c758a'),
            filetypes=[(_tr('ui.source.json.files.f39e4bde'), "*.json"), (_tr('ui.source.all.files.f7857dcc'), "*.*")]
        )
        if not filename:
            return
        try:
            with open(filename, "r", encoding="utf-8") as f:
                data = json.load(f)
            self.current_file = filename
            self.load_topology_dict(data)
        except json.JSONDecodeError as e:
            self._mb_error(_tr('ui.source.open.error.c5b7e40b'), _tr('ui.source.geen.geldig.json.bestand.p0.ae49e9df',p0=e))
        except Exception as e:
            self._mb_error(_tr('ui.source.open.error.c5b7e40b'), _tr('ui.source.could.not.open.file.p0.p1.0f0b2161',p0=type(e).__name__,p1=e))

    def file_save(self):
        if not self.current_file:
            self.file_save_as()
            return
        try:
            data = self.get_topology_dict()
            with open(self.current_file, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2)
            self.status_label.config(text=_tr('ui.source.saved.to.p0.ff885d60',p0=self.current_file))
        except Exception as e:
            self._mb_error(_tr('ui.source.save.error.0d80db17'), _tr('ui.source.could.not.save.file.p0.d6f39cab',p0=e))

    def file_save_as(self):
        filename = filedialog.asksaveasfilename(
            title=_tr('ui.source.save.topology.as.9e3cbf75'),
            defaultextension=".json",
            filetypes=[(_tr('ui.source.json.files.f39e4bde'), "*.json"), (_tr('ui.source.all.files.f7857dcc'), "*.*")]
        )
        if not filename:
            return
        self.current_file = filename
        self.file_save()

    def file_print(self):
        if not self.devices:
            self._mb_info(_tr('ui.source.afdrukken.3da0d6dd'), _tr('ui.source.geen.devices.om.af.te.drukken.5c27b3c2'))
            return

        report = self.build_text_report()

        try:
            fd, path = tempfile.mkstemp(suffix=".txt", prefix="netmap_")
            with os.fdopen(fd, "w", encoding="utf-8") as tmp:
                tmp.write(report)

            if sys.platform.startswith("win"):
                try:
                    os.startfile(path, "print")  # type: ignore[attr-defined]
                    self._mb_info(
                        _tr('ui.source.afdrukken.3da0d6dd'),
                        "Rapport naar het standaard printproces gestuurd.\n"
                        "Indien niets gebeurt, open het bestand handmatig:\n" + path
                    )
                except Exception:
                    os.startfile(path)  # type: ignore[attr-defined]
                    self._mb_info(
                        _tr('ui.source.afdrukken.3da0d6dd'),
                        _tr('ui.source.kon.direct.printen.niet.starten.het.rapport.is.77688c32')
                    )
            else:
                webbrowser.open(f"file://{path}")
                self._mb_info(
                    _tr('ui.source.afdrukken.3da0d6dd'),
                    _tr('ui.source.rapport.geopend.in.de.standaard.editor.print.v.a291097d')
                )
        except Exception as e:
            self._mb_error(_tr('ui.source.print.error.f140be11'), _tr('ui.source.kon.rapport.niet.afdrukken.p0.9bbf5f81',p0=e))

    def file_send(self):
        if not self.devices:
            self._mb_info(_tr('ui.source.verzenden.18802582'), _tr('ui.source.geen.devices.om.te.verzenden.c358f5be'))
            return

        report = self.build_text_report()

        import urllib.parse
        subject = "Network topology report"
        body = report
        mailto = f"mailto:?subject={urllib.parse.quote(subject)}&body={urllib.parse.quote(body)}"

        try:
            webbrowser.open(mailto)
            self._mb_info(
                _tr('ui.source.verzenden.18802582'),
                _tr('ui.source.standaard.mailprogramma.geopend.met.rapport.in.8fe98c5a')
            )
        except Exception as e:
            self._mb_error(_tr('ui.source.verzenden.18802582'), _tr('ui.source.kon.mailclient.niet.openen.p0.9d7f5503',p0=e))

    def build_text_report(self):
        lines = []
        lines.append("Network topology report")
        lines.append("=======================")
        lines.append(f"IP range: {self.range_var.get()}")
        lines.append("")
        lines.append("Devices:")
        for d in self.devices:
            lines.append(f"- IP: {d.ip}")
            lines.append(f"  MAC: {d.mac}")
            lines.append(f"  Hostname: {d.hostname or '-'}")
            lines.append(f"  Type: {d.dev_type}")
            if d.note:
                lines.append("  Note:")
                for ln in d.note.splitlines():
                    lines.append(f"    {ln}")
            if d.ports_summary:
                lines.append(f"  Ports: {d.ports_summary}")
            lines.append("")
        return "\n".join(lines)

    # ------------- OVERIGE GUI ----------------
    def create_widgets(self):
        top_frame = ttk.LabelFrame(self.root, text=_tr('ui.source.network.scan.options.766999f1'))
        top_frame.pack(fill="x", padx=10, pady=10)

        ttk.Label(top_frame, text=_tr('ui.source.ip.range.voor.netdiscover.0315fbbc')).grid(
            row=0, column=0, padx=5, pady=5, sticky="w"
        )
        self.range_var = tk.StringVar(value=_tr('ui.source.192.168.1.0.24.8c010caa'))
        self.range_entry = ttk.Entry(top_frame, textvariable=self.range_var, width=20)
        self.range_entry.grid(row=0, column=1, padx=5, pady=5, sticky="w")

        ttk.Label(top_frame, text=_tr('ui.source.scan.method.0b9ca3b7')).grid(
            row=0, column=2, padx=5, pady=5, sticky="e"
        )
        self.method_var = tk.StringVar(value=_tr('ui.source.auto.0d612c12'))
        method_combo = ttk.Combobox(
            top_frame,
            textvariable=self.method_var,
            values=["auto", "netdiscover", "arp"],
            state="readonly",
            width=12
        )
        method_combo.grid(row=0, column=3, padx=5, pady=5, sticky="w")

        scan_btn = ttk.Button(top_frame, text=_tr('ui.source.scan.network.32c9563f'), command=self.open_scan_wizard)
        scan_btn.grid(row=0, column=4, padx=5, pady=5)

        top_frame.columnconfigure(1, weight=1)
        
                # Interface selectie (voor ARP / netdiscover)
        ttk.Label(top_frame, text=_tr('ui.source.interface.d771152a')).grid(
            row=1, column=0, padx=5, pady=5, sticky="w"
        )

        iface_values = self._interface_display_values()

        iface_combo = ttk.Combobox(
            top_frame,
            textvariable=self.iface_var,
            values=iface_values,
            state="readonly",
            width=40
        )
        iface_combo.grid(row=1, column=1, columnspan=2, padx=5, pady=5, sticky="ew")
        self.iface_combo=iface_combo
        iface_combo.set(self.iface_var.get() or "auto")
        iface_combo.bind("<<ComboboxSelected>>", self._on_interface_selected)
        ttk.Button(top_frame,text="Refresh interfaces",command=self.refresh_interface_list).grid(row=1,column=3,padx=5,pady=5,sticky="w")
        ttk.Button(top_frame,text="Guided analysis",command=self.open_guided_network_analysis).grid(row=1,column=4,columnspan=2,padx=5,pady=5,sticky="ew")

        progress_frame=ttk.LabelFrame(self.root,text=_tr('ui.source.discovery.progress.d61e1896'))
        progress_frame.pack(fill="x",padx=10,pady=(0,6))
        self.scan_progress_var=tk.DoubleVar(value=0)
        self.scan_counter_var=tk.StringVar(value=_tr('ui.source.0.0.fec80cfd'))
        self.scan_percent_var=tk.StringVar(value=_tr('ui.source.0.433bdb13'))
        self.scan_found_var=tk.StringVar(value=_tr('ui.source.0.hosts.2e4cc8ae'))
        self.scan_elapsed_var=tk.StringVar(value=_tr('ui.source.00.00.22441e75'))
        self.scan_progress=ttk.Progressbar(progress_frame,variable=self.scan_progress_var,maximum=1)
        self.scan_progress.grid(row=0,column=0,columnspan=5,sticky="ew",padx=8,pady=(7,4))
        ttk.Label(progress_frame,text=_tr('ui.source.progress.04866c75')).grid(row=1,column=0,sticky="e",padx=(8,2),pady=(0,6))
        ttk.Label(progress_frame,textvariable=self.scan_counter_var,width=22).grid(row=1,column=1,sticky="w",pady=(0,6))
        ttk.Label(progress_frame,textvariable=self.scan_percent_var,width=7).grid(row=1,column=2,sticky="w",pady=(0,6))
        ttk.Label(progress_frame,textvariable=self.scan_found_var,width=12).grid(row=1,column=3,sticky="w",pady=(0,6))
        ttk.Label(progress_frame,textvariable=self.scan_elapsed_var,width=8).grid(row=1,column=4,sticky="w",pady=(0,6))
        progress_frame.columnconfigure(0,weight=1)

        self.scan_btn=scan_btn
        self.stop_scan_btn=ttk.Button(top_frame,text=_tr('ui.source.stop.scan.daa09910'),command=self.stop_network_scan,state="disabled")
        self.stop_scan_btn.grid(row=0,column=5,padx=5,pady=5)

        self.status_label = ttk.Label(self.root, text=_tr('ui.source.ready.a0d73bcd'))
        self.status_label.pack(fill="x", padx=10)

        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill="both", expand=True, padx=10, pady=10)

        self.device_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.device_frame, text=_tr('ui.source.devices.list.cc26ac32'))
        self.create_device_table(self.device_frame)

        self.map_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.map_frame, text=_tr('ui.source.network.map.a16ce3d5'))
        self.create_map_canvas(self.map_frame)

        # --- NIEUW: Traceroute log tab ---
        self.traceroute_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.traceroute_frame, text=_tr('ui.source.traceroute.log.0306d180'))

        self.traceroute_text = tk.Text(self.traceroute_frame, wrap="word")
        self.traceroute_text.pack(fill="both", expand=True)
        self.traceroute_text.configure(state="disabled")  # read-only

    def append_traceroute_log(self, text: str):
        """Append tekst aan de Traceroute-logtab (als die bestaat)."""
        if not hasattr(self, "traceroute_text"):
            return
        self.traceroute_text.configure(state="normal")
        self.traceroute_text.insert("end", text + "\n")
        self.traceroute_text.see("end")
        self.traceroute_text.configure(state="disabled")



    def _enable_tree_sorting(self, tree):
        state={"column":None,"reverse":False}
        def sort_column(column):
            reverse=(state["column"]==column and not state["reverse"])
            state["column"]=column;state["reverse"]=reverse
            def key(iid):
                value=tree.item(iid,"text") if column=="#0" else tree.set(iid,column)
                text=str(value or "").strip()
                try:return (0,int(ipaddress.ip_address(text.split("/",1)[0])))
                except Exception:pass
                try:return (1,float(text.replace("%","").replace(",",".")))
                except Exception:return (2,text.lower())
            children=list(tree.get_children(""))
            children.sort(key=key,reverse=reverse)
            for pos,iid in enumerate(children):tree.move(iid,"",pos)
            for c in tree["columns"]:
                base=str(tree.heading(c).get("text") or "").replace(" ▲","").replace(" ▼","")
                tree.heading(c,text=base)
            base=str(tree.heading(column).get("text") or "").replace(" ▲","").replace(" ▼","")
            tree.heading(column,text=base+(" ▼" if reverse else " ▲"))
        for column in tree["columns"]:
            tree.heading(column,command=lambda c=column:sort_column(c))

    def create_device_table(self, parent):
        columns = ("ip", "mac", "hostname", "type", "status", "note", "ports")
        self.device_tree = ttk.Treeview(parent, columns=columns, show="headings")
        self.device_tree.heading("ip", text=_tr('ui.source.ip.address.99a1caa5'))
        self.device_tree.heading("mac", text=_tr('ui.source.mac.address.9f9d1a2b'))
        self.device_tree.heading("hostname", text=_tr('ui.source.hostname.c983a155'))
        self.device_tree.heading("type", text=_tr('ui.source.type.3deb7456'))
        self.device_tree.heading("status", text=_tr('ui.source.status.bae7d5be'))
        self.device_tree.heading("note", text=_tr('ui.source.note.services.location.4b5e1886'))
        self.device_tree.heading("ports", text=_tr('ui.source.ports.scan.result.03c89b01'))

        self.device_tree.column("ip", width=140)
        self.device_tree.column("mac", width=170)
        self.device_tree.column("hostname", width=180)
        self.device_tree.column("type", width=100)
        self.device_tree.column("status", width=110)
        self.device_tree.column("note", width=260)
        self.device_tree.column("ports", width=220)

        # Grid is intentional here. The previous pack order let the expanding
        # Treeview claim the notebook cavity before the port-scan controls were
        # laid out, so the lowest action rows could disappear below a laptop
        # screen. Rows 1 and 2 are now always reserved for controls.
        parent.columnconfigure(0, weight=1)
        parent.rowconfigure(0, weight=1)
        self.device_tree.grid(row=0, column=0, sticky="nsew", padx=(0,0), pady=(0,0))

        scrollbar = ttk.Scrollbar(parent, orient="vertical", command=self.device_tree.yview)
        scrollbar.grid(row=0, column=1, sticky="ns")
        self.device_tree.configure(yscrollcommand=scrollbar.set)

        self.device_tree.bind("<Double-1>", self.on_device_double_click)
        self._enable_tree_sorting(self.device_tree)

        # Add/Delete
        ctrl_frame = ttk.Frame(parent)
        ctrl_frame.grid(row=1, column=0, columnspan=2, sticky="ew", padx=5, pady=(5, 0))

        add_btn = ttk.Button(ctrl_frame, text=_tr('ui.source.add.device.2d2367c4'), command=self.add_device_dialog)
        add_btn.pack(side="left", padx=(0, 5))

        del_btn = ttk.Button(ctrl_frame, text=_tr('ui.source.delete.selected.8516a714'), command=self.delete_selected_device)
        del_btn.pack(side="left")

        # Portscan blok
        bottom_frame = ttk.LabelFrame(parent, text=_tr('ui.source.port.scan.options.nmap.ff97ffc5'))
        bottom_frame.grid(row=2, column=0, columnspan=2, sticky="ew", pady=5, padx=5)
        bottom_frame.columnconfigure(1, weight=1)

        proto_frame = ttk.Frame(bottom_frame)
        proto_frame.grid(row=0, column=0, rowspan=2, sticky="nw", padx=5, pady=5)
        ttk.Label(proto_frame, text=_tr('ui.source.protocol.c4bba733')).pack(anchor="w")
        ttk.Radiobutton(proto_frame, text=_tr('ui.source.tcp.f544fb30'), variable=self.scan_proto_var, value=_tr('ui.source.tcp.6ce375e3')).pack(anchor="w")
        ttk.Radiobutton(proto_frame, text=_tr('ui.source.udp.e9a6f622'), variable=self.scan_proto_var, value=_tr('ui.source.udp.36cf8bee')).pack(anchor="w")
        ttk.Radiobutton(proto_frame, text=_tr('ui.source.tcp.udp.8d723031'), variable=self.scan_proto_var, value=_tr('ui.source.tcp.udp.c76ef8fc')).pack(anchor="w")

        ports_frame = ttk.Frame(bottom_frame)
        ports_frame.grid(row=0, column=1, sticky="nw", padx=5, pady=5)

        ttk.Label(ports_frame, text=_tr('ui.source.ports.5bbb411e')).grid(row=0, column=0, sticky="w")
        ports_entry = ttk.Entry(ports_frame, textvariable=self.scan_ports_var, width=30)
        ports_entry.grid(row=0, column=1, padx=5, pady=2, sticky="w")

        ttk.Label(
            ports_frame,
            text=_tr('ui.source.gebruik.top.20.of.bv.1.1024.of.22.80.443.2894bbea')
        ).grid(row=1, column=0, columnspan=2, sticky="w")
        ttk.Checkbutton(
            ports_frame,
            text=_tr('ui.source.snelle.2.fasenstrategie.bij.grote.ranges.eerst.dfb5e50b'),
            variable=self.scan_optimized_var
        ).grid(row=2,column=0,columnspan=3,sticky="w",pady=(5,2))
        ttk.Label(ports_frame,text=_tr('ui.source.extra.nmap.parameters.a389aeed')).grid(row=3,column=0,sticky="w")
        ttk.Entry(ports_frame,textvariable=self.scan_nmap_params_var,width=52).grid(
            row=3,column=1,columnspan=2,padx=5,sticky="ew"
        )
        ttk.Label(
            ports_frame,
            text=_tr('ui.source.bijv.t4.max.retries.2.version.intensity.7.poor.eaff11e9')
        ).grid(row=4,column=0,columnspan=3,sticky="w")

        scan_btn = ttk.Button(
            bottom_frame,
            text=_tr('ui.source.port.scan.selected.host.ebd1d5ee'),
            command=self.port_scan_selected
        )
        bulk_scan_btn = ttk.Button(bottom_frame,text=_tr('ui.source.scan.gevonden.hosts.afad39f2'),command=self.scan_discovered_hosts)
        
        
        cve_btn = ttk.Button(
            bottom_frame,
            text=_tr('ui.source.show.cves.for.selected.host.d84130d4'),
            command=self.show_cves_for_selected
        )
        cve_btn.grid(row=1, column=2, sticky="w", padx=5, pady=(0, 5))

        
        scan_btn.grid(row=1, column=1, sticky="w", padx=5, pady=(0, 5))
        bulk_scan_btn.grid(row=2,column=1,sticky="w",padx=5,pady=(0,5))
        ttk.Button(bottom_frame,text=_tr('ui.source.vulnerability.analysis.416476bf'),command=self.run_vulnerability_analysis).grid(row=2,column=2,sticky="w",padx=5,pady=(0,5))
        ttk.Button(bottom_frame,text=_tr('ui.source.analyse.advies.457bf415'),command=self.run_analysis_advice).grid(row=3,column=2,sticky="w",padx=5,pady=(0,5))

    def create_map_canvas(self, parent):
        control_frame = ttk.Frame(parent)
        control_frame.pack(fill="x", pady=5)

        redraw_btn = ttk.Button(control_frame, text=_tr('ui.source.redraw.map.21b1775d'), command=self.draw_network_map)
        redraw_btn.pack(side="left", padx=5)

        self.map_node_size_var = tk.StringVar(value=_tr('ui.source.auto.c614ba7c'))
        ttk.Label(control_frame,text=_tr('ui.source.node.2eac7522')).pack(side="left",padx=(8,2))
        node_size_combo=ttk.Combobox(control_frame,textvariable=self.map_node_size_var,
            values=[_tr('ui.source.auto.c614ba7c'),_tr('netmap.node.mini'),_tr('netmap.node.small'),_tr('netmap.node.normal'),_tr('netmap.node.large')],state="readonly",width=9)
        node_size_combo.pack(side="left",padx=3)
        node_size_combo.bind("<<ComboboxSelected>>",lambda _e:self.draw_network_map())

        self.map_node_style_var=tk.StringVar(value=_tr('ui.source.compact.1df39aa5'))
        ttk.Label(control_frame,text=_tr('ui.source.stijl.24de4a05')).pack(side="left",padx=(8,2))
        style_combo=ttk.Combobox(control_frame,textvariable=self.map_node_style_var,
            values=[_tr('netmap.style.compact'),_tr('netmap.style.card'),_tr('netmap.style.ring')],state="readonly",width=9)
        style_combo.pack(side="left",padx=3)
        style_combo.bind("<<ComboboxSelected>>",lambda _e:self.draw_network_map())

        ttk.Button(control_frame,text=_tr('ui.source.fit.dab564d8'),command=self.fit_network_map).pack(side="left",padx=4)

        ttk.Label(control_frame,text="Find:").pack(side="left",padx=(8,2))
        topo_search=ttk.Entry(control_frame,textvariable=self.topology_search_var,width=16)
        topo_search.pack(side="left",padx=2)
        topo_search.bind("<Return>",lambda _e:self.draw_network_map())
        ttk.Button(control_frame,text="Apply",command=self.draw_network_map).pack(side="left",padx=2)
        ttk.Label(control_frame,text="Relations:").pack(side="left",padx=(8,2))
        rel_combo=ttk.Combobox(control_frame,textvariable=self.topology_relation_filter_var,
            values=["All","Observed","Routed","Inferred"],state="readonly",width=9)
        rel_combo.pack(side="left",padx=2)
        rel_combo.bind("<<ComboboxSelected>>",lambda _e:self.draw_network_map())

        reset_highlights_btn = ttk.Button(control_frame, text=_tr('ui.source.reset.highlights.b6e1c6ca'), command=self.reset_link_colors)
        reset_highlights_btn.pack(side="left", padx=5)

        self.show_labels_var = tk.BooleanVar(value=True)
        show_labels_check = ttk.Checkbutton(
            control_frame,
            text=_tr('ui.source.show.labels.notes.db34a1b2'),
            variable=self.show_labels_var,
            command=self.draw_network_map
        )
        show_labels_check.pack(side="left", padx=5)

        # Professional topology tools, aligned with Network Visualisation.
        visual_frame = ttk.LabelFrame(parent, text="Topology tools")
        visual_frame.pack(fill="x", padx=5, pady=(0, 5))
        ttk.Button(visual_frame, text="Select", command=lambda:self._set_topology_tool("select")).pack(side="left", padx=2)
        ttk.Button(visual_frame, text="Connect", command=lambda:self._set_topology_tool("connect")).pack(side="left", padx=2)
        ttk.Button(visual_frame, text="Duplicate", command=self._duplicate_topology_selected).pack(side="left", padx=2)
        ttk.Button(visual_frame, text="Delete", command=self._delete_topology_selected).pack(side="left", padx=2)
        ttk.Button(visual_frame, text="Crown Jewel", command=self._toggle_crown_selected).pack(side="left", padx=2)
        ttk.Button(visual_frame, text="Inspector", command=self._open_topology_inspector).pack(side="left", padx=2)
        ttk.Separator(visual_frame, orient="vertical").pack(side="left", fill="y", padx=5)
        ttk.Label(visual_frame, text="Layout").pack(side="left", padx=(2,2))
        layout_box=ttk.Combobox(visual_frame,textvariable=self.topology_layout_var,state="readonly",width=13,values=["Grid","Circle","Hierarchical","Force-directed","Zones"])
        layout_box.pack(side="left",padx=2)
        ttk.Button(visual_frame,text="Apply",command=self._apply_topology_layout).pack(side="left",padx=2)
        ttk.Label(visual_frame,text="Layer").pack(side="left",padx=(8,2))
        layer_box=ttk.Combobox(visual_frame,textvariable=self.topology_layer_var,state="readonly",width=10,values=["All","Physical","Logical","Security","OT/ICS","Scenario"])
        layer_box.pack(side="left",padx=2); layer_box.bind("<<ComboboxSelected>>",lambda _e:self.draw_network_map())
        ttk.Checkbutton(visual_frame,text="Grid",variable=self.topology_show_grid_var,command=self.draw_network_map).pack(side="left",padx=4)
        ttk.Checkbutton(visual_frame,text="Snap",variable=self.topology_snap_grid_var).pack(side="left",padx=4)
        ttk.Checkbutton(visual_frame,text="Zones",variable=self.topology_show_zones_var,command=self.draw_network_map).pack(side="left",padx=4)


#===========================

        # --- NIEUW: annotatie-toolbar (boven de kaart) ---
        anno_frame = ttk.LabelFrame(parent, text=_tr('ui.source.annotations.zones.2c7282dc'))
        anno_frame.pack(fill="x", padx=5, pady=(0, 5))

        # --- Notes ---
        ttk.Label(anno_frame, text=_tr('ui.source.note.text.e9218178')).pack(side="left", padx=(5, 2))
        self.anno_text_var = tk.StringVar()
        anno_entry = ttk.Entry(anno_frame, textvariable=self.anno_text_var, width=25)
        anno_entry.pack(side="left", padx=(0, 5))

        ttk.Label(anno_frame, text=_tr('ui.source.note.color.01674206')).pack(side="left", padx=(10, 2))
        self.anno_color_var = tk.StringVar(value=_tr('ui.source.yellow.96de5543'))
        color_combo = ttk.Combobox(
            anno_frame,
            textvariable=self.anno_color_var,
            state="readonly",
            width=10,
            values=["yellow", "lightblue", "lightgreen", "pink", "orange"]
        )
        color_combo.pack(side="left", padx=(0, 5))
        color_combo.set("yellow")

        ttk.Label(anno_frame, text=_tr('ui.source.shape.14edb2c4')).pack(side="left", padx=(10, 2))
        self.anno_shape_var = tk.StringVar(value=_tr('ui.source.rect.c6731fb7'))
        shape_combo = ttk.Combobox(
            anno_frame,
            textvariable=self.anno_shape_var,
            state="readonly",
            width=8,
            values=["rect", "oval"]
        )
        shape_combo.pack(side="left", padx=(0, 5))
        shape_combo.set("rect")

        place_btn = ttk.Button(anno_frame, text=_tr('ui.source.place.note.dc609520'), command=self.start_place_annotation)
        place_btn.pack(side="left", padx=10)

        clear_btn = ttk.Button(anno_frame, text=_tr('ui.source.clear.notes.0a0a8523'), command=self.clear_annotations)
        clear_btn.pack(side="left", padx=(0, 5))

        # --- Zones (DMZ / Intranet / Extranet) ---
        # --- Zone controls in dezelfde balk ---
        ttk.Label(anno_frame, text=_tr('ui.source.zone.label.e12c1984')).pack(side="left", padx=(20, 2))
        self.zone_label_var = tk.StringVar(value=_tr('ui.source.dmz.138a224d'))
        zone_label_entry = ttk.Entry(anno_frame, textvariable=self.zone_label_var, width=10)
        zone_label_entry.pack(side="left", padx=(0, 5))

        ttk.Label(anno_frame, text=_tr('ui.source.zone.type.3ac6145d')).pack(side="left", padx=(5, 2))
        self.zone_type_var = tk.StringVar(value=_tr('ui.source.dmz.e0642f18'))
        zone_type_combo = ttk.Combobox(
            anno_frame,
            textvariable=self.zone_type_var,
            state="readonly",
            width=10,
            values=["dmz", "intranet", "extranet", "untrusted", "other"]
        )
        zone_type_combo.pack(side="left", padx=(0, 5))
        zone_type_combo.set("dmz")

        draw_zone_btn = ttk.Button(anno_frame, text=_tr('ui.source.draw.zone.c901f2e6'), command=self.start_zone_mode)
        draw_zone_btn.pack(side="left", padx=(5, 2))

        clear_zones_btn = ttk.Button(anno_frame, text=_tr('ui.source.clear.zones.70f699a4'), command=self.clear_zones)
        clear_zones_btn.pack(side="left", padx=(0, 5))



#===============================
        zoom_in_btn = ttk.Button(control_frame, text=_tr('ui.source.zoom.d4b1cb4c'), command=lambda: self.change_zoom(1.2))
        zoom_in_btn.pack(side="right", padx=5)
        zoom_out_btn = ttk.Button(control_frame, text=_tr('ui.source.zoom.e1d87673'), command=lambda: self.change_zoom(1 / 1.2))
        zoom_out_btn.pack(side="right", padx=5)
        reset_zoom_btn = ttk.Button(control_frame, text=_tr('ui.source.reset.zoom.e5737972'), command=self.reset_zoom)
        reset_zoom_btn.pack(side="right", padx=5)

        # Network Visualisation parity: Asset Library | topology canvas | Inspector.
        editor = ttk.Panedwindow(parent, orient="horizontal")
        editor.pack(fill="both", expand=True, padx=5, pady=(0, 3))
        self.topology_palette = ttk.Frame(editor, padding=(4,4))
        canvas_host = ttk.Frame(editor)
        self.topology_inspector = ttk.Frame(editor, padding=(7,4))
        editor.add(self.topology_palette, weight=1)
        editor.add(canvas_host, weight=6)
        editor.add(self.topology_inspector, weight=2)
        self._build_topology_asset_library(self.topology_palette)
        self._build_topology_inspector_panel(self.topology_inspector)

        canvas_frame = ttk.Frame(canvas_host)
        canvas_frame.pack(fill="both", expand=True)
        self.map_canvas = tk.Canvas(canvas_frame, bg="#fbfdff", highlightthickness=1, highlightbackground="#cbd5e1")
        self.map_canvas.pack(side="left", fill="both", expand=True)
        y_scroll = ttk.Scrollbar(canvas_frame, orient="vertical", command=self.map_canvas.yview)
        y_scroll.pack(side="right", fill="y")
        x_scroll = ttk.Scrollbar(canvas_host, orient="horizontal", command=self.map_canvas.xview)
        x_scroll.pack(fill="x")
        self.map_canvas.configure(yscrollcommand=y_scroll.set, xscrollcommand=x_scroll.set)

        self.map_canvas.bind("<Control-MouseWheel>", self.on_ctrl_mousewheel)
        self.map_canvas.bind("<Control-Button-4>", self.on_ctrl_mousewheel_linux)
        self.map_canvas.bind("<Control-Button-5>", self.on_ctrl_mousewheel_linux)

        # Slepen / klikken
        self.map_canvas.bind("<ButtonPress-1>", self.on_canvas_button_press)
        self.map_canvas.bind("<B1-Motion>", self.on_canvas_mouse_drag)
        self.map_canvas.bind("<ButtonRelease-1>", self.on_canvas_button_release)

        # Dubbelklik: info / notes
        self.map_canvas.bind("<Double-1>", self.on_canvas_left_click)

        # Rechterklik: highlight link (attack path)
        self.map_canvas.bind("<Button-3>", self.on_canvas_right_click)
        # Middle-button pan leaves left-drag node movement and right-click
        # relationship highlighting unchanged.
        self.map_canvas.bind("<ButtonPress-2>", self._topology_pan_start)
        self.map_canvas.bind("<B2-Motion>", self._topology_pan_move)
        self.root.bind("<Control-d>", lambda _e:self._duplicate_topology_selected())
        self.root.bind("<Control-l>", lambda _e:self._set_topology_tool("connect"))
        self.root.bind("<Delete>", lambda _e:self._delete_topology_selected())

    def _topology_pan_start(self,event):
        self.map_canvas.scan_mark(event.x,event.y)

    def _topology_pan_move(self,event):
        self.map_canvas.scan_dragto(event.x,event.y,gain=1)

    def _map_node_scale(self):
        count=max(1,len(self.devices))
        choice=self.map_node_size_var.get() if hasattr(self,"map_node_size_var") else "Auto"
        return {
            "Mini":.30,"Klein":.44,"Small":.44,"Normaal":.62,"Normal":.62,"Groot":.82,"Large":.82
        }.get(choice, .60 if count<=10 else .44 if count<=25 else .32 if count<=50 else .27 if count<=100 else .23)

    def _map_label_detail(self):
        count=len(self.devices)
        choice=self.map_node_size_var.get() if hasattr(self,"map_node_size_var") else "Auto"
        if choice=="Mini": return 0
        if choice in ("Klein","Small"): return 1
        if choice in ("Normaal","Normal","Groot","Large"): return 2
        return 2 if count<=12 else 1 if count<=30 else 0

    def fit_network_map(self):
        n=len(self.devices)
        self.zoom=max(.25,min(1.0,1.0 if n<=12 else .72 if n<=30 else .52 if n<=60 else .38))
        self.draw_network_map()

    # ------------- ZOOM FUNCTIES ----------------
    def change_zoom(self, factor):
        new_zoom = self.zoom * factor
        if new_zoom < 0.20 or new_zoom > 4.0:
            return
        self.zoom = new_zoom
        self.draw_network_map()

    def reset_zoom(self):
        self.zoom = 1.0
        self.draw_network_map()

    def on_ctrl_mousewheel(self, event):
        if event.delta > 0:
            self.change_zoom(1.1)
        else:
            self.change_zoom(1 / 1.1)

    def on_ctrl_mousewheel_linux(self, event):
        if event.num == 4:
            self.change_zoom(1.1)
        elif event.num == 5:
            self.change_zoom(1 / 1.1)


    def start_place_annotation(self):
        text = (self.anno_text_var.get() or "").strip()
        if not text:
            self._mb_warning(_tr('ui.source.annotation.de3b78b6'), _tr('ui.source.voer.eerst.tekst.in.voor.de.note.357f3b05'))
            return
        self.annotation_mode = True
        self.status_label.config(
            text=_tr('ui.source.annotatie.modus.klik.op.de.kaart.waar.de.note..69089f05')
        )

    def clear_annotations(self):
        if not self.annotations:
            return
        if not self._mb_askyesno(_tr('ui.source.annotations.74dc68d7'), _tr('ui.source.alle.notes.van.de.kaart.verwijderen.812c772a')):
            return
        self.annotations = []
        self.draw_network_map()
        self.status_label.config(text=_tr('ui.source.alle.annotaties.verwijderd.c2d0fd15'))


    def start_zone_mode(self):
        """
        Start modus om een zone te tekenen: eerste klik = beginpunt,
        tweede klik = tegenoverliggende hoek.
        """
        self.zone_mode = True
        self.zone_temp_start = None
        self.status_label.config(
            text=_tr('ui.source.zone.modus.klik.eerste.hoek.van.de.zone.op.de..920ef8c6')
        )

    def clear_zones(self):
        
        dialog = tk.Toplevel(self.root)
        dialog.title(_tr('ui.source.add.zone.a06cebbd'))

        # X/Y/W/H
        x1_var = tk.StringVar()
        y1_var = tk.StringVar()
        x2_var = tk.StringVar()
        y2_var = tk.StringVar()
        color_var = tk.StringVar(value=_tr('ui.source.a0c8ff.ee4b9ff4'))
        if not self.zones:
            return
        if not self._mb_askyesno(_tr('ui.source.zones.182e2eb7'), _tr('ui.source.alle.zones.dmz.intranet.extranet.verwijderen.87cd2db6')):
            return
        self.zones = []
        self.draw_network_map()
        self.status_label.config(text=_tr('ui.source.alle.zones.verwijderd.45318042'))


    def add_zone(self):
        """
        Voeg een 'zone' toe (DMZ / Intranet / Extranet etc.) als
        een gekleurde achtergrond-rechthoek op de map.

        Coördinaten zijn in dezelfde logische eenheden als de kaart:
        neem bijvoorbeeld eerst iets als x1=0, y1=300, x2=1000, y2=700
        en stem het daarna af.
        """
        dialog = tk.Toplevel(self.root)
        dialog.title(_tr('ui.source.add.zone.0279d731'))
        dialog.geometry("360x260")
        dialog.transient(self.root)
        dialog.grab_set()

        frame = ttk.Frame(dialog)
        frame.pack(fill="both", expand=True, padx=10, pady=10)

        # Naam
        ttk.Label(frame, text=_tr('ui.source.naam.bijv.dmz.intranet.ca149318')).grid(row=0, column=0, sticky="w")
        name_var = tk.StringVar(value=_tr('ui.source.dmz.138a224d'))
        name_entry = ttk.Entry(frame, textvariable=name_var, width=25)
        name_entry.grid(row=0, column=1, sticky="w", pady=3)

        # Kleur (simpele preset-lijst)
        ttk.Label(frame, text=_tr('ui.source.kleur.f722216c')).grid(row=1, column=0, sticky="w")
        color_var = tk.StringVar(value=_tr('ui.source.fff4c1.085fabd9'))  # zacht geel
        color_combo = ttk.Combobox(
            frame,
            textvariable=color_var,
            state="readonly",
            values=[
                "#fff4c1",   # DMZ - geel
                "#c1ffe4",   # Intranet - groen
                "#c1d8ff",   # Extranet - blauw
                "#ffd0d0",   # Red zone
                "#e0e0e0",   # Neutraal
            ],
            width=12
        )
        color_combo.grid(row=1, column=1, sticky="w", pady=3)
        color_combo.current(0)

        # Coördinaten
        ttk.Label(frame, text=_tr('ui.source.x1.544030cd')).grid(row=2, column=0, sticky="w")
        x1_var = tk.StringVar(value=_tr('ui.source.100.310b86e0'))
        x1_entry = ttk.Entry(frame, textvariable=x1_var, width=10)
        x1_entry.grid(row=2, column=1, sticky="w", pady=2)

        ttk.Label(frame, text=_tr('ui.source.y1.693d2931')).grid(row=3, column=0, sticky="w")
        y1_var = tk.StringVar(value=_tr('ui.source.300.e26973e6'))
        y1_entry = ttk.Entry(frame, textvariable=y1_var, width=10)
        y1_entry.grid(row=3, column=1, sticky="w", pady=2)

        ttk.Label(frame, text=_tr('ui.source.x2.ad534e39')).grid(row=4, column=0, sticky="w")
        x2_var = tk.StringVar(value=_tr('ui.source.900.28cc2209'))
        x2_entry = ttk.Entry(frame, textvariable=x2_var, width=10)
        x2_entry.grid(row=4, column=1, sticky="w", pady=2)

        ttk.Label(frame, text=_tr('ui.source.y2.28a734c9')).grid(row=5, column=0, sticky="w")
        y2_var = tk.StringVar(value=_tr('ui.source.700.d8e4bbea'))
        y2_entry = ttk.Entry(frame, textvariable=y2_var, width=10)
        y2_entry.grid(row=5, column=1, sticky="w", pady=2)

        # Buttons
        btn_frame = ttk.Frame(dialog)
        btn_frame.pack(fill="x", padx=10, pady=10)

        def on_ok():
            try:
                x1 = float(x1_var.get().strip())
                y1 = float(y1_var.get().strip())
                x2 = float(x2_var.get().strip())
                y2 = float(y2_var.get().strip())
            except ValueError:
                self._mb_error(_tr('ui.source.zone.03efccb4'), _tr('ui.source.x1.y1.x2.y2.moeten.getallen.zijn.4525ac12'))
                return

            if x2 <= x1 or y2 <= y1:
                self._mb_error(_tr('ui.source.zone.03efccb4'), _tr('ui.source.x2.x1.en.y2.y1.moeten.gelden.eeb39316'))
                return

            name = (name_var.get() or "Zone").strip()
            color = color_var.get() or "#fff4c1"

            zone = {
                "name": name,
                "color": color,
                "x1": x1,
                "y1": y1,
                "x2": x2,
                "y2": y2,
            }

            # zorg dat self.zones bestaat
            if not hasattr(self, "zones"):
                self.zones = []

            self.zones.append(zone)
            print("ZONE TOEGEVOEGD:", zone)  # debug
            dialog.destroy()
            self.draw_network_map()
            self.status_label.config(text=_tr('ui.source.zone.p0.toegevoegd.ae71f2f7',p0=name))

        def on_cancel():
            dialog.destroy()

        ttk.Button(btn_frame, text=_tr('ui.source.cancel.77dfd213'), command=on_cancel).pack(side="right", padx=5)
        ttk.Button(btn_frame, text=_tr('ui.source.add.zone.0279d731'), command=on_ok).pack(side="right", padx=5)

        name_entry.focus()
        dialog.wait_window(dialog)

    def add_zone_dialog(self):
        """
        Vraag naam + type (DMZ / Intranet / Extranet / Guest),
        zet de GUI in 'zone plaats'-modus.
        Echte tekening gebeurt pas bij klik op de kaart.
        """
        dialog = tk.Toplevel(self.root)
        dialog.title(_tr('ui.source.nieuwe.zone.bddff6c8'))
        dialog.geometry("360x180")
        dialog.transient(self.root)
        dialog.grab_set()

        frm = ttk.Frame(dialog)
        frm.pack(fill="both", expand=True, padx=10, pady=10)

        ttk.Label(frm, text=_tr('ui.source.naam.van.de.zone.fe858ba9')).grid(row=0, column=0, sticky="w")
        name_var = tk.StringVar(value=_tr('ui.source.dmz.138a224d'))
        name_entry = ttk.Entry(frm, textvariable=name_var, width=25)
        name_entry.grid(row=0, column=1, sticky="w", pady=4)

        ttk.Label(frm, text=_tr('ui.source.type.ee3fb11d')).grid(row=1, column=0, sticky="w")
        type_var = tk.StringVar(value=_tr('ui.source.dmz.rood.bc8ead6b'))
        type_combo = ttk.Combobox(
            frm,
            textvariable=type_var,
            state="readonly",
            values=[
                "DMZ (rood)",
                "Intranet (groen)",
                "Extranet (oranje)",
                "Guest / BYOD (geel)",
                "Custom (blauw)"
            ],
            width=25
        )
        type_combo.grid(row=1, column=1, sticky="w", pady=4)

        btn_frame = ttk.Frame(dialog)
        btn_frame.pack(fill="x", padx=10, pady=10)

        def on_ok():
            name = name_var.get().strip() or "Zone"

            t = type_var.get()
            if t.startswith("DMZ"):
                color = "#ffd0d0"
            elif t.startswith("Intranet"):
                color = "#d0ffd8"
            elif t.startswith("Extranet"):
                color = "#ffe3b3"
            elif t.startswith("Guest"):
                color = "#fffac3"
            else:
                color = "#d0e0ff"

            # NIETS tekenen hier – alleen pending state
            self.pending_zone = {"name": name, "color": color}
            self.zone_place_mode = True

            self.status_label.config(
                text=_tr('ui.source.zone.p0.klaar.klik.nu.op.de.kaart.om.hem.te.pl.c0dfb691',p0=name)
            )
            dialog.destroy()

        def on_cancel():
            dialog.destroy()

        ttk.Button(btn_frame, text=_tr('ui.source.annuleren.c2fbda4e'), command=on_cancel).pack(side="right", padx=5)
        ttk.Button(btn_frame, text=_tr('ui.source.ok.9ce3bd42'), command=on_ok).pack(side="right")

        name_entry.focus()
        dialog.wait_window()


    def clear_zones(self):
        if not self.zones:
            return
        if not self._mb_askyesno(_tr('ui.source.zones.182e2eb7'), _tr('ui.source.alle.zones.van.de.kaart.verwijderen.84bdd1a1')):
            return
        self.zones = []
        self.draw_network_map()
        self.status_label.config(text=_tr('ui.source.alle.zones.verwijderd.45318042'))


    def _valid_discovered_host(self, ip):
        try:
            net=ipaddress.ip_network(self.range_var.get().strip(),strict=False)
            addr=ipaddress.ip_address(str(ip).strip())
        except Exception:
            return False
        return (addr in net and not addr.is_multicast and not addr.is_unspecified
                and not addr.is_loopback and addr != net.network_address
                and addr != net.broadcast_address and str(addr)!="255.255.255.255")

    def _clean_discovered_devices(self, devices):
        merged={}
        for dev in devices or []:
            if not self._valid_discovered_host(dev.ip):
                continue
            key=str(ipaddress.ip_address(dev.ip))
            if key not in merged:
                merged[key]=dev
            else:
                old=merged[key]
                if not old.hostname and dev.hostname: old.hostname=dev.hostname
                if (not old.mac or old.mac=="ff:ff:ff:ff:ff:ff") and dev.mac: old.mac=dev.mac
        return sorted(merged.values(),key=lambda d:ipaddress.ip_address(d.ip))

    def _resolve_nmap(self):
        """Resolve packaged CAMT Nmap first; PATH is only a fallback."""
        if not sys.platform.startswith("win"):
            return shutil.which("nmap") or ""
        here=Path(__file__).resolve()
        candidates=[]
        try: candidates.append(here.parents[2] / "tools" / "nmap" / "nmap.exe")
        except Exception: pass
        candidates.extend([
            here.parent / "tools" / "nmap" / "nmap.exe",
            Path(sys.executable).resolve().parent / "tools" / "nmap" / "nmap.exe",
        ])
        for candidate in candidates:
            if candidate.exists():
                return str(candidate)
        return shutil.which("nmap") or ""

    def _vulnerability_db(self):
        if OfflineIntelligenceDatabase is None:
            return None
        try:
            return OfflineIntelligenceDatabase()
        except Exception as exc:
            print("Vulnerability DB unavailable:",exc)
            return None

    def _detect_default_gateway(self):
        creationflags=getattr(subprocess,"CREATE_NO_WINDOW",0)
        try:
            if sys.platform.startswith("win"):
                cp=subprocess.run(["route","print","-4"],capture_output=True,text=True,creationflags=creationflags,timeout=5)
                for line in cp.stdout.splitlines():
                    m=re.match(r"^\s*0\.0\.0\.0\s+0\.0\.0\.0\s+(\d+\.\d+\.\d+\.\d+)\s+",line)
                    if m:
                        return m.group(1)
            else:
                cp=subprocess.run(["ip","route","show","default"],capture_output=True,text=True,timeout=5)
                m=re.search(r"\bdefault\s+via\s+(\d+\.\d+\.\d+\.\d+)",cp.stdout)
                if m:
                    return m.group(1)
        except Exception:
            pass
        return ""

    def _start_asset_enrichment(self):
        if self.enrichment_worker is not None and self.enrichment_worker.is_alive():
            return
        ips=[d.ip for d in self.devices]
        self.status_label.config(text=_tr('ui.source.scan.complete.p0.devices.asset.enrichment.op.a.14973e9c',p0=len(ips)))
        self.enrichment_worker=threading.Thread(target=self._asset_enrichment_worker,args=(ips,),daemon=True)
        self.enrichment_worker.start()
        self.root.after(100,self._poll_enrichment_queue)

    def _asset_enrichment_worker(self, ips):
        def resolve(ip):
            try:
                return ip,socket.gethostbyaddr(ip)[0]
            except Exception:
                return ip,""
        workers=min(16,max(2,len(ips) or 2))
        with ThreadPoolExecutor(max_workers=workers) as pool:
            futures=[pool.submit(resolve,ip) for ip in ips]
            for fut in as_completed(futures):
                try:
                    self.enrichment_queue.put(fut.result())
                except Exception:
                    pass
        self.enrichment_queue.put(("__DONE__",""))

    def _poll_enrichment_queue(self):
        changed=False
        done=False
        while True:
            try:
                ip,hostname=self.enrichment_queue.get_nowait()
            except queue.Empty:
                break
            if ip=="__DONE__":
                done=True
            elif hostname:
                for dev in self.devices:
                    if dev.ip==ip and dev.hostname!=hostname:
                        dev.hostname=hostname
                        changed=True
                        break
        if changed:
            self.update_device_table()
            self._schedule_live_map_render()
        if done:
            self.status_label.config(text=_tr('ui.source.scan.complete.p0.devices.enrichment.complete.925a80f0',p0=len(self.devices)))
        elif self.enrichment_worker is not None and self.enrichment_worker.is_alive():
            self.root.after(150,self._poll_enrichment_queue)

    def _network_report_context_path(self):
        if get_app_home_dir is not None:
            base=get_app_home_dir()
        else:
            base=Path.home()/"Documents"/"ProjectManager"
        path=base/"reports"/"network_scan_context.json"
        path.parent.mkdir(parents=True,exist_ok=True)
        return path

    def _publish_network_report_context(self):
        """Publish current NetMap observations for Report Studio; no manual bridge step required."""
        assets=[]
        total_cves=0
        online=cached=0
        for dev in self.devices:
            status=getattr(dev,"online_status","unknown")
            if status=="online": online+=1
            elif status in ("cached","offline"): cached+=1
            findings=self.find_cves_for_device(dev)
            exposures=[]
            db=self._vulnerability_db()
            if db is not None:
                try:exposures=db.analyze_service_exposures(list(getattr(dev,"services",[]) or []))
                except Exception as exc:print("Exposure analysis failed:",exc)
            total_cves+=len(findings)
            assets.append({
                "ip":dev.ip,"hostname":dev.hostname,"mac":dev.mac,"type":dev.dev_type,
                "status":status,"gateway":bool(getattr(dev,"is_gateway",False)),
                "services":list(getattr(dev,"services",[]) or []),
                "ports_summary":dev.ports_summary,"note":dev.note,
                "vulnerabilities":findings,
                "exposures":exposures,
            })
        recommendations=[]
        if total_cves:
            recommendations.append("Valideer CVE-kandidaten tegen exacte product-, versie- en vendor/package-informatie voordat mitigatie wordt uitgevoerd.")
        exposure_actions=[]
        for asset in assets:
            for exp in asset.get("exposures",[]):
                action=str(exp.get("next_action") or "").strip()
                if action and action not in exposure_actions:exposure_actions.append(action)
        recommendations.extend(exposure_actions)
        if cached:
            recommendations.append("Verifieer cached/offline-unconfirmed assets met een herhaalde actieve discovery voordat deze als actuele hosts worden beschouwd.")
        if any(a["gateway"] for a in assets):
            recommendations.append("Beoordeel de gateway afzonderlijk op beheerinterfaces, toegangscontrole, firmware/softwareversie en blootgestelde services.")
        if any(a["services"] for a in assets):
            recommendations.append("Beperk niet-noodzakelijke services en beheerpoorten en controleer segmentatie/firewallregels tussen gevonden subnetten.")
        observed_services={str(s.get("service") or "").lower() for a in assets for s in a.get("services",[])}
        observed_ports={int(s.get("port") or 0) for a in assets for s in a.get("services",[]) if str(s.get("port") or "").isdigit()}
        if "ssh" in observed_services or 22 in observed_ports:
            recommendations.append("Controleer SSH-versies, beheeraccounts, key-based authentication en beperk beheer via ACL/VPN tot geautoriseerde beheersegmenten.")
        if observed_services.intersection({"http","https","ssl/http","nginx","apache"}) or observed_ports.intersection({80,443,8080,8443}):
            recommendations.append("Controleer webservices op exacte product/version fingerprints, TLS-configuratie, blootgestelde beheerinterfaces en actuele vendor patches.")
        if "rpcbind" in observed_services or 111 in observed_ports:
            recommendations.append("Beperk rpcbind/RPC tot noodzakelijke hosts en segmenten en valideer welke RPC-services daadwerkelijk extern bereikbaar moeten zijn.")
        if observed_ports.intersection({139,445}):
            recommendations.append("Controleer SMB/NetBIOS op protocolversies, guest/anonymous toegang, signing en segmentatie; valideer Samba/Windows-versies tegen de CVE-catalogus.")
        if not recommendations:
            recommendations.append("Voer service/version-detectie uit op relevante gevonden hosts en herhaal daarna Vulnerability Analysis.")
        payload={
            "schema":"CAMT.NetworkScanReportContext.1",
            "generated_at":time.strftime("%Y-%m-%dT%H:%M:%S"),
            "range":self.range_var.get().strip(),
            "interface":self.iface_var.get(),
            "summary":{"assets":len(assets),"online":online,"cached_or_unconfirmed":cached,
                       "cve_candidates":total_cves},
            "assets":assets,"recommendations":recommendations,
        }
        path=self._network_report_context_path()
        path.write_text(json.dumps(payload,ensure_ascii=False,indent=2),encoding="utf-8")
        return path

    # ------------- SCAN WIZARD / ROUTE PREFLIGHT ----------------
    def _detect_routes(self):
        """Return IPv4 routes in a small cross-platform neutral structure."""
        routes=[]
        creationflags=getattr(subprocess,"CREATE_NO_WINDOW",0)
        try:
            if sys.platform.startswith("win"):
                cp=subprocess.run(["route","print","-4"],capture_output=True,text=True,
                                  creationflags=creationflags,timeout=6)
                for raw in cp.stdout.splitlines():
                    m=re.match(r"^\s*(\d+\.\d+\.\d+\.\d+)\s+(\d+\.\d+\.\d+\.\d+)\s+(\d+\.\d+\.\d+\.\d+|On-link)\s+(\d+\.\d+\.\d+\.\d+)\s+(\d+)",raw)
                    if not m: continue
                    try:
                        network=ipaddress.IPv4Network((m.group(1),m.group(2)),strict=False)
                    except Exception: continue
                    routes.append({"network":str(network),"gateway":m.group(3),"interface":m.group(4),"metric":int(m.group(5))})
            else:
                cp=subprocess.run(["ip","-4","route","show"],capture_output=True,text=True,timeout=6)
                for raw in cp.stdout.splitlines():
                    line=raw.strip()
                    if not line: continue
                    first=line.split()[0]
                    network="0.0.0.0/0" if first=="default" else first
                    try: network=str(ipaddress.ip_network(network,strict=False))
                    except Exception: continue
                    via=re.search(r"\bvia\s+(\d+\.\d+\.\d+\.\d+)",line)
                    dev=re.search(r"\bdev\s+(\S+)",line)
                    metric=re.search(r"\bmetric\s+(\d+)",line)
                    routes.append({"network":network,"gateway":via.group(1) if via else "On-link",
                                   "interface":dev.group(1) if dev else "","metric":int(metric.group(1)) if metric else 0})
        except Exception as exc:
            print("Route detect error:",exc)
        return routes

    def _detect_local_subnets(self):
        """Infer directly connected IPv4 subnets without removing legacy interface detection."""
        found=[]
        try:
            routes=self._detect_routes()
            for r in routes:
                n=ipaddress.ip_network(r["network"],strict=False)
                if n.prefixlen==0 or n.is_loopback or n.is_multicast: continue
                if str(r.get("gateway","")) in ("On-link","0.0.0.0","") and n.prefixlen>=8:
                    if str(n) not in found: found.append(str(n))
        except Exception: pass
        if not found:
            for _name,ip in self.interfaces:
                if not ip: continue
                try:
                    n=ipaddress.ip_network(f"{ip}/24",strict=False)
                    if str(n) not in found: found.append(str(n))
                except Exception: pass
        return found

    def _route_for_target(self,target):
        try: dest=ipaddress.ip_network(target,strict=False).network_address
        except Exception: return None
        candidates=[]
        for r in self._detect_routes():
            try:
                n=ipaddress.ip_network(r["network"],strict=False)
                if dest in n: candidates.append((n.prefixlen,int(r.get("metric",0)),r))
            except Exception: pass
        return sorted(candidates,key=lambda x:(-x[0],x[1]))[0][2] if candidates else None

    def _nmap_preflight_local(self,target):
        result={"target":target,"nmap":"","route":None,"ok":False,"details":[]}
        nmap=self._resolve_nmap(); result["nmap"]=nmap
        if nmap:
            try:
                cp=run_hidden([nmap,"--version"],timeout=6)
                result["details"].append("Nmap: OK" if cp.returncode==0 else "Nmap: failed")
            except Exception as exc: result["details"].append(f"Nmap: {exc}")
        else: result["details"].append("Nmap: not found")
        route=self._route_for_target(target); result["route"]=route
        result["details"].append("Route: "+(f"{route['network']} via {route['gateway']} ({route['interface']})" if route else "not found"))
        privileged=True
        if not sys.platform.startswith("win") and hasattr(os,"geteuid"):
            privileged=(os.geteuid()==0)
        result["details"].append("Privileges: elevated" if privileged else "Privileges: standard user (some Nmap scan types may be limited)")
        result["ok"]=bool(nmap and route)
        return result

    def _ssh_base_command(self,host,user,port,keyfile=""):
        ssh=shutil.which("ssh")
        if not ssh: raise RuntimeError("OpenSSH client (ssh) not found.")
        dest=f"{user}@{host}" if user else host
        cmd=[ssh,"-o","BatchMode=yes","-o","ConnectTimeout=8","-p",str(port or 22)]
        if keyfile: cmd.extend(["-i",keyfile])
        cmd.append(dest)
        return cmd

    def _nmap_preflight_jump(self,target,host,user,port,keyfile=""):
        details=[]
        try:
            base=self._ssh_base_command(host,user,port,keyfile)
            remote="command -v nmap && nmap --version | head -n 1; printf '\\n__UID__='; id -u; printf '\\n__ROUTE__='; (ip route get "+shlex.quote(str(ipaddress.ip_network(target,strict=False).network_address))+" 2>/dev/null || route -n 2>/dev/null | head -n 8)"
            cp=run_hidden(base+[remote],timeout=15)
            if cp.returncode!=0: raise RuntimeError(cp.stderr.strip() or "SSH connection/preflight failed")
            out=cp.stdout or ""
            details.append("SSH connection: OK")
            details.append("Remote Nmap: OK" if "nmap" in out.lower() else "Remote Nmap: not found")
            uid=re.search(r"__UID__=(\d+)",out)
            details.append("Remote privileges: root" if uid and uid.group(1)=="0" else "Remote privileges: standard user")
            route_ok="__ROUTE__=" in out and len(out.split("__ROUTE__=",1)[-1].strip())>0
            details.append("Remote route: detected" if route_ok else "Remote route: not confirmed")
            return {"ok":("nmap" in out.lower() and route_ok),"details":details,"raw":out}
        except Exception as exc:
            details.append(f"SSH/preflight: {exc}")
            return {"ok":False,"details":details,"raw":""}

    def open_guided_network_analysis(self):
        """Guide a user from basic discovery to CAMT analysis without duplicating NetMap scanning."""
        win=tk.Toplevel(self.root); win.title("CAMT Guided Network Analysis"); win.geometry("820x640"); win.transient(self.root)
        _apply_camt_window_icon(win)
        body=ttk.Frame(win,padding=14); body.pack(fill="both",expand=True)
        ttk.Label(body,text="Guided Network Analysis",font=("Segoe UI",14,"bold")).pack(anchor="w")
        ttk.Label(body,text="Use the existing NetMap scan engine, review what was discovered, then continue through CAMT analysis and reporting.",wraplength=770).pack(anchor="w",pady=(2,10))
        summary=tk.StringVar()
        def refresh_summary():
            devices=list(self.devices or []); services=sum(len(getattr(d,"services",[]) or []) for d in devices)
            types={}
            for d in devices:
                k=str(getattr(d,"dev_type","Unknown") or "Unknown"); types[k]=types.get(k,0)+1
            typed=", ".join(f"{v} {k}" for k,v in sorted(types.items(),key=lambda x:(-x[1],x[0]))) or "no classified devices"
            summary.set(f"Current NetMap: {len(devices)} device(s), {services} observed service(s) — {typed}.")
        refresh_summary()
        ttk.Label(body,textvariable=summary,wraplength=770).pack(anchor="w",pady=(0,10))
        steps=ttk.Frame(body); steps.pack(fill="both",expand=True)
        def step(parent,n,title,desc,button,cmd):
            f=ttk.LabelFrame(parent,text=f"{n}. {title}",padding=10); f.pack(fill="x",pady=5)
            f.columnconfigure(0,weight=1); ttk.Label(f,text=desc,wraplength=620).grid(row=0,column=0,sticky="w")
            ttk.Button(f,text=button,command=cmd).grid(row=0,column=1,padx=(10,0))
        def scan(): self.open_scan_wizard()
        def review(): refresh_summary(); self.update_device_table(); self.draw_network_map(); self.root.lift()
        def services(): self.scan_discovered_hosts()
        def vulns(): self.run_vulnerability_analysis(); refresh_summary()
        def advice(): self.run_analysis_advice()
        def report():
            try:
                path=self._publish_network_report_context()
                self._mb_info("CAMT Report Context",f"Network analysis context is ready for Report Studio.\n\n{path}",parent=win)
            except Exception as exc: self._mb_error("Report context",str(exc),parent=win)
        step(steps,1,"Discover","Select Local Interface, VPN/Routed Network or Jump Host/SSH. Preflight verifies the route and Nmap before scanning.","Open Scan Wizard",scan)
        step(steps,2,"Review topology","Review discovered hosts, device classification, routes and the visual topology before deeper scanning.","Review NetMap",review)
        step(steps,3,"Identify services","Run service/version detection only when deeper active scanning is appropriate and authorized.","Service / Version Scan",services)
        step(steps,4,"Correlate findings","Correlate observed services with CAMT's vulnerability data. Results are candidates until product/version evidence confirms them.","Vulnerability Analysis",vulns)
        step(steps,5,"Interpret","Open CAMT Analysis Advice to review observations, analysis stages, CVE correlation and recommended next actions.","Analysis Advice",advice)
        step(steps,6,"Report","Publish the current observations, exposures, CVE candidates and recommendations to the shared Report Studio context.","Prepare Report Context",report)
        foot=ttk.Frame(body); foot.pack(fill="x",pady=(8,0)); ttk.Button(foot,text="Refresh summary",command=refresh_summary).pack(side="left"); ttk.Button(foot,text="Close",command=win.destroy).pack(side="right")

    def open_scan_wizard(self):
        """Three-mode Scan Wizard: local, routed/VPN, or remote Nmap through SSH."""
        win=tk.Toplevel(self.root); win.title("NetMap Scan Wizard"); win.geometry("760x610"); win.transient(self.root); win.grab_set()
        _apply_camt_window_icon(win)
        body=ttk.Frame(win,padding=12); body.pack(fill="both",expand=True)
        mode=tk.StringVar(value="Local Interface")
        target=tk.StringVar(value=(self.range_var.get().strip() or ""))
        iface=tk.StringVar(value=(self.iface_var.get() or "auto"))
        host=tk.StringVar(); user=tk.StringVar(); port=tk.StringVar(value="22"); keyfile=tk.StringVar()
        authorized=tk.BooleanVar(value=False); status=tk.StringVar(value="Select a scan mode and run Preflight.")
        ttk.Label(body,text="Scan mode",font=("Segoe UI",11,"bold")).grid(row=0,column=0,sticky="w")
        mode_combo=ttk.Combobox(body,textvariable=mode,values=["Local Interface","VPN/Routed Network","Jump Host/SSH"],state="readonly",width=24)
        mode_combo.grid(row=0,column=1,sticky="w",padx=8,pady=4)
        ttk.Label(body,text="Target CIDR").grid(row=1,column=0,sticky="w",pady=4); ttk.Entry(body,textvariable=target,width=34).grid(row=1,column=1,sticky="ew",padx=8)
        ttk.Label(body,text="Interface").grid(row=2,column=0,sticky="w",pady=4)
        vals=self._interface_display_values()
        wizard_iface_combo=ttk.Combobox(body,textvariable=iface,values=vals,state="readonly",width=58)
        wizard_iface_combo.grid(row=2,column=1,sticky="ew",padx=8)
        def wizard_iface_changed(event=None):
            d=self._selected_interface_detail(iface.get())
            if d and d.get("network"):
                target.set(d["network"]); status.set(f"Selected {d['name']}: {d['ip']}/{d['prefix']} -> {d['network']}")
                preflight_state["ok"]=False
        wizard_iface_combo.bind("<<ComboboxSelected>>",wizard_iface_changed)
        route_text=tk.Text(body,height=7,width=62); route_text.grid(row=3,column=0,columnspan=3,sticky="nsew",pady=8)
        jump=ttk.LabelFrame(body,text="Jump Host / SSH",padding=8); jump.grid(row=4,column=0,columnspan=3,sticky="ew",pady=4)
        ttk.Label(jump,text="Host").grid(row=0,column=0); ttk.Entry(jump,textvariable=host,width=22).grid(row=0,column=1,padx=4)
        ttk.Label(jump,text="User").grid(row=0,column=2); ttk.Entry(jump,textvariable=user,width=16).grid(row=0,column=3,padx=4)
        ttk.Label(jump,text="Port").grid(row=0,column=4); ttk.Entry(jump,textvariable=port,width=6).grid(row=0,column=5,padx=4)
        ttk.Label(jump,text="SSH key").grid(row=1,column=0,sticky="w",pady=4); ttk.Entry(jump,textvariable=keyfile,width=50).grid(row=1,column=1,columnspan=4,sticky="ew",padx=4)
        ttk.Button(jump,text="Browse",command=lambda:keyfile.set(filedialog.askopenfilename(parent=win) or keyfile.get())).grid(row=1,column=5)
        auth=ttk.Checkbutton(body,text="I confirm that I am authorized to scan the selected network/hosts.",variable=authorized)
        auth.grid(row=5,column=0,columnspan=3,sticky="w",pady=(10,4))
        ttk.Label(body,textvariable=status,wraplength=690).grid(row=6,column=0,columnspan=3,sticky="ew",pady=5)
        body.columnconfigure(1,weight=1); body.rowconfigure(3,weight=1)
        preflight_state={"ok":False}
        def autodetect():
            subs=self._detect_local_subnets(); routes=self._detect_routes()
            if not target.get().strip() and subs: target.set(subs[0])
            route_text.delete("1.0","end")
            route_text.insert("end","Detected subnets:\n"+("\n".join("  "+x for x in subs) or "  none")+"\n\nRoutes:\n")
            for r in routes[:30]: route_text.insert("end",f"  {r['network']}  via {r['gateway']}  interface {r['interface']}  metric {r['metric']}\n")
            status.set(f"Detected {len(subs)} local subnet(s) and {len(routes)} route(s).")
        def preflight():
            try: ipaddress.ip_network(target.get().strip(),strict=False)
            except Exception as exc: status.set(f"Invalid target CIDR: {exc}"); preflight_state["ok"]=False; return
            if mode.get()=="Jump Host/SSH":
                try:pnum=int(port.get() or 22)
                except Exception: status.set("Invalid SSH port."); return
                res=self._nmap_preflight_jump(target.get().strip(),host.get().strip(),user.get().strip(),pnum,keyfile.get().strip())
            else: res=self._nmap_preflight_local(target.get().strip())
            preflight_state["ok"]=bool(res.get("ok")); route_text.delete("1.0","end"); route_text.insert("end","Preflight\n=========\n"+"\n".join(res.get("details",[])))
            status.set("Preflight passed." if preflight_state["ok"] else "Preflight incomplete/failed. Resolve the items above before scanning.")
        def start():
            if not authorized.get(): self._mb_warning("Authorization required","Confirm authorization before starting the scan.",parent=win); return
            if not preflight_state["ok"]: preflight();
            if not preflight_state["ok"]: return
            self.range_var.set(target.get().strip()); self.iface_var.set(iface.get().strip() or "auto")
            selected=mode.get()
            self.scan_context={"mode":{"Local Interface":"local","VPN/Routed Network":"routed","Jump Host/SSH":"jump"}[selected],"route":self._route_for_target(target.get().strip()),"jump_host":{"host":host.get().strip(),"user":user.get().strip(),"port":int(port.get() or 22),"keyfile":keyfile.get().strip()}}
            win.destroy()
            if selected=="Jump Host/SSH": self._start_jump_host_scan(target.get().strip())
            else: self.scan_network()
        buttons=ttk.Frame(body); buttons.grid(row=7,column=0,columnspan=3,sticky="ew",pady=8)
        ttk.Button(buttons,text="Auto-detect subnet/routes",command=autodetect).pack(side="left")
        ttk.Button(buttons,text="Preflight",command=preflight).pack(side="left",padx=6)
        ttk.Button(buttons,text="Start scan",command=start).pack(side="right")
        ttk.Button(buttons,text="Cancel",command=win.destroy).pack(side="right",padx=6)
        autodetect()

    def _start_jump_host_scan(self,target):
        if self.scan_worker is not None and self.scan_worker.is_alive(): return
        net=ipaddress.ip_network(target,strict=False)
        self.scan_stop_event.clear(); self.scan_started_at=time.monotonic(); self.scan_total=max(1,net.num_addresses-2); self.scan_done=0; self.scan_found=0
        self.devices=[]; self.update_device_table(); self.draw_network_map(); self.scan_btn.configure(state="disabled"); self.stop_scan_btn.configure(state="normal")
        self.scan_progress.configure(mode="indeterminate"); self.scan_progress.start(12); self.status_label.config(text=f"Remote Nmap scan via jump host: {target}")
        self.scan_worker=threading.Thread(target=self._jump_host_scan_worker,args=(target,),daemon=True); self.scan_worker.start(); self.root.after(100,self._refresh_scan_progress)

    def _jump_host_scan_worker(self,target):
        try:
            j=self.scan_context.get("jump_host",{}); base=self._ssh_base_command(j.get("host",""),j.get("user",""),j.get("port",22),j.get("keyfile",""))
            # Discovery only here; existing local service/version workflow remains available afterwards.
            remote="nmap -sn -oX - -- "+shlex.quote(target)
            cp=run_hidden(base+[remote],timeout=max(60,min(1800,self.scan_total*2)))
            if cp.returncode!=0: raise RuntimeError(cp.stderr.strip() or "Remote Nmap failed")
            devices=self._devices_from_nmap_xml(cp.stdout)
            self.scan_done=self.scan_total; self.scan_found=len(devices)
            self.root.after(0,lambda d=devices:self._finish_jump_host_scan(d,None))
        except Exception as exc:
            self.root.after(0,lambda e=exc:self._finish_jump_host_scan([],e))

    def _devices_from_nmap_xml(self,xml_text):
        root=ET.fromstring(xml_text); devices=[]
        for h in root.findall("host"):
            st=h.find("status")
            if st is not None and st.get("state")!="up": continue
            ipv4=""; mac=""
            for a in h.findall("address"):
                if a.get("addrtype")=="ipv4": ipv4=a.get("addr","")
                elif a.get("addrtype")=="mac": mac=a.get("addr","").lower()
            if not ipv4: continue
            hn=h.find("hostnames/hostname"); hostname=hn.get("name","") if hn is not None else ""
            dev=Device(ipv4,mac,hostname,self.classify_device(hostname,ipv4,mac),online_status="online")
            devices.append(dev)
        return self._clean_discovered_devices(devices)

    def _finish_jump_host_scan(self,devices,error=None):
        try:self.scan_progress.stop()
        except Exception:pass
        self.scan_progress.configure(mode="determinate",maximum=max(1,self.scan_total)); self.scan_btn.configure(state="normal"); self.stop_scan_btn.configure(state="disabled")
        if error is not None:
            self.status_label.config(text="Jump-host scan failed"); self._mb_error("Jump Host / SSH",str(error)); return
        self.devices=devices; self.live_discovered={d.ip:d for d in devices}; self.scan_done=self.scan_total; self.scan_found=len(devices)
        self.update_device_table(); self.draw_network_map(); self._refresh_scan_progress(schedule_again=False)
        self.status_label.config(text=f"Remote scan complete: {len(devices)} devices imported from Nmap XML.")
        self._start_asset_enrichment()

    # ------------- SCAN LOGICA ----------------
    def scan_network(self):
        """Start hybride discovery in een background thread met zichtbare voortgang."""
        if self.scan_worker is not None and self.scan_worker.is_alive():
            self._mb_info(_tr('ui.source.network.mapper.41a46638'),_tr('ui.source.er.loopt.al.een.scan.gebruik.stop.scan.fa7c3fba'))
            return

        try:
            net=ipaddress.ip_network(self.range_var.get().strip(),strict=False)
        except Exception as exc:
            self._mb_error(_tr('ui.source.scan.error.0eb8e66a'),_tr('ui.source.ongeldige.ip.range.p0.1c7c3904',p0=exc))
            return

        self.scan_stop_event.clear()
        self.scan_started_at=time.monotonic()
        self.scan_total=max(0,net.num_addresses-2) if net.version==4 and net.prefixlen<31 else int(net.num_addresses)
        self.scan_done=0
        self.scan_found=0
        self.live_discovered={}
        self.live_render_pending=False
        while True:
            try:
                self.live_host_queue.get_nowait()
            except queue.Empty:
                break
        self.devices=[]
        self.update_device_table()
        self.draw_network_map()
        self.scan_progress.configure(mode="determinate",maximum=max(1,self.scan_total))
        self.scan_progress_var.set(0)
        self.scan_counter_var.set(f"0 / {self.scan_total:,}".replace(",","."))
        self.scan_percent_var.set("0%")
        self.scan_found_var.set("0 hosts")
        self.scan_elapsed_var.set("00:00")
        self.scan_btn.configure(state="disabled")
        self.stop_scan_btn.configure(state="normal")
        self.status_label.config(text=_tr('ui.source.discovery.gestart.p0.gevonden.hosts.verschijne.785c5d2b',p0=net))

        method=self.method_var.get()
        detail=self._selected_interface_detail(self.iface_var.get())
        self._scan_interface_name=(detail or {}).get("name", "")
        self.scan_worker=threading.Thread(target=self._scan_worker_entry,args=(method,net),daemon=True)
        self.scan_worker.start()
        # GUI polling is started on the Tk thread. Worker threads never call Tk.
        self.live_queue_polling=True
        self.root.after(40,self._poll_live_host_queue)
        self.root.after(50,self._refresh_scan_progress)

    def stop_network_scan(self):
        if self.scan_worker is not None and self.scan_worker.is_alive():
            self.scan_stop_event.set()
            self.stop_scan_btn.configure(state="disabled")
            self.status_label.config(text=_tr('ui.source.scan.wordt.gestopt.3d61724a'))

    def _scan_worker_entry(self, method, net):
        try:
            if method=="arp":
                devices=self.scan_with_arp()
            elif sys.platform.startswith("win"):
                devices=self.scan_with_windows_active_discovery(net)
            elif method=="netdiscover":
                devices=self.scan_with_netdiscover()
            else:
                devices=self.scan_with_linux_active_discovery(net)

            devices=self._clean_discovered_devices(devices)
            stopped=self.scan_stop_event.is_set()
            self.root.after(0,lambda d=devices,st=stopped:self._finish_network_scan(d,st,None))
        except Exception as exc:
            self.root.after(0,lambda e=exc:self._finish_network_scan([],False,e))

    def _finish_network_scan(self, devices, stopped=False, error=None):
        # Process any final discoveries waiting in the thread-safe queue.
        while True:
            try:
                pending_ip=self.live_host_queue.get_nowait()
            except queue.Empty:
                break
            if pending_ip and pending_ip not in self.live_discovered:
                self._publish_live_host(pending_ip,render=False)
        self.scan_btn.configure(state="normal")
        self.stop_scan_btn.configure(state="disabled")
        elapsed=max(0.0,time.monotonic()-self.scan_started_at)
        if error is not None:
            self.status_label.config(text=_tr('ui.source.scan.failed.8f1c0bf4'))
            self._mb_error(_tr('ui.source.scan.error.0eb8e66a'),_tr('ui.source.error.while.scanning.p0.d003e257',p0=error))
            return

        # Merge final enrichment into the live objects so nodes do not disappear/reappear.
        live_by_ip={d.ip:d for d in self.devices}
        for final_dev in devices:
            live=live_by_ip.get(final_dev.ip)
            if live is not None:
                final_dev.pos_x=live.pos_x
                final_dev.pos_y=live.pos_y
        self.devices=devices
        self.live_discovered={d.ip:d for d in devices}
        self.last_traceroute=None
        self.update_device_table()
        self.draw_network_map()
        self.scan_found=len(devices)
        if not stopped:
            self.scan_done=self.scan_total
        self._refresh_scan_progress(schedule_again=False)
        state="Scan gestopt" if stopped else "Scan complete"
        self.status_label.config(text=_tr('ui.source.p0.found.p1.devices.in.p2.1f.s.8c878730',p0=state,p1=len(devices),p2=elapsed))
        if not stopped:
            self._start_asset_enrichment()
        try:self._publish_network_report_context()
        except Exception as exc:print("Report context publish failed:",exc)

    def _refresh_scan_progress(self, schedule_again=True):
        total=max(1,int(self.scan_total or 0))
        done=min(int(self.scan_done or 0),total)
        pct=int((done/total)*100)
        elapsed=max(0.0,time.monotonic()-self.scan_started_at) if self.scan_started_at else 0.0
        self.scan_progress_var.set(done)
        self.scan_counter_var.set(f"{done:,} / {int(self.scan_total or 0):,}".replace(",","."))
        self.scan_percent_var.set(f"{pct}%")
        self.scan_found_var.set(f"{int(self.scan_found or 0)} hosts")
        self.scan_elapsed_var.set(f"{int(elapsed//60):02d}:{int(elapsed%60):02d}")
        if schedule_again and self.scan_worker is not None:
            if self.scan_worker.is_alive():
                self.root.after(250,self._refresh_scan_progress)

    def _queue_live_host(self, ip):
        """Worker-safe: enqueue only; never call Tk from the scan worker."""
        if ip:
            self.live_host_queue.put(ip)

    def _poll_live_host_queue(self):
        """Tk-thread consumer for live discoveries."""
        changed=False
        processed=0
        while processed<128:
            try:
                ip=self.live_host_queue.get_nowait()
            except queue.Empty:
                break
            processed+=1
            if ip and ip not in self.live_discovered:
                self._publish_live_host(ip,render=False)
                changed=True
        if changed:
            self._schedule_live_map_render()
        worker_alive=self.scan_worker is not None and self.scan_worker.is_alive()
        if worker_alive or not self.live_host_queue.empty():
            self.root.after(80,self._poll_live_host_queue)
        else:
            self.live_queue_polling=False


    def _publish_live_host(self, ip, render=True):
        if not ip or ip in self.live_discovered:
            return
        is_gateway=bool(self.gateway_ip and ip==self.gateway_ip)
        dev=Device(ip=ip,mac="",hostname="",dev_type=("gateway/router" if is_gateway else self.classify_device("",ip,"")),is_gateway=is_gateway,online_status="online")
        self.live_discovered[ip]=dev
        self.devices=list(sorted(self.live_discovered.values(),key=lambda d:ipaddress.ip_address(d.ip)))
        self.scan_found=max(self.scan_found,len(self.devices))
        self.update_device_table()
        if render:
            self._schedule_live_map_render()

    def _schedule_live_map_render(self):
        """Throttle topology redraws so many discoveries do not make Tk sluggish."""
        if self.live_render_pending:
            return
        self.live_render_pending=True
        self.root.after(180,self._render_live_map)

    def _render_live_map(self):
        self.live_render_pending=False
        try:
            self.draw_network_map()
        except Exception as exc:
            print("Live map render error:",exc)

    def scan_with_linux_active_discovery(self, net):
        """Probe the selected subnet instead of treating the ARP cache as a scan."""
        if net.version != 4 or net.num_addresses > 65536:
            raise ValueError("Select an IPv4 subnet of /16 or smaller for interactive discovery.")
        nmap = self._resolve_nmap()
        if not nmap:
            raise RuntimeError("Nmap is missing. Rerun the CAMT Linux installer.")
        cmd = [nmap, "-sn", "-n", "-oX", "-"]
        iface = getattr(self, "_scan_interface_name", "")
        if iface and iface != "auto":
            cmd.extend(["-e", iface])
        cmd.extend(["--", str(net)])
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        deadline = time.monotonic() + 180
        try:
            while True:
                if self.scan_stop_event.is_set():
                    proc.terminate()
                    try:
                        proc.communicate(timeout=3)
                    except subprocess.TimeoutExpired:
                        proc.kill()
                        proc.communicate()
                    return []
                if time.monotonic() >= deadline:
                    raise RuntimeError("Network discovery timed out. Select a smaller subnet and retry.")
                try:
                    stdout, stderr = proc.communicate(timeout=0.25)
                    break
                except subprocess.TimeoutExpired:
                    continue
            if proc.returncode != 0:
                raise RuntimeError("Nmap discovery failed: " + (stderr.strip() or str(proc.returncode)))
            devices = self._devices_from_nmap_xml(stdout)
            for device in devices:
                self._queue_live_host(device.ip)
            self.scan_done = self.scan_total
            self.scan_found = len(devices)
            return devices
        finally:
            if proc.poll() is None:
                proc.kill()
                proc.communicate()

    def scan_with_windows_active_discovery(self, net=None):
        """Windows active CIDR sweep, batched, cancellable and progress-aware."""
        if net is None:
            net=ipaddress.ip_network(self.range_var.get().strip(),strict=False)
        if net.version!=4:
            raise ValueError("Alleen IPv4 discovery wordt momenteel ondersteund.")

        hosts=[str(ip) for ip in net.hosts()]
        if len(hosts)>65534:
            raise ValueError("Subnet is te groot voor deze interactieve actieve scan.")

        creationflags=getattr(subprocess,"CREATE_NO_WINDOW",0)
        def probe(ip):
            if self.scan_stop_event.is_set():
                return None
            cp=subprocess.run(
                ["ping","-n","1","-w","140",ip],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                creationflags=creationflags
            )
            return ip if cp.returncode==0 else None

        responsive=set()
        done=0
        workers=min(128,max(16,len(hosts)//64 or 16))
        batch_size=max(workers*4,256)

        with ThreadPoolExecutor(max_workers=workers) as pool:
            for start in range(0,len(hosts),batch_size):
                if self.scan_stop_event.is_set():
                    break
                batch=hosts[start:start+batch_size]
                futures=[pool.submit(probe,ip) for ip in batch]
                for fut in as_completed(futures):
                    if self.scan_stop_event.is_set():
                        break
                    try:
                        ip=fut.result()
                        if ip and ip not in responsive:
                            responsive.add(ip)
                            self._queue_live_host(ip)
                    except Exception:
                        pass
                    done+=1
                    if done%32==0 or done==len(hosts):
                        self.scan_done=done
                        self.scan_found=len(responsive)
                if self.scan_stop_event.is_set():
                    for fut in futures:
                        fut.cancel()
                    break

        cp=subprocess.run(["arp","-a"],capture_output=True,text=True,creationflags=creationflags)
        arp_by_ip={}
        for raw in cp.stdout.splitlines():
            m=re.search(r"(\d+\.\d+\.\d+\.\d+)\s+([\da-fA-F\-]{17})",raw)
            if not m:
                continue
            ip=m.group(1)
            try:
                addr=ipaddress.ip_address(ip)
            except ValueError:
                continue
            if addr not in net or addr.is_multicast or ip in (str(net.network_address),str(net.broadcast_address)):
                continue
            mac=m.group(2).replace("-",":").lower()
            if mac!="ff:ff:ff:ff:ff:ff":
                arp_by_ip[ip]=mac

        self.gateway_ip=self._detect_default_gateway()
        found=responsive | set(arp_by_ip)
        if self.gateway_ip:
            try:
                if ipaddress.ip_address(self.gateway_ip) in net:
                    found.add(self.gateway_ip)
                    if self.gateway_ip not in responsive and self.gateway_ip not in arp_by_ip:
                        self._queue_live_host(self.gateway_ip)
            except Exception:
                pass
        self.scan_found=len(found)
        for observed_ip in sorted(set(arp_by_ip)-responsive,key=ipaddress.ip_address):
            self._queue_live_host(observed_ip)
        devices=[]
        for ip in sorted(found,key=ipaddress.ip_address):
            mac=arp_by_ip.get(ip,"")
            is_gateway=(ip==self.gateway_ip)
            dtype="gateway/router" if is_gateway else self.classify_device("",ip,mac)
            status="online" if ip in responsive else "cached"
            devices.append(Device(ip,mac,"",dtype,is_gateway=is_gateway,online_status=status))
        return devices


    def scan_with_netdiscover(self):
        cidr = self.range_var.get().strip()
        if not cidr:
            raise ValueError("No IP range provided.")

        netdiscover=shutil.which("netdiscover")
        if not netdiscover:
            raise RuntimeError("netdiscover is niet beschikbaar op dit Linux/Unix-systeem. Kies Auto/ARP of installeer netdiscover.")

       # cmd = ["netdiscover", "-P", "-N", "-r", cidr]
        cmd = [netdiscover, "-P", "-N"]

        # Interface uit GUI (best effort)
        iface_sel = self.iface_var.get()
        if iface_sel and iface_sel != "auto":
            # neem stuk vóór "(" als naam
            detail=self._selected_interface_detail(iface_sel)
            iface_name=(detail or {}).get("name") or iface_sel.split("(")[0].strip()
            if iface_name:
                cmd.extend(["-i", iface_name])

        cmd.extend(["-r", cidr])

        self.root.after(0,lambda:self.scan_progress.configure(mode="indeterminate"))
        self.root.after(0,self.scan_progress.start)
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        stdout, stderr = proc.communicate()
        self.root.after(0,self.scan_progress.stop)
        self.root.after(0,lambda:self.scan_progress.configure(mode="determinate"))

        if proc.returncode not in (0, 1):
            raise RuntimeError(f"netdiscover error: {stderr}")

        devices = []
        for line in stdout.splitlines():
            if re.match(r"^\s*IP", line) or line.strip() == "" or line.startswith("Currently scanning"):
                continue
            parts = line.split()
            if len(parts) >= 2:
                ip = parts[0]
                mac = parts[1]
                hostname = ""
                if len(parts) >= 5:
                    hostname = " ".join(parts[4:])
                dev_type = self.classify_device(hostname, ip, mac)
                devices.append(Device(ip, mac, hostname, dev_type))
        return devices

    def scan_with_arp(self):
        if sys.platform.startswith("win"):
            cmd = ["arp", "-a"]
            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            stdout, stderr = proc.communicate()

            if proc.returncode != 0:
                raise RuntimeError(f"arp error: {stderr}")

            # Gekozen interface-ip uit combobox
            selected_ip = None
            iface_sel = self.iface_var.get()
            if iface_sel and iface_sel != "auto":
                detail=self._selected_interface_detail(iface_sel)
                if detail:
                    selected_ip=detail.get("ip") or None

            devices = []
            current_iface_ip = None

            for raw_line in stdout.splitlines():
                line = raw_line.strip()
                if not line:
                    continue

                # "Interface: 192.168.1.10 --- 0x3"
                if line.lower().startswith("interface:"):
                    m_if = re.search(r"Interface:\s+(\d+\.\d+\.\d+\.\d+)", line, re.IGNORECASE)
                    current_iface_ip = m_if.group(1) if m_if else None
                    continue

                # Als een specifieke interface is gekozen, filter op die IP
                if selected_ip and current_iface_ip and current_iface_ip != selected_ip:
                    continue

                # ARP-regel: "  192.168.1.1          00-11-22-33-44-55   dynamisch"
                m2 = re.search(r"(\d+\.\d+\.\d+\.\d+)\s+([\da-fA-F\-]{17})", line)
                if m2:
                    ip = m2.group(1)
                    mac = m2.group(2).replace("-", ":").lower()
                    hostname = ""
                    dev_type = self.classify_device(hostname, ip, mac)
                    devices.append(Device(ip, mac, hostname, dev_type))

            return devices

        else:
            # Unix-achtige variant (geen interfacefilter, maar kan later uitgebreid worden)
            cmd = ["arp", "-a"]
            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            stdout, stderr = proc.communicate()

            if proc.returncode != 0:
                raise RuntimeError(f"arp error: {stderr}")

            devices = []
            for line in stdout.splitlines():
                m = re.search(r"\((\d+\.\d+\.\d+\.\d+)\)\s+at\s+([\da-fA-F:\-]+)", line)
                if m:
                    ip = m.group(1)
                    mac = m.group(2).replace("-", ":").lower()
                    hostname = ""
                    dev_type = self.classify_device(hostname, ip, mac)
                    devices.append(Device(ip, mac, hostname, dev_type))
                    continue

                m2 = re.search(r"(\d+\.\d+\.\d+\.\d+)\s+([\da-fA-F\-]{17})", line)
                if m2:
                    ip = m2.group(1)
                    mac = m2.group(2).replace("-", ":").lower()
                    hostname = ""
                    dev_type = self.classify_device(hostname, ip, mac)
                    devices.append(Device(ip, mac, hostname, dev_type))

            return devices


    # ------------- MANUEEL DEVICE TOEVOEGEN/VERWIJDEREN ----------------
    def add_device_dialog(self):
        dialog = tk.Toplevel(self.root)
        dialog.title(_tr('ui.source.add.device.2d2367c4'))
        dialog.geometry("420x320")
        dialog.transient(self.root)
        dialog.grab_set()

        frame = ttk.Frame(dialog)
        frame.pack(fill="both", expand=True, padx=10, pady=10)

        ttk.Label(frame, text=_tr('ui.source.ip.address.6e084735')).grid(row=0, column=0, sticky="w")
        ip_var = tk.StringVar()
        ip_entry = ttk.Entry(frame, textvariable=ip_var, width=25)
        ip_entry.grid(row=0, column=1, sticky="w", pady=2)

        ttk.Label(frame, text=_tr('ui.source.mac.address.b4162ad1')).grid(row=1, column=0, sticky="w")
        mac_var = tk.StringVar()
        mac_entry = ttk.Entry(frame, textvariable=mac_var, width=25)
        mac_entry.grid(row=1, column=1, sticky="w", pady=2)

        ttk.Label(frame, text=_tr('ui.source.hostname.76945896')).grid(row=2, column=0, sticky="w")
        hostname_var = tk.StringVar()
        hostname_entry = ttk.Entry(frame, textvariable=hostname_var, width=25)
        hostname_entry.grid(row=2, column=1, sticky="w", pady=2)

        ttk.Label(frame, text=_tr('ui.source.device.type.bf52d20a')).grid(row=3, column=0, sticky="w", pady=(5, 0))
        type_var = tk.StringVar(value=_tr('ui.source.iot.c12316ed'))
        type_combo = ttk.Combobox(
            frame,
            textvariable=type_var,
            values=["client", "server", "printer", "storage", "gateway/router", "iot"],
            state="readonly",
            width=22,
        )
        type_combo.grid(row=3, column=1, sticky="w", pady=(5, 0))

        ttk.Label(frame, text=_tr('ui.source.notes.9c3befe7')).grid(row=4, column=0, columnspan=2, sticky="w", pady=(10, 0))
        note_text = tk.Text(frame, wrap="word", height=6)
        note_text.grid(row=5, column=0, columnspan=2, sticky="nsew", pady=5)

        frame.rowconfigure(5, weight=1)
        frame.columnconfigure(1, weight=1)

        btn_frame = ttk.Frame(dialog)
        btn_frame.pack(fill="x", padx=10, pady=5)

        def on_ok():
            ip = ip_var.get().strip()
            if not ip:
                self._mb_warning(_tr('ui.source.missing.ip.017dd3d5'), _tr('ui.source.ip.address.is.required.for.placement.on.the.ma.5f5f69b6'))
                return
            mac = mac_var.get().strip()
            hostname = hostname_var.get().strip()
            dev_type = type_var.get().strip() or "client"
            note = note_text.get("1.0", "end").strip()

            dev = Device(ip=ip, mac=mac, hostname=hostname, dev_type=dev_type, note=note)
            self.devices.append(dev)
            dialog.destroy()
            self.update_device_table()
            self.draw_network_map()

        def on_cancel():
            dialog.destroy()

        ok_btn = ttk.Button(btn_frame, text=_tr('ui.source.add.61cc55aa'), command=on_ok)
        ok_btn.pack(side="right", padx=5)
        cancel_btn = ttk.Button(btn_frame, text=_tr('ui.source.cancel.77dfd213'), command=on_cancel)
        cancel_btn.pack(side="right", padx=5)

        ip_entry.focus()
        dialog.wait_window()

    def delete_selected_device(self):
        item_id = self.device_tree.focus()
        if not item_id:
            self._mb_warning(_tr('ui.source.no.selection.915cf89a'), _tr('ui.source.select.a.device.first.c8b3e3d4'))
            return
        try:
            index = int(item_id)
        except ValueError:
            return
        if index < 0 or index >= len(self.devices):
            return

        dev = self.devices[index]
        if not self._mb_askyesno(
            _tr('ui.source.delete.device.defc80e0'),
            _tr('ui.source.remove.device.p0.p1.from.the.topology.060345fb',p0=dev.ip,p1=dev.hostname or 'no hostname')
        ):
            return

        del self.devices[index]
        self.update_device_table()
        self.draw_network_map()

    # ------------- CLASSIFICATIE ----------------
    def classify_device(self, hostname, ip, mac):
        hn = (hostname or "").lower()
        if any(x in hn for x in ["print", "printer", "officejet", "laserjet"]):
            return "printer"
        if any(x in hn for x in ["srv", "server", "dc", "fileserver"]):
            return "server"
        if any(x in hn for x in ["nas", "storage"]):
            return "storage"
        if ip.endswith(".1") or ip.endswith(".254"):
            return "gateway/router"
        return "client"

    # ------------- TABEL UPDATEN ----------------
    def update_device_table(self):
        for row in self.device_tree.get_children():
            self.device_tree.delete(row)

        for idx, dev in enumerate(self.devices):
            hostname_display = dev.hostname if dev.hostname else "-"
            note_display = dev.note if dev.note else ""
            ports_display = dev.ports_summary if dev.ports_summary else ""
            self.device_tree.insert(
                "",
                "end",
                iid=str(idx),
                values=(dev.ip, dev.mac, hostname_display, dev.dev_type, getattr(dev,"online_status","unknown"), note_display, ports_display)
            )

    # ------------- EDIT DEVICE ----------------
    def on_device_double_click(self, event):
        item_id = self.device_tree.focus()
        if not item_id:
            return
        try:
            index = int(item_id)
        except ValueError:
            return
        if index < 0 or index >= len(self.devices):
            return
        dev = self.devices[index]
        self.open_note_dialog_for_device(dev)

    def open_note_dialog_for_device(self, dev):
        dialog=tk.Toplevel(self.root)
        dialog.title(_tr('ui.source.host.details.p0.cf553f70',p0=dev.ip))
        dialog.geometry("680x520")
        dialog.transient(self.root)
        dialog.grab_set()

        notebook=ttk.Notebook(dialog)
        notebook.pack(fill="both",expand=True,padx=10,pady=10)

        general=ttk.Frame(notebook)
        services_tab=ttk.Frame(notebook)
        cve_tab=ttk.Frame(notebook)
        notes_tab=ttk.Frame(notebook)
        notebook.add(general,text=_tr('ui.source.algemeen.aedfc952'))
        notebook.add(services_tab,text=_tr('ui.source.services.5cbd5840'))
        notebook.add(cve_tab,text=_tr('ui.source.cve.b3940909'))
        notebook.add(notes_tab,text=_tr('ui.source.opmerkingen.353b8db0'))

        hostname_var=tk.StringVar(value=dev.hostname or "")
        type_var=tk.StringVar(value=dev.dev_type or "client")
        status=getattr(dev,"online_status","unknown")

        fields=[
            ("IP-adres",dev.ip),
            ("MAC-adres",dev.mac or "-"),
            ("Status",status),
            ("Gateway","Ja" if getattr(dev,"is_gateway",False) else "Nee"),
        ]
        for row,(label,value) in enumerate(fields):
            ttk.Label(general,text=label+":").grid(row=row,column=0,sticky="w",padx=8,pady=5)
            ttk.Label(general,text=value).grid(row=row,column=1,sticky="w",padx=8,pady=5)

        ttk.Label(general,text=_tr('ui.source.hostname.76945896')).grid(row=4,column=0,sticky="w",padx=8,pady=5)
        ttk.Entry(general,textvariable=hostname_var,width=38).grid(row=4,column=1,sticky="w",padx=8,pady=5)
        ttk.Label(general,text=_tr('ui.source.device.type.bf52d20a')).grid(row=5,column=0,sticky="w",padx=8,pady=5)
        ttk.Combobox(
            general,textvariable=type_var,
            values=["client","server","printer","storage","gateway/router","iot","transit"],
            state="readonly",width=24
        ).grid(row=5,column=1,sticky="w",padx=8,pady=5)

        service_text=tk.Text(services_tab,wrap="none",height=16)
        service_text.pack(fill="both",expand=True,padx=8,pady=8)
        services=list(getattr(dev,"services",[]) or [])
        if services:
            for svc in services:
                service_text.insert(
                    "end",
                    f"{svc.get('port','-')}/{svc.get('protocol','tcp')}  "
                    f"{svc.get('state','open')}  {svc.get('service','')}  "
                    f"{svc.get('product_version','')}\n"
                )
        else:
            service_text.insert("end",dev.ports_summary or _tr('ui.source.geen.service.version.resultaten.beschikbaar.3057ea3b'))
        service_text.configure(state="disabled")

        cve_text=tk.Text(cve_tab,wrap="word",height=16)
        cve_text.pack(fill="both",expand=True,padx=8,pady=8)
        findings=self.find_cves_for_device(dev)
        if findings:
            for f in findings:
                cve_text.insert("end",f"{f.get('id','-')} — {f.get('label','')}\n")
                cve_text.insert("end",f"Status: {f.get('correlation_state','candidate')} | Confidence: {f.get('confidence',0)}%\n")
                if f.get("evidence"): cve_text.insert("end",f"Evidence: {f['evidence']}\n")
                if f.get("reason"): cve_text.insert("end",f"Reden: {f['reason']}\n")
                cve_text.insert("end","\n")
        else:
            cve_text.insert("end",_tr('ui.source.geen.cve.kandidaten.in.de.lokale.correlatiedat.4ebb38b3'))
        cve_text.configure(state="disabled")

        note_text=tk.Text(notes_tab,wrap="word",height=16)
        note_text.pack(fill="both",expand=True,padx=8,pady=8)
        note_text.insert("1.0",dev.note or "")

        buttons=ttk.Frame(dialog)
        buttons.pack(fill="x",padx=10,pady=(0,10))

        def save():
            dev.hostname=hostname_var.get().strip()
            dev.dev_type=type_var.get().strip() or "client"
            dev.note=note_text.get("1.0","end").strip()
            dialog.destroy()
            self.update_device_table()
            self.draw_network_map()

        ttk.Button(buttons,text=_tr('ui.source.opslaan.2b030208'),command=save).pack(side="right",padx=5)
        ttk.Button(buttons,text=_tr('ui.source.sluiten.fe55d210'),command=dialog.destroy).pack(side="right",padx=5)
        dialog.wait_window()


    # ------------- PORTSCAN MET NMAP ----------------
    @staticmethod
    def _port_span_size(ports_input):
        text=str(ports_input or "").strip()
        if not text or text.lower()=="top-20": return 20
        total=0
        for part in text.split(","):
            part=part.strip()
            if not part: continue
            if "-" in part:
                try:
                    lo,hi=part.split("-",1); lo=int(lo); hi=int(hi)
                    total+=max(0,hi-lo+1)
                except Exception: return 0
            else:
                try: int(part); total+=1
                except Exception: return 0
        return total

    @staticmethod
    def _parse_custom_nmap_params(text):
        raw=str(text or "").strip()
        if not raw: return []
        args=shlex.split(raw,posix=(os.name!="nt"))
        forbidden={"-p","--top-ports","-sT","-sS","-sU","-sV","-Pn"}
        conflicts=[a for a in args if a in forbidden or a.startswith("-p=") or a.startswith("--top-ports=")]
        if conflicts:
            raise ValueError("CAMT beheert poort/protocol zelf; verwijder: "+", ".join(conflicts))
        return args

    def _run_nmap_process(self,cmd,timeout):
        proc=subprocess.Popen(cmd,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
        try:
            stdout,stderr=proc.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            proc.kill(); stdout,stderr=proc.communicate()
            raise RuntimeError(f"Nmap timeout na {timeout}s")
        if proc.returncode not in (0,1):
            raise RuntimeError(stderr.strip() or "Nmap scan failed")
        return stdout,stderr

    @staticmethod
    def _parse_nmap_open_rows(stdout):
        rows=[]
        for line in str(stdout or "").splitlines():
            m=re.match(r"^(\d+)/(tcp|udp)\s+(open|open\|filtered)\s+(\S+)(?:\s+(.*))?$",line.strip())
            if m:
                rows.append({"port":int(m.group(1)),"protocol":m.group(2),"state":m.group(3),
                             "service":m.group(4),"product_version":(m.group(5) or "").strip()})
        return rows

    def _run_nmap_service_pass(self,dev,ports_input,proto,optimized=False,extra_params=""):
        nmap=self._resolve_nmap()
        span=self._port_span_size(ports_input)
        extras=self._parse_custom_nmap_params(extra_params)

        if optimized and ports_input and str(ports_input).lower()!="top-20" and span>1200:
            discovery=[nmap,"-Pn","--open","--max-retries","1"]
            if proto=="udp":
                discovery.extend(["-sU","--host-timeout","300s"])
            else:
                discovery.extend(["-sT","-T4","--host-timeout","240s"])
            discovery.extend(extras)
            discovery.extend(["-p",str(ports_input),dev.ip])
            stdout,_=self._run_nmap_process(discovery,330 if proto=="udp" else 270)
            discovered=self._parse_nmap_open_rows(stdout)
            open_ports=sorted({r["port"] for r in discovered if r["state"] in ("open","open|filtered")})
            if not open_ports:
                return []
            # Version detection only on ports that actually responded.
            version=[nmap,"-sV","--version-light","-Pn"]
            if proto=="udp":
                version.extend(["-sU","--max-retries","1","--host-timeout","240s"])
            else:
                version.extend(["-sT","-T4","--host-timeout","180s"])
            version.extend(extras)
            version.extend(["-p",",".join(map(str,open_ports)),dev.ip])
            vout,_=self._run_nmap_process(version,270 if proto=="udp" else 210)
            parsed=self._parse_nmap_open_rows(vout)
            return parsed or discovered

        # Default: FULL RANGE scan exactly as entered by the user.
        cmd=[nmap,"-sV","--version-light","-Pn"]
        if proto=="udp":
            cmd.extend(["-sU","--max-retries","1"])
        else:
            cmd.extend(["-sT"])

        large_explicit=bool(ports_input and str(ports_input).lower()!="top-20" and span>1200)
        if not large_explicit:
            cmd.extend(["--host-timeout","180s" if proto=="udp" else "150s"])

        cmd.extend(extras)
        if not ports_input or str(ports_input).lower()=="top-20":
            cmd.extend(["--top-ports","20"])
        else:
            cmd.extend(["-p",str(ports_input)])
        cmd.append(dev.ip)

        timeout=(1800 if proto=="udp" else 900) if large_explicit else (240 if proto=="udp" else 190)
        stdout,_=self._run_nmap_process(cmd,timeout)
        return self._parse_nmap_open_rows(stdout)


    @staticmethod
    def _service_rows_summary(rows):
        return ", ".join(
            f"{r['port']}/{r['protocol']} {r['service']}" +
            (f" {r['product_version']}" if r.get("product_version") else "") +
            (f" [{r['state']}]" if r.get("state")=="open|filtered" else "")
            for r in rows
        )

    def _scan_host_services(self, dev, ports_input="top-20", proto="tcp", optimized=False, extra_params="", progress=None):
        protocols=["tcp","udp"] if proto=="tcp+udp" else [proto]
        rows=[]; errors=[]
        for scan_proto in protocols:
            pass_error=None
            try:
                pass_rows=self._run_nmap_service_pass(dev,ports_input,scan_proto,optimized,extra_params)
                rows.extend(pass_rows)
            except Exception as exc:
                pass_rows=[]
                pass_error=f"{scan_proto.upper()}: {exc}"
                errors.append(pass_error)
            unique={(r["port"],r["protocol"],r["service"]):r for r in rows}
            rows=list(unique.values())
            dev.services=list(rows)
            dev.ports_summary=self._service_rows_summary(rows) if rows else "No open ports (or none parsed)"
            if progress is not None:
                progress(scan_proto,list(rows),pass_error)
        if errors and rows:
            dev.ports_summary += " | " + " ; ".join(errors)
        if errors and not rows:
            raise RuntimeError(" ; ".join(errors))
        db=self._vulnerability_db()
        if db is not None:
            try: db.replace_network_services(dev.ip,rows)
            except Exception as exc: print("Could not persist network services:",exc)
        return rows


    def _service_scan_busy(self):
        return self.service_scan_worker is not None and self.service_scan_worker.is_alive()

    def _service_scan_worker_run(self, targets, ports, proto, optimized=False, extra_params="", single=False):
        ok=0; failed=0
        for idx,dev in enumerate(targets,1):
            if self.service_scan_stop_event.is_set():
                break
            try:
                def protocol_progress(scan_proto,partial_rows,error):
                    self.service_scan_queue.put(("partial",idx,len(targets),dev.ip,list(partial_rows),
                                                 {"protocol":scan_proto,"error":error}))
                services=self._scan_host_services(
                    dev,ports,proto,optimized,extra_params,
                    protocol_progress if proto=="tcp+udp" else None
                )
                findings=[]
                db=self._vulnerability_db()
                if db is not None and services:
                    try:
                        findings=db.match_network_vulnerabilities(services)
                        db.save_network_vulnerability_findings(dev.ip,findings)
                        dev.vulnerabilities=findings
                    except Exception as exc:
                        print("CVE correlation failed:",exc)
                self.service_scan_queue.put(("result",idx,len(targets),dev.ip,services,findings))
                ok+=1
            except Exception as exc:
                self.service_scan_queue.put(("error",idx,len(targets),dev.ip,[],str(exc)))
                failed+=1
        self.service_scan_queue.put(("done",ok,failed,"",[], ""))

    def _poll_service_scan_queue(self):
        finished=False
        ok=failed=0
        while True:
            try:
                kind,a,b,ip,services,detail=self.service_scan_queue.get_nowait()
            except queue.Empty:
                break
            if kind=="partial":
                meta=detail if isinstance(detail,dict) else {}
                scan_proto=str(meta.get("protocol") or "").upper()
                dev=next((d for d in self.devices if d.ip==ip),None)
                if dev is not None:
                    dev.services=list(services or [])
                    dev.ports_summary=self._service_rows_summary(dev.services) if dev.services else "No open ports (or none parsed)"
                if meta.get("error"):
                    self.status_label.config(text=_tr('ui.source.tcp.udp.p0.p1.p2.gereed.met.fout.p3.eerder.gev.b74de1dc',p0=a,p1=b,p2=scan_proto,p3=len(services or [])))
                else:
                    self.status_label.config(text=_tr('ui.source.tcp.udp.p0.p1.p2.gereed.p3.cumulatieve.poort.e.724ae719',p0=a,p1=b,p2=scan_proto,p3=len(services or [])))
                self.update_device_table()
                self.draw_network_map()
            elif kind=="result":
                findings=detail if isinstance(detail,list) else []
                states={}
                for f in findings:
                    st=str(f.get("correlation_state") or "candidate")
                    states[st]=states.get(st,0)+1
                suffix=(f" • {len(findings)} CVE-kandidaat/kandidaten" if findings else " • geen CVE-match")
                self.status_label.config(text=_tr('ui.source.service.version.scan.p0.p1.p2.voltooid.p3.a5077747',p0=a,p1=b,p2=ip,p3=suffix))
                self.update_device_table()
                self.draw_network_map()
                try:self._publish_network_report_context()
                except Exception as exc:print("Report context publish failed:",exc)
            elif kind=="error":
                self.status_label.config(text=_tr('ui.source.service.version.scan.p0.p1.p2.fout.p3.909c6ff8',p0=a,p1=b,p2=ip,p3=detail))
            elif kind=="done":
                ok,failed=a,b
                finished=True
        if finished:
            self.status_label.config(text=_tr('ui.source.service.version.scan.complete.p0.geslaagd.p1.m.21871245',p0=ok,p1=failed))
            self._mb_info(_tr('ui.source.service.version.scan.de5f827a'),_tr('ui.source.verwerkt.p0.mislukt.p1.529c8b6a',p0=ok,p1=failed))
            return
        if self._service_scan_busy():
            self.root.after(120,self._poll_service_scan_queue)

    def _start_service_scan(self, targets, ports, proto):
        if self._service_scan_busy():
            self._mb_info(_tr('ui.source.service.version.scan.de5f827a'),_tr('ui.source.er.loopt.al.een.service.poortscan.f691bed4'))
            return False
        optimized=bool(self.scan_optimized_var.get())
        extra_params=self.scan_nmap_params_var.get().strip()
        try:
            self._parse_custom_nmap_params(extra_params)
        except Exception as exc:
            self._mb_error(_tr('ui.source.nmap.parameters.f8d02d54'),str(exc))
            return False
        self.service_scan_stop_event.clear()
        while True:
            try:self.service_scan_queue.get_nowait()
            except queue.Empty:break
        self.service_scan_worker=threading.Thread(
            target=self._service_scan_worker_run,
            args=(targets,ports,proto,optimized,extra_params,False),
            daemon=True
        )
        self.service_scan_worker.start()
        self.root.after(100,self._poll_service_scan_queue)
        return True

    def scan_discovered_hosts(self):
        targets=[d for d in self.devices if self._valid_discovered_host(d.ip)]
        if not targets:
            self._mb_info(_tr('ui.source.scan.gevonden.hosts.afad39f2'),_tr('ui.source.geen.geldige.gevonden.hosts.395139f0')); return
        if not self._resolve_nmap():
            self._mb_error(_tr('ui.source.nmap.ontbreekt.344466f0'),_tr('ui.source.de.camt.nmap.runtime.is.niet.beschikbaar.onder.eea0dfb2')); return
        if not self._mb_askyesno(
            _tr('ui.source.scan.gevonden.hosts.afad39f2'),
            _tr('ui.source.voer.service.version.detectie.uit.op.p0.gevond.73fb2012',p0=len(targets))
        ):
            return
        ports=self.scan_ports_var.get().strip() or "top-20"
        proto=self.scan_proto_var.get()
        if self._start_service_scan(targets,ports,proto):
            strategy="2-fasen" if self.scan_optimized_var.get() else "volledige range"
            self.status_label.config(text=_tr('ui.source.service.version.scan.gestart.op.p0.hosts.p1.p2.887058e3',p0=len(targets),p1=proto.upper(),p2=strategy))


    def run_vulnerability_analysis(self):
        if not self.devices:
            self._mb_info(_tr('ui.source.vulnerability.analysis.416476bf'),_tr('ui.source.geen.devices.om.te.analyseren.0c519a0e')); return

        self.vuln_findings.clear()
        total=0
        pending=0
        db=self._vulnerability_db()

        for dev in self.devices:
            services=list(getattr(dev,"services",[]) or [])
            findings=[]
            if db is not None and services:
                try:
                    findings=db.match_network_vulnerabilities(services)
                    db.save_network_vulnerability_findings(dev.ip,findings)
                except Exception as exc:
                    print("SQLite vulnerability correlation failed:",exc)

            if not findings:
                for item in self._match_vulns_for_device(dev):
                    row=dict(item)
                    row["confidence"]=20
                    row["source"]="legacy-signature"
                    row["evidence"]=dev.ports_summary or ""
                    findings.append(row)

            if findings:
                dev.vulnerabilities=findings
                self.vuln_findings[dev]=findings
                total+=len(findings)
                pending+=sum(1 for f in findings if int(f.get("confidence",0))<50)

        self.draw_network_map()
        try:self._publish_network_report_context()
        except Exception as exc:print("Report context publish failed:",exc)
        self._mb_info(
            _tr('ui.source.vulnerability.analysis.416476bf'),
            _tr('ui.source.analyse.voltooid.hosts.met.kandidaat.bevinding.910416ad',p0=len(self.vuln_findings),p1=total,p2=pending)
        )


    def run_analysis_advice(self):
        if not self.devices:
            self._mb_info(_tr('ui.source.analyse.advies.457bf415'),_tr('ui.source.geen.devices.om.te.analyseren.0c519a0e'));return
        db=self._vulnerability_db()
        rows=[]
        for dev in self.devices:
            services=list(getattr(dev,"services",[]) or [])
            exposures=db.analyze_service_exposures(services) if db is not None else []
            cves=self.find_cves_for_device(dev)
            # Promote the displayed analysis stage using available correlation evidence.
            for exp in exposures:
                related=[c for c in cves if f"{exp['port']}/" in str(c.get("evidence",""))]
                if related:
                    best=max(related,key=lambda x:int(x.get("confidence",0)))
                    cstate=str(best.get("correlation_state") or "")
                    if cstate=="version_match":
                        exp["stage"]="Version Match → CVE Candidate"
                        exp["confidence"]=max(exp["confidence"],int(best.get("confidence",0)))
                    elif cstate in ("product_match","package_validation_required"):
                        exp["stage"]="Product Candidate → CVE Candidate"
                        exp["confidence"]=max(exp["confidence"],int(best.get("confidence",0)))
                    exp["cves"]=related
                else:
                    exp["cves"]=[]
                rows.append((dev,exp))

        win=tk.Toplevel(self.root);win.title(_tr('ui.source.analyse.advies.network.mapper.d57ffec7'));win.geometry("1120x700")
        nb=ttk.Notebook(win);nb.pack(fill="both",expand=True,padx=8,pady=8)
        obs=ttk.Frame(nb);ana=ttk.Frame(nb);adv=ttk.Frame(nb)
        nb.add(obs,text=_tr('ui.source.observaties.cc40408c'));nb.add(ana,text=_tr('ui.source.analyse.28b6dc31'));nb.add(adv,text=_tr('ui.source.aanbevelingen.ef66dbf4'))

        tree=ttk.Treeview(obs,columns=("host","port","service","severity","stage","cves"),show="headings")
        for col,label,width in (("host","Host",130),("port","Poort",80),("service","Service",130),
                                ("severity","Exposure",90),("stage","Analysefase",260),("cves","CVE",280)):
            tree.heading(col,text=label);tree.column(col,width=width,anchor="w")
        tree.pack(fill="both",expand=True,padx=6,pady=6)
        for dev,exp in rows:
            cvetxt=", ".join(c.get("id","") for c in exp.get("cves",[])) or "-"
            tree.insert("", "end", values=(dev.ip,f"{exp['port']}/{exp['protocol']}",exp["service"],
                        exp["severity"],exp["stage"],cvetxt))

        analysis_text=tk.Text(ana,wrap="word")
        analysis_text.pack(fill="both",expand=True,padx=8,pady=8)
        if rows:
            for dev,exp in rows:
                analysis_text.insert("end",f"{dev.ip} — {exp['port']}/{exp['protocol']} {exp['service']}\n")
                analysis_text.insert("end",f"{exp['severity']} • {exp['category']} • {exp['stage']}\n")
                analysis_text.insert("end",exp["rationale"]+"\n")
                if exp.get("note"):analysis_text.insert("end",exp["note"]+"\n")
                if exp.get("cves"):
                    analysis_text.insert("end","CVE-correlatie: "+", ".join(
                        f"{c.get('id')} ({c.get('correlation_state')}, {c.get('confidence')}%)" for c in exp["cves"])+"\n")
                analysis_text.insert("end","\n")
        else:
            analysis_text.insert("end",_tr('ui.source.geen.service.exposures.uit.de.huidige.catalogu.3d6dd2a0'))
        analysis_text.configure(state="disabled")

        advice_text=tk.Text(adv,wrap="word")
        advice_text.pack(fill="both",expand=True,padx=8,pady=8)
        seen=set()
        for dev,exp in rows:
            key=(exp["exposure_id"],exp["next_action"])
            if key in seen:continue
            seen.add(key)
            advice_text.insert("end",f"• {exp['severity']} — {exp['title']}\n  {exp['next_action']}\n\n")
        if not rows:
            advice_text.insert("end","Voer service/version-detectie uit of breid de Service Exposure Catalog uit.")
        advice_text.configure(state="disabled")

        # Refresh report context so the report receives the current observations/CVE advice.
        try:self._publish_network_report_context()
        except Exception as exc:print("Report context publish failed:",exc)

        buttons=ttk.Frame(win);buttons.pack(fill="x",padx=8,pady=(0,8))
        ttk.Button(buttons,text=_tr('ui.source.sluiten.fe55d210'),command=win.destroy).pack(side="right")

    def port_scan_selected(self):
        item_id=self.device_tree.focus()
        if not item_id:
            self._mb_warning(_tr('ui.source.no.selection.915cf89a'),_tr('ui.source.select.a.host.first.in.the.device.list.8794b816')); return
        try:index=int(item_id)
        except ValueError:
            self._mb_warning(_tr('ui.source.error.7f2f6a15'),_tr('ui.source.invalid.selection.6cd5f8b0')); return
        if index<0 or index>=len(self.devices):
            self._mb_warning(_tr('ui.source.error.7f2f6a15'),_tr('ui.source.invalid.selection.6cd5f8b0')); return
        dev=self.devices[index]
        if not dev.ip or dev.ip in ("router","0.0.0.0"):
            self._mb_warning(_tr('ui.source.invalid.target.30f5d311'),_tr('ui.source.this.entry.does.not.have.a.valid.ip.to.scan.0e3c10e9')); return
        if not self._resolve_nmap():
            self._mb_error(_tr('ui.source.nmap.ontbreekt.344466f0'),_tr('ui.source.de.camt.nmap.runtime.is.niet.beschikbaar.onder.eea0dfb2')); return

        proto=self.scan_proto_var.get()
        ports_input=self.scan_ports_var.get().strip() or "top-20"
        ports_desc="top-20 ports" if ports_input.lower()=="top-20" else ports_input
        if not self._mb_askyesno(
            _tr('ui.source.port.scan.4608fea9'),
            _tr('ui.source.run.nmap.port.scan.on.p0.protocol.p1.ports.p2..558218e4',p0=dev.ip,p1=proto,p2=ports_desc)
        ):
            return
        if self._start_service_scan([dev],ports_input,proto):
            self.status_label.config(text=_tr('ui.source.port.scan.gestart.op.p0.p1.2cb5ce87',p0=dev.ip,p1=proto.upper()))


    def add_traceroute_hops_to_devices(self, hops, target):
        """
        Voeg traceroute-hops toe als 'transit' nodes in self.devices.
        hops = lijst dicts: {"hop": int, "ip": "x.x.x.x"}
        """
        created = 0
        ip_to_dev = {}

        # Zorg dat transit-devices bestaan
        for h in hops:
            ip = h.get("ip")
            if not ip or ip == "*":
                continue

            # Bestaand device?
            existing = next((d for d in self.devices if d.ip == ip), None)
            if existing:
                # als het nog geen transit is, laten we het type met rust
                ip_to_dev[ip] = existing
                continue

            note = f"Traceroute hop {h.get('hop')} naar {target}"
            dev = Device(
                ip=ip,
                mac="",
                hostname="",
                dev_type="transit",
                note=note
            )
            self.devices.append(dev)
            ip_to_dev[ip] = dev
            created += 1

        # Volgorde van hops bewaren
        self.last_traceroute_hops = []
        for h in hops:
            ip = h.get("ip")
            if not ip or ip not in ip_to_dev:
                continue
            self.last_traceroute_hops.append((h["hop"], ip_to_dev[ip]))

        # UI updaten
        self.update_device_table()
        self.draw_network_map()

        if created:
            self.status_label.config(
                text=_tr('ui.source.traceroute.p0.hops.p1.nieuwe.transit.nodes.toe.cab753f9',p0=len(hops),p1=created)
            )
        else:
            self.status_label.config(
                text=_tr('ui.source.traceroute.p0.hops.geen.nieuwe.nodes.allen.al..26bb3a4e',p0=len(hops))
            )


    # ------------- CANVAS-KLIKS & SLEPEN & HIGHLIGHTS ----------------
    def on_canvas_button_press(self, event):
        # 1) Zone-tekenmodus: twee klikken voor twee hoekpunten
        if self.zone_mode:
            # coord naar logische coördinaten
            lx = event.x / self.zoom
            ly = event.y / self.zoom

            if self.zone_start is None:
                # eerste hoekpunt
                self.zone_start = (lx, ly)
                self.status_label.config(text=_tr('ui.source.zone.mode.klik.het.tweede.hoekpunt.9f9ab0b2'))
            else:
                # tweede hoekpunt -> zone opslaan
                x1, y1 = self.zone_start
                x2, y2 = lx, ly

                # zorg dat x1<x2 en y1<y2
                if x2 < x1:
                    x1, x2 = x2, x1
                if y2 < y1:
                    y1, y2 = y2, y1

                # minimale grootte
                if abs(x2 - x1) < 10 or abs(y2 - y1) < 10:
                    self.status_label.config(text=_tr('ui.source.zone.te.klein.probeer.opnieuw.00d3b99f'))
                else:
                    label = (self.zone_label_var.get() or "").strip()
                    if not label:
                        label = self.zone_type_var.get()
                    ztype = self.zone_type_var.get()
                    color = self._get_zone_color(ztype)

                    self.zones.append({
                        "x1": x1, "y1": y1,
                        "x2": x2, "y2": y2,
                        "label": label,
                        "type": ztype,
                        "color": color,
                    })
                    self.status_label.config(text=_tr('ui.source.zone.p0.toegevoegd.ae71f2f7',p0=label))
                    self.draw_network_map()

                # klaar met deze zone
                self.zone_start = None
                self.zone_mode = False

            return  # NIET verder gaan (anders ook drag-logica triggert)

        # 2) Annotatie-modus (bestond al)
        if self.annotation_mode:
            self.annotation_mode = False
            self.place_annotation_at(event.x, event.y)
            return

        # 3) Asset-library placement mode.
        if getattr(self, "topology_tool", "select") == "add" and getattr(self, "topology_palette_type", None):
            self._add_topology_asset(self.topology_palette_type, event.x, event.y)
            return

        # 4) Device/annotation slepen / connect-tool
        item = self.map_canvas.find_withtag("current")
        if item:
            info = self.canvas_item_map.get(item[0], {})
            dev = info.get("device") if info.get("kind") in ("device", "router") else None
            if dev is not None:
                self.topology_selected_device = dev
                self._refresh_topology_inspector_panel()
                if getattr(self, "topology_tool", "select") == "connect":
                    self._topology_connect_click(dev)
                    return
        self.drag_device = None
        self.drag_annotation = None

        item = self.map_canvas.find_withtag("current")
        if not item:
            return

        item_id = item[0]
        info = self.canvas_item_map.get(item_id)
        if not info:
            return

        kind = info.get("kind")

        if kind == "annotation":
            ann = info.get("annotation")
            if ann:
                self.drag_annotation = ann
                self.drag_last_x = event.x
                self.drag_last_y = event.y
            return

        if kind in ("device","router"):
            dev = info.get("device")
            if dev:
                self.drag_device = dev
                self.drag_last_x = event.x
                self.drag_last_y = event.y

    def _get_zone_color(self, zone_type: str) -> str:
        zone_type = (zone_type or "").lower()
        if zone_type == "dmz":
            return "#fff3cd"   # lichtgeel
        if zone_type == "intranet":
            return "#d4edda"   # lichtgroen
        if zone_type == "extranet":
            return "#d1ecf1"   # lichtblauw
        if zone_type == "untrusted":
            return "#f8d7da"   # lichtrood
        return "#e2e3e5"       # grijs voor 'other'


    def edit_annotation_dialog(self, ann):
        dialog = tk.Toplevel(self.root)
        dialog.title(_tr('ui.source.edit.annotation.ac65c275'))
        dialog.geometry("400x260")
        dialog.transient(self.root)
        dialog.grab_set()

        frame = ttk.Frame(dialog)
        frame.pack(fill="both", expand=True, padx=10, pady=10)

        ttk.Label(frame, text=_tr('ui.source.text.0a328f24')).grid(row=0, column=0, sticky="w")
        txt_var = tk.StringVar(value=ann.get("text", ""))
        txt_entry = ttk.Entry(frame, textvariable=txt_var, width=40)
        txt_entry.grid(row=0, column=1, sticky="w", pady=4)

        ttk.Label(frame, text=_tr('ui.source.color.511a0006')).grid(row=1, column=0, sticky="w")
        color_var = tk.StringVar(value=ann.get("color", "yellow"))
        color_combo = ttk.Combobox(
            frame, textvariable=color_var,
            state="readonly",
            values=["yellow", "lightblue", "lightgreen", "pink", "orange"]
        )
        color_combo.grid(row=1, column=1, sticky="w", pady=4)

        ttk.Label(frame, text=_tr('ui.source.shape.14edb2c4')).grid(row=2, column=0, sticky="w")
        shape_var = tk.StringVar(value=ann.get("shape", "rect"))
        shape_combo = ttk.Combobox(
            frame, textvariable=shape_var,
            state="readonly",
            values=["rect", "oval"]
        )
        shape_combo.grid(row=2, column=1, sticky="w", pady=4)

        btn_frame = ttk.Frame(dialog)
        btn_frame.pack(fill="x", padx=10, pady=10)

        def on_save():
            ann["text"] = txt_var.get()
            ann["color"] = color_var.get()
            ann["shape"] = shape_var.get()
            dialog.destroy()
            self.draw_network_map()

        def on_delete():
            if self._mb_askyesno(_tr('ui.source.delete.annotation.e4cb0d4b'), _tr('ui.source.deze.note.verwijderen.82e692b9')):
                try:
                    self.annotations.remove(ann)
                except ValueError:
                    pass
                dialog.destroy()
                self.draw_network_map()

        ttk.Button(btn_frame, text=_tr('ui.source.delete.f6fdbe48'), command=on_delete).pack(side="left")
        ttk.Button(btn_frame, text=_tr('ui.source.save.efc007a3'), command=on_save).pack(side="right", padx=5)
        ttk.Button(btn_frame, text=_tr('ui.source.cancel.77dfd213'), command=dialog.destroy).pack(side="right")

        txt_entry.focus()
        dialog.wait_window()

    def on_canvas_left_click(self, event):
        """
        Behandel een (double) left-click op de kaart:
        - devices: note/host-edit dialoog
        - router: simpele router-info
        - switch: info over subnet/hosts
        - annotation: annotatie bewerken/verwijderen
        """
        item = self.map_canvas.find_withtag("current")
        if not item:
            return

        item_id = item[0]
        info = self.canvas_item_map.get(item_id)
        if not info:
            return

        kind = info.get("kind")

        if kind == "device":
            dev = info.get("device")
            if dev:
                self.open_note_dialog_for_device(dev)

        elif kind == "router":
            dev = info.get("device")
            if dev:
                # Gateway/router is an asset too: same detail/note editor as hosts.
                self.open_note_dialog_for_device(dev)

        elif kind == "switch":
            subnet = info.get("subnet")
            hosts = info.get("hosts", [])
            msg = f"Switch in subnet {subnet}\nAantal hosts: {len(hosts)}"
            self._mb_info(_tr('ui.source.switch.info.4d25f857'), msg)

        elif kind == "annotation":
            ann = info.get("annotation")
            if ann:
                self.edit_annotation_dialog(ann)
                
        elif kind == "vuln_marker":
            dev = info.get("device")
            findings = info.get("findings") or self.vuln_findings.get(dev, [])
            if not dev or not findings:
                return

            lines = [f"Demo-CVE matches voor {dev.ip}:", ""]
            for sig in findings:
                lines.append(f"- {sig['id']} [{sig['risk']}]")
                lines.append(f"  {sig['label']}")
                lines.append("")
            self._mb_info(_tr('ui.source.cve.overlay.demo.1199569a'), "\n".join(lines))



    def on_canvas_right_click(self, event):
        item = self.map_canvas.find_withtag("current")
        if not item:
            return
        item_id = item[0]
        info = self.canvas_item_map.get(item_id)
        if not info:
            return

        if info.get("kind") in ("link", "host_link"):
            orig = info.get("orig_color", HOST_LINK_COLOR)
            current = self.map_canvas.itemcget(item_id, "fill")
            if current != HIGHLIGHT_COLOR:
                self.map_canvas.itemconfig(item_id, fill=HIGHLIGHT_COLOR, width=3)
            else:
                self.map_canvas.itemconfig(item_id, fill=orig, width=1)
                
                
                
                

    def reset_link_colors(self):
        for item_id, info in self.canvas_item_map.items():
            if info.get("kind") in ("link", "host_link"):
                orig = info.get("orig_color", HOST_LINK_COLOR)
                self.map_canvas.itemconfig(item_id, fill=orig, width=1)



    def place_annotation_at(self, x, y):
        """
        Maak een nieuwe annotation op canvas-coord (x,y),
        sla logisch op (gedeeld door zoom) en teken 'm.
        """
        text = (self.anno_text_var.get() or "").strip()
        if not text:
            return

        color = self.anno_color_var.get() or "yellow"
        shape = self.anno_shape_var.get() or "rect"

        # logische coords, zodat zoom werkt
        lx = x / self.zoom
        ly = y / self.zoom

        ann = {
            "x": lx,
            "y": ly,
            "text": text,
            "color": color,
            "shape": shape,
        }
        self.annotations.append(ann)

        # Kaart opnieuw tekenen (makkelijkste, alles is al centraal daar)
        self.draw_network_map()
        self.status_label.config(text=_tr('ui.source.annotatie.geplaatst.a51b4594'))

    def on_canvas_mouse_drag(self, event):
        if not self.drag_device:
            return

        dx=event.x-self.drag_last_x
        dy=event.y-self.drag_last_y
        self.drag_last_x=event.x
        self.drag_last_y=event.y

        items=self.device_canvas_items.get(self.drag_device,{})
        oval_id=items.get("oval")
        group_tag=items.get("tag")
        line_id=items.get("link")

        # Every visual part of the host has the same tag: background/ring,
        # status marker, vector icon and label move as one object.
        if group_tag:
            self.map_canvas.move(group_tag,dx,dy)
        else:
            for cid in (items.get("oval"),items.get("icon"),items.get("label")):
                if cid:
                    self.map_canvas.move(cid,dx,dy)

        if line_id:
            info=self.canvas_item_map.get(line_id,{})
            sx=info.get("switch_x")
            sy=info.get("switch_y")
            if sx is not None and sy is not None and oval_id:
                coords=self.map_canvas.coords(oval_id)
                if len(coords)>=4:
                    cx=(coords[0]+coords[2])/2.0
                    cy=(coords[1]+coords[3])/2.0
                    self.map_canvas.coords(line_id,sx,sy,cx,cy)

        self._update_scrollregion()


    def on_canvas_button_release(self, event):
        # 1) Annotation loslaten
        if self.drag_annotation is not None:
            key = id(self.drag_annotation)
            items = self.annotation_canvas_items.get(key, {})
            box_id = items.get("box")

            if box_id:
                x1, y1, x2, y2 = self.map_canvas.coords(box_id)
                # we nemen de linkerbovenhoek als referentie
                self.drag_annotation["x"] = x1 / self.zoom
                self.drag_annotation["y"] = y1 / self.zoom

            self.drag_annotation = None
            return

        # 2) Device loslaten
        if self.drag_device:
            items = self.device_canvas_items.get(self.drag_device, {})
            oval_id = items.get("oval")
            if oval_id:
                x1, y1, x2, y2 = self.map_canvas.coords(oval_id)
                cx = (x1 + x2) / 2.0
                cy = (y1 + y2) / 2.0
                # sla logische positie op (gecorrigeerd voor zoom)
                self.drag_device.pos_x = cx / self.zoom
                self.drag_device.pos_y = cy / self.zoom
                if getattr(self, "topology_snap_grid_var", None) is not None and self.topology_snap_grid_var.get():
                    self.drag_device.pos_x = round(self.drag_device.pos_x / 25.0) * 25.0
                    self.drag_device.pos_y = round(self.drag_device.pos_y / 25.0) * 25.0

            moved=self.drag_device
            self.drag_device = None
            if getattr(moved,"dev_type","")=="gateway/router" or getattr(moved,"is_gateway",False):
                self.draw_network_map()


    # ------------- NETWERKKAART TEKENEN ----------------
    def _device_relation_key(self, dev):
        return str(getattr(dev, "asset_id", "") or getattr(dev, "ip", "") or getattr(dev, "hostname", ""))

    def _draw_explicit_topology_map(self, show_labels):
        """Render imported CAMT asset relationships using their authored positions.

        This avoids replacing a cyber-physical topology with synthetic /24 subnet
        switches. Native scan results without explicit relationships keep the classic
        subnet rendering path.
        """
        # Assign a compact grid only to assets without authored coordinates.
        missing=[d for d in self.devices if d.pos_x is None or d.pos_y is None]
        for i,dev in enumerate(missing):
            dev.pos_x=120+(i%6)*150
            dev.pos_y=120+(i//6)*130

        by_key={self._device_relation_key(d): d for d in self.devices if self._device_relation_key(d)}
        # Also accept common aliases used by scenario/topology exporters.
        for d in self.devices:
            if d.ip: by_key.setdefault(str(d.ip), d)
            if d.hostname: by_key.setdefault(str(d.hostname), d)

        # Relationships first, so devices remain visually on top.
        for rel in self.relationships:
            rel_filter=(self.topology_relation_filter_var.get() if hasattr(self,"topology_relation_filter_var") else "All").lower()
            rel_type=str(rel.get("relation_type") or rel.get("type") or rel.get("kind") or "Observed")
            if rel_filter!="all" and rel_type.lower()!=rel_filter:
                continue
            source=str(rel.get("source") or rel.get("from") or "")
            target=str(rel.get("target") or rel.get("to") or "")
            a=by_key.get(source); b=by_key.get(target)
            if not a or not b: continue
            x1=float(a.pos_x)*self.zoom; y1=float(a.pos_y)*self.zoom
            x2=float(b.pos_x)*self.zoom; y2=float(b.pos_y)*self.zoom
            directed=bool(rel.get("directed", True))
            line_id=self.map_canvas.create_line(
                x1,y1,x2,y2,fill="#7a8796",width=max(1,int(1.5*self.zoom)),
                arrow=(tk.LAST if directed else tk.NONE),smooth=True
            )
            self.canvas_item_map[line_id]={"kind":"explicit_link","relationship":rel,"orig_color":"#7a8796"}
            label=str(rel.get("label") or rel.get("type") or "").strip()
            if label and self._map_label_detail()>=2:
                lid=self.map_canvas.create_text((x1+x2)/2,(y1+y2)/2-7*self.zoom,text=label,
                    font=("Segoe UI",max(5,int(6*self.zoom))),fill="#55616f")
                self.canvas_item_map[lid]={"kind":"explicit_link_label","relationship":rel}

        for dev in self.devices:
            x=float(dev.pos_x)*self.zoom; y=float(dev.pos_y)*self.zoom
            if dev.dev_type=="gateway/router" or getattr(dev,"is_gateway",False):
                self._draw_router_node(x,y,dev,show_labels)
            else:
                oval_id,icon_id,label_id=self._draw_device_node(x,y,dev,show_labels)
                self.device_canvas_items[dev]={"oval":oval_id,"icon":icon_id,"label":label_id,"link":None,"tag":f"device-{id(dev)}"}
        self._draw_annotations()
        self._update_scrollregion()

    def draw_network_map(self):
        self.map_canvas.delete("all")
        self._draw_topology_grid()
        self.canvas_item_map = {}
        self.device_canvas_items = {}
        self.annotation_canvas_items = {}

        if not self.devices:
            self.map_canvas.create_text(
                400, 200,
                text=_tr('ui.source.no.devices.found.run.a.network.scan.or.add.dev.3065fcc6'),
                font=("Arial", 14)
            )
            return

        width = self.map_canvas.winfo_width()
        height = self.map_canvas.winfo_height()
        if width < 200:
            width = 1000
        if height < 200:
            height = 600

        # logische afmetingen (voor zoom)
        base_w = width / self.zoom
        base_h = height / self.zoom
        if not hasattr(self,"topology_show_zones_var") or self.topology_show_zones_var.get():
            self._draw_zones()
        show_labels = self.show_labels_var.get()

        if getattr(self, "relationships", None):
            self._draw_explicit_topology_map(show_labels)
            return

        routers = [d for d in self.devices if d.dev_type == "gateway/router"]
        non_routers = [d for d in self.devices 
        if d.dev_type not in ("gateway/router")
        ]

        # Subnets (/24)
        subnets = {}
        for dev in non_routers:
            if dev.ip:
                parts = dev.ip.split(".")
                if len(parts) == 4:
                    subnet_key = f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
                else:
                    subnet_key = "unknown"
            else:
                subnet_key = "unknown"
            subnets.setdefault(subnet_key, []).append(dev)

        router_y0 = base_h * 0.2
        router_count = max(1, len(routers))
        router_spacing0 = base_w / (router_count + 1)

        router_positions = []
        if routers:
            for i, r in enumerate(routers, start=1):
                # Manual router/gateway/entry-point placement has precedence.
                x0 = float(r.pos_x) if r.pos_x is not None else router_spacing0 * i
                y0 = float(r.pos_y) if r.pos_y is not None else router_y0
                router_positions.append((x0, y0, r))
        else:
            x0 = base_w / 2
            dummy = Device(ip="router", mac="", hostname="Logical router", dev_type="gateway/router")
            routers = [dummy]
            router_positions.append((x0, router_y0, dummy))

        subnet_keys = list(subnets.keys())
        if not subnet_keys:
            for (rx0, ry0, r) in router_positions:
                self._draw_router_node(rx0 * self.zoom, ry0 * self.zoom, r, show_labels)
            # ook traceroute-overlay, zelfs als nog geen subnets zijn
            self._draw_traceroute_path(base_w, base_h, router_positions)
            self._draw_annotations()
            self._update_scrollregion()
            return


        subnet_count = len(subnet_keys)
        subnet_row_y0 = base_h * 0.65
        subnet_spacing0 = base_w / (subnet_count + 1)

        # Routers tekenen (OSINT stijl)
        for (rx0, ry0, router_dev) in router_positions:
            self._draw_router_node(rx0 * self.zoom, ry0 * self.zoom, router_dev, show_labels)

        # Subnets + hosts + lijntjes naar hosts
        for idx, subnet_key in enumerate(subnet_keys, start=1):
            cx0 = subnet_spacing0 * idx
            cy0 = subnet_row_y0

            box_width0 = 200 if len(self.devices)>25 else 230
            box_height0 = 180 if len(self.devices)>25 else 205
            x1 = (cx0 - box_width0 / 2) * self.zoom
            y1 = (cy0 - box_height0 / 2) * self.zoom
            x2 = (cx0 + box_width0 / 2) * self.zoom
            y2 = (cy0 + box_height0 / 2) * self.zoom

            self.map_canvas.create_rectangle(
                x1, y1, x2, y2,
                outline="#aaaaaa"
            )
            self.map_canvas.create_text(
                cx0 * self.zoom, (cy0 - box_height0 / 2 + 10) * self.zoom,
                text=_tr('ui.source.subnet.p0.b3c113e0',p0=subnet_key),
                font=("Arial", int(9 * self.zoom))
            )

            # Switch in subnet (OSINT stijl)
            switch_y0 = cy0 - box_height0 / 2 + 50
            sw_r0 = 18
            sw_x = cx0 * self.zoom
            sw_y = switch_y0 * self.zoom
            sw_r = sw_r0 * self.zoom

            sw_id = self.map_canvas.create_oval(
                sw_x - sw_r, sw_y - sw_r,
                sw_x + sw_r, sw_y + sw_r,
                fill=SWITCH_COLOR, outline="black"
            )
            self.map_canvas.create_text(sw_x, sw_y, text=_tr('ui.source.text.276d947e'), font=("Arial", int(12 * self.zoom)))
            hosts = subnets[subnet_key]
            self.canvas_item_map[sw_id] = {
                "kind": "switch",
                "subnet": subnet_key,
                "hosts": hosts
            }

            # Hosts
            h_count = len(hosts)
            if h_count > 0:
                radius0 = 48 if len(self.devices)>25 else 60
                center_hosts_y0 = switch_y0 + 80
                for i, dev in enumerate(hosts):
                    # logische positie
                    if dev.pos_x is not None and dev.pos_y is not None:
                        hx0 = dev.pos_x
                        hy0 = dev.pos_y
                    else:
                        angle = 2 * math.pi * i / h_count
                        hx0 = cx0 + radius0 * math.cos(angle)
                        hy0 = center_hosts_y0 + radius0 * math.sin(angle)
                        dev.pos_x = hx0
                        dev.pos_y = hy0

                    hx = hx0 * self.zoom
                    hy = hy0 * self.zoom

                    # Lijn van switch naar host (OSINT kleur)
                    line_start_y = sw_y + sw_r
                    link_id = self.map_canvas.create_line(
                        sw_x, line_start_y,
                        hx, hy,
                        fill=HOST_LINK_COLOR
                    )
                    self.canvas_item_map[link_id] = {
                        "kind": "host_link",
                        "orig_color": HOST_LINK_COLOR,
                        "device": dev,
                        "switch_x": sw_x,
                        "switch_y": line_start_y,
                    }

                    # Host node tekenen
                    oval_id, icon_id, label_id = self._draw_device_node(hx, hy, dev, show_labels)

                    self.device_canvas_items[dev] = {
                        "oval": oval_id,
                        "icon": icon_id,
                        "label": label_id,
                        "link": link_id,
                        "tag": f"device-{id(dev)}",
                    }

            # Lijn router → switch (OSINT kleur)
            for (rx0, ry0, router_dev) in router_positions:
                rx = rx0 * self.zoom
                ry = ry0 * self.zoom
                link_id = self.map_canvas.create_line(
                    rx, ry + 25 * self.zoom,
                    sw_x, sw_y - sw_r,
                    fill=ROUTER_LINK_COLOR,
                    dash=(3, 3)
                )
                self.canvas_item_map[link_id] = {
                    "kind": "link",
                    "orig_color": ROUTER_LINK_COLOR
                }
        # Zones are already drawn as the background before nodes. Do NOT draw
        # them again here: a second zone rectangle would cover imported nodes
        # and intercept drag/double-click hit testing.
        # Traceroute-baan BOVEN de routers (indien aanwezig)
        self._draw_traceroute_path(base_w, base_h, router_positions)

        # Tekstvak-annotaties bovenop alles tekenen
        self._draw_annotations()

        # Blue Team attack path: pad van compromised hosts naar internet highlighten
        self._highlight_attack_path(router_positions)

        # Mini-legenda
        self._draw_legend()

        self._update_scrollregion()

    def _draw_zones(self):
        """Teken alle zones als semi-transparante vlakken op de achtergrond."""
        if not self.zones:
            return

        for z in self.zones:
            x1v=z.get("x1",z.get("x0")); y1v=z.get("y1",z.get("y0"))
            x2v=z.get("x2"); y2v=z.get("y2")
            if x2v is None and z.get("x0") is not None:
                x2v=z.get("x1"); x1v=z.get("x0")
            if y2v is None and z.get("y0") is not None:
                y2v=z.get("y1"); y1v=z.get("y0")
            if None in (x1v,y1v,x2v,y2v):
                continue
            x1 = float(x1v) * self.zoom
            y1 = float(y1v) * self.zoom
            x2 = float(x2v) * self.zoom
            y2 = float(y2v) * self.zoom
            color = z.get("color", self._get_zone_color(z.get("type", "")))
            rect_id = self.map_canvas.create_rectangle(
                x1, y1, x2, y2,
                fill=color,
                outline=color,
                stipple="gray25"   # geeft mooi “doorzichtig” effect op veel systemen
            )
            self.canvas_item_map[rect_id] = {"kind": "zone", "zone": z}

            label = z.get("label", "")
            if label:
                self.map_canvas.create_text(
                    (x1 + x2) / 2,
                    y1 + 14 * self.zoom,
                    text=label,
                    font=("Arial", int(9 * self.zoom), "bold"),
                    fill="#333333"
                )

    def clear_zones(self):
        if not self.zones:
            return
        if not self._mb_askyesno(_tr('ui.source.zones.182e2eb7'), _tr('ui.source.alle.zones.verwijderen.c05f65fa')):
            return
        self.zones.clear()
        self.draw_network_map()
        self.status_label.config(text=_tr('ui.source.alle.zones.verwijderd.45318042'))


    def _highlight_attack_path(self, router_positions):
        """
        Highlight het pad van 'compromised' hosts richting de router en verder
        naar de traceroute-target (indien traceroute is gedaan).
        Simpel model:
        - host_link-lijnen van compromised devices rood & dik
        - alle router 'link' en 'trace_link' lijnen rood & dik
        """
        compromised = [d for d in self.devices if d.dev_type == "compromised"]
        if not compromised:
            return

        # host_link lijnen van compromised devices
        for item_id, info in self.canvas_item_map.items():
            if info.get("kind") == "host_link" and info.get("device") in compromised:
                self.map_canvas.itemconfig(item_id, fill=HIGHLIGHT_COLOR, width=3)

        # router↔switch links + traceroute links als 'route naar internet'
        for item_id, info in self.canvas_item_map.items():
            if info.get("kind") in ("link", "trace_link"):
                self.map_canvas.itemconfig(item_id, fill=HIGHLIGHT_COLOR, width=3)


    def _zone_color_from_type(self, zone_type):
        """
        Map zone type to canvas-fill kleur.
        (Geen alpha in Tkinter, dus zachte pastelkleuren gebruiken.)
        """
        if zone_type == "dmz":
            return "#ffe0e0"  # zacht rood
        if zone_type == "intranet":
            return "#e0ffe0"  # zacht groen
        if zone_type == "extranet":
            return "#e0f0ff"  # licht blauw
        if zone_type == "custom-yellow":
            return "#fff8cc"
        # fallback
        return "#f0f0f0"

    def _draw_zones(self):
        """Teken alle zones als grote vlakken achter de hosts."""
        if not getattr(self, "zones", None):
            return

        for zone in self.zones:
            x1v=zone.get("x1",zone.get("x0"))
            y1v=zone.get("y1",zone.get("y0"))
            x2v=zone.get("x2")
            y2v=zone.get("y2")
            if x2v is None and zone.get("x0") is not None:
                x2v=zone.get("x1")
                x1v=zone.get("x0")
            if y2v is None and zone.get("y0") is not None:
                y2v=zone.get("y1")
                y1v=zone.get("y0")
            if None in (x1v,y1v,x2v,y2v):
                continue
            x1 = float(x1v) * self.zoom
            y1 = float(y1v) * self.zoom
            x2 = float(x2v) * self.zoom
            y2 = float(y2v) * self.zoom
            color = zone.get("color", "#d0e0ff")
            name = zone.get("name") or zone.get("label") or "Zone"

            rect_id = self.map_canvas.create_rectangle(
                x1, y1, x2, y2,
                fill=color,
                outline=color,
                stipple="gray25"   # beetje “transparant”
            )
            text_id = self.map_canvas.create_text(
                x1 + 10 * self.zoom,
                y1 + 10 * self.zoom,
                anchor="nw",
                text=name,
                font=("Arial", int(10 * self.zoom), "bold")
            )

            self.canvas_item_map[rect_id] = {"kind": "zone", "zone": zone}
            self.canvas_item_map[text_id] = {"kind": "zone", "zone": zone}

      
    def _draw_legend(self):
        """
        Kleine legenda linksboven op de kaart met kleuren/emoji uitleg.
        """
        pad = 10 * self.zoom
        x0 = pad
        y0 = pad
        w = 230 * self.zoom
        h = 150 * self.zoom

        box_id = self.map_canvas.create_rectangle(
            x0, y0, x0 + w, y0 + h,
            fill="#f9f9f9",
            outline="#bbbbbb"
        )
        self.canvas_item_map[box_id] = {"kind": "legend"}

        entries = [
            (ROUTER_COLOR, "🌐 Router / internet edge"),
            (SWITCH_COLOR, "🔀 Switch / subnet core"),
            (CLIENT_COLOR, "💻 Client / workstation"),
            (SERVER_COLOR, "🗄️ Server / infra"),
            (IOT_COLOR, "📱 IoT / BYOD"),
            (PRINTER_COLOR, "🖨️ Printer"),
            ("#ffb3b3", "☠️ Compromised host"),
            (HIGHLIGHT_COLOR, "Attack path highlight"),
        ]

        y = y0 + 8 * self.zoom
        for color, label in entries:
            sw = 14 * self.zoom
            rect_id = self.map_canvas.create_rectangle(
                x0 + 8 * self.zoom,
                y,
                x0 + 8 * self.zoom + sw,
                y + sw,
                fill=color,
                outline="#333333"
            )
            self.canvas_item_map[rect_id] = {"kind": "legend"}

            text_id = self.map_canvas.create_text(
                x0 + 8 * self.zoom + sw + 6 * self.zoom,
                y + sw / 2,
                text=label,
                anchor="w",
                font=("Arial", int(7 * self.zoom))
            )
            self.canvas_item_map[text_id] = {"kind": "legend"}

            y += sw + 4 * self.zoom

  
        
    def export_topology_json(self):
        """
        Export de huidige topology (devices, annotaties, range + evt. traceroute)
        naar een JSON-bestand.
        """
        data = self.get_topology_dict()
        if getattr(self, "last_traceroute", None):
            data["traceroute"] = self.last_traceroute

        filename = filedialog.asksaveasfilename(
            title=_tr('ui.source.export.topology.to.json.f0b90357'),
            defaultextension=".json",
            filetypes=[(_tr('ui.source.json.files.f39e4bde'), "*.json"), (_tr('ui.source.all.files.f7857dcc'), "*.*")]
        )
        if not filename:
            return

        try:
            with open(filename, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2)
            self.status_label.config(text=_tr('ui.source.exported.topology.to.p0.4175a420',p0=filename))
        except Exception as e:
            self._mb_error(_tr('ui.source.export.error.aeb6bacb'), _tr('ui.source.could.not.export.json.p0.6de9d30c',p0=e))
  
        
        
    def _draw_annotations(self):
        """
        Teken alle opgeslagen annotaties (tekstvakjes) op de kaart.
        """
        for ann in self.annotations:
            self._draw_single_annotation(ann)

    def _draw_single_annotation(self, ann):
        x = ann.get("x", 0) * self.zoom
        y = ann.get("y", 0) * self.zoom
        text = ann.get("text", "")
        color = ann.get("color", "yellow")
        shape = ann.get("shape", "rect")

        # simpele vaste maat; kan later dynamisch op tekst
        width = 160 * self.zoom
        height = 60 * self.zoom

        x1 = x
        y1 = y
        x2 = x + width
        y2 = y + height

        if shape == "oval":
            box_id = self.map_canvas.create_oval(x1, y1, x2, y2, fill=color, outline="black")
        else:
            box_id = self.map_canvas.create_rectangle(x1, y1, x2, y2, fill=color, outline="black")

        text_id = self.map_canvas.create_text(
            x1 + 6 * self.zoom,
            y1 + 6 * self.zoom,
            anchor="nw",
            text=text,
            font=("Arial", int(8 * self.zoom)),
            width=width - 12 * self.zoom
        )

        # registratie voor click-events
        self.canvas_item_map[box_id] = {"kind": "annotation", "annotation": ann}
        self.canvas_item_map[text_id] = {"kind": "annotation", "annotation": ann}
                # registratie per-annotation voor slepen
        key = id(ann)
        self.annotation_canvas_items[key] = {
            "box": box_id,
            "text": text_id,
        }



    def _draw_traceroute_path(self, base_w, base_h, router_positions):
        """
        Teken een horizontale traceroute-baan BOVENAAN de kaart,
        met hops in volgorde, verbonden met paarse pijlen.
        """
        if not getattr(self, "last_traceroute_hops", None):
            return

        # Hops op volgorde
        hops = [dev for hop_no, dev in sorted(self.last_traceroute_hops, key=lambda x: x[0])]
        if not hops:
            return

        # Y-positie van de traceroute-lijn (boven routers)
        path_y0 = base_h * 0.08
        path_y = path_y0 * self.zoom

        n = len(hops)
        spacing0 = base_w / (n + 1)

        prev_x = None
        prev_y = None
        show_labels = True

        for idx, dev in enumerate(hops, start=1):
            hx0 = spacing0 * idx
            hx = hx0 * self.zoom
            hy = path_y

            oval_id, icon_id, label_id = self._draw_device_node(hx, hy, dev, show_labels)

            existing = self.device_canvas_items.get(dev, {})
            existing.update({"oval": oval_id, "icon": icon_id, "label": label_id, "tag": f"device-{id(dev)}"})
            self.device_canvas_items[dev] = existing

            if prev_x is not None:
                line_id = self.map_canvas.create_line(
                    prev_x, prev_y, hx, hy,
                    fill="#a020f0",
                    width=2,
                    arrow=tk.LAST
                )
                self.canvas_item_map[line_id] = {
                    "kind": "trace_link",
                    "orig_color": "#a020f0"
                }

            prev_x, prev_y = hx, hy

        # Lijn van eerste router naar eerste hop
        if router_positions and hops:
            rx0, ry0, _router_dev = router_positions[0]
            rx = rx0 * self.zoom
            ry = (ry0 - 25) * self.zoom  # bovenkant routercirkel

            first_x = spacing0 * 1 * self.zoom
            first_y = path_y

            line_id = self.map_canvas.create_line(
                rx, ry, first_x, first_y,
                fill="#a020f0",
                width=2,
                dash=(4, 2),
                arrow=tk.LAST
            )
            self.canvas_item_map[line_id] = {
                "kind": "trace_link",
                "orig_color": "#a020f0"
            }


    def _update_scrollregion(self):
        self.map_canvas.configure(scrollregion=self.map_canvas.bbox("all"))

    def _netvis_icon_kind(self, dev):
        """Map NetMap device classes to the shared Network Visualisation PNG icon set."""
        raw=str(getattr(dev,"dev_type","") or "").strip().lower().replace("_"," ")
        note=" ".join(str(x or "") for x in (getattr(dev,"hostname",""),getattr(dev,"vendor",""),getattr(dev,"note",""))).lower()
        text=f"{raw} {note}"
        if getattr(dev,"is_gateway",False):
            if "firewall" in text or "utm" in text: return "firewall"
            return "gateway"
        rules=(
            (("firewall","utm"),"firewall"), (("router",),"router"), (("switch",),"switch"),
            (("access point","wireless","wifi"," ap "),"access_point"), (("server","domain controller"," dc "),"server"),
            (("laptop","notebook"),"laptop"), (("printer",),"printer"), (("camera","cctv"),"camera"),
            (("plc",),"plc"), (("rtu",),"rtu"), (("hmi",),"hmi"), (("sensor",),"sensor"),
            (("iot",),"iot"), (("storage","nas","san"),"storage"), (("cloud","internet"),"cloud"),
            (("gateway",),"gateway"), (("client","pc","workstation","desktop","endpoint"),"workstation"),
        )
        padded=f" {text} "
        for terms,kind in rules:
            if any(term in padded for term in terms): return kind
        return "workstation"

    def _draw_netvis_png_icon(self, x, y, dev, tag, scale=1.0):
        """Draw the exact 48px device artwork shipped by Network Visualisation."""
        kind=self._netvis_icon_kind(dev)
        icon_path=Path(__file__).resolve().parent / "assets" / "icons" / f"device_{kind}.png"
        if not icon_path.exists(): return None
        try:
            img=tk.PhotoImage(file=str(icon_path))
            # Keep a persistent reference: Tk discards images when Python releases them.
            if not hasattr(self,"_netvis_icon_refs"): self._netvis_icon_refs={}
            key=f"{kind}:{id(dev)}:{round(float(scale),2)}"
            self._netvis_icon_refs[key]=img
            return self.map_canvas.create_image(x,y,image=img,tags=(tag,))
        except Exception:
            return None

    def _draw_router_node(self, x, y, dev, show_labels):
        scale=self._map_node_scale()
        ring=max(18,32*scale)*self.zoom
        gateway=bool(getattr(dev,"is_gateway",False))
        router_accent="#7b1fa2" if gateway else "#1677a7"
        tag=f"router-{id(dev)}"
        oval_id=self.map_canvas.create_oval(x-ring,y-ring,x+ring,y+ring,fill="",outline=router_accent,width=(3 if gateway else 2),tags=(tag,))
        png_id=self._draw_netvis_png_icon(x,y,dev,tag,scale*self.zoom)
        if png_id is None and draw_device_icon:
            draw_device_icon(self.map_canvas,x,y,"router",outline=router_accent,fill="#f7fbff",accent=router_accent,tag=(tag,),scale=scale*self.zoom)
        elif png_id is None:
            self.map_canvas.create_text(x,y,text=_tr('ui.source.r.06576556'),font=("Segoe UI Semibold",max(6,int(11*scale*self.zoom))),tags=(tag,))
        self.canvas_item_map[oval_id]={"kind":"router","device":dev}
        for item_id in self.map_canvas.find_withtag(tag):
            self.canvas_item_map[item_id]={"kind":"router","device":dev}
        lid=None
        if show_labels and self._map_label_detail()>=1:
            label=dev.ip if dev.ip and dev.ip!="router" else (dev.hostname or "Router")
            if gateway:
                label += "\nGATEWAY"
            lid=self.map_canvas.create_text(x,y+ring+9*self.zoom,text=label,font=("Segoe UI",max(6,int(7*self.zoom))),fill=router_accent,tags=(tag,))
            self.canvas_item_map[lid]={"kind":"router","device":dev}
        if dev in self.devices:
            self.device_canvas_items[dev]={"oval":oval_id,"icon":oval_id,"label":lid,"link":None,"tag":tag}
        return oval_id,oval_id


    def _draw_device_node(self, x, y, dev, show_labels):
        findings=self.vuln_findings.get(dev,[])
        scale=self._map_node_scale()
        detail=self._map_label_detail()
        dtype={"client":"pc","gateway/router":"router"}.get(dev.dev_type,dev.dev_type or "device")
        search=(self.topology_search_var.get().strip().lower() if hasattr(self,"topology_search_var") else "")
        search_match=(not search or search in " ".join([str(dev.ip),str(dev.mac),str(dev.hostname),str(dev.dev_type),str(dev.note)]).lower())
        status=getattr(dev,"online_status","unknown")
        accent=("#7b1fa2" if getattr(dev,"is_gateway",False) else
                "#d97706" if findings else
                "#c62828" if dev.dev_type=="compromised" else
                "#2e7d32" if status=="online" else
                "#ef6c00" if status in ("cached","offline") else "#1677a7")
        style=self.map_node_style_var.get() if hasattr(self,"map_node_style_var") else "Compact"
        tag=f"device-{id(dev)}"
        ring=max(15,30*scale)*self.zoom

        # Anchor shape is always present because drag/release uses its centre.
        # It is also tagged, so all visual parts move together.
        if style=="Ring":
            oval_id=self.map_canvas.create_oval(
                x-ring,y-ring,x+ring,y+ring,
                fill="",outline=accent,width=2,tags=(tag,)
            )
        elif style=="Kaart":
            card_w=max(48,86*scale)*self.zoom
            card_h=max(36,62*scale)*self.zoom
            oval_id=self.map_canvas.create_rectangle(
                x-card_w/2,y-card_h/2,x+card_w/2,y+card_h/2,
                fill="#fbfdff",outline="#b8c7d9",width=1,tags=(tag,)
            )
            # Accent strip makes state readable without surrounding every host by a circle.
            self.map_canvas.create_rectangle(
                x-card_w/2,y-card_h/2,x-card_w/2+4*self.zoom,y+card_h/2,
                fill=accent,outline=accent,tags=(tag,)
            )
        else:  # Compact
            # Invisible anchor + small status indicator.
            oval_id=self.map_canvas.create_oval(
                x-ring,y-ring,x+ring,y+ring,
                fill="",outline="",width=0,tags=(tag,)
            )
            dot=max(3,5*scale)*self.zoom
            self.map_canvas.create_oval(
                x+ring*.55,y-ring*.70,x+ring*.55+dot*2,y-ring*.70+dot*2,
                fill=accent,outline="#ffffff",width=1,tags=(tag,)
            )

        icon_id=self._draw_netvis_png_icon(x,y-2*self.zoom,dev,tag,scale*self.zoom)
        if icon_id is None and draw_device_icon:
            draw_device_icon(
                self.map_canvas,x,y-2*self.zoom,dtype,
                outline=accent,fill="#f7fbff",accent=accent,
                tag=(tag,),scale=scale*self.zoom
            )
            icon_id=oval_id
        elif icon_id is None:
            icon_id=self.map_canvas.create_text(
                x,y,text=_tr('ui.source.pc.36f780fd'),fill=accent,
                font=("Segoe UI Semibold",max(6,int(10*scale*self.zoom))),
                tags=(tag,)
            )

        # Register every tagged vector component for clicking/double-clicking.
        self.canvas_item_map[oval_id]={"kind":"device","device":dev}
        for item_id in self.map_canvas.find_withtag(tag):
            self.canvas_item_map[item_id]={"kind":"device","device":dev}

        label_id=None
        if getattr(dev, "crown_jewel", False):
            self.map_canvas.create_text(x, y-ring-8*self.zoom, text="★", fill="#b7791f", font=("Segoe UI Symbol", max(8,int(12*self.zoom))), tags=(tag,))
        if show_labels and detail>=1:
            primary=dev.ip or dev.hostname or getattr(dev,"asset_id","") or dev.dev_type
            lines=[primary]
            if detail>=2 and dev.hostname and dev.hostname!=primary: lines.append(dev.hostname)
            if getattr(dev,"is_gateway",False): lines.append("GATEWAY")
            if status=="online": lines.append("ONLINE")
            elif status in ("cached","offline"): lines.append("OFFLINE / CACHED")
            if findings: lines.append(f"CVE: {len(findings)}")
            label_y=y+(ring+9*self.zoom if style!="Kaart" else max(30,42*scale)*self.zoom)
            label_id=self.map_canvas.create_text(
                x,label_y,text="\n".join(lines),
                font=("Segoe UI",max(6,int(7*self.zoom))),
                justify="center",fill="#25364a",tags=(tag,)
            )
            self.canvas_item_map[label_id]={"kind":"device","device":dev}
        return oval_id,icon_id,label_id


    # ------------------------------------------------------------------
    # Network Visualisation parity tools
    def _build_topology_asset_library(self, parent):
        ttk.Label(parent,text="Asset & Infrastructure Library",font=("TkDefaultFont",10,"bold")).pack(anchor="w")
        ttk.Label(parent,text="Select an asset and click the canvas to place it.",wraplength=190,foreground="#64748b").pack(fill="x",pady=(2,5))
        self.topology_asset_search_var=tk.StringVar(); self.topology_asset_category_var=tk.StringVar(value="All categories")
        ttk.Entry(parent,textvariable=self.topology_asset_search_var,width=20).pack(fill="x",pady=(0,4))
        cats=["All categories"]+list(dict.fromkeys(r[0] for r in NETMAP_ASSET_CATALOG))
        box=ttk.Combobox(parent,textvariable=self.topology_asset_category_var,values=cats,state="readonly",width=22); box.pack(fill="x",pady=(0,5))
        holder=ttk.Frame(parent); holder.pack(fill="both",expand=True)
        c=tk.Canvas(holder,width=190,bg="#f8fafc",highlightthickness=0); sb=ttk.Scrollbar(holder,orient="vertical",command=c.yview); c.configure(yscrollcommand=sb.set)
        sb.pack(side="right",fill="y"); c.pack(side="left",fill="both",expand=True)
        inner=ttk.Frame(c); win=c.create_window((0,0),window=inner,anchor="nw")
        inner.bind("<Configure>",lambda e:c.configure(scrollregion=c.bbox("all"))); c.bind("<Configure>",lambda e:c.itemconfigure(win,width=e.width))
        self._topology_palette_inner=inner
        def rebuild(*_):
            for w in inner.winfo_children(): w.destroy()
            q=self.topology_asset_search_var.get().strip().lower(); cat=self.topology_asset_category_var.get(); current=None; grid=None; idx=0
            for category,t,label,domain,tech in NETMAP_ASSET_CATALOG:
                if cat!="All categories" and category!=cat: continue
                if q and q not in f"{category} {t} {label} {domain} {tech}".lower(): continue
                if category!=current:
                    current=category; idx=0; ttk.Label(inner,text=category,font=("TkDefaultFont",8,"bold"),foreground="#334155").pack(anchor="w",fill="x",pady=(5,2)); grid=ttk.Frame(inner); grid.pack(fill="x")
                # Use the actual Network Visualisation artwork in the existing palette button.
                # Keep a strong reference on self: Tk drops PhotoImage objects otherwise.
                if not hasattr(self, "_topology_asset_images"):
                    self._topology_asset_images = {}
                img = self._topology_asset_images.get(t)
                if img is None:
                    icon_path = Path(__file__).resolve().parent / "assets" / "icons" / f"device_{t}.png"
                    if icon_path.is_file():
                        try:
                            img = tk.PhotoImage(file=str(icon_path))
                            # Network Visualisation artwork is 48x48; preserve native size.
                            self._topology_asset_images[t] = img
                        except tk.TclError:
                            img = None
                if img is not None:
                    b=tk.Button(grid,image=img,text=self._asset_symbol(t),compound="top",width=58,height=68,command=lambda tt=t:self._choose_topology_asset(tt),relief="flat",bd=1,bg="#ffffff",activebackground="#e0f2fe",highlightthickness=1,highlightbackground="#cbd5e1",cursor="hand2")
                else:
                    b=tk.Button(grid,text=self._asset_symbol(t),width=6,height=2,command=lambda tt=t:self._choose_topology_asset(tt),relief="flat",bd=1,bg="#ffffff",activebackground="#e0f2fe",highlightthickness=1,highlightbackground="#cbd5e1",cursor="hand2")
                b.grid(row=idx//3,column=idx%3,padx=2,pady=2); idx+=1
        self.topology_asset_search_var.trace_add("write",rebuild); box.bind("<<ComboboxSelected>>",rebuild); rebuild()
        ttk.Separator(parent,orient="horizontal").pack(fill="x",pady=5)
        actions=ttk.Frame(parent); actions.pack(fill="x")
        ttk.Button(actions,text="Select",command=lambda:self._set_topology_tool("select")).pack(side="left",padx=2)
        ttk.Button(actions,text="Connect",command=lambda:self._set_topology_tool("connect")).pack(side="left",padx=2)
        ttk.Button(actions,text="Delete",command=self._delete_topology_selected).pack(side="left",padx=2)

    @staticmethod
    def _asset_symbol(t):
        symbols={"workstation":"PC","laptop":"LT","server":"SV","historian":"DB","storage":"NAS","printer":"PR","smartphone":"PH","tablet":"TB","smartwatch":"SW","smart_speaker":"SS","smart_tv":"TV","iot":"IoT","camera":"CAM","firewall":"FW","router":"RT","switch":"SW","gateway":"GW","access_point":"AP","vpn_gateway":"VPN","cellular_gateway":"5G","cloud":"CLD","plc":"PLC","rtu":"RTU","ied":"IED","relay":"RLY","hmi":"HMI","scada_server":"SC","engineering_station":"EWS","sensor":"SNS","actuator":"ACT","vfd":"VFD","motor":"MTR","pump":"PMP","valve":"VLV","wind_turbine":"WT","transformer":"TR","substation":"SUB","generator":"GEN","traffic_light":"TL","traffic_controller":"TC","matrix_sign":"VMS","bridge":"BR","lock":"LCK","dam":"DAM","dike":"DIK","pumping_station":"PS","robot":"ROB","building":"BLD","control_room":"CR"}
        return symbols.get(t,(t[:4] or "DEV").upper())

    def _choose_topology_asset(self, t):
        self.topology_palette_type=t; self.topology_tool="add"; self.status_label.config(text=f"Place {t}: click the topology canvas")

    def _add_topology_asset(self, t, sx, sy):
        meta=next((r for r in NETMAP_ASSET_CATALOG if r[1]==t),None); label=meta[2] if meta else t.replace("_"," ").title(); domain=meta[3] if meta else "IT"; tech=meta[4] if meta else "Digital"
        used={str(d.asset_id) for d in self.devices}; base=t[:3] or "dev"; i=1; aid=f"{base}-{i}"
        while aid in used: i+=1; aid=f"{base}-{i}"
        layer="OT/ICS" if domain=="OT/ICS" else ("Physical" if tech in ("Physical","Facility","Cyber-Physical") else ("Security" if t=="firewall" else "Logical"))
        d=Device("","",label,dev_type=t,pos_x=sx/self.zoom,pos_y=sy/self.zoom,asset_id=aid,zone="Unzoned",layer=layer,criticality="Medium")
        d.domain=domain; d.technology=tech; d.vendor=""; d.product=""; d.os=""; d.firmware=""
        self.devices.append(d); self.topology_selected_device=d; self.topology_tool="select"; self.topology_palette_type=None
        self.update_device_table(); self._refresh_topology_inspector_panel(); self.draw_network_map(); self.status_label.config(text=f"Added {label}")

    def _build_topology_inspector_panel(self, parent):
        ttk.Label(parent,text="Inspector",font=("TkDefaultFont",10,"bold")).pack(anchor="w")
        self.topology_inspector_hint=tk.StringVar(value="Select an asset to inspect or edit it."); ttk.Label(parent,textvariable=self.topology_inspector_hint,wraplength=230,foreground="#64748b").pack(fill="x",pady=(2,6))
        form=ttk.Frame(parent); form.pack(fill="both",expand=True); self.topology_inspector_vars={}
        fields=[("Name","hostname"),("Type","dev_type"),("Domain","domain"),("Technology","technology"),("Asset role","asset_role"),("Controller ID","controller_id"),("IP address","ip"),("MAC","mac"),("Vendor","vendor"),("Product","product"),("OS","os"),("Firmware","firmware"),("Zone","zone"),("Layer","layer"),("Criticality","criticality")]
        for r,(lab,attr) in enumerate(fields):
            ttk.Label(form,text=lab).grid(row=r,column=0,sticky="w",pady=2); v=tk.StringVar(); self.topology_inspector_vars[attr]=v; ttk.Entry(form,textvariable=v,width=21).grid(row=r,column=1,sticky="ew",pady=2,padx=(5,0))
        self.topology_inspector_crown=tk.BooleanVar(); ttk.Checkbutton(form,text="Crown jewel",variable=self.topology_inspector_crown).grid(row=len(fields),column=0,columnspan=2,sticky="w",pady=4)
        ttk.Label(form,text="Notes").grid(row=len(fields)+1,column=0,sticky="nw",pady=2); self.topology_inspector_notes=tk.Text(form,height=4,width=20); self.topology_inspector_notes.grid(row=len(fields)+1,column=1,sticky="nsew",pady=2,padx=(5,0))
        btn=ttk.Frame(form); btn.grid(row=len(fields)+2,column=0,columnspan=2,sticky="e",pady=7); ttk.Button(btn,text="Apply",command=self._apply_topology_inspector_panel).pack(side="left",padx=2); ttk.Button(btn,text="Reset",command=self._refresh_topology_inspector_panel).pack(side="left",padx=2)
        form.columnconfigure(1,weight=1)

    def _refresh_topology_inspector_panel(self):
        if not hasattr(self,"topology_inspector_vars"): return
        d=getattr(self,"topology_selected_device",None)
        if d is None:
            self.topology_inspector_hint.set("Select an asset to inspect or edit it.")
            for v in self.topology_inspector_vars.values(): v.set("")
            self.topology_inspector_notes.delete("1.0","end"); self.topology_inspector_crown.set(False); return
        self.topology_inspector_hint.set(f"Selected: {d.hostname or d.ip or d.asset_id}")
        for attr,v in self.topology_inspector_vars.items(): v.set(str(getattr(d,attr,"") or ""))
        self.topology_inspector_notes.delete("1.0","end"); self.topology_inspector_notes.insert("1.0",str(getattr(d,"note","") or "")); self.topology_inspector_crown.set(bool(getattr(d,"crown_jewel",False)))

    def _apply_topology_inspector_panel(self):
        d=getattr(self,"topology_selected_device",None)
        if d is None: return
        for attr,v in self.topology_inspector_vars.items(): setattr(d,attr,v.get().strip())
        d.note=self.topology_inspector_notes.get("1.0","end-1c").strip(); d.crown_jewel=self.topology_inspector_crown.get()
        if not d.asset_id: d.asset_id=d.ip or d.hostname
        self.update_device_table(); self.draw_network_map(); self.status_label.config(text=f"Updated {d.hostname or d.ip or d.asset_id}")

    def _set_topology_tool(self, tool):
        self.topology_tool = tool if tool in ("select", "connect", "add") else "select"
        if self.topology_tool != "connect": self.topology_connect_source = None
        if self.topology_tool != "add": self.topology_palette_type = None
        if self.topology_tool == "connect": msg="Connect: select source and target device"
        elif self.topology_tool == "add": msg=f"Place {getattr(self,'topology_palette_type','asset')}: click the topology canvas"
        else: msg="Select / move topology objects"
        self.status_label.config(text=msg)

    def _topology_connect_click(self, dev):
        if self.topology_connect_source is None:
            self.topology_connect_source = dev
            self.status_label.config(text=f"Connect source: {dev.ip or dev.hostname}. Select target.")
            return
        src = self.topology_connect_source
        self.topology_connect_source = None
        if src is dev:
            self.status_label.config(text="Connect cancelled: source and target are identical.")
            return
        sid = src.asset_id or src.ip or src.hostname
        tid = dev.asset_id or dev.ip or dev.hostname
        if not sid or not tid:
            self.status_label.config(text="Connect failed: both devices require an identifier.")
            return
        for rel in self.relationships:
            if str(rel.get("source", "")) == str(sid) and str(rel.get("target", "")) == str(tid):
                self.status_label.config(text="Relationship already exists.")
                return
        self.relationships.append({"source": sid, "target": tid, "type": "manual", "relation_type": "manual", "label": "", "protocol": "", "directed": False})
        self.status_label.config(text=f"Connected {sid} -> {tid}")
        self.draw_network_map()

    def _duplicate_topology_selected(self):
        dev = getattr(self, "topology_selected_device", None) or getattr(self, "drag_device", None)
        if dev is None:
            self.status_label.config(text="Select a device first.")
            return
        data = dev.to_dict()
        data["asset_id"] = (data.get("asset_id") or data.get("ip") or "asset") + "_copy"
        data["hostname"] = ((data.get("hostname") or data.get("ip") or "device") + " copy")
        data["ip"] = ""
        data["mac"] = ""
        data["pos_x"] = (dev.pos_x or 100) + 45
        data["pos_y"] = (dev.pos_y or 100) + 45
        clone = Device.from_dict(data)
        self.devices.append(clone)
        self.topology_selected_device = clone
        self.update_device_table(); self.draw_network_map()

    def _delete_topology_selected(self):
        dev = getattr(self, "topology_selected_device", None)
        if dev is None or dev not in self.devices:
            self.status_label.config(text="Select a device first.")
            return
        key = str(dev.asset_id or dev.ip or dev.hostname)
        self.devices.remove(dev)
        self.relationships = [r for r in self.relationships if str(r.get("source", "")) != key and str(r.get("target", "")) != key]
        self.topology_selected_device = None
        self.update_device_table(); self.draw_network_map()

    def _toggle_crown_selected(self):
        dev = getattr(self, "topology_selected_device", None)
        if dev is None:
            self.status_label.config(text="Select a device first.")
            return
        dev.crown_jewel = not bool(getattr(dev, "crown_jewel", False))
        self.status_label.config(text=f"Crown Jewel {'enabled' if dev.crown_jewel else 'disabled'}: {dev.ip or dev.hostname}")
        self.draw_network_map()

    def _apply_topology_layout(self):
        devs = list(self.devices)
        if not devs: return
        layout = self.topology_layout_var.get()
        w=max(900, self.map_canvas.winfo_width()); h=max(600, self.map_canvas.winfo_height())
        if layout == "Grid":
            cols=max(1,int(math.ceil(math.sqrt(len(devs)))))
            for i,d in enumerate(devs): d.pos_x=120+(i%cols)*180; d.pos_y=100+(i//cols)*140
        elif layout == "Circle":
            cx,cy=w/(2*self.zoom),h/(2*self.zoom); r=max(140,min(cx,cy)-100)
            for i,d in enumerate(devs):
                a=2*math.pi*i/max(1,len(devs)); d.pos_x=cx+r*math.cos(a); d.pos_y=cy+r*math.sin(a)
        elif layout == "Zones":
            groups={}
            for d in devs: groups.setdefault(getattr(d,"zone","") or "Unzoned",[]).append(d)
            for gi,(zone,items) in enumerate(sorted(groups.items())):
                bx=130+(gi%3)*330; by=110+(gi//3)*260
                for i,d in enumerate(items): d.pos_x=bx+(i%3)*95; d.pos_y=by+(i//3)*90
        elif layout == "Force-directed":
            # Deterministic lightweight force layout; no external dependency.
            n=len(devs); pos={d:[float(d.pos_x or 120+(i%6)*150),float(d.pos_y or 100+(i//6)*120)] for i,d in enumerate(devs)}
            keys={str(d.asset_id or d.ip or d.hostname):d for d in devs}
            edges=[(keys.get(str(r.get("source",""))),keys.get(str(r.get("target","")))) for r in self.relationships]
            edges=[e for e in edges if e[0] is not None and e[1] is not None]
            for _ in range(45):
                delta={d:[0.0,0.0] for d in devs}
                for i,a in enumerate(devs):
                    for b in devs[i+1:]:
                        dx=pos[a][0]-pos[b][0]; dy=pos[a][1]-pos[b][1]; dist=max(20.0,math.hypot(dx,dy)); f=2600/(dist*dist)
                        ux,uy=dx/dist,dy/dist; delta[a][0]+=ux*f;delta[a][1]+=uy*f;delta[b][0]-=ux*f;delta[b][1]-=uy*f
                for a,b in edges:
                    dx=pos[b][0]-pos[a][0];dy=pos[b][1]-pos[a][1];dist=max(1.0,math.hypot(dx,dy));f=(dist-180)*0.018;ux,uy=dx/dist,dy/dist
                    delta[a][0]+=ux*f;delta[a][1]+=uy*f;delta[b][0]-=ux*f;delta[b][1]-=uy*f
                for d in devs: pos[d][0]+=max(-12,min(12,delta[d][0]));pos[d][1]+=max(-12,min(12,delta[d][1]))
            for d,(x,y) in pos.items(): d.pos_x=max(80,x); d.pos_y=max(70,y)
        else: # Hierarchical
            rank={d:0 for d in devs}; keys={str(d.asset_id or d.ip or d.hostname):d for d in devs}
            for _ in range(len(devs)):
                changed=False
                for r in self.relationships:
                    a=keys.get(str(r.get("source",""))); b=keys.get(str(r.get("target","")))
                    if a is not None and b is not None and rank[b] <= rank[a]: rank[b]=rank[a]+1; changed=True
                if not changed: break
            levels={}
            for d in devs: levels.setdefault(min(rank[d],8),[]).append(d)
            for level,items in sorted(levels.items()):
                for i,d in enumerate(items): d.pos_x=130+i*190; d.pos_y=90+level*150
        self.draw_network_map(); self.fit_network_map()

    def _open_topology_inspector(self):
        dev = getattr(self, "topology_selected_device", None)
        if dev is None:
            self.status_label.config(text="Select a device first, then open Inspector.")
            return
        d=tk.Toplevel(self.root); d.title("Topology Inspector"); d.geometry("520x570"); d.transient(self.root)
        frm=ttk.Frame(d,padding=10); frm.pack(fill="both",expand=True)
        fields=[("Hostname","hostname"),("IP address","ip"),("MAC address","mac"),("Device type","dev_type"),("Zone","zone"),("Layer","layer"),("Criticality","criticality"),("Ports / services","ports_summary"),("Notes","note")]
        vars={}
        for row,(label,attr) in enumerate(fields):
            ttk.Label(frm,text=label).grid(row=row,column=0,sticky="nw",padx=(0,8),pady=4)
            v=tk.StringVar(value=str(getattr(dev,attr,"") or "")); vars[attr]=v
            ttk.Entry(frm,textvariable=v,width=46).grid(row=row,column=1,sticky="ew",pady=4)
        crown=tk.BooleanVar(value=bool(getattr(dev,"crown_jewel",False))); ttk.Checkbutton(frm,text="Crown Jewel",variable=crown).grid(row=len(fields),column=1,sticky="w",pady=5)
        rels=[r for r in self.relationships if str(r.get("source",""))==str(dev.asset_id or dev.ip or dev.hostname) or str(r.get("target",""))==str(dev.asset_id or dev.ip or dev.hostname)]
        ttk.Label(frm,text=f"Relationships: {len(rels)}").grid(row=len(fields)+1,column=1,sticky="w",pady=5)
        def save():
            for attr,v in vars.items(): setattr(dev,attr,v.get().strip())
            dev.crown_jewel=crown.get(); self.update_device_table(); self.draw_network_map(); d.destroy()
        ttk.Button(frm,text="Save",command=save).grid(row=len(fields)+2,column=1,sticky="e",pady=12); frm.columnconfigure(1,weight=1)

    def _draw_topology_grid(self):
        if not getattr(self,"topology_show_grid_var",None) or not self.topology_show_grid_var.get(): return
        try:
            x0,y0,x1,y1=self.map_canvas.bbox("all") or (0,0,max(1600,self.map_canvas.winfo_width()),max(1000,self.map_canvas.winfo_height()))
        except Exception: x0,y0,x1,y1=(0,0,1600,1000)
        step=max(12,int(25*self.zoom)); x0=int(x0//step*step);y0=int(y0//step*step)
        for x in range(x0,int(x1)+step,step): self.map_canvas.create_line(x,y0,x,y1,fill="#eef2f6",tags=("topology_grid",))
        for y in range(y0,int(y1)+step,step): self.map_canvas.create_line(x0,y,x1,y,fill="#eef2f6",tags=("topology_grid",))
        self.map_canvas.tag_lower("topology_grid")


if __name__ == "__main__":
    root = tk.Tk()
    app = NetworkMapGUI(root)
    root.mainloop()
