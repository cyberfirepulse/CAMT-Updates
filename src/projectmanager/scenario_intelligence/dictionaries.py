from __future__ import annotations

from dataclasses import dataclass
from types import MappingProxyType
from typing import Final, Mapping

from .models import AssetCategory


@dataclass(frozen=True, slots=True)
class AssetDefinition:
    canonical_type: str
    display_name: str
    category: AssetCategory
    aliases: tuple[str, ...]
    confidence: float = 0.86
    name_prefixes: tuple[str, ...] = ()


_ASSET_DEFINITIONS: Final[tuple[AssetDefinition, ...]] = (
    AssetDefinition("firewall", "Firewall", AssetCategory.NETWORK, ("firewall", "next-generation firewall", "next generation firewall", "ngfw", "packet filter"), 0.94, ("FW", "FIREWALL")),
    AssetDefinition("router", "Router", AssetCategory.NETWORK, ("router", "edge router", "core router", "gateway router"), 0.92, ("RTR", "ROUTER", "GW")),
    AssetDefinition("switch", "Switch", AssetCategory.NETWORK, ("switch", "network switch", "core switch", "access switch", "distributieswitch", "netwerkswitch"), 0.91, ("SW", "SWITCH")),
    AssetDefinition("vpn", "VPN", AssetCategory.NETWORK, ("vpn", "vpn gateway", "vpn concentrator", "virtual private network", "remote access gateway"), 0.91, ("VPN",)),
    AssetDefinition("ssl_vpn", "SSL-VPN", AssetCategory.NETWORK, ("ssl-vpn", "ssl vpn", "sslvpn", "ssl-vpn-appliance", "ssl vpn appliance", "vpn appliance", "edge vpn", "remote access vpn"), 0.97, ("SSLVPN",)),
    AssetDefinition("site_to_site_vpn", "Site-to-site VPN", AssetCategory.NETWORK, ("site-to-site vpn", "site-to-site-vpn", "site to site vpn", "s2s vpn", "ipsec tunnel"), 0.96, ("S2S", "IPSEC")),
    AssetDefinition("jump_host", "Jump host", AssetCategory.SERVER, ("jump host", "jump server", "jumphost", "bastion host", "bastion server"), 0.96, ("JUMP", "BASTION")),
    AssetDefinition("engineering_workstation", "Engineering Workstation", AssetCategory.OT, ("engineering workstation", "engineering-workstation", "engineering station", "engineering laptop", "engineering werkstation", "ews"), 0.98, ("EWS",)),
    AssetDefinition("hmi", "HMI", AssetCategory.OT, ("hmi", "human machine interface", "operator interface", "operator station"), 0.97, ("HMI",)),
    AssetDefinition("rtu", "RTU", AssetCategory.OT, ("rtu", "remote terminal unit"), 0.97, ("RTU",)),
    AssetDefinition("gis_server", "GIS Server", AssetCategory.SERVER, ("gis server", "gis-server", "gis/asset-server", "gis asset server", "asset-server", "asset server", "geographic information system server"), 0.95, ("GIS",)),
    AssetDefinition("active_directory", "Active Directory", AssetCategory.IDENTITY, ("active directory", "ad domain", "windows domain", "domain controller", "domeincontroller", "entra domain services"), 0.95, ("AD", "DC")),
    AssetDefinition("scada", "SCADA", AssetCategory.OT, ("scada", "supervisory control and data acquisition", "scada server", "scada-server", "scada systeem", "scada-systeem"), 0.96, ("SCADA",)),
    AssetDefinition("plc", "PLC", AssetCategory.OT, ("plc", "programmable logic controller", "programmable controller", "programmeerbare logische controller"), 0.97, ("PLC",)),
    AssetDefinition("historian", "Historian", AssetCategory.OT, ("historian", "process historian", "data historian", "industrial historian", "proceshistorian"), 0.94, ("HIST", "HISTORIAN")),
    AssetDefinition("sql_server", "SQL Server", AssetCategory.SERVER, ("sql server", "microsoft sql server", "mssql", "database server", "databaseserver", "sql database"), 0.94, ("SQL", "DB", "MSSQL")),
    AssetDefinition("webserver", "Webserver", AssetCategory.SERVER, ("webserver", "web server", "http server", "https server", "apache server", "nginx server", "iis server"), 0.92, ("WEB", "WWW", "IIS")),
    AssetDefinition("workstation", "Werkstation", AssetCategory.ENDPOINT, ("werkstation", "workstation", "desktop computer", "beheerwerkstation", "operator workstation"), 0.89, ("WS", "WKST", "ENG")),
    AssetDefinition("iot_device", "IoT Device", AssetCategory.IOT, ("iot device", "iot-device", "iot apparaat", "iot-apparaat", "smart device", "connected device"), 0.88, ("IOT",)),
    AssetDefinition("sensor", "Sensor", AssetCategory.IOT, ("sensor", "meetsensor", "druksensor", "temperatuursensor", "niveausensor", "flowsensor", "bewegingssensor"), 0.90, ("SNS", "SENSOR")),
    AssetDefinition("camera", "Camera", AssetCategory.IOT, ("camera", "ip camera", "ip-camera", "cctv", "security camera", "bewakingscamera", "ptz camera"), 0.91, ("CAM", "CCTV")),
    AssetDefinition("bridge", "Brug", AssetCategory.CRITICAL_INFRASTRUCTURE, ("brug", "bridge", "ophaalbrug", "hefbrug", "draaibrug", "verkeersbrug"), 0.93, ("BRUG", "BRIDGE")),
    AssetDefinition("lock", "Sluis", AssetCategory.CRITICAL_INFRASTRUCTURE, ("sluis", "lock", "schutsluis", "keersluis", "sluizencomplex"), 0.94, ("SLUIS", "LOCK")),
    AssetDefinition("dam", "Stuwdam", AssetCategory.CRITICAL_INFRASTRUCTURE, ("stuwdam", "dam", "water dam", "hydroelectric dam"), 0.93, ("DAM", "STUWDAM")),
    AssetDefinition("pumping_station", "Pompstation", AssetCategory.CRITICAL_INFRASTRUCTURE, ("pompstation", "pumping station", "gemaal", "booster station", "waterpompstation"), 0.94, ("POMP", "PUMP", "GEMAAL")),
    AssetDefinition("power_plant", "Energiecentrale", AssetCategory.CRITICAL_INFRASTRUCTURE, ("energiecentrale", "power plant", "power station", "elektriciteitscentrale", "gascentrale", "kolencentrale", "kerncentrale", "windpark"), 0.95, ("PP", "PLANT", "CENTRALE")),
)

ASSET_DEFINITIONS: Final[tuple[AssetDefinition, ...]] = _ASSET_DEFINITIONS
ASSET_DEFINITION_BY_TYPE: Final[Mapping[str, AssetDefinition]] = MappingProxyType(
    {definition.canonical_type: definition for definition in ASSET_DEFINITIONS}
)

FILE_EXTENSION_TO_SOURCE_TYPE: Final[Mapping[str, str]] = MappingProxyType(
    {
        ".txt": "txt",
        ".text": "txt",
        ".log": "txt",
        ".md": "markdown",
        ".markdown": "markdown",
        ".json": "json",
        ".docx": "docx",
        ".pdf": "pdf",
    }
)

IPV4_PATTERN: Final[str] = r"(?<![\d.])(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}(?![\d.])"
HOSTNAME_PATTERN: Final[str] = r"(?<![A-Za-z0-9_-])(?:[A-Za-z][A-Za-z0-9_-]{1,62})(?:\.[A-Za-z0-9][A-Za-z0-9-]{0,62})*(?![A-Za-z0-9_-])"
