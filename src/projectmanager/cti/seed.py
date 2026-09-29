from __future__ import annotations

from .models import Campaign, Malware, Reference, ThreatActor, ToolProfile

SEED_VERSION = "2026.07-expanded-1"
SOURCE_NAME = "ProjectManager Offline CTI Pack"

# Conservative offline comparison profiles. They support hypothesis ranking and
# are not assertions of attribution. Users can merge approved STIX/JSON packs.
_PROFILES = [
("APT1", ["Comment Crew"], "Reported: China", "Espionage", ["Technology","Government","Manufacturing"], ["T1566","T1059","T1003","T1021","T1041","T1071"]),
("APT3", ["Gothic Panda","Buckeye"], "Reported: China", "Espionage", ["Government","Technology"], ["T1190","T1566","T1059","T1003","T1105"]),
("APT5", ["Manganese"], "Reported: China", "Espionage", ["Telecommunications","Technology","Government"], ["T1190","T1078","T1021","T1005","T1041"]),
("APT10", ["Stone Panda","MenuPass"], "Reported: China", "Espionage", ["Technology","Government","Managed Services"], ["T1566","T1059","T1003","T1021","T1105","T1041"]),
("APT12", ["Numbered Panda"], "Reported: China", "Espionage", ["Government","Media"], ["T1566","T1059","T1027","T1105","T1005"]),
("APT16", ["SVCMONDR"], "Reported: China", "Espionage", ["Government","Technology"], ["T1566","T1059","T1027","T1105","T1005"]),
("APT17", ["Deputy Dog"], "Reported: China", "Espionage", ["Government","Technology","Legal"], ["T1190","T1566","T1059","T1105","T1005"]),
("APT18", ["Wekby"], "Reported: China", "Espionage", ["Healthcare","Technology","Government"], ["T1190","T1566","T1059","T1003","T1105"]),
("APT19", ["Codoso"], "Reported: China", "Espionage", ["Legal","Investment","Government"], ["T1566","T1059","T1003","T1105","T1041"]),
("APT20", ["Twivy"], "Reported: China", "Espionage", ["Government","Technology"], ["T1190","T1566","T1059","T1105","T1005"]),
("APT27", ["Emissary Panda"], "Reported: China", "Espionage", ["Government","Technology","Defense"], ["T1190","T1566","T1059","T1003","T1105"]),
("APT28", ["Sofacy","Fancy Bear"], "Reported: Russia", "Espionage", ["Government","Defense","Technology"], ["T1566","T1059.001","T1027","T1003","T1071","T1105"]),
("APT29", ["Cozy Bear","NOBELIUM"], "Reported: Russia", "Espionage", ["Government","Technology","Research"], ["T1078","T1059.001","T1027","T1105","T1071","T1005"]),
("APT30", ["Naikon"], "Reported: China", "Espionage", ["Government","Defense"], ["T1566","T1059","T1027","T1105","T1005"]),
("APT32", ["OceanLotus"], "Reported: Vietnam", "Espionage", ["Government","Media","Technology"], ["T1566","T1059","T1027","T1105","T1005"]),
("APT33", ["Elfin"], "Reported: Iran", "Espionage / Disruption", ["Energy","Aviation","Industrial"], ["T1566","T1059.001","T1003","T1105","T1071","T1486"]),
("APT34", ["OilRig","Helix Kitten"], "Reported: Iran", "Espionage", ["Government","Finance","Energy"], ["T1566","T1059.001","T1053","T1071","T1105","T1005"]),
("APT35", ["Charming Kitten","Phosphorus"], "Reported: Iran", "Espionage", ["Government","Research","Media"], ["T1566","T1078","T1059","T1005","T1071"]),
("APT37", ["ScarCruft"], "Reported: North Korea", "Espionage", ["Government","Defense","Media"], ["T1566","T1059","T1027","T1105","T1005"]),
("APT38", ["Bluenoroff"], "Reported: North Korea", "Financial", ["Finance","Cryptocurrency"], ["T1566","T1059","T1003","T1105","T1041"]),
("APT39", ["Chafer"], "Reported: Iran", "Espionage", ["Telecommunications","Travel","Government"], ["T1566","T1059","T1078","T1021","T1005","T1041"]),
("APT40", ["Leviathan","Gadolinium"], "Reported: China", "Espionage", ["Maritime","Government","Technology"], ["T1190","T1566","T1078","T1105","T1005"]),
("APT41", ["Barium","Winnti"], "Reported: China", "Espionage / Financial", ["Technology","Healthcare","Government"], ["T1190","T1566","T1059","T1003","T1021","T1105"]),
("BlackTech", ["Palmerworm"], "Reported: China", "Espionage", ["Technology","Government","Telecommunications"], ["T1190","T1078","T1021","T1105","T1005"]),
("Bronze Butler", ["Tick"], "Reported: China", "Espionage", ["Technology","Government"], ["T1566","T1059","T1027","T1105","T1005"]),
("Cleaver", ["Threat Group 2889"], "Reported: Iran", "Espionage", ["Critical Infrastructure","Government","Energy"], ["T1190","T1078","T1021","T1046","T1005"]),
("Dark Caracal", [], "Unknown", "Espionage", ["Government","Defense","Media"], ["T1566","T1059","T1105","T1005","T1041"]),
("DarkHotel", ["DUBNIUM"], "Unknown", "Espionage", ["Government","Business","Hospitality"], ["T1566","T1190","T1059","T1105","T1005"]),
("Dragonfly", ["Energetic Bear"], "Reported: Russia", "Espionage / Pre-positioning", ["Energy","Critical Infrastructure","Industrial"], ["T1190","T1078","T1021","T1046","T1005","T1071"]),
("Elderwood", [], "Reported: China", "Espionage", ["Government","Technology","Defense"], ["T1190","T1566","T1059","T1105","T1005"]),
("Equation", ["Equation Group"], "Unknown", "Espionage", ["Government","Defense","Technology"], ["T1190","T1059","T1027","T1005","T1041"]),
("FIN4", [], "Unknown", "Financial", ["Finance","Legal"], ["T1566","T1078","T1005","T1041"]),
("FIN5", [], "Unknown", "Financial", ["Hospitality","Retail"], ["T1078","T1021","T1005","T1041"]),
("FIN6", [], "Unknown", "Financial", ["Retail","Hospitality"], ["T1078","T1003","T1021","T1041"]),
("FIN7", ["Carbanak Group"], "Unknown", "Financial", ["Retail","Hospitality","Finance"], ["T1566","T1059.001","T1003","T1021","T1105","T1071"]),
("FIN8", [], "Unknown", "Financial", ["Finance","Retail"], ["T1566","T1059","T1003","T1021","T1105"]),
("Gamaredon Group", ["Primitive Bear"], "Reported: Russia", "Espionage", ["Government","Defense"], ["T1566","T1059.001","T1027","T1105","T1071","T1005"]),
("Gorgon Group", [], "Unknown", "Espionage / Financial", ["Government","Technology","Finance"], ["T1566","T1059","T1105","T1005"]),
("HAFNIUM", [], "Reported: China", "Espionage", ["Government","Technology","Defense"], ["T1190","T1059","T1078","T1105","T1005"]),
("Honeybee", [], "Unknown", "Espionage", ["Government","Defense"], ["T1566","T1059","T1027","T1105"]),
("Inception", ["Cloud Atlas"], "Unknown", "Espionage", ["Government","Defense","Energy"], ["T1566","T1059","T1027","T1005"]),
("Kimsuky", ["Velvet Chollima"], "Reported: North Korea", "Espionage", ["Government","Research","Education"], ["T1566","T1059.001","T1027","T1552","T1071","T1005"]),
("Lazarus Group", ["Hidden Cobra"], "Reported: North Korea", "Espionage / Financial", ["Finance","Defense","Cryptocurrency"], ["T1566","T1059","T1027","T1003","T1105","T1486"]),
("Lotus Blossom", ["Spring Dragon"], "Unknown", "Espionage", ["Government","Telecommunications"], ["T1566","T1059","T1027","T1105"]),
("Machete", [], "Unknown", "Espionage", ["Government","Military"], ["T1566","T1059","T1005","T1041"]),
("Magic Hound", ["APT35"], "Reported: Iran", "Espionage", ["Government","Research","Media"], ["T1566","T1078","T1059","T1005"]),
("MuddyWater", ["Seedworm"], "Reported: Iran", "Espionage", ["Government","Telecommunications","Energy"], ["T1566","T1059.001","T1078","T1105","T1071","T1005"]),
("Mustang Panda", ["Bronze President"], "Reported: China", "Espionage", ["Government","NGO","Research"], ["T1566","T1059","T1027","T1105","T1071","T1005"]),
("Naikon", [], "Unknown", "Espionage", ["Government","Defense"], ["T1566","T1059","T1105","T1005"]),
("Patchwork", ["Dropping Elephant"], "Unknown", "Espionage", ["Government","Research","Defense"], ["T1566","T1059","T1027","T1105"]),
("Sandworm", ["Voodoo Bear"], "Reported: Russia", "Disruption", ["Energy","Government","Critical Infrastructure"], ["T1190","T1059.001","T1562","T1021","T1489","T1490"]),
("Scarlet Mimic", [], "Unknown", "Espionage", ["Government","Research"], ["T1566","T1059","T1105","T1005"]),
("Scattered Spider", ["UNC3944","Octo Tempest"], "Unknown", "Financial", ["Technology","Telecommunications","Hospitality"], ["T1078","T1566","T1552","T1021","T1562","T1486"]),
("Silence", [], "Unknown", "Financial", ["Finance"], ["T1566","T1059","T1003","T1021","T1041"]),
("Stealth Falcon", [], "Unknown", "Espionage", ["Government","Media"], ["T1566","T1059","T1105","T1005"]),
("TA459", [], "Unknown", "Espionage", ["Government","Research"], ["T1566","T1059","T1105"]),
("TA505", ["Hive0065"], "Unknown", "Financial", ["Finance","Retail","Healthcare"], ["T1566","T1059.001","T1105","T1027","T1003","T1486"]),
("TA551", ["Shathak"], "Unknown", "Financial", ["Cross-sector"], ["T1566","T1059","T1105","T1027"]),
("Threat Group-3390", ["Emissary Panda"], "Reported: China", "Espionage", ["Government","Technology"], ["T1190","T1566","T1059","T1105"]),
("Turla", ["Snake","Venomous Bear"], "Reported: Russia", "Espionage", ["Government","Defense","Research"], ["T1566","T1059","T1027","T1071","T1105","T1005"]),
("Volt Typhoon", ["Vanguard Panda"], "Reported: China", "Espionage / Pre-positioning", ["Critical Infrastructure","Communications","Government"], ["T1078","T1059","T1021","T1087","T1082","T1071"]),
("Windshift", [], "Unknown", "Espionage", ["Government","Defense"], ["T1566","T1059","T1005"]),
("Wizard Spider", ["Grim Spider"], "Unknown", "Financial", ["Finance","Healthcare","Government"], ["T1566","T1059","T1003","T1021","T1486"]),
("XENOTIME", ["TEMP.Veles"], "Reported: state-linked", "Disruption", ["Energy","Critical Infrastructure","Industrial"], ["T1078","T1021","T1046","T1562","T1489","T1565.001"]),
]

def _slug(name: str) -> str:
    return ''.join(ch.lower() if ch.isalnum() else '-' for ch in name).strip('-').replace('--','-')

def build_seed_library() -> dict:
    actors=[]
    for name, aliases, origin, motivation, sectors, techniques in _PROFILES:
        actors.append(ThreatActor(id=f"actor--{_slug(name)}", name=name, aliases=aliases, category="APT / Threat Group", origin=origin, motivation=motivation, confidence=60, techniques=techniques, sectors=sectors, description="Curated offline comparison profile. Validate against locally approved intelligence before operational use.", references=[Reference(title=SOURCE_NAME, source=SOURCE_NAME)]))
    campaigns=[Campaign(id="campaign--example-intrusion",name="Example intrusion campaign",description="Local example campaign.",actor_ids=["actor--apt29"],techniques=["T1078","T1059.001","T1105"],confidence=25)]
    malware=[Malware(id="malware--example-loader",name="Example Loader",malware_type="Loader",platforms=["Windows"],description="Local demonstration object.",actor_ids=["actor--apt28"],techniques=["T1059.001","T1105"])]
    tools=[ToolProfile(id="tool--powershell",name="PowerShell",tool_type="Legitimate administration tool",techniques=["T1059.001"]),ToolProfile(id="tool--psexec",name="PsExec",tool_type="Legitimate administration tool",techniques=["T1021"]),ToolProfile(id="tool--rclone",name="Rclone",tool_type="Legitimate file transfer tool",techniques=["T1567"])]
    relationships=[]
    for actor in actors:
        for technique in actor.techniques:
            relationships.append({"source_id":actor.id,"relationship_type":"uses-technique","target_id":technique,"confidence":actor.confidence,"description":"Offline profile mapping","source":SOURCE_NAME})
    return {"actors":actors,"campaigns":campaigns,"malware":malware,"tools":tools,"iocs":[],"relationships":relationships}
