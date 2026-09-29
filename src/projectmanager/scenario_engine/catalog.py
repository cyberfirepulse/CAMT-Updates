from __future__ import annotations
from .models import NetworkScenario, ScenarioStep, DetectionPoint


def _dp(asset: str, technique: str, source: str, hint: str, coverage: int) -> DetectionPoint:
    return DetectionPoint(asset_id=asset, technique_id=technique, source=source, event_hint=hint, coverage=coverage, confidence=80)


def _step(order:int, asset_name:str, technique:str, action:str, risk:int, rationale:str, phase:str='') -> ScenarioStep:
    return ScenarioStep(order=order, asset_name=asset_name, technique_id=technique, action=action,
                        likelihood=max(20,min(95,risk+10)), impact=max(30,min(100,risk+15)), step_risk=risk,
                        rationale=(phase + ': ' if phase else '') + rationale,
                        detection_points=[_dp('', technique, 'SIEM / EDR', f'Detecteer afwijkende activiteit bij {asset_name}', max(25,75-risk//2))])


def builtin_scenarios() -> list[NetworkScenario]:
    specs = [
        ('Ransomware via webserver','Cybercriminal Group','Critical',[
            ('Internet','T1595','Active Scanning',25,'Reconnaissance','Publiek bereikbare diensten worden geïnventariseerd.'),
            ('Webserver','T1190','Exploit Public-Facing Application',75,'Initial Access','Kwetsbare webapplicatie wordt misbruikt.'),
            ('Applicatieserver','T1059','Command and Scripting Interpreter',80,'Execution','Commando-uitvoering op de applicatieserver.'),
            ('Domain Controller','T1003','OS Credential Dumping',95,'Credential Access','Domeinreferenties worden buitgemaakt.'),
            ('Fileserver','T1486','Data Encrypted for Impact',100,'Impact','Bestanden worden versleuteld.')]),
        ('Domain takeover via VPN','Credential Access Actor','Critical',[
            ('Internet','T1589','Gather Victim Identity Information',25,'Reconnaissance','Gebruikersinformatie wordt verzameld.'),
            ('VPN Gateway','T1133','External Remote Services',70,'Initial Access','Misbruik van extern toegankelijke VPN.'),
            ('Management Server','T1021.006','Windows Remote Management',78,'Lateral Movement','Remote management wordt gebruikt.'),
            ('Domain Controller','T1558','Steal or Forge Kerberos Tickets',98,'Credential Access','Kerberos-misbruik leidt tot domeincontrole.')]),
        ('IoT pivot naar bedrijfsnetwerk','Opportunistic Actor','High',[
            ('Internet','T1595','Active Scanning',30,'Reconnaissance','IoT-diensten worden gevonden.'),
            ('IoT Device','T1190','Exploit Public-Facing Application',65,'Initial Access','Ongepatcht smartdevice wordt overgenomen.'),
            ('Router','T1046','Network Service Discovery',60,'Discovery','Interne services worden onderzocht.'),
            ('Applicatieserver','T1021','Remote Services',80,'Lateral Movement','Pivot naar bedrijfsserver.'),
            ('Database','T1213','Data from Information Repositories',88,'Collection','Bedrijfsgegevens worden verzameld.')]),
        ('Insider data exfiltration','Insider','High',[
            ('Client','T1078','Valid Accounts',45,'Initial Access','Legitiem account wordt gebruikt.'),
            ('Fileserver','T1083','File and Directory Discovery',55,'Discovery','Gevoelige bestanden worden gezocht.'),
            ('Database','T1213','Data from Information Repositories',75,'Collection','Data wordt verzameld.'),
            ('Cloud','T1567','Exfiltration Over Web Service',90,'Exfiltration','Data wordt naar externe cloudopslag gebracht.')]),
        ('OT disruption via IT netwerk','Advanced Persistent Threat','Critical',[
            ('Internet','T1190','Exploit Public-Facing Application',70,'Initial Access','Extern systeem wordt gecompromitteerd.'),
            ('Firewall','T1562.004','Disable or Modify System Firewall',82,'Defense Evasion','Segmentatie wordt verzwakt.'),
            ('Engineering Workstation','T1021.001','Remote Desktop Protocol',85,'Lateral Movement','Werkstation wordt overgenomen.'),
            ('PLC','T0831','Manipulation of Control',100,'Impact','Procesbesturing wordt gewijzigd.')])
    ]
    out=[]
    for name,actor,severity,rows in specs:
        steps=[_step(i+1,a,t,act,r,why,phase) for i,(a,t,act,r,phase,why) in enumerate(rows)]
        overall=round(sum(s.step_risk for s in steps)/len(steps)); coverage=round(sum(dp.coverage for s in steps for dp in s.detection_points)/len(steps))
        sc=NetworkScenario(name=name,description=f'Ingebouwd voorbeeldscenario ({severity}) voor analyse op een scan- of designbaseline.',actor_name=actor,status='Ready',overall_risk=overall,detection_coverage=coverage,residual_risk=round(overall*(1-coverage/100)),steps=steps,
            assumptions=['Assetnamen worden tijdens toepassing gekoppeld aan best passende assets uit de huidige baseline.'],
            recommendations=['Valideer assetmapping voor rapportage.','Vergelijk baseline en projectie en prioriteer blokkades op kritieke stappen.'])
        sc.scenario_id='builtin-'+name.lower().replace(' ','-')
        out.append(sc)
    return out
