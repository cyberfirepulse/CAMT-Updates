from __future__ import annotations
import re
from projectmanager.scenario_import.models import IncidentScenario
from projectmanager.cti.models import ThreatActor
from projectmanager.offline_intelligence.matcher import ThreatAttributionMatcher
from projectmanager.offline_intelligence.scoring import ScoringPolicyStore
from projectmanager.core.shared import get_app_home_dir
from projectmanager.cti.repository import CTIRepository
from .models import ScenarioAnalysis,TechniqueAssessment,ActorAssessment,DetectionAssessment,ImpactAssessment

TECHNIQUES={
'Initial Access':[('T1133','External Remote Services'),('T1190','Exploit Public-Facing Application'),('T1566','Phishing')],
'Credential Access':[('T1003','OS Credential Dumping'),('T1552','Unsecured Credentials')],
'Privilege Escalation':[('T1068','Exploitation for Privilege Escalation'),('T1078','Valid Accounts')],
'Lateral Movement':[('T1021','Remote Services'),('T1021.001','Remote Desktop Protocol'),('T1021.002','SMB/Windows Admin Shares')],
'Discovery':[('T1087','Account Discovery'),('T1046','Network Service Discovery')],
'Exfiltration':[('T1041','Exfiltration Over C2 Channel'),('T1567','Exfiltration Over Web Service')],
'Impact':[('T1489','Service Stop'),('T1490','Inhibit System Recovery'),('T1565.001','Stored Data Manipulation')]
}
DETECTIONS={
'T1133':[('VPN / identity logs','Nieuwe of afwijkende externe login'),('Firewall','Nieuwe remote-access sessie')],
'T1190':[('WAF / web logs','Exploit- of foutpatronen'),('EDR','Onverwacht proces vanuit internet-facing service')],
'T1566':[('Mail security','Kwaadaardige URL/bijlage'),('Endpoint','Office child process of payload')],
'T1003':[('Windows Security / EDR','LSASS access, credential dumping gedrag'),('Sysmon','Process access naar LSASS')],
'T1552':[('DLP / secret scanning','Credentials in bestanden of scripts'),('EDR','Credential search gedrag')],
'T1068':[('EDR','Exploit- of tokenmisbruik'),('Windows Security','Privilege escalation anomalie')],
'T1078':[('Identity telemetry','Afwijkend gebruik van geldig account'),('Windows Security','4624/4672 context')],
'T1021':[('Firewall / NetFlow','Nieuwe beheerverbinding tussen zones'),('EDR','Remote execution tooling')],
'T1021.001':[('Terminal Services','RDP sessie-events'),('Windows Security','Logon type 10')],
'T1021.002':[('Windows Security','5140/5145 share access'),('Sysmon','Remote service/process activity')],
'T1087':[('Identity / EDR','Account enumeration'),('Windows Security','Directory query context')],
'T1046':[('NDR / firewall','Poortscan of service discovery'),('EDR','Discovery tooling')],
'T1041':[('NDR / proxy','Ongebruikelijke outbound dataflow'),('DLP','Gevoelige data naar externe bestemming')],
'T1567':[('Proxy / SaaS logs','Ongebruikelijke upload naar webdienst'),('DLP','Bulk upload')],
'T1489':[('Windows Service Control','Service stop events'),('EDR','Abrupte service termination')],
'T1490':[('Backup / Windows logs','Deletion of shadow copies/backups'),('EDR','Recovery inhibition command')],
'T1565.001':[('Application / database audit','Onverwachte wijziging kritieke data'),('OT telemetry','Setpoint/configuratie gewijzigd')]
}

class ScenarioAnalysisEngine:
    @staticmethod
    def _identity_key(value: str) -> str:
        return " ".join(str(value or "").casefold().replace("_", " ").split())

    def _canonical_actor_groups(self, actors: list[ThreatActor]) -> list[dict]:
        """Collapse duplicate records and explicit alias identities before scoring."""
        if not actors:
            return []

        parent = list(range(len(actors)))

        def find(i):
            while parent[i] != i:
                parent[i] = parent[parent[i]]
                i = parent[i]
            return i

        def union(a, b):
            ra, rb = find(a), find(b)
            if ra != rb:
                parent[rb] = ra

        name_to_indexes = {}
        for index, actor in enumerate(actors):
            key = self._identity_key(actor.name)
            if key:
                name_to_indexes.setdefault(key, []).append(index)

        # Same canonical name always represents one identity.
        for indexes in name_to_indexes.values():
            for index in indexes[1:]:
                union(indexes[0], index)

        # If one record explicitly names another record as an alias, treat it as
        # the same identity. Mere relationships do NOT trigger identity merging.
        for index, actor in enumerate(actors):
            for alias in list(actor.aliases or []):
                alias_key = self._identity_key(alias)
                for other in name_to_indexes.get(alias_key, []):
                    union(index, other)

        grouped = {}
        for index, actor in enumerate(actors):
            grouped.setdefault(find(index), []).append(actor)

        result = []
        for members in grouped.values():
            def representative_score(actor):
                aliases = len(actor.aliases or [])
                description = len((actor.description or "").strip())
                confidence = int(getattr(actor, "confidence", 0) or 0)
                # Prefer the record that carries richer identity metadata.
                return (aliases, description, confidence)

            canonical = max(members, key=representative_score)
            aliases = []
            seen = {self._identity_key(canonical.name)}
            for actor in members:
                for value in [actor.name] + list(actor.aliases or []):
                    key = self._identity_key(value)
                    if not key or key in seen:
                        continue
                    seen.add(key)
                    aliases.append(value)

            result.append({
                "canonical": canonical,
                "members": members,
                "member_ids": {actor.id for actor in members},
                "aliases": aliases,
            })

        return result

    def _generated_assumptions(self, scenario, techniques, actor_matches):
        rows=[]; seen=set()
        def add(cat,conf,text):
            if not text or (cat,text.casefold()) in seen:return
            seen.add((cat,text.casefold())); rows.append(f"[{cat}|{int(conf)}%] {text}")
        for a in list(scenario.assumptions or []):
            add(getattr(a,"category","Expliciete aanname") or "Expliciete aanname",
                getattr(a,"confidence",70) or 70,getattr(a,"statement",""))
        evs=[e for e in list(scenario.events or []) if not any(x in (e.phase+" "+e.description).casefold()
             for x in ("defender","detection","detectie","containment","isolated","soc alert"))]
        if len(evs)>1:add("Afgeleide aanname",65,"De chronologisch gecorreleerde aanvalsevents worden als één samenhangende aanvalsketen behandeld; causaliteit is niet door telemetry alleen bewezen.")
        ids={t.technique_id for t in techniques}
        if "T1190" in ids:add("Afgeleide aanname",75,"Een geobserveerde exploitpoging (T1190) wordt voor de aanvalsketen als succesvolle initial access geïnterpreteerd; succesvolle exploitatie vereist aanvullende bevestiging.")
        if "T1078" in ids:add("Analytische onzekerheid",60,"Gebruik van een geldig account (T1078) wordt als ongeautoriseerd/gecompromitteerd behandeld; de telemetry bewijst niet zelfstandig hoe de credentials zijn verkregen.")
        if any(x.startswith("T1021") for x in ids):add("Afgeleide aanname",75,"Remote-service activiteit wordt als laterale beweging geïnterpreteerd; legitiem beheer moet met identity- en change-context worden uitgesloten.")
        if "T1041" in ids:add("Analytische onzekerheid",65,"Outbound transfer (T1041) wordt als mogelijke exfiltratie behandeld; inhoud, volume en bestemming moeten dit nog bevestigen.")
        ot=[a for a in scenario.assets if any(k in ((a.asset_type+" "+a.name+" "+a.role).casefold()) for k in ("scada","plc","rtu","historian","engineering","ics","ot"))]
        if ot:add("Afgeleide aanname",70,"IT- en OT-events in deze tijdlijn worden als onderdeel van dezelfde incidentketen gecorreleerd; een gedeelde actor of oorzaak is daarmee nog niet bewezen.")
        generic=[a for a in scenario.assets if (a.asset_type or "").casefold() in ("","device","unknown")]
        if generic:add("Ontbrekende informatie",80,f"Voor {len(generic)} asset(s) ontbreekt voldoende rol/type-metadata; assetfunctie en zone moeten worden gevalideerd.")
        if actor_matches:add("Analytische onzekerheid",95,f"{len(actor_matches)} threat-actor match(es) zijn technische/contextuele overeenkomsten en vormen geen attributie zonder onafhankelijke CTI-evidence.")
        return rows

    def analyse(self,scenario:IncidentScenario,actors:list[ThreatActor])->ScenarioAnalysis:
        techniques=[];seen=set()
        for ev in scenario.events:
            # Defender/detection/containment events remain evidence, but are not adversary techniques.
            defender_text=(ev.phase+" "+ev.description).casefold()
            if any(marker in defender_text for marker in ("defender","detection","detectie","containment","isolated","isolate","soc alert")):
                continue
            candidates=TECHNIQUES.get(ev.phase,[])
            chosen=[]
            low=ev.description.lower()
            explicit_ids=[]
            for source_text in (ev.description,ev.source_text,scenario.raw_text):
                for tid in re.findall(r"\bT\d{4}(?:\.\d{3})?\b",source_text or "",flags=re.I):
                    tid=tid.upper()
                    if tid not in explicit_ids: explicit_ids.append(tid)
            if explicit_ids:
                # Explicit source T-IDs always outrank heuristic/default mappings.
                chosen=[(tid,tid) for tid in explicit_ids]
            if not chosen and ev.phase=='Initial Access' and 'vpn' in low: chosen=[('T1133','External Remote Services')]
            elif not chosen and ev.phase=='Lateral Movement' and 'rdp' in low: chosen=[('T1021.001','Remote Desktop Protocol')]
            elif not chosen and ev.phase=='Lateral Movement' and ('smb' in low or 'share' in low): chosen=[('T1021.002','SMB/Windows Admin Shares')]
            elif not chosen and ev.phase=='Impact' and any(x in low for x in ('wijzig','manipul','plc','setpoint')): chosen=[('T1565.001','Stored Data Manipulation')]
            elif not chosen: chosen=candidates[:1]
            supplemental=[]
            if any(x in low for x in ('credential','credentials','wachtwoord','dump')): supplemental.append(('T1003','OS Credential Dumping','Credential Access'))
            if any(x in low for x in ('lateraal','lateral','rdp')) and not any(x[0].startswith('T1021') for x in chosen): supplemental.append(('T1021.001' if 'rdp' in low else 'T1021','Remote Desktop Protocol' if 'rdp' in low else 'Remote Services','Lateral Movement'))
            for item in [(tid,name,ev.phase) for tid,name in chosen]+supplemental:
                tid,name,phase=item
                if tid in seen:continue
                seen.add(tid);techniques.append(TechniqueAssessment(tid,name,phase,[ev.description],75 if phase!='Observed / described' else 45))
        actor_matches=[];scenario_ttps={t.technique_id for t in techniques}
        scenario_text=scenario.raw_text.casefold()
        sectors=[]
        for sector,terms in (("Critical Infrastructure",("brug","sluis","waterkering","scada","plc","ot","critical infrastructure")),("Energy",("energie","energy","centrale","power")),("Government",("overheid","ministerie","government")),("Finance",("bank","finance","betaling")),("Technology",("software","cloud","technology"))):
            if any(term in scenario_text for term in terms): sectors.append(sector)
        policy=ScoringPolicyStore(get_app_home_dir() / "cti").active()
        # Base TTP similarity remains available, but is no longer presented as attribution confidence.
        ranked=ThreatAttributionMatcher().rank(actors,scenario_ttps,sectors=sectors,limit=max(20,len(actors)),policy=policy)
        actor_by_id={actor.id:actor for actor in actors}
        base_by_id={c.actor_id:c for c in ranked}

        groups=self._canonical_actor_groups(actors)
        canonical_id_by_member={}
        for group in groups:
            canonical_id=group["canonical"].id
            for member_id in group["member_ids"]:
                canonical_id_by_member[member_id]=canonical_id

        # Resolve explicit actor/alias mentions from the scenario text.
        explicit_ids=set()
        for actor in actors:
            names=[actor.name]+list(actor.aliases or [])
            if any(name and name.casefold() in scenario_text for name in names):
                explicit_ids.add(actor.id)

        try:
            relationships=CTIRepository().list("relationships")
        except Exception:
            relationships=[]

        relation_by_actor={}
        for rel in relationships:
            relation_by_actor.setdefault(rel.source_id,[]).append(rel)
            relation_by_actor.setdefault(rel.target_id,[]).append(rel)

        candidates=[]
        for group in groups:
            actor=group["canonical"]
            members=group["members"]
            member_ids=group["member_ids"]

            bases=[base_by_id.get(member.id) for member in members if base_by_id.get(member.id) is not None]
            ttp_score=max([base.probability for base in bases] or [0])
            matched_ttps=sorted({ttp for base in bases for ttp in list(base.matched_techniques)})
            matched_sectors=sorted({sector for base in bases for sector in list(base.matched_sectors)})
            matched_regions=sorted({region for base in bases for region in list(base.matched_regions)})

            positive=[]
            for base in bases:
                positive.extend(list(base.evidence))
            positive=list(dict.fromkeys(positive))
            negative=[]

            direct=1.0 if member_ids.intersection(explicit_ids) else 0.0

            linked=[]
            relation_strength=0.0
            explicit_canonical_ids={canonical_id_by_member.get(i,i) for i in explicit_ids}
            for member in members:
                for rel in relation_by_actor.get(member.id,[]):
                    other=rel.target_id if rel.source_id==member.id else rel.source_id
                    other_canonical=canonical_id_by_member.get(other,other)
                    if other_canonical in explicit_canonical_ids and other_canonical != actor.id:
                        linked.append(rel)
                        relation_strength=max(
                            relation_strength,
                            max(0.0,min(1.0,rel.confidence/100.0))
                        )

            profiles=" ".join((member.description or "") for member in members).casefold()
            context_terms=(
                'initial access','handoff','preposition','pre-position',
                'reconnaissance','persistent access','operational impact',
                'destructive','ot','ics','engineering workstation','edge exploitation'
            )
            mentioned_terms=sum(
                1 for term in context_terms
                if term in scenario_text and term in profiles
            )
            profile_score=min(1.0,mentioned_terms/3.0)
            sector_score=(len(matched_sectors)/max(1,len(sectors))) if sectors else 0.0
            context_raw=0.55*direct+0.25*relation_strength+0.12*profile_score+0.08*sector_score
            context_score=round(min(100,max(0,context_raw*100)))

            source_conf=max([
                max(0,min(100,int(getattr(member,"confidence",0) or 0)))
                for member in members
            ] or [0])

            attribution=round(
                min(95,max(0,0.30*ttp_score+0.55*context_score+0.15*source_conf))
            )

            if direct:
                positive.append('Actor of alias expliciet genoemd in scenario')
            if len(members)>1:
                positive.append(
                    'Canonieke identiteit samengevoegd uit '
                    + str(len(members))
                    + ' CTI-records'
                )
            if linked:
                positive.append(
                    'CTI-relatie met expliciet genoemde actor: '
                    + ', '.join(sorted({r.relationship_type for r in linked}))
                )
            if profile_score:
                positive.append(f'Gedrags/archetype-context: {round(profile_score*100)}%')
            if not matched_ttps:
                negative.append('Geen ATT&CK-techniekoverlap')
            if sectors and not matched_sectors:
                negative.append('Geen sectoroverlap')
            if not direct and not linked:
                negative.append('Geen directe actor- of relationele scenario-evidence')

            rationale='; '.join(dict.fromkeys(positive))+'. TTP similarity en context zijn afzonderlijk gewogen; canonieke actoridentiteiten zijn vóór scoring samengevoegd; geen automatische attributie.'

            factor_scores={}
            contributions={}
            for base in bases:
                factor_scores.update(dict(base.factor_scores))
                contributions.update(dict(base.factor_contributions))
            factor_scores.update({
                'direct_identity':direct,
                'relationship_context':relation_strength,
                'profile_context':profile_score,
                'context_match':context_score/100.0,
                'canonical_record_count':float(len(members)),
            })

            policy_base=bases[0] if bases else None
            candidates.append(ActorAssessment(
                actor.id,
                actor.name,
                list(group["aliases"]),
                matched_ttps,
                attribution,
                attribution,
                ttp_match=ttp_score,
                context_match=context_score,
                rationale=rationale,
                policy_id=policy_base.policy_id if policy_base else policy.policy_id,
                policy_name=policy_base.policy_name if policy_base else policy.name,
                policy_version=policy.version,
                policy_mode=policy.mode,
                factor_scores=factor_scores,
                factor_contributions=contributions,
                positive_evidence=list(dict.fromkeys(positive)),
                negative_evidence=list(dict.fromkeys(negative)),
            ))
        candidates.sort(key=lambda x:(x.confidence,x.context_match,x.ttp_match),reverse=True)
        actor_matches=candidates[:12]
        detections=[]
        for t in techniques:
            for src,hint in DETECTIONS.get(t.technique_id,[('General telemetry','Correlatie van endpoint-, identity- en netwerklogs')]):
                detections.append(DetectionAssessment(t.technique_id,src,hint,50,'High' if t.phase in ('Initial Access','Impact') else 'Medium',65))
        impacts=self._impact(scenario)
        impact_score=round(sum(i.score for i in impacts)/len(impacts)) if impacts else 30
        uncertainty=max(0,min(35,len(scenario.assumptions)*4))
        likelihood=max(20,min(90,35+len(techniques)*5-uncertainty//2))
        inherent=round(likelihood*impact_score/100)
        coverage=round(sum(d.coverage for d in detections)/len(detections)) if detections else 0
        residual=max(0,round(inherent*(1-coverage/100)))
        level='Critical' if inherent>=75 else 'High' if inherent>=50 else 'Medium' if inherent>=25 else 'Low'
        rec=[]
        if any(t.phase=='Initial Access' for t in techniques):rec.append('Versterk externe toegang met MFA, patching, logging en bronbeperking.')
        if any(t.phase=='Lateral Movement' for t in techniques):rec.append('Beperk remote services en segmenteer beheer-, IT- en OT-zones.')
        if any(t.phase=='Impact' for t in techniques):rec.append('Definieer herstelprocedures, handmatige fallback en integriteitscontrole voor kritieke processen.')
        if coverage<60:rec.append('Vergroot identity-, endpoint-, netwerk- en applicatietelemetrie voor de beschreven technieken.')
        assumptions=self._generated_assumptions(scenario,techniques,actor_matches)+['[Analytische onzekerheid|90%] ATT&CK-mapping is deterministisch afgeleid uit beschreven/geobserveerde gebeurtenissen en moet inhoudelijk worden gevalideerd.']
        return ScenarioAnalysis(scenario.scenario_id,scenario.title,techniques,actor_matches,detections,impacts,likelihood,impact_score,inherent,coverage,residual,level,assumptions,rec)
    def _impact(self,s:IncidentScenario):
        text=s.raw_text.lower();names=[a.name for a in s.assets]
        rows=[]
        def add(domain,score,why):rows.append(ImpactAssessment(domain,score,'Critical' if score>=80 else 'High' if score>=60 else 'Medium' if score>=35 else 'Low',why,names[:20]))
        add('Operations',85 if any(x in text for x in ('brug','sluis','waterkering','plc','scada','uitval','onbeschikbaar')) else 45,'Mogelijke verstoring van operationele beschikbaarheid en besturing.')
        add('Safety',80 if any(x in text for x in ('brug','sluis','waterkering','kritisch knooppunt','ot')) else 25,'Mogelijke gevolgen voor fysieke veiligheid en veilige bediening.')
        add('Information',65 if any(x in text for x in ('datalek','gestolen','exfil','credential')) else 35,'Mogelijke aantasting van vertrouwelijkheid en integriteit.')
        add('Financial',55 if any(x in text for x in ('uitval','verlies','verstoord')) else 30,'Kosten door verstoring, herstel en onderzoek.')
        add('Reputation / Public trust',60 if any(x in text for x in ('kritisch','publiek','nederland','brug','sluis')) else 30,'Mogelijke maatschappelijke en bestuurlijke impact.')
        return rows
