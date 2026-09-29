from __future__ import annotations

import csv
import html
import io
import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable
from urllib.parse import urlparse
from urllib.request import Request, urlopen

from projectmanager.scenario_intelligence.parser import ScenarioParser, ScenarioParseError
from projectmanager.scenario_intelligence.models import ScenarioSourceType


@dataclass(slots=True)
class IngestCandidate:
    entity_type: str
    value: str
    normalized_value: str
    confidence: int
    context: str = ""
    attributes: dict[str, Any] = field(default_factory=dict)


class CTIIngestionError(ValueError):
    pass



class StructuredScenarioCTIExtractor:
    ACTOR_LABEL_RE=re.compile(
        r"(?i)^\s*(primary\s+actor|secondary\s+actor|threat\s+actor|actor|initial\s+access\s+provider|access\s+provider)\s*[:=-]\s*(.+?)\s*$"
    )
    CAMPAIGN_RE=re.compile(r"(?i)^\s*campaign\s*[:=-]\s*(.*?)\s*$")
    ALIAS_RE=re.compile(r"(?i)^\s*alias(?:es)?\s*[:=-]\s*(.+?)\s*$")
    SECTOR_RE=re.compile(r"(?i)^\s*sector\s*[:=-]\s*(.*?)\s*$")
    ARROW_RE=re.compile(r"^\s*(.+?(?:\s*(?:→|->)\s*.+?)+)\s*$")

    def extract(self,text: str) -> list[IngestCandidate]:
        lines=text.replace("\r\n","\n").replace("\r","\n").splitlines()
        out=[]; seen=set(); actors={}; last_actor=""; pending=None

        def add(kind,value,confidence,context,**attrs):
            value=re.sub(r"\s+"," ",str(value or "")).strip(" \t\r\n—–-|:;,")
            if not value:return
            normalized=GenericCTIExtractor.normalize("region" if kind=="nexus" else kind,value)
            sig=(kind,normalized.casefold(),json.dumps(attrs,sort_keys=True,ensure_ascii=False))
            if not normalized or sig in seen:return
            seen.add(sig)
            out.append(IngestCandidate(kind,value,normalized,confidence,context[:1600],attrs))

        def split_values(raw):
            return [x.strip() for x in re.split(r"\s*[,;|]\s*",raw) if x.strip()]

        for idx,line in enumerate(lines):
            stripped=line.strip()
            if not stripped or set(stripped)<=set("-=_"):
                continue

            if pending and ":" not in stripped and len(stripped)<=100:
                if pending=="campaign":
                    add("campaign",stripped,97,stripped,semantic_role="structured_campaign",mapping="EXPLICIT",source_line=idx+1)
                    pending=None; continue
                if pending=="sector":
                    if stripped.rstrip(":").upper() not in {"THREAT ACTORS","CAMPAIGN OBJECTIVE","EXPECTED ACTOR CORRELATION","EXPECTED CAMPAIGN CLASSIFICATION","ATT&CK"}:
                        add("sector",stripped,90,stripped,semantic_role="structured_sector",mapping="EXPLICIT",source_line=idx+1)
                        continue
                    pending=None

            m=self.CAMPAIGN_RE.match(stripped)
            if m:
                value=m.group(1).strip()
                if value:
                    add("campaign",value,97,line,semantic_role="structured_campaign",mapping="EXPLICIT",source_line=idx+1)
                    pending=None
                else:
                    pending="campaign"
                continue

            m=self.SECTOR_RE.match(stripped)
            if m:
                raw=m.group(1).strip()
                if raw:
                    for value in split_values(raw):
                        add("sector",value,94,line,semantic_role="structured_sector",mapping="EXPLICIT",source_line=idx+1)
                    pending=None
                else:
                    pending="sector"
                continue

            if stripped.rstrip(":").upper() in {"THREAT ACTORS","CAMPAIGN OBJECTIVE","EXPECTED ACTOR CORRELATION","EXPECTED CAMPAIGN CLASSIFICATION","ATT&CK"}:
                pending=None
                continue

            m=self.ACTOR_LABEL_RE.match(stripped)
            if m:
                pending=None
                role=m.group(1).strip().title(); value=m.group(2).strip()
                if value and value.casefold() not in {"unknown","none","n/a"}:
                    add("actor",value,97,line,semantic_role="structured_actor",actor_role=role,mapping="EXPLICIT",source_line=idx+1)
                    actors[value.casefold()]=value; last_actor=value
                    add("relationship",f"{value} -> has-role -> {role}",92,line,
                        semantic_role="actor_role",source_actor=value,target_label=role,
                        relationship_type="has-role",mapping="EXPLICIT")
                continue

            m=self.ALIAS_RE.match(stripped)
            if m and last_actor:
                pending=None
                for alias in split_values(m.group(1)):
                    add("alias",alias,96,line,semantic_role="alias",alias_of=last_actor,mapping="EXPLICIT",source_line=idx+1)
                continue

            m=self.ARROW_RE.match(stripped)
            if m:
                chain=[x.strip() for x in re.split(r"\s*(?:→|->)\s*",m.group(1)) if x.strip()]
                for token in chain:
                    if re.fullmatch(r"(?:APT\d+|UNC\d+|TA\d+|FIN\d+|[A-Z][A-Z0-9_-]{3,})",token):
                        actors.setdefault(token.casefold(),token)
                        add("actor",token,90,line,semantic_role="structured_actor",mapping="EXPLICIT_CHAIN",source_line=idx+1)
                for left,right in zip(chain,chain[1:]):
                    la=actors.get(left.casefold()); ra=actors.get(right.casefold())
                    if la and ra:
                        add("relationship",f"{la} -> hands-off-to -> {ra}",90,line,
                            semantic_role="relationship",source_actor=la,target_actor=ra,
                            relationship_type="hands-off-to",mapping="EXPLICIT_CHAIN")
                    elif la:
                        role=right.title()
                        add("relationship",f"{la} -> has-role -> {role}",88,line,
                            semantic_role="actor_role",source_actor=la,target_label=role,
                            relationship_type="has-role",mapping="EXPLICIT_CHAIN")
        return out


class GenericCTIExtractor:
    """Deterministic CTI extraction for unstructured defensive intelligence sources."""

    ATTACK_RE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b", re.I)
    CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.I)
    SHA256_RE = re.compile(r"(?<![A-Fa-f0-9])[A-Fa-f0-9]{64}(?![A-Fa-f0-9])")
    SHA1_RE = re.compile(r"(?<![A-Fa-f0-9])[A-Fa-f0-9]{40}(?![A-Fa-f0-9])")
    MD5_RE = re.compile(r"(?<![A-Fa-f0-9])[A-Fa-f0-9]{32}(?![A-Fa-f0-9])")
    IPV4_RE = re.compile(r"(?<!\d)(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)(?!\d)")
    URL_RE = re.compile(r"https?://[^\s<>\]\[\)\(\"']+", re.I)
    DOMAIN_RE = re.compile(r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+(?:com|net|org|io|ru|cn|ir|info|biz|co|uk|de|nl|eu|gov|mil|cloud|online|site|top|xyz)\b", re.I)
    ACTOR_TOKEN_RE = re.compile(r"\b(?:APT\d{1,3}|TA\d{3,6}|UNC\d{3,6}|FIN\d{1,4})\b", re.I)
    LABEL_RE = re.compile(r"^\s*(threat\s*actor|actor|group|threat\s*group|malware|tool|campaign|sector|region|aliases?)\s*[:=-]\s*(.+?)\s*$", re.I)

    def extract(self, text: str, known_aliases: Iterable[str] = ()) -> list[IngestCandidate]:
        source = text.replace("\r\n", "\n").replace("\r", "\n")
        candidates: list[IngestCandidate] = []
        try:
            candidates.extend(StructuredScenarioCTIExtractor().extract(source))
        except Exception:
            pass
        try:
            candidates.extend(NarrativeCTIExtractor().extract(source))
        except Exception:
            pass
        try:
            candidates.extend(SemanticCTIMatrixParser().to_candidates(source))
        except Exception:
            pass
        seen: set[tuple[str, str]] = {(c.entity_type, c.normalized_value.casefold()) for c in candidates}

        def add(entity_type: str, value: str, confidence: int, context: str = "", **attrs: Any) -> None:
            value = value.strip().strip(".,;:()[]{}\"'")
            if not value:
                return
            normalized = self.normalize(entity_type, value)
            key = (entity_type, normalized.casefold())
            if not normalized or key in seen:
                return
            seen.add(key)
            candidates.append(IngestCandidate(entity_type, value, normalized, confidence, context[:1000], attrs))

        for line in source.splitlines():
            match = self.LABEL_RE.match(line)
            if not match:
                continue
            label, raw = match.group(1).lower(), match.group(2).strip()
            values = [v.strip() for v in re.split(r"[,;|]", raw) if v.strip()]
            mapping = {
                "threat actor": "actor", "actor": "actor", "group": "actor", "threat group": "actor",
                "malware": "malware", "tool": "tool", "campaign": "campaign", "sector": "sector",
                "region": "region", "alias": "alias", "aliases": "alias",
            }
            for value in values:
                add(mapping[label], value, 92, line)

        for m in self.ACTOR_TOKEN_RE.finditer(source): add("actor", m.group(0), 88, self._context(source, m.start()))
        for alias in sorted({a.strip() for a in known_aliases if a and len(a.strip()) >= 4}, key=len, reverse=True):
            if re.search(rf"(?<![\w-]){re.escape(alias)}(?![\w-])", source, re.I):
                add("actor", alias, 90, f"Known alias matched in source: {alias}", known_alias=True)
        for m in self.ATTACK_RE.finditer(source): add("technique", m.group(0).upper(), 98, self._context(source, m.start()))
        for m in self.CVE_RE.finditer(source): add("cve", m.group(0).upper(), 99, self._context(source, m.start()))
        for m in self.URL_RE.finditer(source): add("url", m.group(0), 99, self._context(source, m.start()))
        for m in self.SHA256_RE.finditer(source): add("sha256", m.group(0).lower(), 100, self._context(source, m.start()))
        for m in self.SHA1_RE.finditer(source): add("sha1", m.group(0).lower(), 100, self._context(source, m.start()))
        for m in self.MD5_RE.finditer(source): add("md5", m.group(0).lower(), 100, self._context(source, m.start()))
        for m in self.IPV4_RE.finditer(source):
            ip = m.group(0)
            if not ip.startswith(("0.", "127.")):
                add("ipv4", ip, 98, self._context(source, m.start()))
        url_hosts = {urlparse(c.normalized_value).hostname.casefold() for c in candidates if c.entity_type == "url" and urlparse(c.normalized_value).hostname}
        for m in self.DOMAIN_RE.finditer(source):
            domain=m.group(0).lower().rstrip('.')
            if domain not in url_hosts:
                add("domain", domain, 95, self._context(source, m.start()))
        return candidates

    @staticmethod
    def normalize(entity_type: str, value: str) -> str:
        value=value.strip()
        if entity_type in {"technique", "cve"}: return value.upper()
        if entity_type in {"domain", "sha256", "sha1", "md5"}: return value.lower().rstrip('.')
        if entity_type == "url": return value.rstrip(".,;)")
        if entity_type == "ipv4": return value
        return re.sub(r"\s+", " ", value)

    @staticmethod
    def _context(text: str, offset: int, radius: int = 180) -> str:
        start=max(0, offset-radius); end=min(len(text), offset+radius)
        return re.sub(r"\s+", " ", text[start:end]).strip()


class CTISourceReader:
    MAX_URL_BYTES = 10 * 1024 * 1024
    SUPPORTED_SUFFIXES = {".txt", ".md", ".markdown", ".json", ".csv", ".html", ".htm", ".docx", ".pdf"}

    def __init__(self) -> None:
        self.parser = ScenarioParser()
        self.last_document_metadata: dict[str, Any] = {}
        self.last_document_warnings: list[str] = []

    def read_file(self, path: str | Path) -> tuple[str, str]:
        source=Path(path).expanduser().resolve()
        if not source.is_file(): raise FileNotFoundError(source)
        suffix=source.suffix.lower()
        if suffix not in self.SUPPORTED_SUFFIXES:
            raise CTIIngestionError(f"Niet-ondersteund CTI-bestand: {source.name}")
        if suffix == ".csv":
            raw=source.read_text(encoding="utf-8-sig", errors="replace")
            rows=list(csv.reader(io.StringIO(raw)))
            return "\n".join(" | ".join(cell for cell in row if cell) for row in rows), str(source)
        if suffix in {".html", ".htm"}:
            return self._html_to_text(source.read_text(encoding="utf-8", errors="replace")), str(source)
        try:
            document=self.parser.parse_file(source)
            self.last_document_metadata=dict(getattr(document,'metadata',{}) or {})
            self.last_document_warnings=list(getattr(document,'warnings',[]) or [])
            return document.text, str(source)
        except (ScenarioParseError, ValueError) as exc:
            raise CTIIngestionError(str(exc)) from exc

    @staticmethod
    def classify_url(url: str) -> str:
        parsed=urlparse((url or "").strip())
        host=(parsed.hostname or "").casefold()
        path=(parsed.path or "/").casefold()
        if host in {"misp-project.org","www.misp-project.org"}:
            return "misp_project_site"
        if "misp" in host or "/events/" in path or "/attributes/" in path:
            if any(token in path for token in ("/restsearch", "/events/view/", "/attributes/view/")) or path.endswith(".json"):
                return "misp_intelligence_endpoint"
            return "possible_misp_instance"
        return "generic_web"

    def read_url(self, url: str) -> tuple[str, str]:
        source_url=url.strip()
        parsed=urlparse(source_url)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            raise CTIIngestionError("Gebruik een geldige http- of https-URL.")
        request=Request(source_url, headers={"User-Agent":"CAMT/1.0.1.2 CTI-Ingestion"})
        try:
            with urlopen(request, timeout=20) as response:
                content_type=(response.headers.get("Content-Type") or "").lower()
                final_url=getattr(response, "url", source_url) or source_url
                content_disposition=(response.headers.get("Content-Disposition") or "").lower()
                data=response.read(self.MAX_URL_BYTES + 1)
        except Exception as exc:
            raise CTIIngestionError(f"URL kon niet worden gelezen: {exc}") from exc
        if len(data) > self.MAX_URL_BYTES:
            raise CTIIngestionError("URL-inhoud is groter dan 10 MB.")

        # Binary document detection MUST happen before decoding.
        # Some CDNs return application/octet-stream or an incorrect text MIME type.
        path=urlparse(final_url).path.casefold()
        is_pdf=(
            data.startswith(b"%PDF-")
            or "application/pdf" in content_type
            or path.endswith(".pdf")
            or ".pdf" in content_disposition
        )
        if is_pdf:
            if not data.startswith(b"%PDF-"):
                raise CTIIngestionError(
                    "De URL lijkt naar een PDF te verwijzen, maar de ontvangen inhoud is geen geldig PDF-bestand."
                )
            try:
                document=self.parser.parse_bytes(
                    data,
                    source_type=ScenarioSourceType.PDF,
                    source_name=Path(urlparse(final_url).path).name or "remote.pdf",
                )
            except (ScenarioParseError, ValueError) as exc:
                raise CTIIngestionError(f"Remote PDF kon niet worden verwerkt: {exc}") from exc
            self.last_document_metadata=dict(getattr(document,"metadata",{}) or {})
            self.last_document_metadata.update({
                "remote_url": final_url,
                "content_type": content_type,
                "remote_pdf": True,
            })
            self.last_document_warnings=list(getattr(document,"warnings",[]) or [])
            return document.text, final_url

        charset="utf-8"
        match=re.search(r"charset=([^;\s]+)", content_type)
        if match:
            charset=match.group(1).strip('"\'')
        text=data.decode(charset, errors="replace")

        # Safety barrier: raw PDF object syntax must never reach the CTI extractor.
        head=text[:8192]
        if (
            "%PDF-" in head
            or re.search(r"(?m)^\s*\d+\s+\d+\s+obj\b", head)
            or "/FlateDecode" in head
            or re.search(r"(?m)^\s*xref\s*$", head)
        ):
            raise CTIIngestionError(
                "Binaire PDF-inhoud gedetecteerd. CAMT heeft de bron geblokkeerd zodat PDF-objectdata "
                "niet als IOC/CTI kan worden geïnterpreteerd."
            )

        if "html" in content_type or "<html" in text[:1000].lower():
            text=self._html_to_text(text)

        self.last_document_metadata={
            "remote_url": final_url,
            "content_type": content_type,
            "remote_pdf": False,
        }
        self.last_document_warnings=[]
        return text, final_url

    def iter_directory(self, path: str | Path) -> Iterable[Path]:
        base=Path(path).expanduser().resolve()
        if not base.is_dir(): raise NotADirectoryError(base)
        for item in sorted(base.rglob("*")):
            if item.is_file() and item.suffix.lower() in self.SUPPORTED_SUFFIXES:
                yield item

    @staticmethod
    def _html_to_text(value: str) -> str:
        value=re.sub(r"(?is)<(script|style|noscript).*?>.*?</\1>", " ", value)
        value=re.sub(r"(?i)<br\s*/?>|</p>|</div>|</li>|</h[1-6]>", "\n", value)
        value=re.sub(r"(?s)<[^>]+>", " ", value)
        value=html.unescape(value)
        return re.sub(r"\n\s*\n+", "\n", re.sub(r"[ \t]+", " ", value)).strip()



class NarrativeCTIExtractor:
    ACTOR_CONTEXT_RE = re.compile(
        r"(?i)\b(?:groups?\s+(?:such as|like|including)|threat actors?\s+(?:such as|like|including)|"
        r"adversar(?:y|ies)\s+(?:such as|like|including)|activity\s+associated\s+with|tracked\s+as)\s+"
        r"(?P<actor>[A-Z][A-Z0-9_-]{3,}|[A-Z][a-z]+(?:\s+[A-Z][A-Za-z0-9]+){0,2})\b"
    )
    BLOCKLIST={"SANS","DRAGOS","OT","ICS","HMI","PLC","RTU","VPN","GIS","SOC","EDR","SIEM","HTTP","HTTPS","CVE","MITRE","ATTACK","SCADA","VFD"}
    BEHAVIOR_MAP=(
        (("exploit internet-facing","exploiting internet-facing","internet-facing infrastructure","edge exploitation"),"T1190","Exploit Public-Facing Application","Initial Access",78),
        (("remote services","remote access","vpn access","external remote services"),"T1133","External Remote Services","Persistence",72),
        (("powershell",),"T1059.001","PowerShell","Execution",86),
        (("valid accounts","valid account","stolen credentials","credential reuse"),"T1078","Valid Accounts","Defense Evasion",76),
        (("trusted relationship","supply chain","supplier access","third-party access","third party access"),"T1199","Trusted Relationship","Initial Access",72),
        (("control-loop mapping","control loop mapping","process mapping"),"T0861","Point & Tag Identification","Discovery",66),
        (("modify parameter","parameter manipulation"),"T0836","Modify Parameter","Impair Process Control",70),
        (("unauthorized command","command manipulation"),"T0855","Unauthorized Command Message","Impair Process Control",68),
    )
    SECTORS=("energy","electricity","power","utilities","water","wastewater","oil","gas","manufacturing","chemical","transportation","rail","maritime","aviation","government","telecommunications","telecom","critical infrastructure")

    def extract(self,text: str) -> list[IngestCandidate]:
        source=text.replace("\r\n","\n").replace("\r","\n")
        sentences=[x.strip() for x in re.split(r"(?<=[.!?])\s+|\n+",source) if x.strip()]
        mentions=[]
        for sentence in sentences:
            found=[]
            for m in self.ACTOR_CONTEXT_RE.finditer(sentence):
                actor=m.group("actor").strip()
                if actor.upper() not in self.BLOCKLIST:
                    found.append(actor)
            mentions.append(list(dict.fromkeys(found)))

        out=[];seen=set();contexts={}
        def add(kind,value,confidence,context,**attrs):
            value=re.sub(r"\s+"," ",str(value or "")).strip(" \t\r\n—–-|:;,")
            if not value:return
            normalized=GenericCTIExtractor.normalize("region" if kind=="nexus" else kind,value)
            sig=(kind,normalized.casefold(),json.dumps(attrs,sort_keys=True,ensure_ascii=False))
            if not normalized or sig in seen:return
            seen.add(sig)
            out.append(IngestCandidate(kind,value,normalized,confidence,context[:1600],attrs))

        for i,names in enumerate(mentions):
            for actor in names:
                parts=[]
                if i>0 and not mentions[i-1]: parts.append(sentences[i-1])
                parts.append(sentences[i])
                if i+1<len(sentences) and not mentions[i+1]: parts.append(sentences[i+1])
                ctx=" ".join(parts)
                contexts.setdefault(actor,[]).append(ctx)
                add("actor",actor,88,ctx,semantic_role="narrative_actor",detection="narrative_context",source_sentence=i+1)

        for actor,windows in contexts.items():
            ctx=" ".join(dict.fromkeys(windows));cf=ctx.casefold()
            explicit={x.upper() for x in GenericCTIExtractor.ATTACK_RE.findall(ctx)}
            for tid in sorted(explicit):
                add("technique",tid,98,ctx,semantic_role="actor_technique",actor=actor,mapping="EXPLICIT",source="narrative_context")
            for terms,tid,name,tactic,confidence in self.BEHAVIOR_MAP:
                if tid in explicit:continue
                matched=next((term for term in terms if term in cf),None)
                if matched:
                    add("technique",tid,confidence,ctx,semantic_role="actor_technique",actor=actor,mapping="INFERRED",inferred_from=matched,technique_name=name,tactic=tactic,source="narrative_context")
            for sector in self.SECTORS:
                if sector in cf:
                    add("sector",sector.title(),80,ctx,semantic_role="actor_sector",actor=actor,source="narrative_context")
            for malware_class in ("wiper","ransomware","backdoor","loader","implant"):
                if re.search(rf"(?i)\b{malware_class}\b",ctx):
                    add("malware",malware_class.title(),74,ctx,semantic_role="actor_malware_class",actor=actor,malware_class=malware_class,mapping="INFERRED_CLASS")
        return out


@dataclass(slots=True)
class SemanticMatrixRow:
    primary_actor: str
    related_actor: str
    nexus: str = ""
    aliases: list[str] = field(default_factory=list)
    rationale: str = ""
    relationship_type: str = "related-to"
    archetype: str = ""


class SemanticCTIMatrixParser:
    HEADING_RE = re.compile(r"^\s*#{1,6}\s*(?P<actor>[^—\n#]+?)\s*—\s*archetype:\s*(?P<archetype>.+?)\s*$", re.I)

    @staticmethod
    def clean(value: str) -> str:
        value = re.sub(r"[*_`]+", "", value or "")
        return re.sub(r"\s+", " ", value).strip().strip("—–-| ")

    @classmethod
    def aliases(cls, value: str) -> list[str]:
        value = cls.clean(value)
        if not value or value in {"-", "—"}:
            return []
        return [cls.clean(x) for x in re.split(r"\s*/\s*|,\s*", value) if cls.clean(x)]

    @staticmethod
    def relationship(rationale: str) -> str:
        v = (rationale or "").casefold()
        if any(x in v for x in ("draagt over", "handoff", "toegang te leveren", "toegangleverancier", "voedt")):
            return "hands-off-access-to"
        if "overlap" in v:
            return "overlaps-with"
        if any(x in v for x in ("dichtstbijzijnde match", "vergelijkbaar", "analoog", "zelfde impact")):
            return "behaviorally-similar-to"
        return "related-to"

    def parse(self, text: str) -> list[SemanticMatrixRow]:
        primary = ""
        archetype = ""
        rows = []
        for raw in text.replace("\r\n", "\n").replace("\r", "\n").splitlines():
            line = raw.strip()
            h = self.HEADING_RE.match(line)
            if h:
                primary = self.clean(h.group("actor"))
                archetype = self.clean(h.group("archetype"))
                continue
            if not primary or not line.startswith("|"):
                continue
            cells = [self.clean(c) for c in line.strip("|").split("|")]
            if len(cells) < 4:
                continue
            if not cells[0] or cells[0].casefold().startswith(("vergelijkbaar", "---", "actor")):
                continue
            related, nexus, alias_cell, rationale = cells[:4]
            rows.append(SemanticMatrixRow(
                primary_actor=primary,
                related_actor=related,
                nexus=nexus,
                aliases=self.aliases(alias_cell),
                rationale=rationale,
                relationship_type=self.relationship(rationale),
                archetype=archetype,
            ))
        return rows

    def to_candidates(self, text: str) -> list[IngestCandidate]:
        result = []
        seen = set()

        def add(kind, value, confidence, context, **attrs):
            value = self.clean(value)
            if not value:
                return
            normalized = GenericCTIExtractor.normalize("region" if kind == "nexus" else kind, value)
            signature = (kind, normalized.casefold(), json.dumps(attrs, sort_keys=True, ensure_ascii=False))
            if signature in seen:
                return
            seen.add(signature)
            result.append(IngestCandidate(kind, value, normalized, confidence, context[:1000], attrs))

        for row in self.parse(text):
            add("actor", row.primary_actor, 98, row.archetype,
                semantic_role="primary_actor", archetype=row.archetype)
            add("actor", row.related_actor, 96, row.rationale,
                semantic_role="related_actor", primary_actor=row.primary_actor,
                relationship_type=row.relationship_type, nexus=row.nexus)
            if row.nexus:
                add("nexus", row.nexus, 92, row.rationale,
                    semantic_role="nexus", related_actor=row.related_actor)
            for alias in row.aliases:
                add("alias", alias, 97, row.rationale,
                    semantic_role="alias", alias_of=row.related_actor)
            add("relationship",
                f"{row.primary_actor} -> {row.relationship_type} -> {row.related_actor}",
                96, row.rationale,
                semantic_role="relationship",
                source_actor=row.primary_actor,
                target_actor=row.related_actor,
                relationship_type=row.relationship_type)
        return result
