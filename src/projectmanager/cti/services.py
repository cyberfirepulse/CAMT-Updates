from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import asdict
from typing import Any

from .repository import CTIRepository


class CTIService:
    def __init__(self, repository: CTIRepository):
        self.repository = repository

    def search(self, kind: str, query: str = "") -> list[Any]:
        query = query.strip().lower()
        values = self.repository.list(kind)
        if not query:
            return sorted(values, key=lambda item: str(getattr(item, "name", getattr(item, "value", ""))).lower())
        result = []
        for item in values:
            text = " ".join(str(value) for value in asdict(item).values()).lower()
            if query in text:
                result.append(item)
        return result

    def actor_similarity(self, left_id: str, right_id: str) -> dict[str, Any]:
        left = self.repository.get(left_id)
        right = self.repository.get(right_id)
        if not left or not right:
            return {"score": 0, "shared_techniques": [], "shared_sectors": [], "shared_tools": [], "shared_malware": []}
        lt, rt = set(left.techniques), set(right.techniques)
        union = lt | rt
        ttp_score = round(100 * len(lt & rt) / len(union)) if union else 0
        sector_union = set(left.sectors) | set(right.sectors)
        sector_score = round(100 * len(set(left.sectors) & set(right.sectors)) / len(sector_union)) if sector_union else 0
        score = round(ttp_score * 0.8 + sector_score * 0.2)
        return {
            "score": score,
            "ttp_score": ttp_score,
            "sector_score": sector_score,
            "shared_techniques": sorted(lt & rt),
            "shared_sectors": sorted(set(left.sectors) & set(right.sectors)),
            "shared_tools": sorted(set(left.tool_ids) & set(right.tool_ids)),
            "shared_malware": sorted(set(left.malware_ids) & set(right.malware_ids)),
        }

    @staticmethod
    def _similarity_set(left, right) -> int:
        a,b=set(left or ()),set(right or ())
        return round(100*len(a&b)/len(a|b)) if a|b else 0

    def similar_actors(self, actor_id: str, limit: int = 10) -> list[dict[str, Any]]:
        source=self.repository.get(actor_id)
        if not source:return []
        result=[]
        for other in self.repository.list("actors"):
            if other.id==source.id:continue
            ttp=self._similarity_set(source.techniques,other.techniques); sector=self._similarity_set(source.sectors,other.sectors)
            tools=self._similarity_set(source.tool_ids,other.tool_ids); malware=self._similarity_set(source.malware_ids,other.malware_ids)
            regions=self._similarity_set(source.regions,other.regions); campaigns=self._similarity_set(source.campaign_ids,other.campaign_ids)
            score=round(ttp*.45+sector*.18+tools*.10+malware*.10+regions*.07+campaigns*.10)
            shared_t=sorted(set(source.techniques)&set(other.techniques)); shared_s=sorted(set(source.sectors)&set(other.sectors))
            shared_tools=sorted(set(source.tool_ids)&set(other.tool_ids)); shared_mal=sorted(set(source.malware_ids)&set(other.malware_ids))
            evidence=sum(bool(x) for x in (source.techniques,other.techniques,source.sectors,other.sectors,source.tool_ids,other.tool_ids,source.malware_ids,other.malware_ids))
            confidence="High" if evidence>=6 and score>=55 else ("Medium" if evidence>=3 and score>=25 else "Low")
            why=[]
            if shared_t:why.append(f"{len(shared_t)} gedeelde TTP(s)")
            if shared_s:why.append("sector: "+", ".join(shared_s[:3]))
            if shared_tools:why.append(f"{len(shared_tools)} gedeelde tool(s)")
            if shared_mal:why.append(f"{len(shared_mal)} gedeelde malwarefamilie(s)")
            result.append({"actor_id":other.id,"actor":other.name,"similarity":score,"ttp":ttp,"sector":sector,"tools":tools,"malware":malware,
                           "regions":regions,"campaigns":campaigns,"confidence":confidence,"shared_techniques":shared_t,"shared_sectors":shared_s,
                           "shared_tools":shared_tools,"shared_malware":shared_mal,"reason":"; ".join(why) or "Beperkte gedeelde evidence"})
        return sorted(result,key=lambda x:(-x["similarity"],-x["ttp"],x["actor"].casefold()))[:max(1,limit)]

    def actor_trend_watch(self, actor_id: str, limit: int = 10) -> dict[str, Any]:
        actor=self.repository.get(actor_id); peers=self.similar_actors(actor_id,limit)
        return {"actor":getattr(actor,"name",""),"source":"local SQLite CTI","interpretation":"Behavioural similarity; not actor attribution.",
                "peers":peers,"watch_techniques":sorted({x for p in peers[:5] for x in p["shared_techniques"]}),
                "watch_sectors":sorted({x for p in peers[:5] for x in p["shared_sectors"]})}

    def graph(self, root_id: str | None = None, depth: int = 2) -> dict[str, Any]:
        relationships = self.repository.list("relationships")
        adjacency: dict[str, list[tuple[str, str, int]]] = defaultdict(list)
        for rel in relationships:
            adjacency[rel.source_id].append((rel.target_id, rel.relationship_type, rel.confidence))
            adjacency[rel.target_id].append((rel.source_id, rel.relationship_type, rel.confidence))
        selected: set[str] = set()
        if root_id:
            queue = deque([(root_id, 0)])
            while queue:
                node, level = queue.popleft()
                if node in selected or level > depth:
                    continue
                selected.add(node)
                for target, _, _ in adjacency.get(node, []):
                    queue.append((target, level + 1))
        else:
            selected = set(adjacency)
        nodes = []
        for object_id in sorted(selected):
            obj = self.repository.get(object_id)
            label = getattr(obj, "name", getattr(obj, "value", object_id)) if obj else object_id
            node_type = object_id.split("--", 1)[0] if "--" in object_id else ("technique" if object_id.startswith("T") else "external")
            nodes.append({"id": object_id, "label": label, "type": node_type})
        edges = [{"source": rel.source_id, "target": rel.target_id, "type": rel.relationship_type, "confidence": rel.confidence} for rel in relationships if rel.source_id in selected and rel.target_id in selected]
        return {"nodes": nodes, "edges": edges}
