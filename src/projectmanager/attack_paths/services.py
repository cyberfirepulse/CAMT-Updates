from __future__ import annotations
from collections import defaultdict, deque
from .models import AttackPath, AttackNode, AttackEdge

class AttackPathService:
    def validate(self, path: AttackPath) -> list[str]:
        issues: list[str] = []
        ids = {n.node_id for n in path.nodes}
        if not path.name.strip(): issues.append("Naam ontbreekt.")
        if not path.nodes: issues.append("Het aanvalspad bevat geen nodes.")
        for edge in path.edges:
            if edge.source_id not in ids: issues.append(f"Edge {edge.edge_id}: bron ontbreekt.")
            if edge.target_id not in ids: issues.append(f"Edge {edge.edge_id}: doel ontbreekt.")
            if edge.source_id == edge.target_id: issues.append(f"Edge {edge.edge_id}: zelfkoppeling.")
        if self.has_cycle(path): issues.append("Het pad bevat een cyclus; controleer of dit bewust is.")
        return issues

    def has_cycle(self, path: AttackPath) -> bool:
        graph = defaultdict(list)
        indegree = {n.node_id: 0 for n in path.nodes}
        for e in path.edges:
            if e.enabled and e.source_id in indegree and e.target_id in indegree:
                graph[e.source_id].append(e.target_id); indegree[e.target_id] += 1
        q = deque([n for n, d in indegree.items() if d == 0]); seen = 0
        while q:
            n = q.popleft(); seen += 1
            for nxt in graph[n]:
                indegree[nxt] -= 1
                if indegree[nxt] == 0: q.append(nxt)
        return seen != len(indegree)

    def summary(self, path: AttackPath) -> dict:
        risks = [max(0, min(100, int(n.risk))) for n in path.nodes]
        likelihoods = [max(0, min(100, int(e.likelihood))) for e in path.edges if e.enabled]
        return {
            "nodes": len(path.nodes), "edges": len(path.edges),
            "average_risk": round(sum(risks)/len(risks), 1) if risks else 0,
            "average_likelihood": round(sum(likelihoods)/len(likelihoods), 1) if likelihoods else 0,
            "max_risk": max(risks, default=0),
            "attack_techniques": sorted({n.attack_id for n in path.nodes if n.attack_id}),
        }

    def add_default_scenario(self, path: AttackPath) -> None:
        if path.nodes: return
        specs = [
            ("Internet", "Entry Point", 100, 180, 35, ""),
            ("Exposed service", "Asset", 330, 180, 55, "T1190"),
            ("Command execution", "Technique", 560, 180, 70, "T1059"),
            ("Credential access", "Technique", 790, 180, 80, "T1003"),
            ("Critical data", "Goal", 1020, 180, 90, "T1486"),
        ]
        for title, typ, x, y, risk, attack in specs:
            path.nodes.append(AttackNode(title=title, node_type=typ, x=x, y=y, risk=risk, attack_id=attack))
        for a, b in zip(path.nodes, path.nodes[1:]):
            path.edges.append(AttackEdge(source_id=a.node_id, target_id=b.node_id, likelihood=60))
