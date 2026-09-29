from __future__ import annotations
from .models import RiskItem
class RiskWorkspaceService:
    def level(self, score: float) -> str:
        if score>=20:return "Kritiek"
        if score>=12:return "Hoog"
        if score>=6:return "Middel"
        return "Laag"
    def summary(self, risks:list[RiskItem]):
        open_items=[r for r in risks if r.status not in {"Gesloten","Geaccepteerd"}]
        return {"total":len(risks),"open":len(open_items),"critical":sum(1 for r in open_items if r.residual_score>=20),"high":sum(1 for r in open_items if 12<=r.residual_score<20),"average_residual":round(sum(r.residual_score for r in open_items)/len(open_items),1) if open_items else 0.0}
    def prioritized(self,risks:list[RiskItem]): return sorted(risks,key=lambda r:(r.status not in {"Gesloten"},r.residual_score,r.inherent_score),reverse=True)
