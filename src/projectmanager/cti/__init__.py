from .models import Campaign, IOC, Malware, Relationship, ThreatActor, ToolProfile

__all__ = ["Campaign", "IOC", "Malware", "Relationship", "ThreatActor", "ToolProfile", "CTIRepository", "CTIService"]


def __getattr__(name: str):
    if name == "CTIRepository":
        from .repository import CTIRepository
        return CTIRepository
    if name == "CTIService":
        from .services import CTIService
        return CTIService
    raise AttributeError(name)
