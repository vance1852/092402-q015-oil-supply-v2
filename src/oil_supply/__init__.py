"""油气供应韧性与调度领域包。"""

__all__ = ["SupplyService"]


def __getattr__(name: str):
    if name == "SupplyService":
        from .service import SupplyService

        return SupplyService
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
