from __future__ import annotations

from math import cos, pi, sin
from pathlib import Path
from typing import Callable

from PIL import Image, ImageDraw, ImageFont

from .models import ScenarioIntelligenceResult


class ScenarioReportRasterizer:
    WIDTH = 1400
    HEIGHT = 820
    BACKGROUND = (7, 19, 35)
    PANEL = (16, 44, 67)
    TEXT = (238, 248, 255)
    MUTED = (155, 184, 200)
    CYAN = (54, 209, 220)
    ORANGE = (255, 176, 32)
    RED = (255, 92, 92)
    PINK = (255, 77, 141)
    PURPLE = (138, 108, 255)

    def __init__(self) -> None:
        self.font = self._font(16)
        self.small = self._font(12)
        self.title = self._font(30, bold=True)
        self.heading = self._font(20, bold=True)

    def render_all(self, result: ScenarioIntelligenceResult, output_dir: str | Path) -> dict[str, Path]:
        target = Path(output_dir)
        target.mkdir(parents=True, exist_ok=True)
        renderers: dict[str, Callable[[ScenarioIntelligenceResult], Image.Image]] = {
            "baseline_network": self._baseline_network,
            "scenario_overlay": self._scenario_overlay,
            "attack_path": self._attack_path,
            "scenario_timeline": self._timeline,
            "risk_coverage": self._risk_coverage,
            "digital_twin": self._digital_twin,
            "mitre_matrix": self._mitre_matrix,
            "trust_zones": self._trust_zones,
            "asset_inventory": self._asset_inventory,
            "dataflows": self._dataflows,
            "choke_points": lambda r: self._special_assets(r, "Choke Points", set(r.analysis.choke_point_ids), self.ORANGE),
            "crown_jewels": lambda r: self._special_assets(r, "Crown Jewels", set(r.analysis.crown_jewel_ids), self.PINK),
            "single_points_of_failure": lambda r: self._special_assets(r, "Single Points of Failure", set(r.analysis.single_point_of_failure_ids), self.RED),
            "mitigations": self._mitigations,
        }
        output: dict[str, Path] = {}
        for key, renderer in renderers.items():
            path = target / f"{key}.png"
            renderer(result).save(path, format="PNG", optimize=True)
            output[key] = path
        return output

    def _font(self, size: int, bold: bool = False) -> ImageFont.ImageFont:
        names = [
            "C:/Windows/Fonts/segoeuib.ttf" if bold else "C:/Windows/Fonts/segoeui.ttf",
            "DejaVuSans-Bold.ttf" if bold else "DejaVuSans.ttf",
        ]
        for name in names:
            try:
                return ImageFont.truetype(name, size=size)
            except OSError:
                continue
        return ImageFont.load_default()

    def _page(self, title: str, subtitle: str) -> tuple[Image.Image, ImageDraw.ImageDraw]:
        image = Image.new("RGB", (self.WIDTH, self.HEIGHT), self.BACKGROUND)
        draw = ImageDraw.Draw(image)
        draw.rounded_rectangle((12, 12, self.WIDTH - 12, self.HEIGHT - 12), radius=28, outline=(35, 82, 110), width=2)
        draw.text((50, 34), title, fill=self.TEXT, font=self.title)
        draw.text((50, 78), subtitle, fill=(127, 185, 216), font=self.small)
        return image, draw

    def _positions(self, result: ScenarioIntelligenceResult) -> dict[str, tuple[float, float]]:
        if not result.assets:
            return {}
        cx, cy = 700, 440
        radius = min(300, 90 + len(result.assets) * 12)
        count = len(result.assets)
        return {
            asset.asset_id: (
                cx + radius * cos(2 * pi * index / count - pi / 2),
                cy + radius * sin(2 * pi * index / count - pi / 2),
            )
            for index, asset in enumerate(result.assets)
        }

    def _draw_network(self, draw: ImageDraw.ImageDraw, result: ScenarioIntelligenceResult, highlighted: set[str] | None = None) -> None:
        highlighted = highlighted or set()
        positions = self._positions(result)
        risks = {item.asset_id: item for item in result.analysis.asset_risks}
        for relation in result.relationships:
            if relation.source_asset_id in positions and relation.target_asset_id in positions:
                draw.line((*positions[relation.source_asset_id], *positions[relation.target_asset_id]), fill=(60, 120, 154), width=3)
        for asset in result.assets:
            x, y = positions[asset.asset_id]
            risk = risks.get(asset.asset_id)
            color = self.CYAN
            if asset.asset_id in highlighted:
                color = self.PINK
            elif risk and risk.score >= 75:
                color = self.RED
            elif risk and risk.score >= 50:
                color = self.ORANGE
            draw.ellipse((x - 32, y - 32, x + 32, y + 32), fill=self.PANEL, outline=color, width=5)
            type_text = asset.canonical_type[:13]
            bbox = draw.textbbox((0, 0), type_text, font=self.small)
            draw.text((x - (bbox[2] - bbox[0]) / 2, y - 8), type_text, fill=self.TEXT, font=self.small)
            name = asset.display_name[:24]
            bbox = draw.textbbox((0, 0), name, font=self.small)
            draw.text((x - (bbox[2] - bbox[0]) / 2, y + 39), name, fill=self.MUTED, font=self.small)

    def _baseline_network(self, result: ScenarioIntelligenceResult) -> Image.Image:
        image, draw = self._page("Baseline Network Diagram", f"{len(result.assets)} assets · {len(result.relationships)} relaties")
        self._draw_network(draw, result)
        return image

    def _scenario_overlay(self, result: ScenarioIntelligenceResult) -> Image.Image:
        affected = {asset_id for event in result.events for asset_id in event.asset_ids}
        image, draw = self._page("Scenario Overlay", f"{len(affected)} getroffen assets · risk {result.analysis.overall_risk_score:.0f}/100")
        self._draw_network(draw, result, affected)
        return image

    def _digital_twin(self, result: ScenarioIntelligenceResult) -> Image.Image:
        image, draw = self._page("Cyber Digital Twin", "Crown jewels en risicodragende verbindingen")
        self._draw_network(draw, result, set(result.analysis.crown_jewel_ids))
        return image

    def _dataflows(self, result: ScenarioIntelligenceResult) -> Image.Image:
        image, draw = self._page("Dataflows", "Gerichte scenario-relaties en gegevensstromen")
        self._draw_network(draw, result)
        return image

    def _attack_path(self, result: ScenarioIntelligenceResult) -> Image.Image:
        image, draw = self._page("Attack Paths", f"{len(result.analysis.attack_paths)} afgeleide aanvalspaden")
        asset_names = {asset.asset_id: asset.display_name for asset in result.assets}
        y = 130
        for path in result.analysis.attack_paths[:5]:
            draw.text((55, y), f"{path.name} · {path.risk_score:.0f}/100", fill=(255, 207, 112), font=self.heading)
            y += 44
            for index, step in enumerate(path.steps[:8]):
                x = 65 + index * 160
                draw.rounded_rectangle((x, y, x + 130, y + 62), radius=14, fill=self.PANEL, outline=self.RED, width=3)
                draw.text((x + 9, y + 10), asset_names.get(step.target_asset_id, step.target_asset_id)[:18], fill=self.TEXT, font=self.small)
                draw.text((x + 9, y + 36), ", ".join(step.technique_ids)[:19], fill=(143, 204, 232), font=self.small)
                if index < min(len(path.steps), 8) - 1:
                    draw.line((x + 130, y + 31, x + 154, y + 31), fill=self.ORANGE, width=4)
            y += 105
        if not result.analysis.attack_paths:
            draw.text((60, 150), "Geen aanvalspad afgeleid.", fill=self.MUTED, font=self.heading)
        return image

    def _timeline(self, result: ScenarioIntelligenceResult) -> Image.Image:
        image, draw = self._page("Scenario Timeline", f"{len(result.events)} gebeurtenissen")
        for index, event in enumerate(sorted(result.events, key=lambda value: value.sequence)[:18]):
            y = 125 + index * 36
            draw.ellipse((68, y - 6, 82, y + 8), fill=self.CYAN)
            if index < min(18, len(result.events)) - 1:
                draw.line((75, y + 8, 75, y + 36), fill=(60, 120, 154), width=2)
            draw.text((98, y - 7), f"{(event.timestamp_text or str(event.sequence))[:14]} · {event.description[:130]}", fill=self.TEXT, font=self.font)
        return image

    def _risk_coverage(self, result: ScenarioIntelligenceResult) -> Image.Image:
        image, draw = self._page("Risk / Coverage Overview", "Automatisch berekende managementindicatoren")
        values = [
            ("Scenario risk", result.analysis.overall_risk_score, self.RED),
            ("ATT&CK mapping", min(100, len(result.analysis.techniques) * 12), self.ORANGE),
            ("Mitigation coverage", min(100, len(result.analysis.mitigations) * 10), self.CYAN),
        ]
        for index, (name, value, color) in enumerate(values):
            y = 170 + index * 155
            draw.text((80, y), name, fill=self.TEXT, font=self.heading)
            draw.rounded_rectangle((80, y + 42, 1200, y + 92), radius=18, fill=(23, 54, 76))
            draw.rounded_rectangle((80, y + 42, 80 + 1120 * value / 100, y + 92), radius=18, fill=color)
            draw.text((1220, y + 52), f"{value:.0f}%", fill=self.TEXT, font=self.heading)
        return image

    def _mitre_matrix(self, result: ScenarioIntelligenceResult) -> Image.Image:
        image, draw = self._page("MITRE ATT&CK Matrix", f"{len(result.analysis.techniques)} technieken")
        grouped: dict[str, list] = {}
        for technique in result.analysis.techniques:
            grouped.setdefault(technique.tactic, []).append(technique)
        tactics = list(grouped) or ["Geen mapping"]
        column = max(180, 1260 // len(tactics))
        for index, tactic in enumerate(tactics):
            x = 45 + index * column
            draw.rounded_rectangle((x, 120, x + column - 12, 178), radius=12, fill=(24, 67, 93))
            draw.text((x + 10, 138), tactic[:22], fill=self.TEXT, font=self.font)
            for row, technique in enumerate(grouped.get(tactic, [])[:10]):
                y = 195 + row * 52
                draw.rounded_rectangle((x, y, x + column - 12, y + 42), radius=9, fill=self.PANEL, outline=self.CYAN, width=2)
                draw.text((x + 8, y + 4), technique.technique_id, fill=(126, 233, 240), font=self.small)
                draw.text((x + 8, y + 22), technique.name[:25], fill=self.TEXT, font=self.small)
        return image

    def _trust_zones(self, result: ScenarioIntelligenceResult) -> Image.Image:
        image, draw = self._page("Trust Zones", f"{len(result.trust_zones)} zones")
        for index, zone in enumerate(result.trust_zones[:12]):
            x = 55 + (index % 3) * 445
            y = 125 + (index // 3) * 155
            draw.rounded_rectangle((x, y, x + 410, y + 125), radius=20, fill=self.PANEL, outline=self.PURPLE, width=3)
            draw.text((x + 20, y + 16), zone.name, fill=(203, 188, 255), font=self.heading)
            draw.text((x + 20, y + 52), f"Trust level {zone.trust_level} · {zone.zone_type}", fill=self.MUTED, font=self.small)
            names = [asset.display_name for asset in result.assets if asset.asset_id in zone.asset_ids]
            draw.text((x + 20, y + 82), ", ".join(names)[:58], fill=self.TEXT, font=self.small)
        return image

    def _asset_inventory(self, result: ScenarioIntelligenceResult) -> Image.Image:
        image, draw = self._page("Asset Inventory", f"{len(result.assets)} herkende devices en systemen")
        for index, asset in enumerate(result.assets[:30]):
            x = 55 + (index % 3) * 445
            y = 120 + (index // 3) * 64
            draw.rounded_rectangle((x, y, x + 410, y + 48), radius=12, fill=self.PANEL, outline=(47, 120, 154), width=2)
            draw.text((x + 14, y + 5), asset.canonical_type, fill=self.CYAN, font=self.small)
            draw.text((x + 14, y + 25), asset.display_name[:42], fill=self.TEXT, font=self.small)
        return image

    def _special_assets(self, result: ScenarioIntelligenceResult, title: str, ids: set[str], color: tuple[int, int, int]) -> Image.Image:
        image, draw = self._page(title, f"{len(ids)} automatisch geïdentificeerd")
        asset_map = {asset.asset_id: asset for asset in result.assets}
        for index, asset_id in enumerate(sorted(ids)):
            asset = asset_map.get(asset_id)
            if not asset:
                continue
            x = 75 + (index % 4) * 325
            y = 145 + (index // 4) * 140
            draw.rounded_rectangle((x, y, x + 285, y + 100), radius=22, fill=self.PANEL, outline=color, width=4)
            draw.text((x + 18, y + 28), asset.display_name[:28], fill=self.TEXT, font=self.font)
            draw.text((x + 18, y + 61), asset.canonical_type, fill=color, font=self.small)
        if not ids:
            draw.text((490, 390), "Geen assets in deze categorie", fill=self.MUTED, font=self.heading)
        return image

    def _mitigations(self, result: ScenarioIntelligenceResult) -> Image.Image:
        image, draw = self._page("Possible Mitigations", f"{len(result.analysis.mitigations)} voorgestelde maatregelen")
        for index, mitigation in enumerate(result.analysis.mitigations[:12]):
            x = 55 + (index % 2) * 660
            y = 120 + (index // 2) * 106
            draw.rounded_rectangle((x, y, x + 625, y + 88), radius=16, fill=self.PANEL, outline=self.CYAN, width=2)
            draw.text((x + 16, y + 10), mitigation.title[:68], fill=(126, 233, 240), font=self.font)
            draw.text((x + 16, y + 37), mitigation.description[:92], fill=self.TEXT, font=self.small)
            draw.text((x + 16, y + 63), f"Prioriteit: {mitigation.priority.value} · {mitigation.control_family}", fill=(255, 207, 112), font=self.small)
        return image
