from __future__ import annotations

from html import escape
from pathlib import Path
from typing import Iterable

from PIL import Image, ImageDraw, ImageFont


def _font(size: int, bold: bool = False):
    names = ["C:/Windows/Fonts/segoeuib.ttf" if bold else "C:/Windows/Fonts/segoeui.ttf", "DejaVuSans-Bold.ttf" if bold else "DejaVuSans.ttf"]
    for name in names:
        try: return ImageFont.truetype(name, size)
        except OSError: pass
    return ImageFont.load_default()


def _rows(events: Iterable[object]) -> list[tuple[str, str, str]]:
    return [(str(getattr(e,"timestamp_text","") or f"Stap {getattr(e,'order',i+1)}"), str(getattr(e,"phase","") or "Gebeurtenis"), str(getattr(e,"description","") or "Geen beschrijving")) for i,e in enumerate(events)]


def export_timeline_png(events: Iterable[object], path: str | Path) -> Path:
    rows=_rows(events); width=1500; card_h=118; height=max(240,90+len(rows)*card_h)
    image=Image.new("RGB",(width,height),"white"); draw=ImageDraw.Draw(image); title=_font(24,True); head=_font(16,True); body=_font(14)
    draw.text((45,28),"Incident Timeline",fill="black",font=title); y=78
    for timestamp,phase,description in rows:
        draw.rounded_rectangle((45,y,width-45,y+94),radius=10,outline="#777777",width=2)
        draw.text((62,y+12),timestamp,fill="#333333",font=head); draw.text((245,y+12),phase,fill="#111111",font=head)
        text=description if len(description)<=145 else description[:142]+"..."; draw.text((62,y+48),text,fill="#333333",font=body)
        y+=card_h
    target=Path(path); target.parent.mkdir(parents=True,exist_ok=True); image.save(target,"PNG"); return target


def export_timeline_svg(events: Iterable[object], path: str | Path) -> Path:
    rows=_rows(events); width=1500; card_h=118; height=max(240,90+len(rows)*card_h); parts=[f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" viewBox="0 0 {width} {height}">','<rect width="100%" height="100%" fill="white"/>','<text x="45" y="48" font-family="Segoe UI,Arial" font-size="26" font-weight="600">Incident Timeline</text>']; y=78
    for timestamp,phase,description in rows:
        parts.append(f'<rect x="45" y="{y}" width="1410" height="94" rx="10" fill="white" stroke="#777" stroke-width="2"/>')
        parts.append(f'<text x="62" y="{y+32}" font-family="Segoe UI,Arial" font-size="16" font-weight="600">{escape(timestamp)}</text>')
        parts.append(f'<text x="245" y="{y+32}" font-family="Segoe UI,Arial" font-size="16" font-weight="600">{escape(phase)}</text>')
        desc=description if len(description)<=170 else description[:167]+"..."; parts.append(f'<text x="62" y="{y+68}" font-family="Segoe UI,Arial" font-size="14">{escape(desc)}</text>'); y+=card_h
    parts.append('</svg>'); target=Path(path); target.parent.mkdir(parents=True,exist_ok=True); target.write_text("\n".join(parts),encoding="utf-8"); return target
