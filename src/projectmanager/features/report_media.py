from __future__ import annotations

import io
import re
import tkinter as tk
from pathlib import Path
from tkinter import ttk
from typing import Iterable

from PIL import Image, ImageDraw, ImageFont, ImageTk

IMAGE_PATTERN = re.compile(r"^\s*!\[(?P<label>[^\]]*)\]\((?P<path>[^)]+)\)\s*$")
TABLE_SEPARATOR = re.compile(r"^\s*\|?(?:\s*:?-{3,}:?\s*\|)+\s*$")


def markdown_images(content: str) -> list[tuple[int, str, str]]:
    return [
        (number, match.group("label").strip(), match.group("path").strip())
        for number, line in enumerate(content.splitlines(), 1)
        if (match := IMAGE_PATTERN.match(line))
    ]


def markdown_tables(content: str) -> list[tuple[int, int, list[list[str]]]]:
    lines = content.splitlines()
    result: list[tuple[int, int, list[list[str]]]] = []
    index = 0
    while index + 1 < len(lines):
        if "|" not in lines[index] or not TABLE_SEPARATOR.match(lines[index + 1]):
            index += 1
            continue
        start = index
        rows = [_split_table_row(lines[index])]
        index += 2
        while index < len(lines) and "|" in lines[index] and lines[index].strip():
            rows.append(_split_table_row(lines[index]))
            index += 1
        width = max((len(row) for row in rows), default=0)
        rows = [row + [""] * (width - len(row)) for row in rows]
        result.append((start + 1, index, rows))
    return result


def _split_table_row(line: str) -> list[str]:
    stripped = line.strip().strip("|")
    return [cell.strip() for cell in stripped.split("|")]


def resolve_image_path(reference: str, document_path: Path | None) -> Path:
    path = Path(reference.strip().strip('"').strip("'"))
    if path.is_absolute():
        return path
    base = document_path.parent if document_path else Path.cwd()
    return (base / path).resolve()




def _open_report_image(path: Path) -> Image.Image:
    """Open raster images and CAMT SVG report artifacts as a Pillow image."""
    if path.suffix.lower() == ".svg":
        # Backward-compatible fallback for old reports. New CAMT reports use PNG artifacts
        # and therefore do not require Cairo/cairosvg or native DLLs on Windows.
        image = Image.new("RGB", (1200, 180), (247, 251, 254))
        draw = ImageDraw.Draw(image)
        draw.text((24, 24), "Legacy SVG visual", fill=(21, 54, 74))
        draw.text((24, 62), path.name, fill=(70, 85, 95))
        draw.text((24, 100), "Regenerate the report with the current Exercise Network Assessment module for the full PNG visual.", fill=(70, 85, 95))
        return image
    image = Image.open(path); image.load(); return image

def _hide_source_line(editor, start: str, end: str) -> None:
    editor.tag_add("report_source_markup", start, end)


def _table_widget(editor, rows: list[list[str]], max_width: int) -> ttk.Frame:
    frame = ttk.Frame(editor, padding=(2, 6))
    columns = max((len(row) for row in rows), default=1)
    column_width = max(9, min(30, int(max_width / max(columns, 1) / 8)))
    for col in range(columns):
        frame.columnconfigure(col, weight=1)
    for row_index, row in enumerate(rows):
        for col_index, value in enumerate(row):
            label = ttk.Label(
                frame,
                text=value,
                anchor="center" if row_index == 0 else "w",
                justify="left",
                padding=(7, 5),
                relief="solid",
                borderwidth=1,
                wraplength=max(90, int(max_width / max(columns, 1)) - 16),
                font=("Segoe UI", 10, "bold" if row_index == 0 else "normal"),
            )
            label.grid(row=row_index, column=col_index, sticky="nsew")
            label.configure(width=column_width)
    return frame


def insert_inline_images(editor, content: str, document_path: Path | None, max_width: int = 820):
    """Render Markdown tables and images as real embedded widgets in a Tk Text.

    The Markdown source remains in the document model but is visually collapsed. The
    returned references must be retained by the caller for the lifetime of the Text.
    """
    references: list[object] = []
    missing: list[str] = []
    # Remove previously embedded report widgets before rebuilding the rich view.
    try:
        for key, value, index in reversed(editor.dump("1.0", "end", window=True, image=True)):
            try:
                if key == "window":
                    widget = editor.nametowidget(value)
                    editor.delete(index)
                    widget.destroy()
                elif key == "image":
                    editor.delete(index)
            except Exception:
                continue
    except Exception:
        pass
    editor.tag_configure("report_source_markup", elide=True, spacing1=0, spacing3=0)
    editor.tag_remove("report_source_markup", "1.0", "end")

    blocks: list[tuple[int, str, object]] = []
    for start, end, rows in markdown_tables(content):
        blocks.append((start, "table", (start, end, rows)))
    for line_number, label, reference in markdown_images(content):
        blocks.append((line_number, "image", (line_number, label, reference)))

    # Descending order keeps the original source line indexes stable.
    for _, kind, payload in sorted(blocks, key=lambda item: item[0], reverse=True):
        if kind == "table":
            start, end, rows = payload
            try:
                widget = _table_widget(editor, rows, max_width)
                insert_at = f"{end + 1}.0" if end < int(editor.index("end-1c").split(".")[0]) else "end-1c"
                editor.window_create(insert_at, window=widget, padx=4, pady=8)
                _hide_source_line(editor, f"{start}.0", f"{end}.end+1c")
                references.append(widget)
            except Exception:
                continue
        else:
            line_number, label, reference = payload
            path = resolve_image_path(reference, document_path)
            if not path.exists():
                missing.append(str(path))
                continue
            try:
                with _open_report_image(path) as source:
                    image = source.convert("RGBA")
                    if image.width > max_width:
                        height = max(1, round(image.height * max_width / image.width))
                        image = image.resize((max_width, height), Image.Resampling.LANCZOS)
                    photo = ImageTk.PhotoImage(image)
                holder = ttk.Frame(editor, padding=(4, 8))
                ttk.Label(holder, image=photo, anchor="center").pack()
                if label:
                    ttk.Label(holder, text=label, anchor="center", justify="center").pack(fill="x", pady=(5, 0))
                insert_line = line_number + 1
                insert_at = f"{insert_line}.0" if insert_line <= int(editor.index("end-1c").split(".")[0]) else "end-1c"
                editor.window_create(insert_at, window=holder, padx=4, pady=8)
                _hide_source_line(editor, f"{line_number}.0", f"{line_number}.end+1c")
                references.extend([holder, photo])
            except Exception:
                missing.append(str(path))
    references.reverse()
    missing.reverse()
    return references, missing


def _font(size: int, bold: bool = False) -> ImageFont.ImageFont:
    candidates = [
        "C:/Windows/Fonts/segoeuib.ttf" if bold else "C:/Windows/Fonts/segoeui.ttf",
        "DejaVuSans-Bold.ttf" if bold else "DejaVuSans.ttf",
    ]
    for candidate in candidates:
        try:
            return ImageFont.truetype(candidate, size=size)
        except OSError:
            continue
    return ImageFont.load_default()


def _text_pages(title: str, content: str, page_size: tuple[int, int] = (1240, 1754)) -> list[Image.Image]:
    width, height = page_size
    margin = 80
    title_font = _font(30, bold=True)
    body_font = _font(18)
    heading_font = _font(23, bold=True)
    line_height = 29
    pages: list[Image.Image] = []
    image = Image.new("RGB", page_size, "white")
    draw = _draw_page_header(image, title, "CAMT Professional - Network / Security Report")
    y = 155
    table_lines = {number for start, end, _ in markdown_tables(content) for number in range(start, end + 1)}

    def new_page():
        page = Image.new("RGB", page_size, "white")
        return page, _draw_page_header(page,title,"CAMT Professional"), 155

    for number, raw in enumerate(content.splitlines(), 1):
        if IMAGE_PATTERN.match(raw) or number in table_lines:
            continue
        text = raw.strip()
        font = heading_font if text.startswith("#") else body_font
        text = text.lstrip("# ")
        text = re.sub(r"\*\*([^*]+)\*\*", r"\1", text)
        text = re.sub(r"\*([^*]+)\*", r"\1", text)
        if text.startswith("- "):
            text="• "+text[2:]
        if not text:
            y += line_height // 2
            continue
        max_chars = 105 if font is body_font else 85
        words = text.split(); lines=[]; current=""
        for word in words:
            candidate=f"{current} {word}".strip()
            if len(candidate)>max_chars and current:
                lines.append(current); current=word
            else: current=candidate
        if current: lines.append(current)
        for line in lines:
            if y + line_height > height - margin:
                pages.append(image); image, draw, y = new_page()
            draw.text((margin, y), line, fill="black", font=font)
            y += line_height + (4 if font is heading_font else 0)
    pages.append(image)
    return pages


def _draw_page_header(page: Image.Image, title: str, subtitle: str = "") -> ImageDraw.ImageDraw:
    draw=ImageDraw.Draw(page)
    w,h=page.size
    draw.rectangle((0,0,w,118),fill="#17365d")
    draw.rectangle((0,112,w,118),fill="#2a8fa3")
    draw.text((58,34),title,fill="white",font=_font(28,True))
    if subtitle:
        draw.text((60,78),subtitle,fill="#d9edf4",font=_font(14))
    return draw


def _kpi_page(rows: list[list[str]], title: str, page_size=(1240,1754)) -> Image.Image:
    page=Image.new("RGB",page_size,"#eef2f6")
    draw=_draw_page_header(page,title,"Executive dashboard")
    cards=rows[1:] if rows else []
    card_w=520; card_h=125; gapx=35; gapy=28; start_x=80; start_y=175
    label_font=_font(17,True); value_font=_font(30,True)
    for i,row in enumerate(cards):
        if len(row)<2: continue
        col=i%2; r=i//2
        x=start_x+col*(card_w+gapx); y=start_y+r*(card_h+gapy)
        draw.rounded_rectangle((x,y,x+card_w,y+card_h),radius=16,fill="white",outline="#d7e2ec",width=2)
        draw.text((x+22,y+20),str(row[0]),fill="#617083",font=label_font)
        draw.text((x+22,y+57),str(row[1]),fill="#17365d",font=value_font)
    return page


def _wrap_cell(draw, text: str, font, max_width: int, max_lines: int = 4) -> list[str]:
    words=str(text or "").split()
    lines=[]; current=""
    for word in words:
        candidate=(current+" "+word).strip()
        if draw.textbbox((0,0),candidate,font=font)[2] > max_width and current:
            lines.append(current); current=word
            if len(lines)>=max_lines: break
        else:
            current=candidate
    if current and len(lines)<max_lines: lines.append(current)
    if len(lines)==max_lines and words:
        lines[-1]=lines[-1][:max(1,len(lines[-1])-1)]+"…"
    return lines or [""]


def _table_pages(rows: list[list[str]], title: str, page_size=(1240,1754)) -> list[Image.Image]:
    if not rows: return []
    # KPI table becomes visual cards.
    if len(rows[0])>=2 and rows[0][0].strip().lower()=="kpi":
        return [_kpi_page(rows,title,page_size)]

    headers=rows[0]; data=rows[1:]
    pages=[]; index=0
    font=_font(13); head=_font(14,True)
    margin=45; top=150; bottom=55
    columns=max(1,len(headers))
    # Wider practical distribution for the 8-column Network Asset Inventory.
    if columns==8:
        widths=[150,110,120,95,85,330,70,80]
        scale=(page_size[0]-2*margin)/sum(widths)
        widths=[int(w*scale) for w in widths]
    else:
        widths=[(page_size[0]-2*margin)//columns]*columns

    while index<len(data) or (not data and not pages):
        page=Image.new("RGB",page_size,"white")
        draw=_draw_page_header(page,title,"Network Asset Intelligence")
        y=top
        # header
        x=margin; header_h=48
        for c,h in enumerate(headers):
            w=widths[c] if c<len(widths) else widths[-1]
            draw.rectangle((x,y,x+w,y+header_h),fill="#245b88")
            for li,line in enumerate(_wrap_cell(draw,h,head,w-12,2)):
                draw.text((x+6,y+8+li*17),line,fill="white",font=head)
            x+=w
        y+=header_h

        row_no=0
        while index<len(data):
            row=data[index]
            line_sets=[]
            max_lines=1
            for c,value in enumerate(row):
                w=widths[c] if c<len(widths) else widths[-1]
                ls=_wrap_cell(draw,value,font,w-12,4)
                line_sets.append(ls); max_lines=max(max_lines,len(ls))
            row_h=max(38,12+max_lines*18)
            if y+row_h>page_size[1]-bottom:
                break
            fill="#f6f9fc" if row_no%2 else "white"
            x=margin
            for c,ls in enumerate(line_sets):
                w=widths[c] if c<len(widths) else widths[-1]
                draw.rectangle((x,y,x+w,y+row_h),fill=fill,outline="#dbe4ee",width=1)
                for li,line in enumerate(ls):
                    draw.text((x+6,y+7+li*18),line,fill="#172536",font=font)
                x+=w
            y+=row_h; index+=1; row_no+=1
        pages.append(page)
        if not data: break
    return pages


def export_pdf(path: Path, title: str, content: str, image_references: Iterable[str], document_path: Path | None) -> None:
    # Defensive compatibility with reports accidentally saved with literal newline escapes.
    if "\\n" in content and "\n" not in content:
        content=content.replace("\\n","\n")
    pages = _text_pages(title, content)
    for _, _, rows in markdown_tables(content):
        pages.extend(_table_pages(rows, title, pages[0].size))
    refs = list(dict.fromkeys([ref for _, _, ref in markdown_images(content)] + [str(x) for x in image_references]))
    page_size = pages[0].size; margin=55; caption_font=_font(20, True)
    for reference in refs:
        source_path=resolve_image_path(reference,document_path)
        if not source_path.exists(): continue
        with _open_report_image(source_path) as source:
            image=source.convert("RGB")
        available=(page_size[0]-margin*2,page_size[1]-margin*2-55)
        ratio=min(available[0]/image.width,available[1]/image.height,1.0)
        image=image.resize((max(1,round(image.width*ratio)),max(1,round(image.height*ratio))),Image.Resampling.LANCZOS)
        page=Image.new("RGB",page_size,"white"); draw=ImageDraw.Draw(page)
        draw.text((margin,32),source_path.stem.replace("_"," ").title(),fill="black",font=caption_font)
        page.paste(image,((page_size[0]-image.width)//2,85+(available[1]-image.height)//2)); pages.append(page)
    first,*rest=pages; first.save(path,"PDF",resolution=144.0,save_all=True,append_images=rest)


def export_rtf(path: Path, content: str, image_references: Iterable[str], document_path: Path | None) -> None:
    def escape(value: str) -> str:
        return value.replace("\\","\\\\").replace("{","\\{").replace("}","\\}").replace("\n","\\par\n")
    blocks=["{\\rtf1\\ansi\\deff0{\\fonttbl{\\f0 Segoe UI;}{\\f1 Consolas;}}\\fs22\n",escape(content),"\\par\n"]
    refs=list(dict.fromkeys([ref for _,_,ref in markdown_images(content)]+[str(x) for x in image_references]))
    for reference in refs:
        source_path=resolve_image_path(reference,document_path)
        if not source_path.exists(): continue
        with _open_report_image(source_path) as source:
            image=source.convert("RGB")
            if image.width>1200:
                image=image.resize((1200,max(1,round(image.height*1200/image.width))),Image.Resampling.LANCZOS)
            buffer=io.BytesIO(); image.save(buffer,format="PNG")
        blocks.append(f"\\par\\qc\\b {escape(source_path.stem.replace('_',' ').title())}\\b0\\par\n")
        blocks.append(f"{{\\pict\\pngblip\\picw{image.width}\\pich{image.height}\\picwgoal{image.width*15}\\pichgoal{image.height*15}\n{buffer.getvalue().hex()}\n}}\\par\n")
    blocks.append("}"); path.write_text("".join(blocks),encoding="ascii",errors="backslashreplace")
