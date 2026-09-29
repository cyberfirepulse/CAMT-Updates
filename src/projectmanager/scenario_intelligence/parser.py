from __future__ import annotations

import io
import json
import re
import zlib
import unicodedata
from pathlib import Path
from typing import Any, Iterable
from xml.etree import ElementTree
from zipfile import BadZipFile, ZipFile

from .dictionaries import FILE_EXTENSION_TO_SOURCE_TYPE
from .models import ParsedScenarioDocument, ScenarioSourceType, TextSegment


class ScenarioParseError(ValueError):
    pass


class ScenarioParser:
    _SPACE_RE = re.compile(r"[ \t\f\v]+")
    _BLANK_LINES_RE = re.compile(r"\n{3,}")
    _PDF_LITERAL_RE = re.compile(rb"\((?:\\.|[^\\()])*\)\s*Tj")
    _PDF_ARRAY_RE = re.compile(rb"\[(.*?)\]\s*TJ", re.DOTALL)
    _PDF_ARRAY_LITERAL_RE = re.compile(rb"\((?:\\.|[^\\()])*\)")
    _PDF_HEX_RE = re.compile(rb"<([0-9A-Fa-f\s]+)>\s*Tj")

    def parse_file(self, path: str | Path) -> ParsedScenarioDocument:
        source_path = Path(path).expanduser().resolve()
        if not source_path.is_file():
            raise FileNotFoundError(f"Bestand niet gevonden: {source_path}")
        source_type = self._source_type_for_suffix(source_path.suffix)
        try:
            data = source_path.read_bytes()
        except OSError as exc:
            raise ScenarioParseError(f"Bestand kan niet worden gelezen: {source_path}") from exc
        document = self.parse_bytes(data, source_type=source_type, source_name=source_path.name)
        document.metadata["path"] = str(source_path)
        document.metadata["size_bytes"] = len(data)
        return document

    def parse_text(self, text: str, source_name: str = "Geplakte tekst") -> ParsedScenarioDocument:
        normalized = self._normalize_text(text)
        segments = self._segments_from_plain_text(normalized)
        return ParsedScenarioDocument(
            text=normalized,
            source_type=ScenarioSourceType.TEXT,
            source_name=source_name,
            segments=segments,
            metadata={"character_count": len(normalized)},
        )

    def parse_bytes(
        self,
        data: bytes,
        *,
        source_type: ScenarioSourceType | str,
        source_name: str = "scenario",
    ) -> ParsedScenarioDocument:
        try:
            kind = source_type if isinstance(source_type, ScenarioSourceType) else ScenarioSourceType(source_type)
        except ValueError as exc:
            raise ScenarioParseError(f"Niet-ondersteund brontype: {source_type}") from exc
        if not data:
            raise ScenarioParseError("Het bronbestand is leeg.")
        if kind in {ScenarioSourceType.TEXT, ScenarioSourceType.TXT, ScenarioSourceType.MARKDOWN}:
            text = self._decode_text(data)
            segments = self._segments_from_markdown(text) if kind is ScenarioSourceType.MARKDOWN else self._segments_from_plain_text(text)
            return self._document(text, kind, source_name, segments)
        if kind is ScenarioSourceType.JSON:
            return self._parse_json(data, source_name)
        if kind is ScenarioSourceType.DOCX:
            return self._parse_docx(data, source_name)
        if kind is ScenarioSourceType.PDF:
            return self._parse_pdf(data, source_name)
        raise ScenarioParseError(f"Niet-ondersteund brontype: {kind.value}")

    def _parse_json(self, data: bytes, source_name: str) -> ParsedScenarioDocument:
        try:
            payload = json.loads(self._decode_text(data))
        except json.JSONDecodeError as exc:
            raise ScenarioParseError(f"Ongeldige JSON op regel {exc.lineno}, kolom {exc.colno}.") from exc
        segments: list[TextSegment] = []
        values: list[str] = []
        for path, value in self._walk_json(payload):
            rendered = self._json_scalar_to_text(value)
            if not rendered:
                continue
            values.append(rendered)
            segments.append(TextSegment(text=rendered, index=len(segments), json_path=path))
        if not values:
            raise ScenarioParseError("JSON bevat geen analyseerbare tekstwaarden.")
        text = self._normalize_text("\n".join(values))
        return self._document(text, ScenarioSourceType.JSON, source_name, segments, {"json_root_type": type(payload).__name__})

    def _parse_docx(self, data: bytes, source_name: str) -> ParsedScenarioDocument:
        try:
            with ZipFile(io.BytesIO(data)) as archive:
                xml_data = archive.read("word/document.xml")
                core_properties = self._read_docx_core_properties(archive)
        except (BadZipFile, KeyError, OSError) as exc:
            raise ScenarioParseError("Ongeldig of beschadigd DOCX-bestand.") from exc
        try:
            root = ElementTree.fromstring(xml_data)
        except ElementTree.ParseError as exc:
            raise ScenarioParseError("DOCX document.xml bevat ongeldige XML.") from exc
        namespace = "{http://schemas.openxmlformats.org/wordprocessingml/2006/main}"
        segments: list[TextSegment] = []
        paragraphs: list[str] = []
        for paragraph_index, paragraph in enumerate(root.iter(f"{namespace}p")):
            parts: list[str] = []
            for node in paragraph.iter():
                if node.tag == f"{namespace}t" and node.text:
                    parts.append(node.text)
                elif node.tag == f"{namespace}tab":
                    parts.append("\t")
                elif node.tag in {f"{namespace}br", f"{namespace}cr"}:
                    parts.append("\n")
            text = self._normalize_inline("".join(parts))
            if text:
                paragraphs.append(text)
                segments.append(TextSegment(text=text, index=len(segments), paragraph=paragraph_index))
        document_text = self._normalize_text("\n".join(paragraphs))
        return self._document(document_text, ScenarioSourceType.DOCX, source_name, segments, core_properties)

    def _parse_pdf(self, data: bytes, source_name: str) -> ParsedScenarioDocument:
        if not data.startswith(b"%PDF-"): raise ScenarioParseError("Ongeldig PDF-bestand.")
        external=self._extract_pdf_with_library(data); warnings=[]
        if external is not None and any(x.strip() for x in external[0]): raw_pages,backend=external
        else:
            raw_pages=self._extract_pdf_fallback(data); backend="builtin"
            warnings.append("Ingebouwde PDF-extractor gebruikt; complexe font-encodings kunnen beperkt zijn.")
        pages=[self._clean_pdf_page(x) for x in raw_pages]
        nonempty=[x for x in pages if x.strip()]
        quality=self._pdf_quality("\n".join(nonempty)); empty=sum(not x.strip() for x in pages)
        pdf_type="scanned" if (not nonempty or (pages and empty/len(pages)>=.80)) else ("hybrid" if empty else "text")
        if quality<45: warnings.append(f"Lage extractiekwaliteit ({quality}%): controleer CTI-resultaten vóór SQLite commit.")
        elif quality<70: warnings.append(f"Middelmatige extractiekwaliteit ({quality}%): review aanbevolen.")
        if pdf_type=="scanned": warnings.append("PDF lijkt image-only/scanned; OCR is nodig voor betrouwbare extractie.")
        segments=[TextSegment(text=x,index=i,page=i+1) for i,x in enumerate(pages) if x.strip()]
        doc=self._document(self._normalize_text("\n\n".join(x.text for x in segments)),ScenarioSourceType.PDF,source_name,segments,
            {"page_count":len(pages),"pdf_backend":backend,"pdf_type":pdf_type,"extraction_quality":quality,"empty_pages":empty})
        doc.warnings.extend(warnings); return doc

    @staticmethod
    def _clean_pdf_page(text: str) -> str:
        text=unicodedata.normalize("NFKC",text or "").replace("\u00ad","").replace("\ufffd"," ")
        text="".join(ch if ch in "\n\t" or (unicodedata.category(ch)[0]!="C" and not 0xE000<=ord(ch)<=0xF8FF) else " " for ch in text)
        text=re.sub(r"(?<=\\w)-\\s*\\n\\s*(?=[a-z])","",text)
        text=re.sub(r"[ \\t]+"," ",text); text=re.sub(r" *\\n *","\\n",text); text=re.sub(r"\\n{3,}","\\n\\n",text)
        return text.strip()

    @staticmethod
    def _pdf_quality(text: str) -> int:
        chars=[c for c in text if not c.isspace()]
        if not chars:return 0
        readable=sum(c.isalnum() or c in ".,;:!?()[]{}'/@#%&+-_=–—€$£" for c in chars)
        return max(0,min(100,round(100*readable/len(chars))))

    def _extract_pdf_with_library(self, data: bytes) -> tuple[list[str], str] | None:
        reader_class: Any = None
        backend = ""
        try:
            from pypdf import PdfReader as reader_class  # type: ignore[no-redef]
            backend = "pypdf"
        except ImportError:
            try:
                from PyPDF2 import PdfReader as reader_class  # type: ignore[no-redef]
                backend = "PyPDF2"
            except ImportError:
                return None
        try:
            reader = reader_class(io.BytesIO(data))
            if getattr(reader, "is_encrypted", False):
                try:
                    result = reader.decrypt("")
                except Exception as exc:
                    raise ScenarioParseError("Versleutelde PDF kan niet zonder wachtwoord worden gelezen.") from exc
                if not result:
                    raise ScenarioParseError("Versleutelde PDF kan niet zonder wachtwoord worden gelezen.")
            pages = [self._normalize_text(page.extract_text() or "") for page in reader.pages]
        except ScenarioParseError:
            raise
        except Exception:
            return None
        return pages, backend

    def _extract_pdf_fallback(self, data: bytes) -> list[str]:
        streams = self._pdf_streams(data)
        texts: list[str] = []
        for stream in streams:
            extracted = self._extract_pdf_text_operators(stream)
            if extracted:
                texts.append(extracted)
        if not texts:
            raise ScenarioParseError("PDF bevat geen tekst die zonder aanvullende PDF-bibliotheek kan worden geëxtraheerd.")
        return texts

    def _pdf_streams(self, data: bytes) -> Iterable[bytes]:
        pattern = re.compile(rb"<<(.*?)>>\s*stream\r?\n", re.DOTALL)
        for match in pattern.finditer(data):
            start = match.end()
            end = data.find(b"endstream", start)
            if end < 0:
                continue
            stream = data[start:end].rstrip(b"\r\n")
            dictionary = match.group(1)
            if b"/FlateDecode" in dictionary:
                try:
                    stream = zlib.decompress(stream)
                except zlib.error:
                    try:
                        stream = zlib.decompress(stream, -zlib.MAX_WBITS)
                    except zlib.error:
                        continue
            yield stream

    def _extract_pdf_text_operators(self, stream: bytes) -> str:
        chunks: list[tuple[int, str]] = []
        for match in self._PDF_LITERAL_RE.finditer(stream):
            chunks.append((match.start(), self._decode_pdf_literal(match.group(0).split(b")", 1)[0] + b")")))
        for match in self._PDF_ARRAY_RE.finditer(stream):
            values = [self._decode_pdf_literal(item.group(0)) for item in self._PDF_ARRAY_LITERAL_RE.finditer(match.group(1))]
            chunks.append((match.start(), "".join(values)))
        for match in self._PDF_HEX_RE.finditer(stream):
            try:
                raw = bytes.fromhex(re.sub(rb"\s+", b"", match.group(1)).decode("ascii"))
            except (ValueError, UnicodeDecodeError):
                continue
            chunks.append((match.start(), self._decode_pdf_bytes(raw)))
        chunks.sort(key=lambda item: item[0])
        return self._normalize_text("\n".join(text for _, text in chunks if text.strip()))

    def _decode_pdf_literal(self, token: bytes) -> str:
        raw = token[1:-1]
        output = bytearray()
        index = 0
        escapes = {ord("n"): 10, ord("r"): 13, ord("t"): 9, ord("b"): 8, ord("f"): 12}
        while index < len(raw):
            byte = raw[index]
            if byte != 0x5C:
                output.append(byte)
                index += 1
                continue
            index += 1
            if index >= len(raw):
                break
            escaped = raw[index]
            if escaped in escapes:
                output.append(escapes[escaped])
                index += 1
            elif escaped in b"()\\":
                output.append(escaped)
                index += 1
            elif escaped in b"\r\n":
                if escaped == 13 and index + 1 < len(raw) and raw[index + 1] == 10:
                    index += 1
                index += 1
            elif 48 <= escaped <= 55:
                digits = bytes([escaped])
                index += 1
                for _ in range(2):
                    if index < len(raw) and 48 <= raw[index] <= 55:
                        digits += bytes([raw[index]])
                        index += 1
                    else:
                        break
                output.append(int(digits, 8))
            else:
                output.append(escaped)
                index += 1
        return self._decode_pdf_bytes(bytes(output))

    @staticmethod
    def _decode_pdf_bytes(raw: bytes) -> str:
        if raw.startswith(b"\xfe\xff"):
            return raw[2:].decode("utf-16-be", errors="replace")
        if raw.startswith(b"\xff\xfe"):
            return raw[2:].decode("utf-16-le", errors="replace")
        if len(raw) >= 4 and raw.count(b"\x00") > len(raw) // 4:
            try:
                return raw.decode("utf-16-be")
            except UnicodeDecodeError:
                pass
        return raw.decode("cp1252", errors="replace")

    @staticmethod
    def _read_docx_core_properties(archive: ZipFile) -> dict[str, Any]:
        try:
            root = ElementTree.fromstring(archive.read("docProps/core.xml"))
        except (KeyError, ElementTree.ParseError):
            return {}
        values: dict[str, Any] = {}
        for child in root:
            name = child.tag.rsplit("}", 1)[-1]
            if child.text and child.text.strip():
                values[name] = child.text.strip()
        return values

    def _segments_from_plain_text(self, text: str) -> list[TextSegment]:
        normalized = self._normalize_text(text)
        return [
            TextSegment(text=paragraph, index=index, paragraph=index)
            for index, paragraph in enumerate(part.strip() for part in re.split(r"\n\s*\n|\n", normalized))
            if paragraph
        ]

    def _segments_from_markdown(self, text: str) -> list[TextSegment]:
        normalized = self._normalize_text(text)
        segments: list[TextSegment] = []
        heading: str | None = None
        buffer: list[str] = []

        def flush() -> None:
            if not buffer:
                return
            content = self._normalize_inline(" ".join(buffer))
            buffer.clear()
            if content:
                segments.append(TextSegment(text=content, index=len(segments), paragraph=len(segments), heading=heading))

        for line in normalized.splitlines():
            heading_match = re.match(r"^\s{0,3}#{1,6}\s+(.+?)\s*#*\s*$", line)
            if heading_match:
                flush()
                heading = heading_match.group(1).strip()
                segments.append(TextSegment(text=heading, index=len(segments), heading=heading))
            elif not line.strip():
                flush()
            else:
                clean = re.sub(r"^\s*(?:[-*+] |\d+[.)]\s+|>\s*)", "", line).strip()
                if clean:
                    buffer.append(clean)
        flush()
        return segments or self._segments_from_plain_text(normalized)

    @classmethod
    def _walk_json(cls, value: Any, path: str = "$") -> Iterable[tuple[str, Any]]:
        if isinstance(value, dict):
            for key, child in value.items():
                child_path = f"{path}.{key}" if str(key).isidentifier() else f"{path}[{json.dumps(str(key), ensure_ascii=False)}]"
                yield from cls._walk_json(child, child_path)
        elif isinstance(value, list):
            for index, child in enumerate(value):
                yield from cls._walk_json(child, f"{path}[{index}]")
        elif value is not None:
            yield path, value

    @staticmethod
    def _json_scalar_to_text(value: Any) -> str:
        if isinstance(value, str):
            return value.strip()
        if isinstance(value, bool):
            return "true" if value else "false"
        if isinstance(value, (int, float)):
            return str(value)
        return ""

    @staticmethod
    def _decode_text(data: bytes) -> str:
        encodings = ("utf-8-sig", "utf-16", "cp1252", "latin-1")
        for encoding in encodings:
            try:
                return data.decode(encoding)
            except UnicodeDecodeError:
                continue
        return data.decode("utf-8", errors="replace")

    @classmethod
    def _normalize_inline(cls, text: str) -> str:
        return cls._SPACE_RE.sub(" ", text.replace("\u00a0", " ")).strip()

    @classmethod
    def _normalize_text(cls, text: str) -> str:
        if not isinstance(text, str):
            raise TypeError("Scenario-inhoud moet tekst zijn.")
        text = text.replace("\r\n", "\n").replace("\r", "\n").replace("\x00", "")
        lines = [cls._SPACE_RE.sub(" ", line.replace("\u00a0", " ")).rstrip() for line in text.split("\n")]
        return cls._BLANK_LINES_RE.sub("\n\n", "\n".join(lines)).strip()

    @staticmethod
    def _source_type_for_suffix(suffix: str) -> ScenarioSourceType:
        raw = FILE_EXTENSION_TO_SOURCE_TYPE.get(suffix.casefold())
        if raw is None:
            supported = ", ".join(sorted(FILE_EXTENSION_TO_SOURCE_TYPE))
            raise ScenarioParseError(f"Niet-ondersteund bestandstype '{suffix or '<geen>'}'. Ondersteund: {supported}")
        return ScenarioSourceType(raw)

    def _document(
        self,
        text: str,
        source_type: ScenarioSourceType,
        source_name: str,
        segments: list[TextSegment],
        metadata: dict[str, Any] | None = None,
    ) -> ParsedScenarioDocument:
        normalized = self._normalize_text(text)
        if not normalized:
            raise ScenarioParseError("Het scenario bevat geen analyseerbare tekst.")
        return ParsedScenarioDocument(
            text=normalized,
            source_type=source_type,
            source_name=source_name,
            segments=segments,
            metadata={"character_count": len(normalized), **(metadata or {})},
        )
