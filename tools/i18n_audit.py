from __future__ import annotations
from pathlib import Path
import ast,json,re,sys
DUTCH_RE=re.compile(r"\b(geen|geïnstalleerd|instellingen|opgeslagen|mislukt|selecteer|verwijder|waarschuwing|onbekend|toevoegen|toepassen|gereed|relaties|broncode|bijwerken|opschonen|stoppen|huidig|kandidaat|kandidaten|bewijsbestanden|gevisualiseerd|eigenschappen|afdrukken|verzenden|notitie|publiceer|installeer|kwetsbaar|onderzoeksvraag|bronpassages|gerangschikt|vervolgquery|interpretatie|verschillen|uitvoer|observaties|niveau|aandacht|aanpak|aangetroffen)\b",re.I)
def fn(n):
    if isinstance(n,ast.Name):return n.id
    if isinstance(n,ast.Attribute):
        a=fn(n.value);return f"{a}.{n.attr}" if a else n.attr
    return ""
def parents(t):
    d={}
    for n in ast.walk(t):
        for c in ast.iter_child_nodes(n):d[c]=n
    return d
def scan_file(path,nl,en):
    try:t=ast.parse(path.read_text(encoding="utf-8"))
    except Exception:return []
    pm=parents(t);out=[]
    nl_values={str(v):k for k,v in nl.items() if isinstance(v,str)}
    for n in ast.walk(t):
        if not(isinstance(n,ast.Constant) and isinstance(n.value,str) and DUTCH_RE.search(n.value)):continue
        p=pm.get(n)
        if isinstance(p,ast.Call) and fn(p.func) in {"_tr","tr","_ui","translate_presentation","translate_generated","_t"}:continue
        q=p;sink=False
        for _ in range(5):
            if isinstance(q,ast.Call):
                name=fn(q.func)
                if name.split(".")[-1] in {"Label","Button","Checkbutton","Radiobutton","LabelFrame","title","heading","configure","config","insert","set"} or name.startswith(("messagebox.","simpledialog.","filedialog.")):
                    sink=True;break
            q=pm.get(q)
        if not sink:continue
        key=nl_values.get(n.value)
        # A catalogued literal is allowed only when a valid English counterpart exists.
        if not key or not isinstance(en.get(key),str) or en.get(key)==n.value or DUTCH_RE.search(en.get(key,"")):
            out.append((n.lineno,n.value))
    return out
def main(root):
    root=Path(root)
    en=json.loads((root/"src/projectmanager/i18n/locales/en.json").read_text(encoding="utf-8"))
    nl=json.loads((root/"src/projectmanager/i18n/locales/nl.json").read_text(encoding="utf-8"))
    py=[]
    for p in list((root/"src/projectmanager").rglob("*.py"))+list((root/"plugins").rglob("*.py")):
        for ln,s in scan_file(p,nl,en):py.append((str(p.relative_to(root)),ln,s))
    mixed=[(k,v) for k,v in en.items() if isinstance(v,str) and DUTCH_RE.search(v)]
    parity=set(en)^set(nl)
    print("CAMT 1.2.0 Beta 9 i18n release gate")
    print("Unlocalized Dutch presentation sinks:",len(py))
    print("Mixed Dutch in EN locale:",len(mixed))
    print("EN/NL key parity differences:",len(parity))
    for x in py[:50]:print("PY",x)
    for x in mixed[:50]:print("EN",x)
    return 1 if py or mixed or parity else 0
if __name__=="__main__":
    raise SystemExit(main(sys.argv[1] if len(sys.argv)>1 else "."))
