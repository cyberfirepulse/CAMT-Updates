from __future__ import annotations
import argparse, ast, json, re
from pathlib import Path

ROOT=Path(__file__).resolve().parent
SRC=ROOT/'src/projectmanager'; PLUG=ROOT/'plugins'; I18N=SRC/'i18n'; LOC=I18N/'locales'
DUTCH_STRONG={
 'geen','selecteer','kies','verwijderen','opslaan','sluiten','annuleren','zoeken','instellingen','nieuwe','bestand','bestanden','werkruimte','mislukt','gereed','beschrijving','huidige','volgende','vorige','toevoegen','aanmaken','controleren','verversen','vernieuwen','bron','doel','geladen','uitvoeren','uitgevoerd','gebruiker','gebruikers','prullenbak','rapporten','risico','projectmap','basismap','overzicht','wijzigingen','ontbreken','ontbreekt','gevonden','opgeslagen','openen','tonen','gebruiken','omdat','vanuit','waarschuwing','beschikbaar','herstellen','opschonen','aanvalspad'
}
UI_KW={'text','label','title','message','detail','prompt','heading'}
DIALOG={'showinfo','showwarning','showerror','askyesno','askokcancel','askquestion','askstring','askinteger','askfloat','askopenfilename','asksaveasfilename','askdirectory'}

def load(p): return json.loads(p.read_text(encoding='utf-8'))
def looks_dutch(s): return bool(set(re.findall(r"[a-zà-ÿ]+",str(s).lower())) & DUTCH_STRONG)
def is_tr_call(n):
    return isinstance(n,ast.Call) and ((isinstance(n.func,ast.Name) and n.func.id in {'_tr','tr','i18n_tr'}) or (isinstance(n.func,ast.Attribute) and n.func.attr in {'tr','_tr'}))
def raw_dutch_in(node):
    out=[]
    def visit(x):
        if is_tr_call(x):
            return
        if isinstance(x,ast.Constant) and isinstance(x.value,str) and looks_dutch(x.value):
            out.append((x.lineno,x.value.strip().replace('\n',' ↵ ')[:220]))
            return
        for child in ast.iter_child_nodes(x):
            visit(child)
    visit(node)
    return out

def _legacy_source_file(p: Path) -> bool:
    """Return True for obvious archival/backup Python source files.

    These files can legitimately contain historical hardcoded UI strings, but they are
    not part of the active CAMT runtime unless another source file imports/references
    them. Strict i18n therefore reports them as warnings when unreferenced, and as
    errors when they are still active.
    """
    stem=p.stem.lower()
    return (
        stem.endswith(('_old','_backup','_bak','_legacy','_copy'))
        or stem.startswith(('old_','backup_','legacy_'))
    )

def _legacy_is_referenced(p: Path) -> bool:
    stem=p.stem
    # Conservative textual check catches normal imports and dynamic loader strings.
    patterns=(
        re.compile(rf'\bimport\s+[^\n#]*\b{re.escape(stem)}\b'),
        re.compile(rf'\bfrom\s+[^\n#]+\bimport\s+[^\n#]*\b{re.escape(stem)}\b'),
        re.compile(rf'["\'](?:[^"\']*\.)?{re.escape(stem)}["\']'),
    )
    for base in (SRC,PLUG):
        for other in base.rglob('*.py'):
            if other == p or '__pycache__' in other.parts:
                continue
            try: text=other.read_text(encoding='utf-8',errors='replace')
            except Exception: continue
            if any(rx.search(text) for rx in patterns):
                return True
    return False

def scan_source():
    rows=[]; legacy_rows=[]; active_legacy=[]
    for base in (SRC,PLUG):
        for p in base.rglob('*.py'):
            if '__pycache__' in p.parts or 'i18n' in p.parts: continue
            legacy=_legacy_source_file(p)
            try: tree=ast.parse(p.read_text(encoding='utf-8',errors='replace'))
            except Exception as exc:
                rows.append((p,0,'parse',str(exc))); continue
            local=[]
            for n in ast.walk(tree):
                if not isinstance(n,ast.Call): continue
                name=n.func.attr if isinstance(n.func,ast.Attribute) else n.func.id if isinstance(n.func,ast.Name) else ''
                for kw in n.keywords:
                    if kw.arg in UI_KW:
                        for line,text in raw_dutch_in(kw.value): local.append((p,line,f'UI {kw.arg}',text))
                if name in DIALOG:
                    for a in n.args[:2]:
                        for line,text in raw_dutch_in(a): local.append((p,line,'dialog',text))
                if name=='insert' and isinstance(n.func,ast.Attribute) and len(n.args)>=2:
                    recv=ast.unparse(n.func.value).lower()
                    if any(x in recv for x in ('text','console','output','preview','details','help','log')):
                        for line,text in raw_dutch_in(n.args[1]): local.append((p,line,'text.insert',text))
                if name in ('append','extend') and isinstance(n.func,ast.Attribute):
                    recv=ast.unparse(n.func.value).lower()
                    if any(x in recv for x in ('lines','messages','details','summary','info','help','tips')):
                        for a in n.args:
                            for line,text in raw_dutch_in(a): local.append((p,line,'visible text builder',text))
            if legacy and local:
                if _legacy_is_referenced(p):
                    active_legacy.extend(local)
                else:
                    legacy_rows.extend(local)
            else:
                rows.extend(local)
    # remove duplicates
    def uniq(items):
        out=[];seen=set()
        for p,l,k,t in items:
            sig=(str(p),l,k,t)
            if sig not in seen: seen.add(sig);out.append((p,l,k,t))
        return out
    return uniq(rows), uniq(legacy_rows), uniq(active_legacy)

def main():
    ap=argparse.ArgumentParser();ap.add_argument('--strict',action='store_true');args=ap.parse_args()
    errors=[]
    nl=load(LOC/'nl.json'); en=load(LOC/'en.json')
    diff=sorted(set(nl)^set(en))
    if diff: errors.append(f'Locale key mismatch: {len(diff)} key(s)')
    help_nl=load(SRC/'help_content/nl.json'); help_en=load(SRC/'help_content/en.json')
    if set(help_nl)!=set(help_en): errors.append('Help Center NL/EN topic mismatch')
    netmap=PLUG/'network_digital_twin'
    nm_nl=load(netmap/'help_content.nl.json'); nm_en=load(netmap/'help_content.en.json')
    if set(nm_nl)!=set(nm_en): errors.append('NetMap help NL/EN topic mismatch')
    manifest=load(netmap/'plugin.json')
    if not isinstance(manifest.get('description_i18n'),dict) or not {'nl','en'}<=set(manifest['description_i18n']): errors.append('NetMap plugin description_i18n incomplete')
    source_rows, legacy_rows, active_legacy_rows=scan_source()
    # Generated English resource text must not contain strong Dutch UI words.
    residual=[]
    for k,v in en.items():
        if isinstance(v,str) and looks_dutch(v): residual.append((k,v.replace('\n',' ↵ ')[:220]))
    # Old generic NetMap help must no longer be referenced by the loader.
    nm_src=(netmap/'netmap_source.py').read_text(encoding='utf-8')
    if 'with_name("help_content.json")' in nm_src or 'os.path.join(base_dir, "help_content.json")' in nm_src:
        errors.append('NetMap still loads legacy help_content.json')
    if source_rows: errors.append(f'Hardcoded Dutch-looking UI presentation strings: {len(source_rows)}')
    if active_legacy_rows: errors.append(f'Legacy/backup Python source is still referenced and contains Dutch UI strings: {len(active_legacy_rows)}')
    if residual: errors.append(f'Dutch-looking text remains in EN locale: {len(residual)}')
    report=[
      'CAMT 1.2.0 Beta 10 — NL/EN SOURCE-LEVEL I18N AUDIT','='*72,
      f'Locale keys NL: {len(nl)}',f'Locale keys EN: {len(en)}',
      f'Help Center topics NL/EN: {len(help_nl)}/{len(help_en)}',
      f'NetMap help topics NL/EN: {len(nm_nl)}/{len(nm_en)}',
      f'Hardcoded Dutch-looking presentation strings: {len(source_rows)}',
      f'Unreferenced legacy/archive UI findings (warning only): {len(legacy_rows)}',
      f'Referenced legacy/archive UI findings: {len(active_legacy_rows)}',
      f'Dutch-looking EN locale residuals: {len(residual)}',''
    ]
    if source_rows:
      report.append('SOURCE FINDINGS')
      for p,l,k,t in source_rows[:100]: report.append(f'- {p.relative_to(ROOT)}:{l} [{k}] {t}')
      report.append('')
    if legacy_rows:
      report.append('LEGACY/ARCHIVE FINDINGS (WARNING ONLY; NOT ACTIVE)')
      for p,l,k,t in legacy_rows[:100]: report.append(f'- {p.relative_to(ROOT)}:{l} [{k}] {t}')
      report.append('')
    if active_legacy_rows:
      report.append('REFERENCED LEGACY/ARCHIVE FINDINGS (ERROR)')
      for p,l,k,t in active_legacy_rows[:100]: report.append(f'- {p.relative_to(ROOT)}:{l} [{k}] {t}')
      report.append('')
    if residual:
      report.append('EN LOCALE FINDINGS')
      for k,v in residual[:100]: report.append(f'- {k}: {v}')
      report.append('')
    report += ['RESULT: '+('FAIL' if errors else 'PASS')]
    if errors: report += ['','ERRORS']+['- '+x for x in errors]
    text='\n'.join(report)+'\n'; print(text); (ROOT/'CAMT_I18N_AUDIT.txt').write_text(text,encoding='utf-8')
    return 1 if (errors and args.strict) else 0
if __name__=='__main__': raise SystemExit(main())
