from __future__ import annotations
import json
from pathlib import Path
from typing import Any, Callable

_LANGUAGE = "nl"
_CATALOGS: dict[str, dict[str,str]] = {}
_LEGACY: dict[str,str] = {}
_VALUE_TO_KEY: dict[str, dict[str, str]] = {}
_HOOKS_INSTALLED = False
_LANGUAGE_GETTER: Callable[[], str] | None = None


def _base_dir() -> Path:
    return Path(__file__).resolve().parent


def _load_json(path: Path) -> dict:
    try:
        data=json.loads(path.read_text(encoding="utf-8"))
        return data if isinstance(data,dict) else {}
    except Exception:
        return {}


def _ensure_loaded() -> None:
    global _CATALOGS,_LEGACY,_VALUE_TO_KEY
    if not _CATALOGS:
        for lang in ("nl","en"):
            _CATALOGS[lang]=_load_json(_base_dir()/"locales"/f"{lang}.json")
    if not _VALUE_TO_KEY and _CATALOGS:
        for lang, catalog in _CATALOGS.items():
            _VALUE_TO_KEY[lang] = {str(value): str(key) for key, value in catalog.items() if isinstance(value, str) and value}
    if not _LEGACY:
        _LEGACY={str(k):str(v) for k,v in _load_json(_base_dir()/"legacy_map.json").items()}


def normalize_language(language: str | None) -> str:
    raw=str(language or "nl").lower().replace("_","-")
    return "en" if raw.startswith("en") else "nl"


def set_language(language: str) -> str:
    global _LANGUAGE
    _LANGUAGE=normalize_language(language)
    return _LANGUAGE


def get_language() -> str:
    if _LANGUAGE_GETTER:
        try:return normalize_language(_LANGUAGE_GETTER())
        except Exception:pass
    return _LANGUAGE


def tr(key: str, default: str | None=None, language: str | None=None, **values: Any) -> str:
    _ensure_loaded(); lang=normalize_language(language or get_language())
    cat=_CATALOGS.get(lang,{})
    fallback=_CATALOGS.get("nl",{})
    value=cat.get(key, fallback.get(key, default if default is not None else key))
    try:return str(value).format(**values)
    except Exception:return str(value)


def translate_legacy(text: Any, language: str | None=None) -> Any:
    if not isinstance(text,str) or not text:return text
    _ensure_loaded(); lang=normalize_language(language or get_language())
    # Exact source-level UI resources first, then the legacy compatibility map.
    # This intentionally does not machine-translate report/evidence content.
    stripped=text.strip()
    if not stripped or len(stripped)>320 or "\n" in stripped:return text
    value = None
    for source_lang in ("nl", "en"):
        key = _VALUE_TO_KEY.get(source_lang, {}).get(stripped)
        if key:
            value = _CATALOGS.get(lang, {}).get(key)
            if value is not None:
                break
    if value is None:
        if lang=="en":
            value=_LEGACY.get(stripped)
        else:
            reverse={v:k for k,v in _LEGACY.items()}
            value=reverse.get(stripped)
    if value is None:return text
    # preserve surrounding whitespace
    left=len(text)-len(text.lstrip()); right=len(text)-len(text.rstrip())
    return text[:left]+value+(text[len(text)-right:] if right else "")



def translate_presentation(text: Any, language: str | None=None) -> Any:
    """Translate an exact CAMT presentation string from the locale catalogs.

    Multiline strings are supported. Arbitrary evidence and user content remain
    untouched because only exact catalog values are translated.
    """
    if not isinstance(text,str) or not text:
        return text
    _ensure_loaded()
    lang=normalize_language(language or get_language())
    stripped=text.strip()
    if not stripped:
        return text
    value=None
    for source_lang in ("nl","en"):
        key=_VALUE_TO_KEY.get(source_lang,{}).get(stripped)
        if key:
            value=_CATALOGS.get(lang,{}).get(key)
            if value is not None:
                break
    if value is None:
        return text
    left=len(text)-len(text.lstrip()); right=len(text)-len(text.rstrip())
    return text[:left]+str(value)+(text[len(text)-right:] if right else "")


def translate_generated(text: Any, language: str | None=None) -> Any:
    """Translate catalogued CAMT-generated fragments inside presentation text.

    This exists for legacy modules that compose status/answer strings with counts
    or asset names. Only known catalog fragments of six or more characters are
    replaced; source evidence and arbitrary user text are not machine-translated.
    """
    if not isinstance(text,str) or not text:
        return text
    exact=translate_presentation(text,language)
    if exact != text:
        return exact
    _ensure_loaded()
    lang=normalize_language(language or get_language())
    out=text
    source=_CATALOGS.get("nl",{})
    target=_CATALOGS.get(lang,{})
    pairs=[]
    for key,nl_value in source.items():
        en_value=target.get(key)
        if not (isinstance(nl_value,str) and isinstance(en_value,str)):
            continue
        if nl_value==en_value or len(nl_value.strip())<6:
            continue
        if nl_value in out:
            pairs.append((nl_value,en_value))
    for old,new in sorted(pairs,key=lambda x:len(x[0]),reverse=True):
        out=out.replace(old,new)
    return out

def install_tk_hooks(language_getter: Callable[[],str] | None=None) -> None:
    global _HOOKS_INSTALLED,_LANGUAGE_GETTER
    if language_getter is not None:_LANGUAGE_GETTER=language_getter
    if _HOOKS_INSTALLED:return
    _HOOKS_INSTALLED=True
    try:
        import tkinter as tk
        from tkinter import ttk
        original_options=tk.Misc._options
        def options(self, cnf, kw=None):
            # Preserve Tkinter's native option merging/callback registration and
            # translate only presentation values in the resulting option tuple.
            raw=original_options(self, cnf, kw)
            out=[]
            for i,item in enumerate(raw):
                if i>0 and raw[i-1] in ("-text","-label","-title","-message","-detail") and isinstance(item,str):
                    item=translate_legacy(item)
                out.append(item)
            return tuple(out)
        tk.Misc._options=options
        original_title=tk.Wm.wm_title
        def wm_title(self,string=None):
            if string is not None:string=translate_legacy(string)
            return original_title(self,string)
        tk.Wm.wm_title=wm_title; tk.Wm.title=wm_title
        original_heading=ttk.Treeview.heading
        def heading(self,column,option=None,**kw):
            if "text" in kw:kw["text"]=translate_legacy(kw["text"])
            return original_heading(self,column,option,**kw)
        ttk.Treeview.heading=heading
        # CAMT v11.4 presentation enforcement.
        original_var_set=tk.Variable.set
        def variable_set(self,value):
            if isinstance(value,str):
                value=translate_generated(value)
            return original_var_set(self,value)
        tk.Variable.set=variable_set

        original_text_insert=tk.Text.insert
        def text_insert(self,index,chars,*args):
            if isinstance(chars,str):
                chars=translate_generated(chars)
            return original_text_insert(self,index,chars,*args)
        tk.Text.insert=text_insert

        original_tree_insert=ttk.Treeview.insert
        def tree_insert(self,parent,index,iid=None,**kw):
            if isinstance(kw.get("text"),str):
                kw["text"]=translate_generated(kw["text"])
            values=kw.get("values")
            if isinstance(values,(list,tuple)):
                kw["values"]=type(values)(translate_generated(v) if isinstance(v,str) else v for v in values)
            return original_tree_insert(self,parent,index,iid=iid,**kw)
        ttk.Treeview.insert=tree_insert

        try:
            from tkinter import messagebox as _mb
            for _name in ("showinfo","showwarning","showerror","askyesno","askokcancel","askretrycancel","askquestion"):
                _orig=getattr(_mb,_name,None)
                if not callable(_orig):
                    continue
                def _make_mb(orig):
                    def _wrapped(title=None,message=None,*a,**kw):
                        if isinstance(title,str): title=translate_generated(title)
                        if isinstance(message,str): message=translate_generated(message)
                        if isinstance(kw.get("detail"),str): kw["detail"]=translate_generated(kw["detail"])
                        return orig(title,message,*a,**kw)
                    return _wrapped
                setattr(_mb,_name,_make_mb(_orig))
        except Exception:
            pass
    except Exception:
        pass


def refresh_widget_tree(root, language: str | None=None) -> None:
    lang=normalize_language(language or get_language());set_language(lang)
    try:
        import tkinter as tk
        from tkinter import ttk
        seen=set()
        def walk(w):
            if id(w) in seen:return
            seen.add(id(w))
            try:
                if hasattr(w,"cget") and hasattr(w,"configure"):
                    current=w.cget("text")
                    if isinstance(current,str) and current:
                        new=translate_legacy(current,lang)
                        if new!=current:w.configure(text=new)
            except Exception:pass
            try:
                if isinstance(w,ttk.Treeview):
                    cols=list(w["columns"])
                    show=str(w.cget("show") or "")
                    if "tree" in show:cols=["#0"]+cols
                    for c in cols:
                        try:
                            cur=w.heading(c,"text");new=translate_legacy(cur,lang)
                            if new!=cur:w.heading(c,text=new)
                        except Exception:pass
            except Exception:pass
            try:
                if isinstance(w,tk.Menu):
                    end=w.index("end")
                    if end is not None:
                        for i in range(end+1):
                            try:
                                cur=w.entrycget(i,"label")
                                if cur:
                                    new=translate_legacy(cur,lang)
                                    if new!=cur:w.entryconfigure(i,label=new)
                            except Exception:pass
            except Exception:pass
            try:
                for child in w.winfo_children():walk(child)
            except Exception:pass
        walk(root)
        try:
            for child in root.winfo_children():
                if isinstance(child,tk.Toplevel):
                    cur=child.title();new=translate_legacy(cur,lang)
                    if new!=cur:child.title(new)
        except Exception:pass
    except Exception:pass


def module_context(language: str | None=None) -> dict[str,Any]:
    lang=normalize_language(language or get_language())
    return {"language":lang,"locale":"en_US" if lang=="en" else "nl_NL","tr":lambda key,default=None,**kw:tr(key,default,lang,**kw),"translate_ui":lambda text:translate_legacy(text,lang)}
