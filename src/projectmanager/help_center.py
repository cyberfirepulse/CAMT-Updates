from __future__ import annotations

from projectmanager.i18n import tr as _tr
import re
from tkinter import BOTH, END, LEFT, RIGHT, VERTICAL, HORIZONTAL, Text, StringVar
from tkinter import ttk


class _LocalizedHelpTopics:
    """Mapping-like loader for language-specific Help Center content."""
    def __init__(self) -> None:
        self._cache: dict[str, dict[str, tuple[str, str]]] = {}

    def _data(self) -> dict[str, tuple[str, str]]:
        from projectmanager.i18n import get_language
        lang = "en" if str(get_language()).lower().startswith("en") else "nl"
        if lang not in self._cache:
            import json
            from pathlib import Path
            path = Path(__file__).resolve().parent / "help_content" / f"{lang}.json"
            raw = json.loads(path.read_text(encoding="utf-8"))
            self._cache[lang] = {str(k): (str(v[0]), str(v[1])) for k, v in raw.items()}
        return self._cache[lang]

    def keys(self): return self._data().keys()
    def items(self): return self._data().items()
    def values(self): return self._data().values()
    def get(self, key, default=None): return self._data().get(key, default)
    def __getitem__(self, key): return self._data()[key]
    def __iter__(self): return iter(self._data())
    def __len__(self): return len(self._data())
    def __contains__(self, key): return key in self._data()


HELP_TOPICS = _LocalizedHelpTopics()


class HelpCenter:
    @staticmethod
    def _font_family(app) -> str:
        for attr in ("ui_font_family", "font_family", "_font_family"):
            value = getattr(app, attr, None)
            if isinstance(value, str) and value.strip():
                return value.strip()
        method = getattr(app, "_ui_font_family", None)
        if callable(method):
            try:
                value = method()
                if isinstance(value, str) and value.strip():
                    return value.strip()
            except Exception:
                pass
        return "Segoe UI"

    @staticmethod
    def _font_size(app, default: int = 10) -> int:
        for attr in ("ui_font_size", "font_size"):
            value = getattr(app, attr, None)
            try:
                if value is not None:
                    return max(8, min(24, int(value)))
            except (TypeError, ValueError):
                pass
        return default

    @classmethod
    def _body_font(cls, app):
        method = getattr(app, "_ui_font", None)
        if callable(method):
            try:
                return method(cls._font_size(app))
            except Exception:
                pass
        return (cls._font_family(app), cls._font_size(app))

    @staticmethod
    def _new_window(app):
        method = getattr(app, "_new_tool_window", None)
        if callable(method):
            try:
                return method()
            except Exception:
                pass
        import tkinter as tk
        return tk.Toplevel(getattr(app, "root", None))

    @staticmethod
    def _run_self_test_safe(app) -> None:
        method = getattr(app, "_run_self_test", None)
        if callable(method):
            method()
            return
        from tkinter import messagebox
        messagebox.showinfo(_tr('ui.source.camt.self.test.4680651e'), _tr('ui.source.de.self.test.functie.is.in.deze.build.niet.bes.44877d8b'))

    def __init__(self, app, initial_topic: str = "overview") -> None:
        self.app = app
        self.window = self._new_window(app)
        self.window.title(_tr('ui.source.camt.help.center.0197da79'))
        sw=max(1000,self.window.winfo_screenwidth()); sh=max(700,self.window.winfo_screenheight())
        ww=min(1320,sw-80); wh=min(820,sh-100)
        self.window.geometry(f"{ww}x{wh}+{max(20,(sw-ww)//2)}+{max(20,(sh-wh)//2)}")
        self.window.minsize(900, 600)

        outer = ttk.Frame(self.window, padding=10)
        outer.pack(fill=BOTH, expand=True)
        outer.rowconfigure(1, weight=1)
        outer.columnconfigure(0, weight=1)

        searchbar = ttk.Frame(outer)
        searchbar.grid(row=0, column=0, sticky="ew", pady=(0, 8))
        searchbar.columnconfigure(1, weight=1)
        ttk.Label(searchbar, text=_tr('ui.source.zoeken.744bd8f7')).grid(row=0, column=0, padx=(0, 6))
        self.search_var = StringVar()
        entry = ttk.Entry(searchbar, textvariable=self.search_var)
        entry.grid(row=0, column=1, sticky="ew")
        ttk.Button(searchbar, text=_tr('ui.source.zoeken.2d890f1f'), command=self._search).grid(row=0, column=2, padx=(6, 0))
        ttk.Button(searchbar, text=_tr('ui.source.alles.tonen.274aedbe'), command=self._populate).grid(row=0, column=3, padx=(6, 0))

        pane = ttk.Panedwindow(outer, orient=HORIZONTAL)
        pane.grid(row=1, column=0, sticky="nsew")

        left = ttk.Frame(pane, padding=4)
        right = ttk.Frame(pane, padding=4)
        pane.add(left, weight=1)
        pane.add(right, weight=4)

        left.rowconfigure(0, weight=1)
        left.columnconfigure(0, weight=1)
        self.tree = ttk.Treeview(left, show="tree", selectmode="browse")
        ytree = ttk.Scrollbar(left, orient=VERTICAL, command=self.tree.yview)
        self.tree.configure(yscrollcommand=ytree.set)
        self.tree.grid(row=0, column=0, sticky="nsew")
        ytree.grid(row=0, column=1, sticky="ns")

        right.rowconfigure(2, weight=1)
        right.columnconfigure(0, weight=1)
        self.heading = ttk.Label(right, text="", font=(self._font_family(app), max(12, self._font_size(app) + 2), "bold"))
        self.art_label = ttk.Label(right)
        self.art_label.grid(row=0, column=0, sticky="ew", pady=(0, 8))
        self.heading.grid(row=1, column=0, sticky="w", pady=(0, 8))

        textframe = ttk.Frame(right)
        textframe.grid(row=2, column=0, sticky="nsew")
        textframe.rowconfigure(0, weight=1)
        textframe.columnconfigure(0, weight=1)
        self.text = Text(textframe, wrap="word", font=self._body_font(app), padx=14, pady=12, borderwidth=0)
        y = ttk.Scrollbar(textframe, orient=VERTICAL, command=self.text.yview)
        x = ttk.Scrollbar(textframe, orient=HORIZONTAL, command=self.text.xview)
        self.text.configure(yscrollcommand=y.set, xscrollcommand=x.set)
        self.text.grid(row=0, column=0, sticky="nsew")
        y.grid(row=0, column=1, sticky="ns")
        x.grid(row=1, column=0, sticky="ew")
        self.text.configure(state="disabled")

        status = ttk.Frame(outer)
        status.grid(row=2, column=0, sticky="ew", pady=(8, 0))
        ttk.Label(status, text=_tr('ui.source.camt.professional.edition.lokale.help.geschikt.72259c7e')).pack(side=LEFT)
        ttk.Button(status, text=_tr('ui.source.self.test.3f6edd76'), command=lambda: self._run_self_test_safe(app)).pack(side=RIGHT)
        ttk.Button(status, text=_tr('ui.source.sluiten.fe55d210'), command=self.window.destroy).pack(side=RIGHT, padx=(0, 6))

        self.tree.bind("<<TreeviewSelect>>", self._on_select)
        entry.bind("<Return>", lambda _event: self._search())
        self._categories = self._load_categories()
        self._topic_category = {}
        for _c in self._categories:
            for _t in _c.get("topics") or []:
                self._topic_category[str(_t)] = _c
        self._configure_text_tags()
        self._populate()
        self._select_topic(initial_topic)

    def _ui_items(self, keys=None):
        keys = keys or HELP_TOPICS.keys()
        return sorted(((key, HELP_TOPICS[key][0]) for key in keys), key=lambda item: item[1].casefold())

    def _load_categories(self):
        try:
            import json
            from pathlib import Path
            p = Path(__file__).resolve().parent / "help_content" / "categories.json"
            return sorted(json.loads(p.read_text(encoding="utf-8")).get("categories") or [], key=lambda x:int(x.get("order",999)))
        except Exception:
            return []

    def _configure_text_tags(self):
        family=self._font_family(self.app); base=self._font_size(self.app)
        self.text.tag_configure("h2", font=(family,base+2,"bold"), spacing1=10, spacing3=4)
        self.text.tag_configure("bullet", lmargin1=18, lmargin2=34, spacing1=2, spacing3=2)
        self.text.tag_configure("number", lmargin1=18, lmargin2=34, spacing1=2, spacing3=2)
        self.text.tag_configure("body", spacing1=1, spacing3=2)

    def _populate(self) -> None:
        self.search_var.set("")
        self.tree.delete(*self.tree.get_children())
        inserted=set()
        for c in self._categories:
            cid=f"cat:{c.get('id')}"
            self.tree.insert("",END,iid=cid,text=_tr(str(c.get("title_key") or "")),open=True)
            for topic in c.get("topics") or []:
                if topic in HELP_TOPICS:
                    self.tree.insert(cid,END,iid=topic,text=HELP_TOPICS[topic][0]); inserted.add(topic)
        rest=[k for k in HELP_TOPICS.keys() if k not in inserted]
        for k in sorted(rest,key=lambda x:HELP_TOPICS[x][0].casefold()):
            self.tree.insert("",END,iid=k,text=HELP_TOPICS[k][0])

    def _set_items(self, keys) -> None:
        self.tree.delete(*self.tree.get_children())
        for key, title in self._ui_items(keys):
            self.tree.insert("", END, iid=key, text=title)

    def _select_topic(self, topic: str) -> None:
        if topic not in HELP_TOPICS:
            topic = "overview"
        if not self.tree.exists(topic):
            self._populate()
        self.tree.selection_set(topic)
        self.tree.focus(topic)
        self.tree.see(topic)
        self._render(topic)

    def _on_select(self, _event=None) -> None:
        selection = self.tree.selection()
        if selection and not str(selection[0]).startswith("cat:"):
            self._render(selection[0])

    def _render(self, key: str) -> None:
        title, body = HELP_TOPICS.get(key, ("Help", ""))
        self.heading.configure(text=title)
        try:
            from tkinter import PhotoImage
            from projectmanager.core.shared import get_runtime_resource_root
            c=self._topic_category.get(key) or {}; rel=str(c.get("artwork") or "")
            if rel:
                if not hasattr(self,"_help_images"): self._help_images={}
                if rel not in self._help_images:
                    img=PhotoImage(file=str(get_runtime_resource_root()/rel)); factor=max(1,img.width()//700,img.height()//145)
                    if factor>1: img=img.subsample(factor,factor)
                    self._help_images[rel]=img
                self.art_label.configure(image=self._help_images[rel])
            else: self.art_label.configure(image="")
        except Exception:
            self.art_label.configure(image="")
        self.text.configure(state="normal"); self.text.delete("1.0",END)
        for line in body.strip().splitlines():
            s=line.strip()
            if not s: self.text.insert(END,"\n","body"); continue
            if s.startswith("- "): self.text.insert(END,"• "+s[2:]+"\n","bullet"); continue
            if re.match(r"^\d+\.\s+",s): self.text.insert(END,s+"\n","number"); continue
            if len(s)<50 and not s.endswith('.') and not s.endswith(':'):
                self.text.insert(END,s+"\n","h2"); continue
            self.text.insert(END,s+"\n","body")
        self.text.configure(state="disabled"); self.text.yview_moveto(0)

    def _search(self) -> None:
        query = self.search_var.get().strip().casefold()
        if not query:
            self._populate()
            return
        tokens = [token for token in re.split(r"\s+", query) if token]
        matches = []
        for key, (title, body) in HELP_TOPICS.items():
            haystack = f"{title}\n{body}".casefold()
            if all(token in haystack for token in tokens):
                matches.append(key)
        self._set_items(matches)
        if matches:
            self._select_topic(matches[0])
        else:
            self.heading.configure(text=_tr('ui.source.geen.resultaten.52b3936d'))
            self.text.configure(state="normal")
            self.text.delete("1.0", END)
            self.text.insert("1.0", _tr('ui.source.geen.help.onderwerp.gevonden.voor.p0.54347348',p0=self.search_var.get()))
            self.text.configure(state="disabled")
