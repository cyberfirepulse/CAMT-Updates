from __future__ import annotations
from projectmanager.i18n.runtime import tr as _tr
from projectmanager.i18n import tr as _tr
from projectmanager.core.shared import *
from projectmanager.core.shared import (
    _dt
)
from projectmanager.presentation.dialogs import *

from projectmanager.ui.safe_config import safe_configure

class SettingsThemeI18NMixin:
        def _load_app_settings(self) -> None:
            """Laad app-instellingen uit Documents\\ProjectManager\\settings.json."""
            data = load_json_file(get_settings_path(), {})
            if not isinstance(data, dict):
                return

            try:
                self.root_path_var.set(data.get("last_root", self.root_path_var.get()))
                self.scan_profile_var.set(data.get("scan_profile", self.scan_profile_var.get()))
                self.scan_depth_var.set(int(data.get("scan_depth", self.scan_depth_var.get())))
                self.incremental_scan_var.set(bool(data.get("incremental_scan", self.incremental_scan_var.get())))
                self.theme_var.set(data.get("theme", self.theme_var.get()))
                self.ui_font_size = int(data.get("font_size", self.ui_font_size))
                self.ui_mono_font_size = int(data.get("mono_font_size", self.ui_mono_font_size))
                self.details_wide = bool(data.get("details_wide", self.details_wide))
                self.favorites_first_var.set(bool(data.get("favorites_first", self.favorites_first_var.get())))
                self.only_favorites_var.set(bool(data.get("only_favorites", self.only_favorites_var.get())))
                if hasattr(self, "dashboard_filter_var"):
                    self.dashboard_filter_var.set(data.get("dashboard_filter", "Alle"))

                self.initial_window_geometry = str(data.get("window_geometry", "") or "")
                self.last_selected_project_path = str(data.get("last_selected_project_path", "") or "")
                self.saved_column_widths = {str(k): int(v) for k, v in (data.get("project_column_widths", {}) or {}).items() if str(k).strip()}
                self.workspace_var.set(str(data.get("workspace", "Standaard") or "Standaard"))
                self.language_var.set(str(data.get("language", "nl") or "nl"))
                self.saved_sash_positions = [int(x) for x in (data.get("main_sash_positions", []) or []) if str(x).isdigit()]
                self.left_panel_visible = bool(data.get("left_panel_visible", True))
                self.dashboard_task_group_states = dict(data.get("dashboard_task_group_states", {}) or {})
                self.dashboard_task_group_order = [str(x) for x in (data.get("dashboard_task_group_order", []) or [])]
                self.solution_explorer_visible = bool(data.get("solution_explorer_visible", True))
                self.solution_explorer_sash = int(data.get("solution_explorer_sash", 285) or 285)
                self.right_panel_visible = bool(data.get("right_panel_visible", True))
                self.compact_mode = bool(data.get("compact_mode", False))
                self.ui_font_family = str(data.get("ui_font_family", self.ui_font_family) or self.ui_font_family)
                self.ui_mono_font_family = str(data.get("ui_mono_font_family", self.ui_mono_font_family) or self.ui_mono_font_family)
                self.ui_scaling = float(data.get("ui_scaling", self.ui_scaling) or self.ui_scaling)
                self.ui_tree_row_height = int(data.get("ui_tree_row_height", self.ui_tree_row_height) or self.ui_tree_row_height)
                self.ui_color_overrides = dict(data.get("ui_color_overrides", {}) or {})
                self.ui_visible_project_columns = [str(x) for x in (data.get("ui_visible_project_columns", []) or [])]
                self.ui_heading_color = str(data.get("ui_heading_color", "") or "")
                self.ui_alt_row_color = str(data.get("ui_alt_row_color", "") or "")
                self.ui_high_color = str(data.get("ui_high_color", self.ui_high_color) or self.ui_high_color)
                self.ui_medium_color = str(data.get("ui_medium_color", self.ui_medium_color) or self.ui_medium_color)
                self.ui_low_color = str(data.get("ui_low_color", self.ui_low_color) or self.ui_low_color)
                self.ui_info_color = str(data.get("ui_info_color", self.ui_info_color) or self.ui_info_color)
                self.ui_use_theme_colors = bool(data.get("ui_use_theme_colors", True))
                if data.get("detail_page") and hasattr(self, "detail_page_var"):
                    self.detail_page_var.set(str(data.get("detail_page")))

                locations = data.get("scan_locations", [])
                if isinstance(locations, list):
                    self.scan_locations = [str(p) for p in locations if str(p).strip()]
                if self.root_path_var.get() and self.root_path_var.get() not in self.scan_locations:
                    self.scan_locations.insert(0, self.root_path_var.get())
                self._configure_default_fonts()
            except Exception:
                pass
        def _save_app_settings(self) -> None:
            """Sla app-instellingen op."""
            data = {
                "last_root": self.root_path_var.get(),
                "scan_profile": self.scan_profile_var.get(),
                "scan_depth": int(self.scan_depth_var.get()),
                "incremental_scan": bool(self.incremental_scan_var.get()),
                "theme": self.theme_var.get(),
                "font_size": int(self.ui_font_size),
                "mono_font_size": int(self.ui_mono_font_size),
                "details_wide": bool(getattr(self, "details_wide", False)),
                "favorites_first": bool(self.favorites_first_var.get()),
                "only_favorites": bool(self.only_favorites_var.get()),
                "dashboard_filter": self.dashboard_filter_var.get() if hasattr(self, "dashboard_filter_var") else "Alle",
                "detail_page": self.detail_page_var.get() if hasattr(self, "detail_page_var") else "Details",
                "window_geometry": self.root.winfo_geometry() if hasattr(self, "root") else "",
                "project_column_widths": self._capture_project_column_widths() if hasattr(self, "project_tree") else dict(getattr(self, "saved_column_widths", {})),
                "last_selected_project_path": str(self.selected_project.path) if self.selected_project else getattr(self, "last_selected_project_path", ""),
                "workspace": self.workspace_var.get() if hasattr(self, "workspace_var") else "Standaard",
                "language": self.language_var.get() if hasattr(self, "language_var") else "nl",
                "main_sash_positions": self._capture_main_sashes(),
                "left_panel_visible": bool(getattr(self, "left_panel_visible", True)),
                "dashboard_task_group_states": dict(getattr(self, "dashboard_task_group_states", {}) or {}),
                "dashboard_task_group_order": list(getattr(self, "dashboard_task_group_order", []) or []),
                "solution_explorer_visible": bool(getattr(self, "solution_explorer_visible", True)),
                "solution_explorer_sash": int(self._capture_solution_sash()),
                "right_panel_visible": bool(getattr(self, "right_panel_visible", True)),
                "compact_mode": bool(getattr(self, "compact_mode", False)),
                "ui_font_family": getattr(self, "ui_font_family", "Segoe UI"),
                "ui_mono_font_family": getattr(self, "ui_mono_font_family", "Consolas"),
                "ui_scaling": float(getattr(self, "ui_scaling", 1.35)),
                "ui_tree_row_height": int(getattr(self, "ui_tree_row_height", UI_TREE_ROW_HEIGHT)),
                "ui_color_overrides": dict(getattr(self, "ui_color_overrides", {})),
                "ui_visible_project_columns": list(getattr(self, "ui_visible_project_columns", [])),
                "ui_heading_color": getattr(self, "ui_heading_color", ""),
                "ui_alt_row_color": getattr(self, "ui_alt_row_color", ""),
                "ui_high_color": getattr(self, "ui_high_color", "#dc2626"),
                "ui_medium_color": getattr(self, "ui_medium_color", "#f59e0b"),
                "ui_low_color": getattr(self, "ui_low_color", "#16a34a"),
                "ui_info_color": getattr(self, "ui_info_color", "#2563eb"),
                "ui_use_theme_colors": bool(getattr(self, "ui_use_theme_colors", True)),
                "scan_locations": list(dict.fromkeys([self.root_path_var.get(), *self.scan_locations])),
                "last_saved": _dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            }
            try:
                write_json_file(get_settings_path(), data)
            except Exception as exc:
                print(f"Instellingen opslaan mislukt: {exc}", file=sys.stderr)
        def _font(self, size: int | None = None, bold: bool = False, family: str | None = None) -> str:
            """
            Geef een Tkinter named font terug.

            Belangrijk:
            Gebruik hier geen losse fontstring zoals "TkDefaultFont".
            Tcl splitst dat soms als family=Segoe en size=UI, met de fout:
            expected integer but got "UI".

            Named fonts hebben geen spaties in de fontnaam en zijn daardoor stabieler.
            """
            font_size = int(size if size is not None else self.ui_font_size)
            if family is None:
                family = getattr(self, "ui_font_family", "Segoe UI")
            weight = "bold" if bold else "normal"
            safe_family = re.sub(r"[^A-Za-z0-9_]", "", family) or "SegoeUI"
            name = f"PM_{safe_family}_{font_size}_{weight}"

            if not hasattr(self, "_font_cache"):
                self._font_cache = {}

            if name not in self._font_cache:
                try:
                    self._font_cache[name] = tkfont.Font(
                        root=self.root,
                        name=name,
                        family=family,
                        size=font_size,
                        weight=weight,
                    )
                except Exception:
                    # Fallback zonder spaties in family.
                    self._font_cache[name] = tkfont.Font(
                        root=self.root,
                        name=name,
                        family="Arial",
                        size=font_size,
                        weight=weight,
                    )
            else:
                try:
                    self._font_cache[name].configure(
                        family=family,
                        size=font_size,
                        weight=weight,
                    )
                except Exception:
                    pass

            return name
        def _mono_font(self, size: int | None = None, bold: bool = False) -> str:
            """Geef een monospace named font terug."""
            font_size = int(size if size is not None else self.ui_mono_font_size)
            return self._font(font_size, bold=bold, family=getattr(self, "ui_mono_font_family", "Consolas"))
        def _configure_default_fonts(self) -> None:
            """Zet Tkinter default fonts groter en consistenter voor Windows 11."""
            try:
                # 1.35 is een veilige basis voor moderne Windows-schermen.
                # Bij A-/A+ blijft de fontgrootte zelf leidend.
                self.root.tk.call("tk", "scaling", float(getattr(self, "ui_scaling", 1.35)))
            except Exception:
                pass

            for font_name in (
                "TkDefaultFont",
                "TkTextFont",
                "TkFixedFont",
                "TkMenuFont",
                "TkHeadingFont",
                "TkCaptionFont",
                "TkSmallCaptionFont",
                "TkIconFont",
                "TkTooltipFont",
            ):
                try:
                    f = tkfont.nametofont(font_name)
                    family = getattr(self, "ui_mono_font_family", "Consolas") if font_name == "TkFixedFont" else getattr(self, "ui_font_family", "Segoe UI")
                    size = self.ui_mono_font_size if font_name == "TkFixedFont" else self.ui_font_size
                    f.configure(family=family, size=size)
                except Exception:
                    pass

            try:
                self.root.option_add("*Font", self._font(self.ui_font_size))
            except Exception:
                pass
        def _change_font_size(self, delta: int) -> None:
            """Vergroot/verklein de applicatiefonts via A- en A+."""
            self.ui_font_size = max(9, min(18, self.ui_font_size + delta))
            self.ui_mono_font_size = max(9, min(18, self.ui_mono_font_size + delta))
            self._configure_default_fonts()
            self._apply_theme()

            if hasattr(self, "note_text"):
                self.note_text.configure(font=self._font(self.ui_font_size))
            if hasattr(self, "output_text"):
                self.output_text.configure(font=self._mono_font(self.ui_mono_font_size))
            if hasattr(self, "status_var"):
                self.status_var.set(_tr('ui.source.lettergrootte.p0.pt.e227dd9c',p0=self.ui_font_size))
            if hasattr(self, "_save_app_settings"):
                self._save_app_settings()
        def _apply_saved_window_state(self) -> None:
            """v1.1: herstel venstergrootte en projectkolommen uit settings.json."""
            geom = getattr(self, "initial_window_geometry", "")
            if geom and re.match(r"^\d+x\d+([+-]\d+[+-]\d+)?$", geom):
                try:
                    self.root.geometry(geom)
                except Exception:
                    pass
            self._apply_saved_column_widths()
        def _capture_project_column_widths(self) -> dict[str, int]:
            """Bewaar huidige kolombreedtes van de projectlijst."""
            widths: dict[str, int] = {}
            if not hasattr(self, "project_tree"):
                return widths
            try:
                for col in self.project_tree["columns"]:
                    widths[str(col)] = int(self.project_tree.column(col, "width"))
            except Exception:
                pass
            return widths
        def _apply_saved_column_widths(self) -> None:
            """Herstel kolombreedtes na het opbouwen van de Treeview."""
            if not hasattr(self, "project_tree"):
                return
            for col, width in getattr(self, "saved_column_widths", {}).items():
                try:
                    if col in self.project_tree["columns"] and int(width) > 20:
                        self.project_tree.column(col, width=int(width))
                except Exception:
                    pass
        def _theme_choices(self) -> list[str]:
            """Thema's in logische volgorde voor menu's en instellingen."""
            built_in = ["soft_dark", "soft_light", "slate", "blue", "forest", "sand", "matrix", "dark", "light"]
            custom = sorted(k for k in self.themes if k.startswith("custom_"))
            return built_in + custom
        def _theme_label(self, theme: str) -> str:
            labels = {
                "soft_dark": "Zacht donker",
                "soft_light": "Zacht licht",
                "slate": "Slate",
                "blue": "Blauw licht",
                "forest": "Groen licht",
                "sand": "Zand",
                "matrix": "Matrix",
                "dark": "Donker klassiek",
                "light": "Licht klassiek",
            }
            if theme in self.themes and isinstance(self.themes[theme], dict) and self.themes[theme].get("_label"):
                return str(self.themes[theme]["_label"])
            return labels.get(theme, theme)
        def _theme_from_label(self, label: str) -> str:
            reverse = {self._theme_label(key): key for key in self._theme_choices()}
            return reverse.get(label, label)
        def _current_theme(self) -> dict[str, str]:
            """Bepaal de effectieve stijl volgens: thema -> expliciete UI-overrides."""
            base = dict(self.themes.get(self.theme_var.get(), self.themes["soft_dark"]))
            if not getattr(self, "ui_use_theme_colors", True):
                for key, value in getattr(self, "ui_color_overrides", {}).items():
                    if key in base and isinstance(value, str) and value.strip():
                        base[key] = value.strip()
                if getattr(self, "ui_heading_color", ""):
                    base["heading"] = self.ui_heading_color
                if getattr(self, "ui_alt_row_color", ""):
                    base["tree_alt"] = self.ui_alt_row_color
            return base
        def _workspace_consistency_manager(self):
            manager=getattr(self,"_workspace_ui_manager",None)
            if manager is None:
                from projectmanager.ui.consistency import WorkspaceConsistencyManager
                manager=WorkspaceConsistencyManager(self)
                self._workspace_ui_manager=manager
            return manager

        def _new_tool_window(self, parent=None):
            """Create a normal, resizable and centrally themed application tool window.

            Window chrome is enforced centrally by WorkspaceConsistencyManager:
            win.resizable(True, True)
            win.attributes("-toolwindow", False)
            """
            return self._workspace_consistency_manager().create_window(parent=parent)

        def _tool_header(self,parent,title,subtitle="",actions=()):
            return self._workspace_consistency_manager().create_header(parent,title=title,subtitle=subtitle,actions=actions)

        def _tool_statusbar(self,parent,text="Gereed"):
            return self._workspace_consistency_manager().create_statusbar(parent,text)

        def _tool_panedwindow(self,parent,orient=HORIZONTAL):
            return self._workspace_consistency_manager().standard_panedwindow(parent,orient)

        def _refresh_all_tool_themes(self):
            manager=getattr(self,"_workspace_ui_manager",None)
            if manager is not None:
                manager.refresh_all()

        def _apply_theme_to_window(self, window) -> None:
            """Apply the current palette recursively to an already open Tk tool."""
            theme=self._current_theme()
            mapping={
                Frame: {"bg": theme.get("panel", theme.get("bg"))},
                Label: {"bg": theme.get("panel", theme.get("bg")), "fg": theme.get("text")},
                Button: {"bg": theme.get("panel2", theme.get("panel")), "fg": theme.get("text"),
                         "activebackground": theme.get("accent"), "activeforeground": theme.get("bg")},
                Listbox: {"bg": theme.get("panel", theme.get("bg")), "fg": theme.get("text"),
                          "selectbackground": theme.get("accent"), "selectforeground": theme.get("bg")},
                Text: {"bg": theme.get("panel", theme.get("bg")), "fg": theme.get("text"),
                       "insertbackground": theme.get("accent")},
                Canvas: {"bg": theme.get("bg")},
            }
            def walk(widget):
                for cls, options in mapping.items():
                    if isinstance(widget, cls):
                        safe_configure(widget, **options)
                        break
                for child in widget.winfo_children(): walk(child)
            try:
                safe_configure(window, bg=theme.get("bg"))
                walk(window)
            except (TclError, AttributeError):
                return

        def _apply_theme(self) -> None:
            c = self._current_theme()

            self.root.configure(bg=c["bg"])
            for canvas_name in ("left_canvas", "right_canvas"):
                canvas = getattr(self, canvas_name, None)
                if canvas is not None:
                    try:
                        canvas.configure(background=c["panel"])
                    except Exception:
                        pass

            self.style.configure(
                ".",
                background=c["bg"],
                foreground=c["text"],
                fieldbackground=c["entry"],
                bordercolor=c["border"],
                lightcolor=c["border"],
                darkcolor=c["border"],
            )

            self.style.configure("TFrame", background=c["bg"])
            self.style.configure("Panel.TFrame", background=c["panel"], relief="flat")
            self.style.configure("Card.TFrame", background=c["panel2"], relief="flat")
            self.style.configure("TLabel", background=c["bg"], foreground=c["text"])
            self.style.configure("Panel.TLabel", background=c["panel"], foreground=c["text"])
            self.style.configure("Card.TLabel", background=c["panel2"], foreground=c["text"])
            self.style.configure("Muted.TLabel", background=c["panel"], foreground=c["muted"])
            self.style.configure("Title.TLabel", background=c["bg"], foreground=c["text"], font=self._font(self.ui_font_size + 7, bold=True))
            self.style.configure("Section.TLabel", background=c["panel"], foreground=c["accent"], font=self._font(self.ui_font_size + 1, bold=True))
            self.style.configure("Dashboard.TLabel", background=c["panel2"], foreground=c["text"], font=self._font(self.ui_font_size + 1, bold=True))
            self.style.configure("TaskPaneHeader.TButton", anchor="w", padding=(8, 6), font=self._font(self.ui_font_size, bold=True))

            self.style.configure(
                "TButton",
                background=c["button"],
                foreground=c["text"],
                borderwidth=0,
                focusthickness=0,
                padding=(14, 9),
                font=self._font(self.ui_font_size),
            )
            self.style.map(
                "TButton",
                background=[("active", c["button_active"]), ("pressed", c["button_active"])],
                foreground=[("disabled", c["muted"])],
            )

            self.style.configure(
                "Accent.TButton",
                background=c["accent"],
                foreground="#ffffff",
                padding=(14, 9),
                font=self._font(self.ui_font_size, bold=True),
            )
            self.style.configure(
                "Toolbar.TFrame",
                background=c["panel2"],
                relief="flat",
            )
            self.style.configure(
                "Toolbar.TButton",
                background=c["button"],
                foreground=c["text"],
                borderwidth=0,
                focusthickness=0,
                padding=(10, 7),
                font=self._font(max(9, self.ui_font_size - 1), bold=True),
            )
            self.style.map(
                "Toolbar.TButton",
                background=[("active", c["button_active"]), ("pressed", c["button_active"])],
                foreground=[("disabled", c["muted"])],
            )
            self.style.configure(
                "ToolbarAccent.TButton",
                background=c["accent"],
                foreground="#ffffff",
                borderwidth=0,
                padding=(10, 7),
                font=self._font(max(9, self.ui_font_size - 1), bold=True),
            )
            self.style.configure(
                "ToolbarDanger.TButton",
                background=c["danger"],
                foreground="#ffffff",
                borderwidth=0,
                padding=(10, 7),
                font=self._font(max(9, self.ui_font_size - 1), bold=True),
            )

            self.style.map("Accent.TButton", background=[("active", c["accent"])])

            self.style.configure(
                "Danger.TButton",
                background=c["danger"],
                foreground="#ffffff",
                padding=(14, 9),
                font=self._font(self.ui_font_size, bold=True),
            )

            self.style.configure(
                "TEntry",
                fieldbackground=c["entry"],
                foreground=c["text"],
                borderwidth=1,
                insertcolor=c["text"],
                padding=9,
            )

            self.style.configure(
                "TCombobox",
                fieldbackground=c["entry"],
                background=c["button"],
                foreground=c["text"],
                arrowcolor=c["text"],
                bordercolor=c["border"],
                lightcolor=c["border"],
                darkcolor=c["border"],
                padding=6,
            )
            self.style.map(
                "TCombobox",
                fieldbackground=[("readonly", c["entry"])],
                background=[("readonly", c["button"]), ("active", c["button_active"])],
                foreground=[("readonly", c["text"])],
            )

            self.style.configure(
                "TSpinbox",
                fieldbackground=c["entry"],
                background=c["button"],
                foreground=c["text"],
                arrowcolor=c["text"],
                bordercolor=c["border"],
                padding=6,
            )

            self.style.configure(
                "Horizontal.TProgressbar",
                background=c["accent"],
                troughcolor=c["panel2"],
                bordercolor=c["border"],
                lightcolor=c["accent"],
                darkcolor=c["accent"],
            )

            self.style.configure(
                "Vertical.TScrollbar",
                background=c["button"],
                troughcolor=c["panel"],
                arrowcolor=c["text"],
                bordercolor=c["border"],
            )
            self.style.configure(
                "Horizontal.TScrollbar",
                background=c["button"],
                troughcolor=c["panel"],
                arrowcolor=c["text"],
                bordercolor=c["border"],
            )

            self.style.configure(
                "Treeview",
                background=c["tree_bg"],
                foreground=c["text"],
                fieldbackground=c["tree_bg"],
                rowheight=int(getattr(self, "ui_tree_row_height", UI_TREE_ROW_HEIGHT)) + max(0, self.ui_font_size - UI_FONT_DEFAULT_SIZE) * 3,
                borderwidth=0,
                font=self._font(self.ui_font_size),
            )
            self.style.map(
                "Treeview",
                background=[("selected", c["accent"])],
                foreground=[("selected", "#ffffff")],
            )
            self.style.configure(
                "Treeview.Heading",
                background=c.get("heading", c["panel2"]),
                foreground=c["text"],
                relief="flat",
                padding=9,
                font=self._font(self.ui_font_size, bold=True),
            )
            self.style.map("Treeview.Heading", background=[("active", c["button_active"])])

            self.style.configure(
                "TNotebook",
                background=c["panel"],
                borderwidth=0,
            )
            self.style.configure(
                "TNotebook.Tab",
                background=c["panel2"],
                foreground=c["text"],
                padding=(14, 9),
            )
            self.style.map(
                "TNotebook.Tab",
                background=[("selected", c["accent"])],
                foreground=[("selected", "#ffffff")],
            )

            # v5.0: de detailpagina's gebruiken voortaan een eigen compacte navigatie.
            # De oude tabregel blijft technisch bestaan maar wordt visueel verborgen.
            try:
                self.style.layout("Hidden.TNotebook.Tab", [])
            except Exception:
                pass
            self.style.configure("Hidden.TNotebook", background=c["panel"], borderwidth=0)

            self.style.configure(
                "TCheckbutton",
                background=c["panel"],
                foreground=c["text"],
                font=self._font(self.ui_font_size),
            )

            # Repaint Treeview tags
            if hasattr(self, "project_tree"):
                self.project_tree.tag_configure("odd", background=c["tree_bg"])
                self.project_tree.tag_configure("even", background=c["tree_alt"])
                self.project_tree.tag_configure("duplicate", foreground=c["warning"])
                self.project_tree.tag_configure("health_ok", foreground=c["ok"])
                self.project_tree.tag_configure("health_warn", foreground=c["warning"])
                self.project_tree.tag_configure("health_bad", foreground=c["danger"])
                visible = getattr(self, "ui_visible_project_columns", [])
                if visible:
                    try:
                        self.project_tree.configure(displaycolumns=tuple(col for col in visible if col in self.project_tree["columns"]))
                    except Exception:
                        pass

            if hasattr(self, "note_text"):
                self.note_text.configure(
                    background=c["entry"],
                    foreground=c["text"],
                    insertbackground=c["text"],
                    highlightbackground=c["border"],
                    highlightcolor=c["accent"],
                    font=self._font(self.ui_font_size),
                )

            if hasattr(self, "output_text"):
                self.output_text.configure(
                    background=c["entry"],
                    foreground=c["text"],
                    insertbackground=c["text"],
                    highlightbackground=c["border"],
                    highlightcolor=c["accent"],
                    font=self._mono_font(self.ui_mono_font_size),
                )
        def _palette_font_larger(self) -> None:
            self._change_font_size(1)
        def _palette_font_smaller(self) -> None:
            self._change_font_size(-1)
        def _theme_storage_dir(self) -> Path:
            path = get_app_home_dir() / "themes"
            path.mkdir(parents=True, exist_ok=True)
            return path
        def _open_theme_manager(self) -> None:
            """Open de Theme Manager en beheer ingebouwde en aangepaste kleurthema's."""
            win = self._new_tool_window()
            win.title(_tr('ui.source.theme.manager.v.p0.7493a200',p0=APP_VERSION))
            win.geometry("860x680")
            win.minsize(760, 560)
            win.transient(self.root)

            shell = ttk.Frame(win, padding=14)
            shell.pack(fill=BOTH, expand=True)
            ttk.Label(shell, text=_tr('ui.source.theme.manager.8e0232ec'), style="Title.TLabel").pack(anchor="w")
            ttk.Label(
                shell,
                text=_tr('ui.source.thema.s.beheren.uitsluitend.kleuren.fonts.scha.d47e5124'),
                style="Muted.TLabel",
                wraplength=800,
            ).pack(anchor="w", pady=(0, 12))

            body = ttk.PanedWindow(shell, orient="horizontal")
            body.pack(fill=BOTH, expand=True)
            left = ttk.Frame(body, padding=6)
            right = ttk.Frame(body, padding=6)
            body.add(left, weight=1)
            body.add(right, weight=3)

            theme_list = ttk.Treeview(left, columns=("kind",), show="tree headings", height=18, selectmode="browse")
            theme_list.heading("#0", text=_tr('ui.source.thema.b2f1380a'))
            theme_list.heading("kind", text=_tr('ui.source.type.3deb7456'))
            theme_list.column("#0", width=170, minwidth=120)
            theme_list.column("kind", width=90, minwidth=70, anchor="w")
            theme_scroll = ttk.Scrollbar(left, orient="vertical", command=theme_list.yview)
            theme_list.configure(yscrollcommand=theme_scroll.set)
            theme_list.pack(side=LEFT, fill=BOTH, expand=True)
            theme_scroll.pack(side=RIGHT, fill=Y)

            color_keys = [
                ("bg", "Venster"), ("panel", "Panelen"), ("panel2", "Toolbar / kaarten"),
                ("tree_bg", "Tabellen"), ("tree_alt", "Afwisselende rij"), ("entry", "Invoervelden"),
                ("text", "Tekst"), ("muted", "Gedempte tekst"), ("accent", "Accent / selectie"),
                ("button", "Knoppen"), ("button_active", "Knop hover"), ("border", "Randen"),
                ("warning", "Waarschuwing"), ("danger", "Fout / hoog"), ("ok", "Succes / laag"),
            ]
            editor = ttk.LabelFrame(right, text=_tr('ui.source.kleuren.49d92fdf'), padding=10)
            editor.pack(fill=BOTH, expand=True)
            editor.columnconfigure(0, weight=1)
            vars_by_key: dict[str, StringVar] = {}

            for idx, (key, label) in enumerate(color_keys):
                row = ttk.Frame(editor)
                row.grid(row=idx, column=0, sticky="ew", pady=3)
                ttk.Label(row, text=label, width=22).pack(side=LEFT)
                var = StringVar()
                vars_by_key[key] = var
                ttk.Entry(row, textvariable=var, width=14).pack(side=LEFT, padx=(0, 6))
                swatch = ttk.Label(row, text=_tr('ui.source.text.08e02d82'), relief="solid")
                swatch.pack(side=LEFT, padx=(0, 6))

                def choose(v=var):
                    value = colorchooser.askcolor(color=v.get() or None, parent=win)[1]
                    if value:
                        v.set(value)

                ttk.Button(row, text=_tr('ui.source.kies.72ecad5d'), command=choose).pack(side=LEFT)
                var.trace_add("write", lambda *_a, v=var, w=swatch: self._safe_configure_swatch(w, v.get()))

            original_theme = self.theme_var.get()
            original_use = self.ui_use_theme_colors
            original_overrides = dict(self.ui_color_overrides)
            selected_key = StringVar(value=original_theme)

            def refresh_list(select: str | None = None) -> None:
                wanted = select or selected_key.get() or self.theme_var.get()
                theme_list.delete(*theme_list.get_children())
                selected_iid = ""
                for key in self._theme_choices():
                    if key not in self.themes:
                        continue
                    kind = "Aangepast" if key.startswith("custom_") else "Ingebouwd"
                    iid = theme_list.insert("", END, text=self._theme_label(key), values=(kind,), tags=(key,))
                    if key == wanted:
                        selected_iid = iid
                if not selected_iid and theme_list.get_children():
                    selected_iid = theme_list.get_children()[0]
                if selected_iid:
                    theme_list.selection_set(selected_iid)
                    theme_list.focus(selected_iid)
                    theme_list.see(selected_iid)

            def selected_theme_key() -> str:
                selection = theme_list.selection()
                if selection:
                    tags = theme_list.item(selection[0], "tags")
                    if tags:
                        return str(tags[0])
                fallback = selected_key.get() or self.theme_var.get()
                return fallback if fallback in self.themes else "soft_dark"

            def load_selected(_event=None) -> None:
                key = selected_theme_key()
                selected_key.set(key)
                data = self.themes.get(key, self.themes["soft_dark"])
                for color_key, var in vars_by_key.items():
                    var.set(str(data.get(color_key, "")))

            def edited_colors(base_key: str | None = None) -> dict[str, str]:
                key = base_key or selected_theme_key()
                data = dict(self.themes.get(key, self.themes["soft_dark"]))
                for color_key, var in vars_by_key.items():
                    value = var.get().strip()
                    if value:
                        try:
                            win.winfo_rgb(value)
                        except Exception as exc:
                            raise ValueError(f"Ongeldige kleur bij '{color_key}': {value}") from exc
                        data[color_key] = value
                return data

            def preview() -> None:
                try:
                    self.themes["__preview__"] = edited_colors()
                except ValueError as exc:
                    messagebox.showerror(_tr('ui.source.ongeldige.kleur.f4f393d9'), str(exc), parent=win)
                    return
                self.theme_var.set("__preview__")
                self.ui_use_theme_colors = True
                self._apply_theme()
                self._refresh_toolbar_icons()
                self._refresh_all_tool_themes()

            def apply_selected() -> None:
                key = selected_theme_key()
                if key not in self.themes:
                    return
                # Niet-opgeslagen wijzigingen blijven alleen via 'Opslaan als...' bewaard.
                self.themes.pop("__preview__", None)
                self.theme_var.set(key)
                self.ui_use_theme_colors = True
                self.ui_color_overrides = {}
                if hasattr(self, "quick_theme_var"):
                    self.quick_theme_var.set(self._theme_label(key))
                self._apply_theme()
                self._refresh_toolbar_icons()
                self._refresh_all_tool_themes()
                self._save_app_settings()
                win.destroy()

            def save_as() -> None:
                name = simpledialog.askstring(_tr('ui.source.thema.opslaan.fb5c6f4b'), _tr('ui.source.naam.voor.het.aangepaste.thema.4691fb22'), parent=win)
                if not name:
                    return
                safe = re.sub(r"[^A-Za-z0-9_-]+", "_", name.strip()).strip("_") or "theme"
                key = "custom_" + safe.lower()
                try:
                    data = edited_colors()
                except ValueError as exc:
                    messagebox.showerror(_tr('ui.source.ongeldige.kleur.f4f393d9'), str(exc), parent=win)
                    return
                data["_label"] = name.strip()
                self.themes[key] = data
                write_json_file(
                    self._theme_storage_dir() / f"{key}.json",
                    {"key": key, "label": name.strip(), "colors": {k: v for k, v in data.items() if not k.startswith("_")}},
                )
                selected_key.set(key)
                refresh_list(key)
                load_selected()

            def export_theme() -> None:
                key = selected_theme_key()
                data = self.themes.get(key)
                if not data:
                    return
                path = filedialog.asksaveasfilename(
                    parent=win,
                    title=_tr('ui.source.thema.exporteren.8b1630f7'),
                    defaultextension=".json",
                    filetypes=[(_tr('ui.source.json.031a4e76'), "*.json")],
                    initialfile=f"{key}.json",
                )
                if path:
                    write_json_file(
                        Path(path),
                        {"key": key, "label": self._theme_label(key), "colors": {k: v for k, v in data.items() if not k.startswith("_")}},
                    )

            def import_theme() -> None:
                path = filedialog.askopenfilename(parent=win, title=_tr('ui.source.thema.importeren.a79e051c'), filetypes=[(_tr('ui.source.json.031a4e76'), "*.json")])
                if not path:
                    return
                payload = load_json_file(Path(path), {})
                colors = payload.get("colors", {}) if isinstance(payload, dict) else {}
                if not isinstance(colors, dict) or not all(k in colors for k in ("bg", "panel", "text", "accent")):
                    messagebox.showerror(_tr('ui.source.ongeldig.thema.285f5d38'), _tr('ui.source.het.bestand.bevat.geen.geldig.project.manager..53dd1c64'), parent=win)
                    return
                try:
                    for value in colors.values():
                        if isinstance(value, str) and value:
                            win.winfo_rgb(value)
                except Exception:
                    messagebox.showerror(_tr('ui.source.ongeldig.thema.285f5d38'), _tr('ui.source.het.thema.bevat.n.of.meer.ongeldige.kleurwaard.190f116a'), parent=win)
                    return
                label = str(payload.get("label", Path(path).stem)).strip() or Path(path).stem
                safe = re.sub(r"[^A-Za-z0-9_-]+", "_", label).strip("_") or "imported"
                key = "custom_" + safe.lower()
                colors = dict(colors)
                colors["_label"] = label
                self.themes[key] = colors
                write_json_file(
                    self._theme_storage_dir() / f"{key}.json",
                    {"key": key, "label": label, "colors": {k: v for k, v in colors.items() if not k.startswith("_")}},
                )
                selected_key.set(key)
                refresh_list(key)
                load_selected()

            def delete_theme() -> None:
                key = selected_theme_key()
                if not key.startswith("custom_"):
                    messagebox.showinfo(_tr('ui.source.theme.manager.8e0232ec'), _tr('ui.source.ingebouwde.thema.s.kunnen.niet.worden.verwijde.0ff8b75f'), parent=win)
                    return
                if not messagebox.askyesno(_tr('ui.source.thema.verwijderen.89a138bc'), _tr('ui.source.aangepast.thema.p0.verwijderen.7b0411d2',p0=self._theme_label(key)), parent=win):
                    return
                try:
                    (self._theme_storage_dir() / f"{key}.json").unlink(missing_ok=True)
                except Exception as exc:
                    messagebox.showerror(_tr('ui.source.thema.verwijderen.89a138bc'), _tr('ui.source.het.themabestand.kon.niet.worden.verwijderd.p0.842f63a6',p0=exc), parent=win)
                    return
                self.themes.pop(key, None)
                selected_key.set(original_theme if original_theme in self.themes else "soft_dark")
                refresh_list(selected_key.get())
                load_selected()

            def cancel() -> None:
                self.themes.pop("__preview__", None)
                self.theme_var.set(original_theme)
                self.ui_use_theme_colors = original_use
                self.ui_color_overrides = original_overrides
                if hasattr(self, "quick_theme_var"):
                    self.quick_theme_var.set(self._theme_label(original_theme))
                self._apply_theme()
                self._refresh_toolbar_icons()
                self._refresh_all_tool_themes()
                win.destroy()

            theme_list.bind("<<TreeviewSelect>>", load_selected)
            theme_list.bind("<Double-1>", lambda _event: apply_selected())
            buttons = ttk.Frame(shell)
            buttons.pack(fill=X, pady=(10, 0))
            ttk.Button(buttons, text=_tr('ui.source.importeren.44537bde'), command=import_theme).pack(side=LEFT)
            ttk.Button(buttons, text=_tr('ui.source.exporteren.2ab8edec'), command=export_theme).pack(side=LEFT, padx=5)
            ttk.Button(buttons, text=_tr('ui.source.opslaan.als.801b04c4'), command=save_as).pack(side=LEFT)
            ttk.Button(buttons, text=_tr('ui.source.verwijderen.6bc766d0'), command=delete_theme).pack(side=LEFT, padx=5)
            ttk.Button(buttons, text=_tr('ui.source.voorbeeld.36b2d63f'), command=preview).pack(side=LEFT, padx=(16, 0))
            ttk.Button(buttons, text=_tr('ui.source.toepassen.cd5dbaea'), style="Accent.TButton", command=apply_selected).pack(side=RIGHT)
            ttk.Button(buttons, text=_tr('ui.source.annuleren.c2fbda4e'), command=cancel).pack(side=RIGHT, padx=6)
            win.protocol("WM_DELETE_WINDOW", cancel)
            win.bind("<Escape>", lambda _event: cancel())
            refresh_list()
            load_selected()
        def _open_ui_studio(self) -> None:
            """v7.8: uitgebreide editor voor vormgeving, fonts, kleuren en kolommen."""
            win = self._new_tool_window()
            win.title(_tr('ui.source.personal.ui.studio.v.p0.7f65d9bf',p0=APP_VERSION))
            win.geometry("920x720")
            win.minsize(780, 620)
            win.transient(self.root)

            notebook = ttk.Notebook(win)
            notebook.pack(fill=BOTH, expand=True, padx=12, pady=12)
            tab_font = ttk.Frame(notebook, padding=14)
            tab_colors = ttk.Frame(notebook, padding=14)
            tab_columns = ttk.Frame(notebook, padding=14)
            tab_preview = ttk.Frame(notebook, padding=14)
            notebook.add(tab_font, text=_tr('ui.source.lettertypen.schaal.2a363576'))
            notebook.add(tab_colors, text=_tr('ui.source.kleuren.49d92fdf'))
            notebook.add(tab_columns, text=_tr('ui.source.projectkolommen.173fc11e'))
            notebook.add(tab_preview, text=_tr('ui.source.live.preview.131a90af'))

            # v7.8.1: live preview moet volledig teruggedraaid kunnen worden.
            original_ui_state = {
                "font_family": self.ui_font_family, "mono_family": self.ui_mono_font_family,
                "font_size": self.ui_font_size, "mono_size": self.ui_mono_font_size,
                "scaling": self.ui_scaling, "row_height": self.ui_tree_row_height,
                "overrides": dict(self.ui_color_overrides), "visible_columns": list(self.ui_visible_project_columns),
                "high": self.ui_high_color, "medium": self.ui_medium_color,
                "low": self.ui_low_color, "info": self.ui_info_color,
                "use_theme": self.ui_use_theme_colors,
            }
            families = sorted(set(tkfont.families(self.root)))
            font_family_var = StringVar(value=self.ui_font_family)
            mono_family_var = StringVar(value=self.ui_mono_font_family)
            font_size_var = IntVar(value=self.ui_font_size)
            mono_size_var = IntVar(value=self.ui_mono_font_size)
            scaling_var = StringVar(value=_tr('ui.source.p0.2f.8c1cc648',p0=self.ui_scaling))
            row_height_var = IntVar(value=self.ui_tree_row_height)
            # v7.9.2: deze variabele werd gebruikt door collect_values() en de
            # live-preview traces, maar was niet aangemaakt. Daardoor crashte
            # Personal UI Studio direct bij openen.
            use_theme_colors_var = BooleanVar(value=self.ui_use_theme_colors)

            def form_row(parent, label, widget_factory):
                row = ttk.Frame(parent)
                row.pack(fill=X, pady=6)
                ttk.Label(row, text=label, width=24).pack(side=LEFT)
                widget = widget_factory(row)
                widget.pack(side=LEFT, fill=X, expand=True)
                return widget

            form_row(tab_font, "Interfacelettertype", lambda p: ttk.Combobox(p, textvariable=font_family_var, values=families, state="readonly"))
            form_row(tab_font, "Monospace-lettertype", lambda p: ttk.Combobox(p, textvariable=mono_family_var, values=families, state="readonly"))
            form_row(tab_font, "Interfacegrootte", lambda p: ttk.Spinbox(p, from_=8, to=24, textvariable=font_size_var))
            form_row(tab_font, "Monospace-grootte", lambda p: ttk.Spinbox(p, from_=8, to=24, textvariable=mono_size_var))
            form_row(tab_font, "Tk-schaalfactor", lambda p: ttk.Combobox(p, textvariable=scaling_var, values=["1.00","1.15","1.25","1.35","1.50","1.75","2.00"], state="readonly"))
            form_row(tab_font, "Rijhoogte tabellen", lambda p: ttk.Spinbox(p, from_=22, to=64, textvariable=row_height_var))
            ttk.Checkbutton(
                tab_font,
                text=_tr('ui.source.gebruik.kleuren.van.het.actieve.thema.1493c977'),
                variable=use_theme_colors_var,
            ).pack(anchor="w", pady=(10, 0))
            ttk.Label(
                tab_font,
                text=(
                    _tr('ui.source.ingeschakeld.theme.manager.bepaalt.de.basiskle.e666c3d0')
                ),
                style="Muted.TLabel",
                wraplength=700,
            ).pack(anchor="w", pady=(4, 0))
            ttk.Label(tab_font, text=_tr('ui.source.wijzigingen.kunnen.direct.worden.bekeken.via.l.dd21cfd5'), style="Muted.TLabel", wraplength=700).pack(anchor="w", pady=(16,0))

            color_keys = [
                ("bg", "Vensterachtergrond"), ("panel", "Paneelachtergrond"),
                ("panel2", "Kaarten / toolbar"), ("tree_bg", "Tabelachtergrond"),
                ("tree_alt", "Afwisselende tabelrij"), ("entry", "Invoervelden"),
                ("text", "Tekstkleur"), ("muted", "Gedempte tekst"),
                ("accent", "Accent / selectie"), ("button", "Knoppen"),
                ("button_active", "Knop hover"), ("border", "Randen"),
            ]
            color_vars = {}
            colors_grid = ttk.Frame(tab_colors)
            colors_grid.pack(fill=X)

            def choose_color(var):
                chosen = colorchooser.askcolor(color=var.get() or None, parent=win)[1]
                if chosen:
                    var.set(chosen)
                    refresh_preview()

            current = self._current_theme()
            for idx, (key, label) in enumerate(color_keys):
                row = ttk.Frame(colors_grid)
                row.grid(row=idx//2, column=idx%2, sticky="ew", padx=6, pady=5)
                colors_grid.columnconfigure(idx%2, weight=1)
                ttk.Label(row, text=label, width=22).pack(side=LEFT)
                var = StringVar(value=self.ui_color_overrides.get(key, current.get(key, "")))
                color_vars[key] = var
                ttk.Entry(row, textvariable=var, width=10).pack(side=LEFT, padx=(0,5))
                ttk.Button(row, text=_tr('ui.source.kies.72ecad5d'), command=lambda v=var: choose_color(v)).pack(side=LEFT)

            severity_frame = ttk.LabelFrame(tab_colors, text=_tr('ui.source.secure.coding.ernstkleuren.8994bcb6'), padding=10)
            severity_frame.pack(fill=X, pady=(16,0))
            severity_vars = {
                "high": StringVar(value=self.ui_high_color), "medium": StringVar(value=self.ui_medium_color),
                "low": StringVar(value=self.ui_low_color), "info": StringVar(value=self.ui_info_color),
            }
            for key, label in (("high","Hoog"),("medium","Middel"),("low","Laag"),("info","Informatie")):
                row=ttk.Frame(severity_frame); row.pack(side=LEFT,padx=(0,12))
                ttk.Label(row,text=label).pack(anchor="w")
                ttk.Entry(row,textvariable=severity_vars[key],width=10).pack(side=LEFT)
                ttk.Button(row,text=_tr('ui.source.text.df316e17'),width=3,command=lambda v=severity_vars[key]:choose_color(v)).pack(side=LEFT,padx=3)

            all_columns = list(self.project_tree["columns"]) if hasattr(self, "project_tree") else []
            visible_now = set(self.ui_visible_project_columns or all_columns)
            column_vars = {}
            ttk.Label(tab_columns, text=_tr('ui.source.selecteer.welke.kolommen.in.de.projectlijst.zi.a8f88b50'), wraplength=700).pack(anchor="w", pady=(0,10))
            canvas = Canvas(tab_columns, highlightthickness=0)
            scroll = ttk.Scrollbar(tab_columns, orient="vertical", command=canvas.yview)
            inner = ttk.Frame(canvas)
            canvas.create_window((0,0), window=inner, anchor="nw")
            canvas.configure(yscrollcommand=scroll.set)
            canvas.pack(side=LEFT, fill=BOTH, expand=True); scroll.pack(side=RIGHT, fill=Y)
            inner.bind("<Configure>", lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
            for i, col in enumerate(all_columns):
                var=BooleanVar(value=col in visible_now); column_vars[col]=var
                ttk.Checkbutton(inner,text=col,variable=var).grid(row=i//3,column=i%3,sticky="w",padx=8,pady=4)

            preview_card = ttk.Frame(tab_preview, style="Card.TFrame", padding=16)
            preview_card.pack(fill=BOTH, expand=True)
            preview_title = ttk.Label(preview_card, text=_tr('ui.source.project.manager.live.preview.cd3d5dbc'), style="Title.TLabel")
            preview_title.pack(anchor="w")
            preview_text = Text(preview_card, height=8, wrap="word")
            preview_text.pack(fill=BOTH, expand=True, pady=12)
            preview_text.insert("1.0", _tr('ui.source.hoog.risico.hardcoded.credentials.middel.risic.7a0c1d46'))
            preview_tree = ttk.Treeview(preview_card, columns=("status","project","score"), show="headings", height=4)
            for c,t,w in (("status","Status",120),("project","Project",280),("score","Score",100)):
                preview_tree.heading(c,text=t); preview_tree.column(c,width=w)
            preview_tree.pack(fill=X)
            preview_tree.insert("",END,values=("Actief","Voorbeeldproject",88),tags=("p1",))
            preview_tree.insert("",END,values=("Controle","Security Lab",72),tags=("p2",))

            def collect_values(apply_columns=True):
                self.ui_font_family = font_family_var.get() or "Segoe UI"
                self.ui_mono_font_family = mono_family_var.get() or "Consolas"
                self.ui_font_size = int(font_size_var.get())
                self.ui_mono_font_size = int(mono_size_var.get())
                self.ui_scaling = float(scaling_var.get())
                self.ui_tree_row_height = int(row_height_var.get())
                self.ui_use_theme_colors = bool(use_theme_colors_var.get())
                self.ui_color_overrides = {k:v.get().strip() for k,v in color_vars.items() if v.get().strip()}
                self.ui_high_color = severity_vars["high"].get().strip() or "#dc2626"
                self.ui_medium_color = severity_vars["medium"].get().strip() or "#f59e0b"
                self.ui_low_color = severity_vars["low"].get().strip() or "#16a34a"
                self.ui_info_color = severity_vars["info"].get().strip() or "#2563eb"
                if apply_columns:
                    chosen=[c for c,v in column_vars.items() if v.get()]
                    self.ui_visible_project_columns = chosen or all_columns

            def refresh_preview():
                collect_values(apply_columns=False)
                self._font_cache = {}
                self._configure_default_fonts()
                self._apply_theme()
                c=self._current_theme()
                preview_text.configure(background=c["entry"],foreground=c["text"],insertbackground=c["text"],font=self._mono_font())
                preview_tree.tag_configure("p1",background=c["tree_bg"])
                preview_tree.tag_configure("p2",background=c["tree_alt"])
                win.update_idletasks()

            def save():
                collect_values(True)
                self._font_cache = {}
                self._configure_default_fonts()
                self._apply_theme()
                self._save_app_settings()
                self.status_var.set(_tr('ui.source.personal.ui.studio.instellingen.opgeslagen.53b92e57'))
                win.destroy()

            def reset():
                self.ui_font_family="Segoe UI"; self.ui_mono_font_family="Consolas"
                self.ui_font_size=UI_FONT_DEFAULT_SIZE; self.ui_mono_font_size=UI_MONO_FONT_DEFAULT_SIZE
                self.ui_scaling=1.35; self.ui_tree_row_height=UI_TREE_ROW_HEIGHT
                self.ui_color_overrides={}; self.ui_use_theme_colors=True; self.ui_visible_project_columns=all_columns
                self.ui_high_color="#dc2626"; self.ui_medium_color="#f59e0b"; self.ui_low_color="#16a34a"; self.ui_info_color="#2563eb"
                self._font_cache={}; self._configure_default_fonts(); self._apply_theme(); self._save_app_settings()
                win.destroy(); self._open_ui_studio()

            def cancel_ui_studio():
                self.ui_font_family = original_ui_state["font_family"]
                self.ui_mono_font_family = original_ui_state["mono_family"]
                self.ui_font_size = original_ui_state["font_size"]
                self.ui_mono_font_size = original_ui_state["mono_size"]
                self.ui_scaling = original_ui_state["scaling"]
                self.ui_tree_row_height = original_ui_state["row_height"]
                self.ui_color_overrides = dict(original_ui_state["overrides"])
                self.ui_visible_project_columns = list(original_ui_state["visible_columns"])
                self.ui_high_color = original_ui_state["high"]
                self.ui_medium_color = original_ui_state["medium"]
                self.ui_low_color = original_ui_state["low"]
                self.ui_info_color = original_ui_state["info"]
                self.ui_use_theme_colors = original_ui_state["use_theme"]
                self._font_cache = {}; self._configure_default_fonts(); self._apply_theme()
                win.destroy()

            buttons=ttk.Frame(win,padding=(12,0,12,12)); buttons.pack(fill=X)
            ttk.Button(buttons,text=_tr('ui.source.live.preview.toepassen.ce042327'),command=refresh_preview).pack(side=LEFT)
            ttk.Button(buttons,text=_tr('ui.source.standaard.herstellen.017b9d55'),command=reset).pack(side=LEFT,padx=6)
            ttk.Button(buttons,text=_tr('ui.source.opslaan.2b030208'),style="Accent.TButton",command=save).pack(side=RIGHT)
            ttk.Button(buttons,text=_tr('ui.source.annuleren.c2fbda4e'),command=cancel_ui_studio).pack(side=RIGHT,padx=6)
            win.protocol("WM_DELETE_WINDOW", cancel_ui_studio)

            for var in [font_family_var,mono_family_var,font_size_var,mono_size_var,scaling_var,row_height_var,use_theme_colors_var]:
                try: var.trace_add("write",lambda *_: refresh_preview())
                except Exception: pass
            refresh_preview()
        def _open_settings_window(self) -> None:
            """Eenvoudig instellingenvenster voor v1.0."""
            win = self._new_tool_window()
            win.title(_tr('ui.source.instellingen.project.manager.v.p0.e483aff1',p0=APP_VERSION))
            win.geometry("620x560")
            win.transient(self.root)

            frame = ttk.Frame(win, padding=14)
            frame.pack(fill=BOTH, expand=True)

            ttk.Label(frame, text=_tr('ui.source.instellingen.fd08ea9c'), style="Section.TLabel").pack(anchor="w", pady=(0, 10))

            def row(label: str):
                r = ttk.Frame(frame)
                r.pack(fill=X, pady=(0, 8))
                ttk.Label(r, text=label, width=22).pack(side=LEFT)
                return r

            r = row(self._tr("settings.root", "Hoofdmap"))
            root_var = StringVar(value=self.root_path_var.get())
            ttk.Entry(r, textvariable=root_var).pack(side=LEFT, fill=X, expand=True)

            r = row(self._tr("settings.scan_profile", "Scanprofiel"))
            profile_var = StringVar(value=self.scan_profile_var.get())
            ttk.Combobox(r, textvariable=profile_var, values=list(SCAN_PROFILES.keys()), state="readonly").pack(side=LEFT, fill=X, expand=True)

            r = row(self._tr("settings.scan_depth", "Scandiepte"))
            depth_var = IntVar(value=int(self.scan_depth_var.get()))
            ttk.Spinbox(r, from_=2, to=40, textvariable=depth_var, width=6).pack(side=LEFT)

            r = row(self._tr("settings.language", "Taal / Language"))
            language_ui_var = StringVar(value="Nederlands" if self.language_var.get() == "nl" else "English")
            ttk.Combobox(r, textvariable=language_ui_var, values=["Nederlands", "English"], state="readonly").pack(side=LEFT, fill=X, expand=True)

            r = row(self._tr("settings.theme", "Thema"))
            theme_var = StringVar(value=self._theme_label(self.theme_var.get()))
            ttk.Combobox(
                r,
                textvariable=theme_var,
                values=[self._theme_label(t) for t in self._theme_choices()],
                state="readonly",
            ).pack(side=LEFT, fill=X, expand=True)

            r = row(self._tr("settings.font_size", "Lettergrootte"))
            font_var = IntVar(value=int(self.ui_font_size))
            ttk.Spinbox(r, from_=9, to=18, textvariable=font_var, width=6).pack(side=LEFT)

            fav_var = BooleanVar(value=self.favorites_first_var.get())
            only_fav_var = BooleanVar(value=self.only_favorites_var.get())
            details_var = BooleanVar(value=bool(self.details_wide))
            backup_var = BooleanVar(value=self.backup_before_cleanup_var.get())
            ttk.Checkbutton(frame, text=_tr('ui.source.favorieten.bovenaan.f1cafc7e'), variable=fav_var).pack(anchor="w")
            ttk.Checkbutton(frame, text=_tr('ui.source.alleen.favorieten.tonen.b9ca2acb'), variable=only_fav_var).pack(anchor="w")
            ttk.Checkbutton(frame, text=_tr('ui.source.detailpaneel.breed.339591b8'), variable=details_var).pack(anchor="w")
            ttk.Checkbutton(frame, text=_tr('ui.source.backup.v.r.opschonen.standaard.aan.01bd91c9'), variable=backup_var).pack(anchor="w")

            workspace_var = StringVar(value=self.workspace_var.get())
            left_visible_var = BooleanVar(value=self.left_panel_visible)
            right_visible_var = BooleanVar(value=self.right_panel_visible)
            compact_var = BooleanVar(value=self.compact_mode)
            r = row(self._tr("settings.workspace", "Workspace"))
            ttk.Combobox(r, textvariable=workspace_var, values=["Standaard", "Ontwikkeling", "Projectanalyse", "Portfolio", "Presentatie"], state="readonly").pack(side=LEFT, fill=X, expand=True)
            ttk.Checkbutton(frame, text=_tr('ui.source.linkerpaneel.zichtbaar.45dd5c85'), variable=left_visible_var).pack(anchor="w")
            ttk.Checkbutton(frame, text=_tr('ui.source.rechterpaneel.zichtbaar.ff127f97'), variable=right_visible_var).pack(anchor="w")
            ttk.Checkbutton(frame, text=_tr('ui.source.compacte.werkruimte.6f04f152'), variable=compact_var).pack(anchor="w", pady=(0, 10))

            ttk.Label(frame, text=_tr('ui.source.scanlocaties.n.per.regel.50155d36')).pack(anchor="w")
            loc_text = Text(frame, height=8, wrap="none", font=self._mono_font(self.ui_mono_font_size))
            loc_text.pack(fill=BOTH, expand=True, pady=(4, 10))
            loc_text.insert("1.0", "\n".join(list(dict.fromkeys([self.root_path_var.get(), *self.scan_locations]))))

            btns = ttk.Frame(frame)
            btns.pack(fill=X)

            def save() -> None:
                self.root_path_var.set(root_var.get().strip())
                self.scan_profile_var.set(profile_var.get())
                self.scan_depth_var.set(int(depth_var.get()))
                self.theme_var.set(self._theme_from_label(theme_var.get()))
                new_language = "en" if language_ui_var.get() == "English" else "nl"
                self.language_var.set(new_language)
                self.ui_font_size = int(font_var.get())
                self.ui_mono_font_size = max(9, int(font_var.get()) - 1)
                self.favorites_first_var.set(bool(fav_var.get()))
                self.only_favorites_var.set(bool(only_fav_var.get()))
                self.details_wide = bool(details_var.get())
                self.backup_before_cleanup_var.set(bool(backup_var.get()))
                self.workspace_var.set(workspace_var.get())
                self.left_panel_visible = bool(left_visible_var.get())
                self.right_panel_visible = bool(right_visible_var.get())
                self.compact_mode = bool(compact_var.get())
                self.scan_locations = [line.strip() for line in loc_text.get("1.0", END).splitlines() if line.strip()]
                self._configure_default_fonts()
                self._apply_theme()
                if hasattr(self, "right_panel"):
                    self.right_panel.configure(width=700 if self.details_wide else 540)
                self._refresh_location_combo()
                self._apply_workspace(self.workspace_var.get(), save=False)
                self._apply_filter(update_status=False)
                self._save_app_settings()
                if hasattr(self, "_apply_language_runtime"):
                    self._apply_language_runtime(new_language, refresh=True)
                self.status_var.set(self._tr("settings.saved", _tr("settings.saved")))
                win.destroy()

            ttk.Button(btns, text=self._tr("settings.save", "Opslaan"), style="Accent.TButton", command=save).pack(side=RIGHT, padx=(6, 0))
            ttk.Button(btns, text=self._tr("settings.cancel", "Annuleren"), command=win.destroy).pack(side=RIGHT)
        def _reset_app_settings(self) -> None:
            if not messagebox.askyesno(_tr('ui.source.instellingen.resetten.2ef470f0'), _tr('ui.source.instellingenbestand.verwijderen.de.projectinde.db4e9da4')):
                return
            try:
                p = get_settings_path()
                if p.exists():
                    p.unlink()
                self.status_var.set(_tr('ui.source.instellingen.verwijderd.herstart.de.app.voor.e.eb650cd1'))
            except Exception as exc:
                messagebox.showerror(_tr('ui.source.reset.mislukt.3171579b'), str(exc))
        def _set_theme(self, theme: str) -> None:
            theme = self._theme_from_label(theme)
            if theme not in self.themes:
                theme = "soft_dark"
            self.theme_var.set(theme)
            # Een bewuste themakeuze herstelt de volledige themakleuren. Fonts,
            # schaal, rijhoogte en kolommen uit UI Studio blijven behouden.
            self.ui_use_theme_colors = True
            if hasattr(self, "quick_theme_var"):
                self.quick_theme_var.set(self._theme_label(theme))
            self._apply_theme()
            self._refresh_toolbar_icons()
            self._refresh_all_tool_themes()
            self._save_app_settings()
