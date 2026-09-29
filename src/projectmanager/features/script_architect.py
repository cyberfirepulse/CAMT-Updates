from __future__ import annotations
from projectmanager.i18n import tr as _tr
from projectmanager.core.shared import *
from projectmanager.core.shared import (
    _dt
)
from projectmanager.presentation.dialogs import *

class ScriptArchitectMixin:
        def _restore_last_selection(self) -> None:
            """Selecteer het laatst gebruikte project opnieuw als het nog zichtbaar is."""
            target = getattr(self, "last_selected_project_path", "")
            if not target or not hasattr(self, "project_tree"):
                return
            for p in self.filtered_projects:
                if str(p.path) == target:
                    iid = str(id(p))
                    try:
                        if self.project_tree.exists(iid):
                            self.project_tree.selection_set(iid)
                            self.project_tree.focus(iid)
                            self.project_tree.see(iid)
                            self.selected_project = p
                            self._show_project_details(p)
                    except Exception:
                        pass
                    return
        def _restore_solution_layout(self) -> None:
            if not hasattr(self, "center_vertical_paned"):
                return
            try:
                panes = list(self.center_vertical_paned.panes())
                explorer_id = str(self.solution_explorer_pane)
                project_id = str(self.project_list_pane)
                if self.solution_explorer_visible:
                    if explorer_id not in panes:
                        self.center_vertical_paned.insert(0, self.solution_explorer_pane, weight=1)
                    panes = list(self.center_vertical_paned.panes())
                    if project_id not in panes:
                        self.center_vertical_paned.add(self.project_list_pane, weight=4)
                    self.root.after(50, lambda: self._set_solution_sash_safely(self.solution_explorer_sash))
                    if hasattr(self, "solution_toggle_button"):
                        self.solution_toggle_button.configure(text=_tr('ui.source.explorer.inklappen.b2f62cb7'))
                    if hasattr(self, "solution_restore_button"):
                        self.solution_restore_button.configure(text=_tr('ui.source.explorer.inklappen.b2f62cb7'))
                else:
                    if explorer_id in panes:
                        self.solution_explorer_sash = self._capture_solution_sash()
                        self.center_vertical_paned.forget(self.solution_explorer_pane)
                    if hasattr(self, "solution_toggle_button"):
                        self.solution_toggle_button.configure(text=_tr('ui.source.explorer.tonen.ef815897'))
                    if hasattr(self, "solution_restore_button"):
                        self.solution_restore_button.configure(text=_tr('ui.source.explorer.tonen.ef815897'))
            except Exception:
                pass
        def _restore_flexible_layout(self) -> None:
            if not hasattr(self, "main_paned"):
                return
            self._set_panel_visibility(self.left_panel_visible, self.right_panel_visible)
            if hasattr(self, "sidebar_toggle_button"):
                self.sidebar_toggle_button.configure(text="◀ Dashboard" if self.left_panel_visible else "▶ Dashboard")
            positions = self.saved_sash_positions or [245, max(650, self.root.winfo_width() - 570)]
            for index, pos in enumerate(positions[:2]):
                try:
                    self.main_paned.sashpos(index, int(pos))
                except Exception:
                    pass
        def _repair_profile_for_project(self, project: ProjectInfo) -> str:
            """Kies een passend standards-profiel op basis van de bestaande analyse."""
            tags = {str(t).lower() for t in (project.tags or [])}
            ptype = (project.project_type or "").lower()
            if "tkinter" in tags or any(project.path.glob("*.py")) and any("tkinter" in safe_read_text(f).lower() for f in list(project.path.glob("*.py"))[:8]):
                return "Python Tkinter"
            if "expo" in ptype or "expo" in tags or (project.path / "app.json").exists():
                return "Expo / React Native"
            if "react native" in ptype or "react native" in tags:
                return "Expo / React Native"
            if "android" in ptype or "android" in tags:
                return "Android"
            if "platformio" in ptype or project.platformio_present or (project.path / "platformio.ini").exists():
                return "PlatformIO"
            if "arduino" in ptype or (project.ino_file or list(project.path.glob("*.ino"))):
                return "Arduino"
            if "raspberry" in ptype or "raspberry pi" in tags:
                return "Raspberry Pi"
            if "powershell" in ptype or list(project.path.glob("*.ps1")):
                return "PowerShell"
            if "rust" in ptype or (project.path / "Cargo.toml").exists():
                return "Rust"
            if ".net" in ptype or list(project.path.glob("*.csproj")) or list(project.path.glob("*.sln")):
                return ".NET"
            if "node" in ptype or ((project.path / "package.json").exists() and "react native" not in tags):
                return "Node.js"
            if "python" in ptype or list(project.path.glob("*.py")):
                return "Python Desktop"
            return "Generic"
        def _repair_file_content(self, project: ProjectInfo, relative_name: str, profile: str) -> str:
            """Genereer veilige basisinhoud; bestaande bestanden worden nooit overschreven."""
            name = project.name
            desc = (project.user_note or f"{name} softwareproject.").strip()
            today = _dt.datetime.now().strftime("%Y-%m-%d")
            if relative_name == "README.md":
                return f"# {name}\n\n{desc}\n\n## Status\n\n{normalize_workflow_status(project.user_status)}\n\n## Projecttype\n\n{profile}\n\n## Installatie\n\nNog documenteren.\n\n## Gebruik\n\nNog documenteren.\n\n## Bouwen en testen\n\nNog documenteren.\n\n## Projectstructuur\n\nZie de mappen in dit project.\n"
            if relative_name == "CHANGELOG.md":
                return f"# Changelog\n\n## Onuitgebracht\n\n- Projectstructuur gecontroleerd met Project Manager v{APP_VERSION}.\n\n## {today}\n\n- Projectdocumentatie aangemaakt.\n"
            if relative_name == "TODO.md":
                return "# TODO\n\n- [ ] Projectdoel controleren\n- [ ] Installatie beschrijven\n- [ ] Build uitvoeren\n- [ ] Tests vastleggen\n- [ ] Releasecriteria bepalen\n"
            if relative_name == "ROADMAP.md":
                return "# Roadmap\n\n## Huidige versie\n\n- Bestaande functionaliteit inventariseren\n- Projectstructuur professionaliseren\n- Build en tests controleren\n\n## Volgende release\n\n- Nieuwe functionaliteit vastleggen\n- Acceptatiecriteria bepalen\n- Releasechecklist afronden\n\n## Latere ontwikkeling\n\n- Groei en grotere wijzigingen per hoofdversie plannen\n"
            if relative_name == "REQUIREMENTS.md":
                return f"# Requirements\n\n## Functionele eisen\n\n- Beschrijf wat {name} moet uitvoeren.\n\n## Technische eisen\n\n- Platform: {profile}\n- Afhankelijkheden: nog inventariseren\n\n## Acceptatiecriteria\n\n- Build slaagt\n- Kernfunctionaliteit is getest\n- Documentatie is bijgewerkt\n"
            if relative_name == "SECURITY.md":
                return "# Security\n\n## Beveiligingsmeldingen\n\nLeg beveiligingsproblemen niet vast in openbare issues wanneer het project openbaar wordt gepubliceerd.\n\n## Onderhoud\n\n- Houd afhankelijkheden actueel.\n- Bewaar geen wachtwoorden, tokens of sleutels in broncode.\n- Controleer releasebestanden vóór distributie.\n"
            if relative_name == ".gitignore":
                return new_project_gitignore(profile)
            if relative_name == "pyproject.toml":
                module = python_identifier_from_name(name)
                return f'[project]\nname = "{module.replace("_", "-")}"\nversion = "0.1.0"\ndescription = "{desc.replace(chr(34), chr(39))}"\nrequires-python = ">=3.11"\ndependencies = []\n'
            if relative_name == "requirements.txt":
                return "# Voeg Python-afhankelijkheden hier toe.\n"
            if relative_name == "package.json":
                return json.dumps({"name": python_identifier_from_name(name).replace("_", "-"), "version": "0.1.0", "private": True, "scripts": {"start": "node src/index.js", "test": "echo No tests configured"}, "dependencies": {}, "devDependencies": {}}, indent=2) + "\n"
            if relative_name == "app.json":
                return json.dumps({"expo": {"name": name, "slug": python_identifier_from_name(name).replace("_", "-"), "version": "0.1.0", "android": {"package": project.package_name or package_name_from_project(name)}}}, indent=2) + "\n"
            if relative_name == "Cargo.toml":
                return f'[package]\nname = "{python_identifier_from_name(name).replace("_", "-")}"\nversion = "0.1.0"\nedition = "2021"\n\n[dependencies]\n'
            if relative_name == "platformio.ini":
                return "[env:esp32dev]\nplatform = espressif32\nboard = esp32dev\nframework = arduino\nmonitor_speed = 115200\n"
            return f"# {relative_name}\n\nAangemaakt door Project Manager v{APP_VERSION}.\n"
        def _execute_project_repair(self, project: ProjectInfo, profile: str, actions: list[dict], make_backup: bool) -> tuple[list[str], Path | None]:
            """Voer uitsluitend geselecteerde, veilige herstelacties uit."""
            backup_path = self._repair_backup_project(project) if make_backup else None
            results: list[str] = []
            for action in actions:
                if not action.get("selected"):
                    continue
                target = Path(action["target"])
                rel = str(action["relative"])
                try:
                    if action["kind"] == "folder":
                        if target.exists():
                            results.append(f"OVERGESLAGEN map aanwezig: {rel}")
                        else:
                            target.mkdir(parents=True, exist_ok=True)
                            results.append(f"AANGEMAAKT map: {rel}")
                    elif action["kind"] == "file":
                        if target.exists():
                            results.append(f"OVERGESLAGEN bestand aanwezig: {rel}")
                        else:
                            target.parent.mkdir(parents=True, exist_ok=True)
                            target.write_text(self._repair_file_content(project, rel, profile), encoding="utf-8")
                            results.append(f"AANGEMAAKT bestand: {rel}")
                    elif action["kind"] == "metadata":
                        data = load_project_meta(project.path)
                        data.setdefault("project_id", self._ensure_project_id(project))
                        data.setdefault("status", normalize_workflow_status(project.user_status))
                        data.setdefault("project_standard", profile)
                        data["last_repair"] = _dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                        save_project_meta(project.path, data)
                        results.append(f"BIJGEWERKT metadata: {rel}")
                except Exception as exc:
                    results.append(f"MISLUKT {rel}: {exc}")
            return results, backup_path
        def _show_project_repair_wizard(self) -> None:
            """Open de v6.1 Project Herstelwizard voor het geselecteerde project."""
            project = self.selected_project
            if not project or not project.path.exists():
                messagebox.showinfo(_tr('ui.source.project.herstelwizard.91dcef85'), _tr('ui.source.selecteer.eerst.een.bestaand.project.f9407f83'))
                return

            win = self._new_tool_window()
            win.title(_tr('ui.source.project.herstelwizard.v6.1.p0.9392b194',p0=project.name))
            win.geometry("980x760")
            win.minsize(860, 650)
            win.transient(self.root)
            win.grab_set()

            outer = ttk.Frame(win, padding=14)
            outer.pack(fill=BOTH, expand=True)
            ttk.Label(outer, text=_tr('ui.source.project.herstelwizard.91dcef85'), style="Title.TLabel").pack(anchor="w")
            ttk.Label(outer, text=_tr('ui.source.p0.p1.6bd76975',p0=project.name,p1=project.path), style="Muted.TLabel", wraplength=900).pack(anchor="w", pady=(0, 10))

            controls = ttk.Frame(outer)
            controls.pack(fill=X, pady=(0, 8))
            ttk.Label(controls, text=_tr('ui.source.standards.profiel.83f1d08c')).pack(side=LEFT)
            profile_var = StringVar(value=self._repair_profile_for_project(project))
            profile_combo = ttk.Combobox(controls, textvariable=profile_var, values=list(PROJECT_STANDARD_PROFILES.keys()), state="readonly", width=25)
            profile_combo.pack(side=LEFT, padx=(8, 14))
            backup_var = BooleanVar(value=True)
            ttk.Checkbutton(controls, text=_tr('ui.source.automatische.zip.back.up.v.r.uitvoeren.7d251aa4'), variable=backup_var).pack(side=LEFT)

            summary_var = StringVar(value=_tr('ui.source.analyse.wordt.voorbereid.26f689bd'))
            ttk.Label(outer, textvariable=summary_var, style="Muted.TLabel").pack(anchor="w", pady=(0, 6))

            cols = ("use", "kind", "item", "status")
            tree = ttk.Treeview(outer, columns=cols, show="headings", selectmode="extended")
            for col, title, width in [("use", "Uitvoeren", 90), ("kind", "Type", 100), ("item", "Onderdeel", 480), ("status", "Status", 140)]:
                tree.heading(col, text=title)
                tree.column(col, width=width, anchor="w")
            tree.pack(fill=BOTH, expand=True)
            actions: list[dict] = []

            def refresh() -> None:
                nonlocal actions
                for item in tree.get_children():
                    tree.delete(item)
                effective = profile_var.get()
                actions = self._analyze_project_repair(project, effective)
                missing = sum(1 for a in actions if a["status"] == "Ontbreekt")
                present = len(actions) - missing
                summary_var.set(_tr('ui.source.profiel.p0.controles.p1.aanwezig.p2.ontbreekt..6f1dc942',p0=effective,p1=len(actions),p2=present,p3=missing))
                for idx, action in enumerate(actions):
                    tree.insert("", END, iid=str(idx), values=("Ja" if action["selected"] else "Nee", action["kind"].capitalize(), action["relative"], action["status"]))

            def toggle(_event=None) -> None:
                for iid in tree.selection():
                    idx = int(iid)
                    actions[idx]["selected"] = not actions[idx]["selected"]
                    a = actions[idx]
                    tree.item(iid, values=("Ja" if a["selected"] else "Nee", a["kind"].capitalize(), a["relative"], a["status"]))

            tree.bind("<Double-1>", toggle)
            profile_combo.bind("<<ComboboxSelected>>", lambda _e: refresh())

            buttons = ttk.Frame(outer)
            buttons.pack(fill=X, pady=(10, 0))

            def preview() -> None:
                selected = [a for a in actions if a.get("selected")]
                lines = [_tr('ui.source.p0.v.p1.project.herstelwizard.dry.run.b03e261c',p0=APP_NAME,p1=APP_VERSION), _tr('ui.source.project.p0.e06d67de',p0=project.name), f"Pad: {project.path}", f"Profiel: {profile_var.get()}", "", "GEPLANDE ACTIES"]
                if not selected:
                    lines.append(_tr('ui.source.geen.acties.geselecteerd.abed6be7'))
                for a in selected:
                    lines.append(f"- {a['kind'].upper()}: {a['relative']} ({a['status']})")
                log = write_action_log("project_repair_dry_run", lines)
                self._show_text_window(_tr('ui.source.project.herstelwizard.dry.run.920623fb'), "\n".join(lines) + f"\n\nLog: {log}")

            def execute() -> None:
                selected = [a for a in actions if a.get("selected")]
                if not selected:
                    messagebox.showinfo(_tr('ui.source.project.herstelwizard.91dcef85'), _tr('ui.source.geen.herstelacties.geselecteerd.bf914150'))
                    return
                if not messagebox.askyesno(_tr('ui.source.project.herstelwizard.91dcef85'), _tr('ui.source.p0.geselecteerde.herstelacties.uitvoeren.besta.f6344a4f',p0=len(selected),p1='ja' if backup_var.get() else 'nee')):
                    return
                try:
                    before_missing = sum(1 for a in actions if a["status"] == "Ontbreekt")
                    results, backup_path = self._execute_project_repair(project, profile_var.get(), actions, bool(backup_var.get()))
                    refreshed = self._analyze_project_repair(project, profile_var.get())
                    after_missing = sum(1 for a in refreshed if a["status"] == "Ontbreekt")
                    lines = [f"{APP_NAME} v{APP_VERSION} - Herstelrapport", _tr('ui.source.project.p0.e06d67de',p0=project.name), _tr('ui.source.project.id.p0.33a1ac8f',p0=self._ensure_project_id(project)), f"Profiel: {profile_var.get()}", f"Datum: {_dt.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", f"Ontbrekend vóór: {before_missing}", f"Ontbrekend na: {after_missing}", f"Back-up: {backup_path or 'Niet gemaakt'}", "", *results]
                    stamp = _dt.datetime.now().strftime("%Y-%m-%d_%H%M%S")
                    report = get_report_dir() / f"project_herstel_{python_identifier_from_name(project.name)}_{stamp}.txt"
                    report.write_text("\n".join(lines), encoding="utf-8")
                    write_action_log("project_repair", lines)
                    self.status_var.set(_tr('ui.source.project.herstelwizard.gereed.p0.631e84ad',p0=project.name))
                    self._reanalyze_selected_project()
                    self._show_text_window(_tr('ui.source.project.herstelwizard.rapport.ea4f4fb0'), "\n".join(lines) + f"\n\nRapport: {report}")
                    win.destroy()
                except Exception as exc:
                    messagebox.showerror(_tr('ui.source.project.herstelwizard.mislukt.d4ec4296'), str(exc))

            ttk.Button(buttons, text=_tr('ui.source.sluiten.fe55d210'), command=win.destroy).pack(side=RIGHT)
            ttk.Button(buttons, text=_tr('ui.source.uitvoeren.e7b915e5'), style="Accent.TButton", command=execute).pack(side=RIGHT, padx=(0, 6))
            ttk.Button(buttons, text=_tr('ui.source.dry.run.preview.efda73d2'), command=preview).pack(side=RIGHT, padx=(0, 6))
            ttk.Button(buttons, text=_tr('ui.source.selectie.omkeren.20767baf'), command=toggle).pack(side=LEFT)
            refresh()
        def _show_project_architect_wizard(self) -> None:
            """Open de Project Architect voor het geselecteerde project."""
            projects = self._get_selected_projects()
            project = projects[0] if projects else (self.selected_project if self.selected_project else None)
            if not project:
                messagebox.showinfo(
                    _tr('ui.source.project.architect.a8e46aad'),
                    _tr('ui.source.selecteer.eerst.een.bestaand.project.gebruik.v.4966701f'),
                )
                return
            dialog = ProjectArchitectWizardDialog(self.root, project)
            self.root.wait_window(dialog.window)
            if not dialog.result:
                return
            self._apply_project_architecture(project, dialog.result)
        def _architect_document_contents(self, project: ProjectInfo, data: dict) -> dict[str, str]:
            """Genereer alle v7.0 architectuurdocumenten uit één ontwerpmodel."""
            name = project.name
            vision = data.get("vision", "").strip() or f"{name} wordt ontwikkeld als een onderhoudbaar softwareproduct."
            purpose = data.get("purpose", "").strip() or "Nog nader vastleggen."
            audience = data.get("audience", "").strip() or "Nog nader vastleggen."
            platform_name = data.get("platform", "").strip() or project.project_type or "Generic"
            architecture = data.get("architecture", "").strip() or "Modulair, lokaal beheersbaar en uitbreidbaar."
            constraints = data.get("constraints", "").strip() or "Geen aanvullende beperkingen vastgelegd."
            test_strategy = data.get("test_strategy", "").strip() or "Handmatige functionele test en technische buildcontrole per release."
            risks = [x.strip() for x in data.get("risks", "").splitlines() if x.strip()]
            releases = data.get("releases", []) or []
            today = _dt.datetime.now().strftime("%Y-%m-%d")

            roadmap = [f"# Roadmap – {name}", "", f"> Gegenereerd met {APP_NAME} v{APP_VERSION} op {today}.", "", "## Productrichting", "", vision, ""]
            release_plan = [f"# Releaseplan – {name}", "", "## Releasebeleid", "", "Iedere release wordt pas afgerond nadat functionaliteit, build, documentatie en acceptatiecriteria zijn gecontroleerd.", ""]
            requirements = [f"# Requirements – {name}", "", "## Doel", "", purpose, "", "## Doelgroep", "", audience, "", "## Functionele hoofdeisen", ""]
            req_no = 1
            for rel in releases:
                version = rel.get("version", "").strip() or "Ongepland"
                title = rel.get("title", "").strip() or f"Release {version}"
                features = rel.get("features", []) or []
                criteria = rel.get("criteria", []) or []
                phase = rel.get("phase", "Gepland")
                roadmap += [f"## Versie {version} – {title}", "", f"**Fase:** {phase}", "", "### Functionaliteit", ""]
                if features:
                    roadmap += [f"- {x}" for x in features]
                else:
                    roadmap += ["- Nog invullen"]
                roadmap += ["", "### Gereed wanneer", ""]
                roadmap += [f"- [ ] {x}" for x in criteria] if criteria else ["- [ ] Releasecriteria nog invullen"]
                roadmap += [""]
                release_plan += [f"## Versie {version} – {title}", "", f"Status: **{phase}**", "", "### Scope", ""]
                release_plan += [f"- {x}" for x in features] if features else ["- Nog invullen"]
                release_plan += ["", "### Acceptatiecriteria", ""]
                release_plan += [f"- [ ] {x}" for x in criteria] if criteria else ["- [ ] Nog invullen"]
                release_plan += ["", "### Standaard releasecontrole", "", "- [ ] Build slaagt", "- [ ] Kernfunctionaliteit getest", "- [ ] Documentatie bijgewerkt", "- [ ] CHANGELOG bijgewerkt", "- [ ] Back-up of tag gemaakt", ""]
                for feature in features:
                    requirements += [f"- **FR-{req_no:03d}:** {feature}"]
                    req_no += 1
            if req_no == 1:
                requirements += ["- Functionele eisen nog invullen."]
            requirements += ["", "## Niet-functionele eisen", "", f"- Platform: {platform_name}", f"- Architectuur: {architecture}", f"- Beperkingen: {constraints}", "- Het project moet reproduceerbaar gebouwd kunnen worden.", "- Belangrijke fouten moeten begrijpelijk worden gemeld.", "- Projectdocumentatie moet bij iedere release worden bijgewerkt.", ""]

            arch_doc = f"""# Architectuur – {name}

    ## Productvisie

    {vision}

    ## Doel en doelgroep

    **Doel:** {purpose}

    **Doelgroep:** {audience}

    ## Platform

    {platform_name}

    ## Architectuurkeuze

    {architecture}

    ## Ontwerpprincipes

    - Scheid interface, domeinlogica, opslag en externe integraties waar mogelijk.
    - Behoud achterwaartse compatibiliteit binnen een minor release.
    - Grote brekende wijzigingen horen in een nieuwe hoofdversie.
    - Configuratie en metadata blijven overdraagbaar en controleerbaar.
    - Nieuwe functionaliteit krijgt expliciete acceptatiecriteria.

    ## Beperkingen

    {constraints}

    ## Groei

    De roadmap is leidend voor functionele groei. Nieuwe ideeën worden eerst aan een geplande release gekoppeld voordat implementatie begint.
    """
            test_doc = [f"# Testplan – {name}", "", "## Teststrategie", "", test_strategy, "", "## Controles per release", "", "- [ ] Applicatie start zonder fout", "- [ ] Bestaande kernfunctionaliteit blijft werken", "- [ ] Nieuwe functies voldoen aan acceptatiecriteria", "- [ ] Negatieve/foutscenario's zijn getest", "- [ ] Build- en distributiebestand zijn gecontroleerd", "- [ ] Documentatie en versienummers zijn bijgewerkt", "", "## Release-specifieke tests", ""]
            for rel in releases:
                version = rel.get("version", "Ongepland")
                test_doc += [f"### Versie {version}", ""]
                criteria = rel.get("criteria", []) or []
                test_doc += [f"- [ ] Test: {x}" for x in criteria] if criteria else ["- [ ] Tests nog vastleggen"]
                test_doc += [""]
            risk_doc = [f"# Risicoanalyse – {name}", "", "## Bekende risico's", ""]
            risk_doc += [f"- [ ] {r}" for r in risks] if risks else ["- [ ] Nog geen projectspecifieke risico's vastgelegd."]
            risk_doc += ["", "## Standaard beheersmaatregelen", "", "- Maak een back-up vóór grote structuurwijzigingen.", "- Houd secrets en sleutels buiten broncode en Git.", "- Controleer afhankelijkheden en buildtools vóór releases.", "- Voer brekende wijzigingen alleen in een hoofdversie door.", "- Leg afwijkingen van de roadmap expliciet vast.", ""]
            vision_doc = f"""# Productvisie – {name}

    ## Visie

    {vision}

    ## Probleem dat het product oplost

    {purpose}

    ## Doelgroep

    {audience}

    ## Waarde

    - Duidelijke, onderhoudbare kernfunctionaliteit.
    - Gecontroleerde groei per release.
    - Transparante requirements, risico's en releasecriteria.

    ## Afbakening

    {constraints}
    """
            return {
                "PRODUCT_VISION.md": vision_doc,
                "ROADMAP.md": "\n".join(roadmap).rstrip() + "\n",
                "RELEASE_PLAN.md": "\n".join(release_plan).rstrip() + "\n",
                "REQUIREMENTS.md": "\n".join(requirements).rstrip() + "\n",
                "ARCHITECTURE.md": arch_doc,
                "TEST_PLAN.md": "\n".join(test_doc).rstrip() + "\n",
                "RISKS.md": "\n".join(risk_doc).rstrip() + "\n",
            }
        def _apply_project_architecture(self, project: ProjectInfo, data: dict) -> None:
            """Schrijf gekozen architectuurdocumenten veilig naar het project."""
            docs = self._architect_document_contents(project, data)
            selected = set(data.get("documents", docs.keys()))
            overwrite = bool(data.get("overwrite", False))
            backup_path = None
            existing = [project.path / name for name in selected if (project.path / name).exists()]
            if existing:
                stamp = _dt.datetime.now().strftime("%Y-%m-%d_%H%M%S")
                backup_path = get_app_home_dir() / BACKUP_DIR_NAME / f"Architect_{sanitize_project_folder_name(project.name)}_{stamp}.zip"
                backup_path.parent.mkdir(parents=True, exist_ok=True)
                with zipfile.ZipFile(backup_path, "w", zipfile.ZIP_DEFLATED) as zf:
                    for file_path in existing:
                        zf.write(file_path, arcname=file_path.name)
                    meta_path = project.path / USER_META_FILE
                    if meta_path.exists():
                        zf.write(meta_path, arcname=USER_META_FILE)
            written, skipped = [], []
            for name, content in docs.items():
                if name not in selected:
                    continue
                target = project.path / name
                if target.exists() and not overwrite:
                    skipped.append(name)
                    continue
                target.write_text(content, encoding="utf-8")
                written.append(name)
            meta = load_project_meta(project.path)
            meta["project_architect"] = {
                "version": 1,
                "updated_at": _dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "vision": data.get("vision", ""),
                "purpose": data.get("purpose", ""),
                "audience": data.get("audience", ""),
                "platform": data.get("platform", ""),
                "architecture": data.get("architecture", ""),
                "constraints": data.get("constraints", ""),
                "test_strategy": data.get("test_strategy", ""),
                "risks": [x.strip() for x in data.get("risks", "").splitlines() if x.strip()],
                "releases": data.get("releases", []),
            }
            if data.get("releases"):
                meta["planned_version"] = data["releases"][0].get("version", "")
            save_project_meta(project.path, meta)
            report_lines = [_tr('ui.source.project.architect.p0.0f4f4d5f',p0=project.name), "", _tr('ui.source.project.p0.e06d67de',p0=project.path), f"Geschreven: {len(written)}", f"Overgeslagen: {len(skipped)}", "", _tr('ui.source.geschreven.bestanden.cba96046')]
            report_lines += [f"- {x}" for x in written] or ["- Geen"]
            report_lines += ["", "Overgeslagen bestaande bestanden:"] + ([f"- {x}" for x in skipped] or ["- Geen"])
            if backup_path:
                report_lines += ["", f"Back-up: {backup_path}"]
            report = write_action_log("project_architect", report_lines)
            self._reanalyze_selected_project()
            messagebox.showinfo(_tr('ui.source.project.architect.a8e46aad'), _tr('ui.source.architectuur.verwerkt.geschreven.p0.overgeslag.92ab2c82',p0=len(written),p1=len(skipped),p2=report))
