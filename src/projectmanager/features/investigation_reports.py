from __future__ import annotations
from projectmanager.i18n import tr as _tr
from projectmanager.core.shared import *
from projectmanager.core.shared import (
    _dt,
    _sdc_simple_pdf
)
from projectmanager.presentation.dialogs import *
from projectmanager.features.report_media import export_pdf, export_rtf, insert_inline_images

class InvestigationReportsMixin:
        def _v90_network_scan_context(self) -> dict:
            path=get_app_home_dir()/"reports"/"network_scan_context.json"
            try:
                data=json.loads(path.read_text(encoding="utf-8"))
                return data if isinstance(data,dict) else {}
            except Exception:
                return {}

        def _v90_network_scan_report_block(self) -> str:
            ctx=self._v90_network_scan_context()
            assets=ctx.get("assets") or []
            if not assets:return ""
            summary=ctx.get("summary") or {}
            lines=[
                "",
                "## Netwerkobservaties (CAMT Network Mapper)",
                "",
                f"**Scanbereik:** {ctx.get('range','-')}  ",
                f"**Interface:** {ctx.get('interface','-')}  ",
                f"**Assets:** {summary.get('assets',len(assets))}  ",
                f"**Online bevestigd:** {summary.get('online',0)}  ",
                f"**Cached/onbevestigd:** {summary.get('cached_or_unconfirmed',0)}  ",
                f"**CVE-kandidaten:** {summary.get('cve_candidates',0)}",
                "",
                "### Geobserveerde assets",
                "",
                "| Host | Type | Status | Services | Exposures | CVE-kandidaten |",
                "| --- | --- | --- | --- | --- | --- |",
            ]
            for asset in assets:
                host=asset.get("ip","-")
                if asset.get("hostname"):host+=f" ({asset['hostname']})"
                services=asset.get("services") or []
                svc=", ".join(f"{x.get('port','')}/{x.get('protocol','')} {x.get('service','')}" for x in services) or asset.get("ports_summary","-") or "-"
                exposures=asset.get("exposures") or []
                exptxt=", ".join(f"{x.get('port','')}/{x.get('protocol','')} {x.get('severity','')} {x.get('title','')}" for x in exposures) or "-"
                cves=asset.get("vulnerabilities") or []
                cvetxt=", ".join(f"{x.get('id','')} [{x.get('correlation_state','candidate')}]" for x in cves) or "-"
                lines.append(f"| {host} | {asset.get('type','-')} | {asset.get('status','unknown')} | {svc[:180]} | {exptxt[:220]} | {cvetxt[:220]} |")
                note=str(asset.get("note") or "").strip()
                if note:
                    lines.extend(["",f"**Observatie {asset.get('ip','-')}:** {note}"])
            lines.extend(["","### Automatisch afgeleide adviezen",""])
            for rec in ctx.get("recommendations") or []:
                lines.append(f"- {rec}")
            lines.extend([
                "",
                _tr('ui.source.bron.camt.network.mapper.cve.vermeldingen.zijn.972bc58d'),
                "",
            ])
            return "\n".join(lines)

        def _create_project_library_report(self) -> None:
            """Maak uitgebreid Project Library-rapport."""
            lines = [
                _tr('ui.source.p0.v.p1.project.library.rapport.262c9084',p0=APP_NAME,p1=APP_VERSION),
                f"Gemaakt: {_dt.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
                f"Totaal projecten: {len(self.projects)}",
                "",
            ]

            for status in PROJECT_WORKFLOW_STATUSES:
                items = sorted(
                    [p for p in self.projects if normalize_workflow_status(p.user_status) == status],
                    key=lambda p: (p.project_group.lower(), p.name.lower()),
                )
                lines.append("=" * 90)
                lines.append(_tr('ui.source.p0.p1.project.en.d13f9e25',p0=status,p1=len(items)))
                lines.append(WORKFLOW_EXPLANATIONS.get(status, ""))
                lines.append("")
                for p in items:
                    lines.append(f"- {p.name}")
                    lines.append(f"  Type: {p.project_type}")
                    lines.append(f"  Groep: {p.project_group or '-'}")
                    lines.append(f"  Familie: {p.family_name or '-'} / {p.family_role or '-'}")
                    lines.append(f"  Kwaliteit: {p.quality_status} ({p.quality_score}/100)")
                    lines.append(f"  Intelligence: {p.intelligence_status} ({p.intelligence_score}/100), actie: {p.intelligence_action}")
                    lines.append(_tr('ui.source.risico.p0.p1.100.97754e13',p0=p.intelligence_risk_level,p1=p.intelligence_risk_score))
                    lines.append(f"  Build: {p.build_readiness_status} ({p.build_readiness_score}/100)")
                    lines.append(f"  Laatst gewijzigd: {p.modified_text or '-'}")
                    lines.append(f"  Grootte: {format_bytes(p.size_bytes)}")
                    lines.append(f"  Opruimbaar: {format_bytes(p.cleanup_bytes)}")
                    lines.append(f"  Pad: {p.path}")
                    if p.user_note:
                        lines.append(f"  Notitie: {p.user_note[:180]}")
                    lines.append("")

            report_path = get_report_dir() / f"project_library_{_dt.datetime.now().strftime('%Y-%m-%d_%H%M%S')}.txt"
            report_path.write_text("\n".join(lines), encoding="utf-8")
            self.status_var.set(_tr('ui.source.project.library.rapport.gemaakt.p0.74a1ab85',p0=report_path))
            messagebox.showinfo(_tr('ui.source.project.library.rapport.8e4da106'), _tr('ui.source.rapport.opgeslagen.p0.70696287',p0=report_path))
        def _create_git_center_report(self) -> None:
            """Maak Git Center-rapport voor alle projecten."""
            git_projects = [p for p in self.projects if p.git_present]
            no_git = [p for p in self.projects if not p.git_present]

            lines = [
                f"{APP_NAME} v{APP_VERSION} - Git Center rapport",
                f"Gemaakt: {_dt.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
                f"Totaal projecten: {len(self.projects)}",
                f"Git-projecten: {len(git_projects)}",
                f"Zonder Git: {len(no_git)}",
                "",
            ]

            for p in sorted(git_projects, key=lambda item: (item.git_remote or "", item.name.lower())):
                lines.append("=" * 90)
                lines.append(p.name)
                lines.append(f"Pad: {p.path}")
                lines.extend(git_project_summary(p))
                lines.append("")

            if no_git:
                lines.append("=" * 90)
                lines.append("Projecten zonder Git")
                lines.append("=" * 90)
                for p in sorted(no_git, key=lambda item: item.name.lower()):
                    lines.append(f"- {p.name} | {p.project_type} | {p.path}")

            report_path = get_report_dir() / f"git_center_{_dt.datetime.now().strftime('%Y-%m-%d_%H%M%S')}.txt"
            report_path.write_text("\n".join(lines), encoding="utf-8")
            self.status_var.set(_tr('ui.source.git.center.rapport.gemaakt.p0.c222e1af',p0=report_path))
            messagebox.showinfo(_tr('ui.source.git.center.rapport.6dd1fefc'), _tr('ui.source.rapport.opgeslagen.p0.70696287',p0=report_path))
        def _create_build_center_report(self) -> None:
            lines = [
                f"{APP_NAME} v{APP_VERSION} - Build Center rapport",
                f"Gemaakt: {_dt.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
                f"Totaal projecten: {len(self.projects)}",
                "",
            ]
            status_counts: dict[str, int] = {}
            for p in self.projects:
                status = p.last_build_status or "Geen build"
                status_counts[status] = status_counts.get(status, 0) + 1

            lines.append("Samenvatting:")
            for status, count in sorted(status_counts.items()):
                lines.append(f"- {status}: {count}")
            lines.append("")

            for p in sorted(self.projects, key=lambda item: (item.last_build_status or "ZZZ", item.name.lower())):
                lines.append("=" * 90)
                lines.append(f"{p.name}")
                lines.append(f"Type: {p.project_type}")
                lines.append(f"Workflow: {p.user_status}")
                lines.append(f"Build-readiness: {p.build_readiness_status} ({p.build_readiness_score}/100)")
                lines.append(f"Laatste build: {p.last_build_status or '-'}")
                lines.append(f"Exitcode: {p.last_build_exitcode or '-'}")
                lines.append(f"Tijd: {p.last_build_at or '-'}")
                lines.append(f"Profiel: {p.last_build_profile or '-'}")
                lines.append(f"Command: {p.last_build_command or '-'}")
                lines.append(f"Artifacts: {p.last_build_artifacts or '-'}")
                lines.append(f"Historie-items: {len(p.build_history or [])}")
                lines.append(f"Pad: {p.path}")
                lines.append("")

            report_path = get_report_dir() / f"build_center_{_dt.datetime.now().strftime('%Y-%m-%d_%H%M%S')}.txt"
            report_path.write_text("\n".join(lines), encoding="utf-8")
            self.status_var.set(_tr('ui.source.build.center.rapport.gemaakt.p0.7ea218dd',p0=report_path))
            messagebox.showinfo(_tr('ui.source.build.center.rapport.43f754ad'), _tr('ui.source.rapport.opgeslagen.p0.70696287',p0=report_path))
        def _save_dependency_report(self, project: ProjectInfo, data: dict, release: dict) -> Path:
            lines = [f"{APP_NAME} v{APP_VERSION} — Release & Dependency Intelligence", _tr('ui.source.project.p0.e06d67de',p0=project.name), f"Pad: {project.path}", f"Datum: {_dt.datetime.now():%Y-%m-%d %H:%M:%S}", ""]
            for title, key in (("DECLARED DEPENDENCIES", "declared"), ("IMPORTS", "imports"), ("EXTERNE TOOLS", "external_tools"), ("ONTBREKEND", "missing"), ("SCRIPTRELATIES", "relations")):
                lines.append(title)
                entries = data.get(key, [])
                if not entries:
                    lines.append(_tr('ui.source.geen.56ef3330'))
                else:
                    for item in entries:
                        lines.append("- " + " | ".join(f"{k}={v}" for k, v in item.items()))
                lines.append("")
            lines.append("RELEASES")
            for item in release.get("releases", []):
                lines.append(f"- v{item['version']} | {item['status']}")
            lines.append("")
            lines.append("RELEASEBLOKKADES")
            lines += [f"- {x}" for x in release.get("blockers", [])] or ["- Geen duidelijke blokkades"]
            path = get_report_dir() / f"release_dependency_{sanitize_project_folder_name(project.name)}_{_dt.datetime.now():%Y-%m-%d_%H%M%S}.txt"
            path.write_text("\n".join(lines), encoding="utf-8")
            messagebox.showinfo(_tr('ui.source.rapport.opgeslagen.c1c08c65'), _tr('ui.source.rapport.opgeslagen.p0.70696287',p0=path))
            return path
        def _create_release_dependency_report(self) -> None:
            project = self._selected_or_prompt_project_for_intelligence()
            if not project:
                return
            scripts, _ = scan_project_scripts_detailed(project.path, check_ads=False)
            data = analyze_project_dependencies(project.path, scripts)
            release = analyze_project_releases(project)
            self._save_dependency_report(project, data, release)
        def _create_intelligence_report(self) -> None:
            """Maak Project Intelligence-rapport."""
            if self.projects:
                for p in self.projects:
                    if not p.intelligence_status or p.intelligence_status == "Onbekend":
                        analyze_project_intelligence(p, self.projects)

            lines = [
                _tr('ui.source.p0.v.p1.project.intelligence.rapport.2543b5ac',p0=APP_NAME,p1=APP_VERSION),
                f"Gemaakt: {_dt.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
                f"Totaal projecten: {len(self.projects)}",
                "",
            ]

            groups = {
                "Release-kandidaten": [p for p in self.projects if p.intelligence_status == "Release-kandidaat"],
                "Hoog risico": [p for p in self.projects if p.intelligence_risk_score >= 75],
                "Archiefkandidaten": [p for p in self.projects if p.intelligence_status == "Archiefkandidaat"],
                "Opruimkandidaten": [p for p in self.projects if p.intelligence_status in {"Opruimkandidaat", "Verwijderkandidaat"}],
                "Build-risico": [p for p in self.projects if p.intelligence_status == "Build-risico"],
                "Duplicaatkans hoog": [p for p in self.projects if p.intelligence_duplicate_probability >= 60],
                "Documentatie ontbreekt": [p for p in self.projects if not p.readme_present],
            }

            lines.append("Samenvatting:")
            for name, items in groups.items():
                lines.append(f"- {name}: {len(items)}")
            lines.append("")

            for group_name, items in groups.items():
                lines.append("=" * 90)
                lines.append(group_name)
                lines.append("=" * 90)
                if not items:
                    lines.append(_tr('ui.source.geen.projecten.9aff3580'))
                    lines.append("")
                    continue
                for p in sorted(items, key=lambda item: (-item.intelligence_risk_score, item.name.lower())):
                    lines.append(intelligence_summary_line(p))
                    lines.append(f"  Type: {p.project_type}")
                    lines.append(f"  Workflow: {p.user_status}")
                    lines.append(f"  Familie: {p.family_name or '-'} / {p.family_role or '-'}")
                    lines.append(f"  Laatste build: {p.last_build_status or '-'}")
                    lines.append(f"  Laatst gewijzigd: {project_age_days(p)} dag(en) geleden")
                    lines.append(f"  Pad: {p.path}")
                    if p.intelligence_warnings:
                        lines.append("  Waarschuwingen:")
                        for warning in p.intelligence_warnings[:4]:
                            lines.append(f"  - {warning}")
                    lines.append("")

            lines.append("=" * 90)
            lines.append("Alle projecten op score")
            lines.append("=" * 90)
            for p in sorted(self.projects, key=lambda item: (item.intelligence_score, -item.intelligence_risk_score, item.name.lower())):
                lines.append(intelligence_summary_line(p))
                lines.append(f"  Pad: {p.path}")

            report_path = get_report_dir() / f"project_intelligence_{_dt.datetime.now().strftime('%Y-%m-%d_%H%M%S')}.txt"
            report_path.write_text("\n".join(lines), encoding="utf-8")
            self.status_var.set(_tr('ui.source.project.intelligence.rapport.gemaakt.p0.e52c8661',p0=report_path))
            messagebox.showinfo(_tr('ui.source.project.intelligence.rapport.b8568408'), _tr('ui.source.rapport.opgeslagen.p0.70696287',p0=report_path))
        def _create_family_report(self) -> None:
            """Maak een rapport van projectfamilies en varianten."""
            groups: dict[str, list[ProjectInfo]] = {}
            for p in self.projects:
                if p.family_key:
                    groups.setdefault(p.family_key, []).append(p)

            lines = [
                f"{APP_NAME} v{APP_VERSION} - projectfamilies rapport",
                f"Gemaakt: {_dt.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
                "",
            ]

            family_groups = [(key, items) for key, items in groups.items() if len(items) > 1]
            family_groups.sort(key=lambda kv: (family_display_name(kv[0]).lower(), -len(kv[1])))

            lines.append(f"Families met meerdere varianten: {len(family_groups)}")
            lines.append("")

            for key, items in family_groups:
                lines.append("=" * 80)
                lines.append(f"Familie: {family_display_name(key)}")
                lines.append(f"Aantal varianten: {len(items)}")
                lines.append("")
                for item in sorted(items, key=family_sort_key, reverse=True):
                    lines.append(f"- {item.name}")
                    lines.append(f"  Rol: {item.family_role or '-'}")
                    lines.append(f"  Zekerheid: {item.family_confidence}%")
                    lines.append(f"  Type: {item.project_type}")
                    lines.append(f"  Versie: {item.project_version_label or item.version_name or '-'}")
                    lines.append(f"  Quality: {item.quality_status} ({item.quality_score})")
                    lines.append(f"  Laatst gewijzigd: {item.modified_text or '-'}")
                    lines.append(f"  Opruimbaar: {format_bytes(item.cleanup_bytes)}")
                    lines.append(f"  Pad: {item.path}")
                    lines.append(f"  Reden: {item.family_reason or '-'}")
                    lines.append("")
                lines.append("")

            if not family_groups:
                lines.append(_tr('ui.source.geen.duidelijke.projectfamilies.met.meerdere.v.2dfb9408'))

            report_path = get_report_dir() / f"projectfamilies_{_dt.datetime.now().strftime('%Y-%m-%d_%H%M%S')}.txt"
            report_path.write_text("\n".join(lines), encoding="utf-8")
            self.status_var.set(_tr('ui.source.projectfamilies.rapport.gemaakt.p0.72605b00',p0=report_path))
            messagebox.showinfo(_tr('ui.source.projectfamilies.rapport.002380b6'), _tr('ui.source.rapport.opgeslagen.p0.70696287',p0=report_path))
        def _create_quality_report(self) -> None:
            if not self.projects:
                messagebox.showinfo(_tr('ui.source.geen.data.ec45aa59'), _tr('ui.source.er.zijn.nog.geen.projecten.gevonden.e1d933e5'))
                return
            default_name = f"quality_rapport_{_dt.datetime.now().strftime('%Y-%m-%d')}.txt"
            path = filedialog.asksaveasfilename(
                title=_tr('ui.source.quality.rapport.opslaan.7a3323c0'),
                defaultextension=".txt",
                initialfile=default_name,
                filetypes=[(_tr('ui.source.tekstbestand.205a9c5a'), "*.txt"), (_tr('ui.source.alle.bestanden.3b98611e'), "*.*")],
            )
            if not path:
                return
            projects = sorted(self.filtered_projects or self.projects, key=lambda p: (p.quality_score, p.name.lower()))
            lines = [
                f"{APP_NAME} v{APP_VERSION}",
                _tr('ui.source.project.quality.rapport.282e7e07'),
                f"Datum: {_dt.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
                "",
            ]
            for p in projects:
                lines.append(f"{p.name}")
                lines.append(f"  Type: {p.project_type}")
                lines.append(f"  Pad: {p.path}")
                lines.append(f"  Quality: {p.quality_status} ({p.quality_score}/100)")
                lines.append(f"  Build-readiness: {p.build_readiness_status} ({p.build_readiness_score}/100)")
                lines.append(f"  Snapshot: {p.snapshot_diff_summary or '-'}")
                lines.append("  Redenen:")
                for reason in p.quality_reasons:
                    lines.append(f"  - {reason}")
                lines.append("")
            Path(path).write_text("\n".join(lines), encoding="utf-8")
            log = write_action_log("quality_report", [f"Rapport: {path}", f"Aantal projecten: {len(projects)}"])
            self.status_var.set(_tr('ui.source.quality.rapport.opgeslagen.log.p0.4d0655aa',p0=log))
            messagebox.showinfo(_tr('ui.source.rapport.gereed.fb529fb6'), _tr('ui.source.rapport.opgeslagen.p0.70696287',p0=path))
        def _create_build_readiness_report(self) -> None:
            if not self.projects:
                messagebox.showinfo(_tr('ui.source.geen.data.ec45aa59'), _tr('ui.source.er.zijn.nog.geen.projecten.gevonden.e1d933e5'))
                return
            default_name = f"build_readiness_{_dt.datetime.now().strftime('%Y-%m-%d')}.txt"
            path = filedialog.asksaveasfilename(
                title=_tr('ui.source.build.readiness.rapport.opslaan.a375f638'),
                defaultextension=".txt",
                initialfile=default_name,
                filetypes=[(_tr('ui.source.tekstbestand.205a9c5a'), "*.txt"), (_tr('ui.source.alle.bestanden.3b98611e'), "*.*")],
            )
            if not path:
                return
            projects = sorted(self.filtered_projects or self.projects, key=lambda p: (p.build_readiness_score, p.name.lower()))
            lines = [
                f"{APP_NAME} v{APP_VERSION}",
                "Build readiness rapport",
                f"Datum: {_dt.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
                "",
                "Toolcheck:",
            ]
            for name, tool_path in collect_tool_status().items():
                lines.append(_tr('ui.source.p0.p1.1de3d4b9',p0=name,p1='gevonden - ' + tool_path if tool_path else 'ontbreekt'))
            lines.extend(["", "Projecten:", ""])
            for p in projects:
                lines.append(f"{p.name}")
                lines.append(f"  Type: {p.project_type}")
                lines.append(f"  Groep: {p.project_group or '-'}")
                lines.append(f"  Pad: {p.path}")
                lines.append(f"  Build-readiness: {p.build_readiness_status} ({p.build_readiness_score}/100)")
                lines.append(f"  Startcommando: {p.start_command or self._guess_start_command(p) or '-'}")
                for reason in p.build_readiness_reasons:
                    lines.append(f"  - {reason}")
                lines.append("")
            Path(path).write_text("\n".join(lines), encoding="utf-8")
            log = write_action_log("build_readiness_report", [f"Rapport: {path}", f"Aantal projecten: {len(projects)}"])
            self.status_var.set(_tr('ui.source.build.readiness.rapport.opgeslagen.log.p0.975bf0bb',p0=log))
            messagebox.showinfo(_tr('ui.source.rapport.gereed.fb529fb6'), _tr('ui.source.rapport.opgeslagen.p0.70696287',p0=path))
        def _create_project_report(self) -> None:
            if not self.projects:
                messagebox.showinfo(_tr('ui.source.geen.data.ec45aa59'), _tr('ui.source.er.zijn.nog.geen.projecten.gevonden.e1d933e5'))
                return

            default_name = f"projectrapport_{_dt.datetime.now().strftime('%Y-%m-%d')}.txt"
            path = filedialog.asksaveasfilename(
                title=_tr('ui.source.projectrapport.opslaan.b90ac741'),
                defaultextension=".txt",
                initialfile=default_name,
                filetypes=[(_tr('ui.source.tekstbestand.205a9c5a'), "*.txt"), (_tr('ui.source.alle.bestanden.3b98611e'), "*.*")],
            )
            if not path:
                return

            projects = list(self.filtered_projects or self.projects)
            total_size = sum(p.size_bytes for p in projects)
            cleanup_size = sum(p.cleanup_bytes for p in projects)
            type_counts: dict[str, int] = {}
            for p in projects:
                type_counts[p.project_type] = type_counts.get(p.project_type, 0) + 1

            largest = sorted(projects, key=lambda p: p.size_bytes, reverse=True)[:10]
            oldest = sorted([p for p in projects if p.modified_ts], key=lambda p: p.modified_ts)[:10]
            cleanup = sorted(projects, key=lambda p: p.cleanup_bytes, reverse=True)[:10]
            duplicates = [p for p in projects if p.duplicate_hint]
            no_git = [p for p in projects if not p.git_present]
            weak = sorted(projects, key=lambda p: p.health_score)[:10]
            low_quality = sorted(projects, key=lambda p: p.quality_score)[:10]
            favorites = [p for p in projects if p.favorite]
            android_not_release = [p for p in projects if ("Android" in p.tags or "Android" in p.project_type or "Expo" in p.tags) and not str(p.android_release_status).startswith("Release klaar")]
            likely_backups = [p for p in projects if p.version_role in {"Backup", "Oudere versie", "Testversie", "Tijdelijk"}]
            embedded_projects = [p for p in projects if any(t in p.tags for t in ["Raspberry Pi", "Arduino", "ESP32", "ESP8266", "PlatformIO"])]
            raspberry_projects = [p for p in projects if "Raspberry Pi" in p.tags]
            arduino_projects = [p for p in projects if "Arduino" in p.tags or "PlatformIO" in p.tags or p.project_type in {"Arduino", "Arduino / PlatformIO", "ESP32", "ESP8266"}]

            lines = [
                f"{APP_NAME} v{APP_VERSION}",
                f"Projectrapport",
                f"Datum: {_dt.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
                "",
                "SAMENVATTING",
                f"Aantal projecten: {len(projects)}",
                f"Totale grootte: {format_bytes(total_size)}",
                f"Geschat opruimbaar: {format_bytes(cleanup_size)}",
                f"Projecten zonder Git: {len(no_git)}",
                f"Mogelijke duplicaten: {len(duplicates)}",
                f"Favorieten: {len(favorites)}",
                f"Android niet release-klaar: {len(android_not_release)}",
                f"Embedded/hardware projecten: {len(embedded_projects)}",
                f"Raspberry Pi projecten: {len(raspberry_projects)}",
                f"Arduino/ESP/PlatformIO projecten: {len(arduino_projects)}",
                f"Waarschijnlijke backups/test/oud: {len(likely_backups)}",
                f"Projecten quality < 60: {len([p for p in projects if p.quality_score < 60])}",
                "",
                "PROJECTTYPES",
            ]
            for t, count in sorted(type_counts.items(), key=lambda x: x[0].lower()):
                lines.append(f"- {t}: {count}")

            def section(title: str, items: list[ProjectInfo], formatter) -> None:
                lines.extend(["", title])
                if not items:
                    lines.append(_tr('ui.source.geen.items.be9cf315'))
                    return
                for item in items:
                    lines.append(formatter(item))

            section("GROOTSTE PROJECTEN", largest, lambda p: f"- {p.name} | {format_bytes(p.size_bytes)} | {p.path}")
            section("OUDSTE PROJECTEN", oldest, lambda p: f"- {p.name} | {p.modified_text} | {p.path}")
            section("GROOTSTE OPRUIMKANDIDATEN", cleanup, lambda p: f"- {p.name} | {format_bytes(p.cleanup_bytes)} | {p.path}")
            section("ZWAKSTE PROJECTSTATUS", weak, lambda p: f"- {p.name} | {p.health_status} ({p.health_score}) | {p.path}")
            section("ZWAKSTE PROJECTKWALITEIT", low_quality, lambda p: f"- {p.name} | {p.quality_status} ({p.quality_score}) | {p.path}")
            section("MOGELIJKE DUPLICATEN", duplicates, lambda p: f"- {p.name} | score {p.duplicate_score} | {p.duplicate_hint} | {p.path}")
            section("PROJECTEN ZONDER GIT", no_git[:25], lambda p: f"- {p.name} | {p.project_type} | {p.path}")
            section("FAVORIETEN", favorites[:25], lambda p: f"- {p.name} | {p.project_type} | {p.path}")
            section("ANDROID NIET RELEASE-KLAAR", android_not_release[:25], lambda p: f"- {p.name} | {p.android_release_status} | {p.path}")
            section("RASPBERRY PI PROJECTEN", raspberry_projects[:25], lambda p: f"- {p.name} | GPIO: {'Ja' if p.gpio_used else 'Nee'} | Camera: {'Ja' if p.camera_used else 'Nee'} | Services: {'Ja' if p.systemd_service_present else 'Nee'} | {p.path}")
            section("ARDUINO / ESP / PLATFORMIO PROJECTEN", arduino_projects[:25], lambda p: f"- {p.name} | {p.project_type} | board: {p.embedded_board or '-'} | platform: {p.embedded_platform or '-'} | envs: {', '.join(p.platformio_envs) if p.platformio_envs else '-'} | {p.path}")
            section("WAARSCHIJNLIJKE BACKUPS/TEST/OUD", likely_backups[:25], lambda p: f"- {p.name} | {p.version_role} | {p.project_version_label} | {p.path}")

            try:
                Path(path).write_text("\n".join(lines), encoding="utf-8")
                log = write_action_log("report", [f"Rapport: {path}", f"Aantal projecten: {len(projects)}"])
                self.status_var.set(_tr('ui.source.rapport.opgeslagen.p0.7ae23b66',p0=path))
                messagebox.showinfo(_tr('ui.source.rapport.gereed.fb529fb6'), _tr('ui.source.rapport.opgeslagen.p0.log.p1.25c9db3e',p0=path,p1=log))
            except Exception as exc:
                messagebox.showerror(_tr('ui.source.rapport.mislukt.6f7a2b20'), str(exc))
        def _create_release_report(self) -> None:
            """Maak een v1.0 release-/beheer-rapport van de zichtbare projectset."""
            if not self.projects:
                messagebox.showinfo(_tr('ui.source.geen.data.ec45aa59'), _tr('ui.source.er.zijn.nog.geen.projecten.gevonden.e1d933e5'))
                return
            projects = list(self.filtered_projects or self.projects)
            path = get_report_dir() / f"ProjectManager_release_report_{_dt.datetime.now().strftime('%Y-%m-%d_%H%M%S')}.txt"
            total_size = sum(p.size_bytes for p in projects)
            cleanup_size = sum(p.cleanup_bytes for p in projects)
            duplicates = [p for p in projects if p.duplicate_hint or p.duplicate_score > 0]
            no_git = [p for p in projects if not p.git_present]
            no_readme = [p for p in projects if not p.readme_present]
            release_ready = [p for p in projects if str(p.android_release_status).startswith("Release klaar")]
            not_buildable = [p for p in projects if p.build_readiness_score < 60]
            favorites = [p for p in projects if p.favorite]
            active = [p for p in projects if (p.user_status or "actief").lower() == "actief"]
            largest = sorted(projects, key=lambda p: p.size_bytes, reverse=True)[:15]
            cleanup_top = sorted(projects, key=lambda p: p.cleanup_bytes, reverse=True)[:15]

            lines = [
                f"{APP_NAME} v{APP_VERSION}",
                "Release-rapport / v1.0 beheeroverzicht",
                f"Datum: {_dt.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
                "",
                "SAMENVATTING",
                f"Aantal projecten: {len(projects)}",
                f"Totale grootte: {format_bytes(total_size)}",
                f"Geschat opruimbaar: {format_bytes(cleanup_size)}",
                f"Mogelijke duplicaten: {len(duplicates)}",
                f"Projecten zonder Git: {len(no_git)}",
                f"Projecten zonder README: {len(no_readme)}",
                f"Release-klare Android/Expo-projecten: {len(release_ready)}",
                f"Niet of beperkt bouwbaar: {len(not_buildable)}",
                f"Favorieten: {len(favorites)}",
                f"Actieve projecten: {len(active)}",
                "",
                "GROOTSTE PROJECTEN",
            ]
            for p in largest:
                lines.append(f"- {p.name} | {format_bytes(p.size_bytes)} | {p.project_type} | {p.path}")
            lines.extend(["", "GROOTSTE OPRUIMKANDIDATEN"])
            for p in cleanup_top:
                lines.append(f"- {p.name} | opruimbaar {format_bytes(p.cleanup_bytes)} | {p.path}")
            lines.extend(["", "DUPLICATEN"])
            lines.extend([f"- {p.name} | score {p.duplicate_score} | {p.duplicate_hint} | {p.path}" for p in duplicates[:50]] or [_tr('ui.source.geen.duplicaatsignalen.cc37a558')])
            lines.extend(["", "PROJECTEN ZONDER GIT"])
            lines.extend([f"- {p.name} | {p.path}" for p in no_git[:50]] or [_tr('ui.source.geen.e3ab833b')])
            lines.extend(["", "PROJECTEN ZONDER README"])
            lines.extend([f"- {p.name} | {p.path}" for p in no_readme[:50]] or [_tr('ui.source.geen.e3ab833b')])
            lines.extend(["", "NIET/BEGRENSD BOUWBAAR"])
            for p in not_buildable[:50]:
                lines.append(f"- {p.name} | {p.build_readiness_status} ({p.build_readiness_score}/100) | {p.path}")
                for reason in p.build_readiness_reasons[:5]:
                    lines.append(f"  - {reason}")
            path.write_text("\n".join(lines), encoding="utf-8")
            log = write_action_log("release_report", [f"Rapport: {path}", f"Aantal projecten: {len(projects)}"])
            self.status_var.set(_tr('ui.source.release.rapport.opgeslagen.p0.3b42d123',p0=path))
            messagebox.showinfo(_tr('ui.source.release.rapport.gereed.1e498026'), _tr('ui.source.rapport.opgeslagen.p0.log.p1.25c9db3e',p0=path,p1=log))
        def _open_report_dir(self) -> None:
            windows_open_path(get_report_dir())
        def _bulk_report_selected(self) -> None:
            projects = self._get_selected_projects()
            if not projects:
                messagebox.showinfo(_tr('ui.source.geen.selectie.60b466be'), _tr('ui.source.selecteer.eerst.n.of.meer.projecten.9b241af5'))
                return
            lines = [
                f"{APP_NAME} v{APP_VERSION}",
                "Selectierapport",
                f"Datum: {_dt.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
                f"Aantal geselecteerd: {len(projects)}",
                f"Totale grootte: {format_bytes(sum(p.size_bytes for p in projects))}",
                f"Opruimbaar: {format_bytes(sum(p.cleanup_bytes for p in projects))}",
                "",
            ]
            for p in projects:
                lines.extend([
                    f"- {p.name}",
                    f"  Type: {p.project_type}",
                    f"  Workflow: {p.user_status or 'Actief'}",
                    f"  Groep: {p.project_group or '-'}",
                    f"  Kwaliteit: {p.quality_status} ({p.quality_score}/100)",
                    f"  Build: {p.build_readiness_status}",
                    f"  Opruimbaar: {format_bytes(p.cleanup_bytes)}",
                    f"  Pad: {p.path}",
                    "",
                ])
            self._show_text_window(_tr('ui.source.rapport.van.selectie.a040fbcd'), "\n".join(lines))
        def _create_portfolio_report(self) -> None:
            groups=self._portfolio_groups(); stamp=_dt.datetime.now().strftime("%Y-%m-%d_%H%M%S")
            path=get_report_dir()/f"portfolio_rapport_{stamp}.txt"
            lines=[f"{APP_NAME} v{APP_VERSION}","PORTFOLIO-RAPPORT",f"Datum: {_dt.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",f"Projecten: {len(self.projects)}",f"Totale grootte: {format_bytes(sum(p.size_bytes for p in self.projects))}",""]
            for title,items in groups.items():
                lines.extend([title.upper(),"-"*len(title)])
                if not items: lines.append(_tr('ui.source.geen.projecten.9aff3580'))
                for p in sorted(items,key=lambda x:x.name.lower()): lines.append(_tr('ui.source.p0.p1.p2.risico.p3.100.git.p4.readme.p5.p6.78453583',p0=p.name,p1=p.project_type,p2=normalize_workflow_status(p.user_status),p3=p.intelligence_risk_score,p4='ja' if p.git_present else 'nee',p5='ja' if p.readme_present else 'nee',p6=p.path))
                lines.append("")
            path.write_text("\n".join(lines),encoding="utf-8")
            self.status_var.set(_tr('ui.source.portfolio.rapport.opgeslagen.p0.965ae310',p0=path))
            self._show_text_window(_tr('ui.source.portfolio.rapport.ac829d7e'), "\n".join(lines)+f"\nBestand: {path}")
        def _create_architecture_report(self) -> None:
            projects = self._get_selected_projects()
            project = projects[0] if projects else (self.selected_project if self.selected_project else None)
            if not project:
                return
            meta = load_project_meta(project.path).get("project_architect", {})
            if not meta:
                messagebox.showinfo(_tr('ui.source.architectuurrapport.62acfee2'), _tr('ui.source.voor.dit.project.zijn.nog.geen.project.archite.2cfa4f9a'))
                return
            lines = [f"{APP_NAME} v{APP_VERSION} – Architectuurrapport", "", _tr('ui.source.project.p0.e06d67de',p0=project.name), f"Pad: {project.path}", f"Bijgewerkt: {meta.get('updated_at','-')}", "", "PRODUCTVISIE", meta.get("vision", "-"), "", _tr('ui.source.doel.bd8329b6'), meta.get("purpose", "-"), "", "DOELGROEP", meta.get("audience", "-"), "", "PLATFORM", meta.get("platform", "-"), "", "ARCHITECTUUR", meta.get("architecture", "-"), "", "RELEASES"]
            for rel in meta.get("releases", []):
                lines += [f"- {rel.get('version','-')} | {rel.get('title','-')} | {rel.get('phase','-')}"]
            path = get_report_dir() / f"architectuur_{sanitize_project_folder_name(project.name)}_{_dt.datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
            path.write_text("\n".join(lines), encoding="utf-8")
            self._show_text_window(_tr('ui.source.architectuurrapport.62acfee2'), "\n".join(lines))
        def _v90_case_dir(self, case_id: str) -> Path:
            safe = re.sub(r"[^A-Za-z0-9_.-]+", "_", case_id.strip()) or "CASE"
            path = self._v90_home() / "cases" / safe
            for sub in ("reports", "evidence", "attachments", "exports", "screenshots"):
                (path / sub).mkdir(parents=True, exist_ok=True)
            return path
        def _show_report_studio_new(self) -> None:
            self._show_report_studio(new_report=True)
        def _open_report_from_menu(self) -> None:
            path=filedialog.askopenfilename(title=_tr('ui.source.open.report.studio.document.eae75c56'),filetypes=[(_tr('ui.source.report.studio.7d55a3c4'), "*.pmreport.json"),(_tr('ui.source.markdown.23e67fce'), "*.md"),(_tr('ui.source.tekst.31262d81'), "*.txt"),(_tr('ui.source.alle.bestanden.3b98611e'),"*.*")])
            if path:
                self._show_report_studio(open_path=Path(path))
        def _show_report_studio(self, event=None, new_report: bool=False, initial_tab: str="Editor", open_path: Path|None=None) -> None:
            existing=getattr(self,"_report_studio",None)
            if existing is not None:
                try:
                    if existing.winfo_exists():
                        existing.deiconify(); existing.lift(); existing.focus_force()
                        if open_path: self._v90_load_into_editor(open_path)
                        return
                except Exception: pass
            win=self._new_tool_window(); self._report_studio=win
            win.title(_tr('ui.source.professional.report.editor.projectmanager.v.p0.605dab79',p0=APP_VERSION))
            win.geometry("1580x940"); win.minsize(1120,720); win.resizable(True,True)
            try:
                if platform.system().lower()=="windows": win.state("zoomed")
            except Exception: pass
            win.rowconfigure(2,weight=1); win.columnconfigure(0,weight=1)

            project=getattr(self,"selected_project",None)
            project_path=Path(project.path) if project else None
            project_name=project.name if project else "Geen project geselecteerd"
            self._v91_dirty=False; self._v91_autosave_id=None; self._v91_images=[]; self._v91_image_refs=[]; self._v91_preview_image_refs=[]
            self._v93_reviews=[]; self._v93_audit=[]; self._v93_locked=False; self._v93_publication_profile="Intern"

            def close_editor():
                if self._v91_dirty and not messagebox.askyesno(_tr('ui.source.niet.opgeslagen.wijzigingen.e6c7734d'),_tr('ui.source.rapport.sluiten.zonder.eerst.op.te.slaan.dff375a2'),parent=win): return
                if self._v91_autosave_id:
                    try: win.after_cancel(self._v91_autosave_id)
                    except Exception: pass
                setattr(self,"_report_studio",None); win.destroy()
            win.protocol("WM_DELETE_WINDOW",close_editor)

            # Volwaardige editor-menubalk
            menubar=Menu(win)
            file_m=Menu(menubar,tearoff=False); edit_m=Menu(menubar,tearoff=False); search_m=Menu(menubar,tearoff=False)
            insert_m=Menu(menubar,tearoff=False); format_m=Menu(menubar,tearoff=False); view_m=Menu(menubar,tearoff=False); report_m=Menu(menubar,tearoff=False)
            review_m=Menu(menubar,tearoff=False); publish_m=Menu(menubar,tearoff=False); help_m=Menu(menubar,tearoff=False)
            menubar.add_cascade(label=_tr('ui.source.bestand.6e8cf3e6'),menu=file_m); menubar.add_cascade(label=_tr('ui.source.bewerken.881805ef'),menu=edit_m); menubar.add_cascade(label=_tr('ui.source.zoeken.2d890f1f'),menu=search_m)
            menubar.add_cascade(label=_tr('ui.source.invoegen.a98e2c21'),menu=insert_m); menubar.add_cascade(label=_tr('ui.source.opmaak.13510b15'),menu=format_m); menubar.add_cascade(label=_tr('ui.source.beeld.cc3edcff'),menu=view_m)
            menubar.add_cascade(label=_tr('ui.source.rapport.f25c405b'),menu=report_m); menubar.add_cascade(label=_tr('ui.source.review.e29a79fe'),menu=review_m); menubar.add_cascade(label=_tr('ui.source.publiceren.83a7dddc'),menu=publish_m)
            menubar.add_cascade(label=_tr('ui.source.help.c47ae153'),menu=help_m); win.config(menu=menubar)

            header=ttk.Frame(win,padding=(10,6)); header.grid(row=0,column=0,sticky="ew")
            ttk.Label(header,text=_tr('ui.source.professional.report.editor.7cc61cd7'),style="Title.TLabel").pack(side=LEFT)
            self._v90_status=StringVar(value=_tr('ui.source.project.p0.e06d67de',p0=project_name))
            ttk.Label(header,textvariable=self._v90_status).pack(side=RIGHT)

            # Toolbar met compacte pictogrammen en tekst
            toolbar=ttk.Frame(win,padding=(8,4)); toolbar.grid(row=1,column=0,sticky="ew")
            def tb(text,cmd,tip=""):
                b=ttk.Button(toolbar,text=text,command=cmd,width=max(3,min(15,len(text)+1))); b.pack(side=LEFT,padx=2)
                try:
                    if tip: ToolTip(b,tip)
                except Exception: pass
                return b

            main=ttk.PanedWindow(win,orient="horizontal"); main.grid(row=2,column=0,sticky="nsew",padx=8,pady=(0,4))
            left=ttk.Frame(main,padding=6); center=ttk.Frame(main,padding=4); right=ttk.Frame(main,padding=6)
            main.add(left,weight=2); main.add(center,weight=7); main.add(right,weight=2)

            # Casegegevens en sjablonen
            ttk.Label(left,text=_tr('ui.source.case.document.912b56fe'),style="Heading.TLabel").pack(anchor="w")
            case_id=StringVar(value=_tr('ui.source.case.p0.9bf6cfc4',p0=_dt.datetime.now().strftime('%Y%m%d-%H%M')))
            title_var=StringVar(value=_tr('ui.source.onderzoeksrapport.p0.c1ae3d02',p0=project_name))
            author_var=StringVar(value=os.environ.get("USERNAME") or os.environ.get("USER") or "Onderzoeker")
            template_var=StringVar(value=_tr('ui.source.security.assessment.639123ed'))
            case_status_var=StringVar(value=_tr('ui.source.nieuw.8762a532'))
            classification_var=StringVar(value=_tr('ui.source.intern.f841f984'))
            for label,var in (("Case-ID",case_id),("Titel",title_var),("Onderzoeker",author_var)):
                ttk.Label(left,text=label).pack(anchor="w",pady=(5,0)); ttk.Entry(left,textvariable=var).pack(fill=X)
            ttk.Label(left,text=_tr('ui.source.case.status.83e82632')).pack(anchor="w",pady=(7,0))
            ttk.Combobox(left,textvariable=case_status_var,state="readonly",values=["Nieuw","In onderzoek","Analyse","Review","Concept rapport","Goedgekeurd","Afgesloten","Gearchiveerd"]).pack(fill=X)
            ttk.Label(left,text=_tr('ui.source.classificatie.b74681c2')).pack(anchor="w",pady=(7,0))
            ttk.Combobox(left,textvariable=classification_var,state="readonly",values=["Openbaar","Intern","Vertrouwelijk","Strikt vertrouwelijk","Onderwijs","Concept"]).pack(fill=X)
            ttk.Label(left,text=_tr('ui.source.rapportsjabloon.cc020201')).pack(anchor="w",pady=(7,0))
            template_box=ttk.Combobox(left,textvariable=template_var,state="readonly",values=list(self._v90_templates()),height=12); template_box.pack(fill=X)
            ttk.Separator(left).pack(fill=X,pady=8)
            ttk.Label(left,text=_tr('ui.source.toolbox.sleep.naar.rapport.9ff2e997'),style="Heading.TLabel").pack(anchor="w")
            toolbox=ttk.Treeview(left,show="tree",height=10,selectmode="browse")
            toolbox.pack(fill=X,pady=(4,8))
            toolbox_items=[
                ("Tekstblok","Tekst"),("Managementsamenvatting","Managementsamenvatting"),("Finding","Finding"),
                ("Evidenceblok","Evidenceblok"),("Risicomatrix","Risicomatrix"),("Tijdlijn","Tijdlijn"),
                ("Hostoverzicht","Hostoverzicht"),("VM-imageoverzicht","VM-imageoverzicht"),
                ("Memoryanalyse","Memoryanalyse"),("Compliance-matrix","Compliance-matrix"),
                ("Aanbevelingen","Aanbevelingen"),("Conclusie","Conclusie"),("Handtekening","Handtekening")]
            for iid,label in toolbox_items: toolbox.insert("","end",iid="tool_"+iid,text="▣ "+label,values=(iid,))
            ttk.Label(left,text=_tr('ui.source.documentstructuur.2fff60a8'),style="Heading.TLabel").pack(anchor="w")
            outline=ttk.Treeview(left,show="tree",height=12); outline.pack(fill=BOTH,expand=True,pady=(4,0))

            # Centrale documenttabs
            docs=ttk.Notebook(center); docs.pack(fill=BOTH,expand=True)
            page=ttk.Frame(docs); notes_page=ttk.Frame(docs); preview_page=ttk.Frame(docs)
            docs.add(page,text=_tr('ui.source.rapport.a240ddb3')); docs.add(notes_page,text=_tr('ui.source.notities.15b26007')); docs.add(preview_page,text=_tr('ui.source.preview.6d8d0c56'))
            page.rowconfigure(0,weight=1); page.columnconfigure(0,weight=1)
            page_canvas=Canvas(page,highlightthickness=0,background="#d7d7d7")
            page_canvas.grid(row=0,column=0,sticky="nsew")
            editor=Text(page_canvas,wrap="word",undo=True,maxundo=-1,padx=58,pady=45,borderwidth=1,relief="solid")
            editor_window=page_canvas.create_window(40,20,anchor="nw",window=editor,width=900,height=1180)
            vscroll=ttk.Scrollbar(page,orient="vertical",command=page_canvas.yview); vscroll.grid(row=0,column=1,sticky="ns")
            page_canvas.configure(yscrollcommand=vscroll.set,scrollregion=(0,0,1000,1240))
            def resize_page(_e=None):
                w=max(760,min(980,page_canvas.winfo_width()-80)); page_canvas.itemconfigure(editor_window,width=w)
            page_canvas.bind("<Configure>",resize_page)
            notes=Text(notes_page,wrap="word",undo=True,padx=14,pady=12); notes.pack(fill=BOTH,expand=True)
            preview=Text(preview_page,wrap="word",state="disabled",padx=20,pady=16); preview.pack(fill=BOTH,expand=True)

            family=(self.ui_font_family.get() if hasattr(getattr(self,'ui_font_family',None),'get') else "Segoe UI")
            editor.configure(font=(family,11),spacing1=1,spacing3=2)
            tag_defs={
                "title":dict(font=(family,22,"bold"),justify="center",spacing1=12,spacing3=16),
                "h1":dict(font=(family,18,"bold"),spacing1=14,spacing3=8),
                "h2":dict(font=(family,15,"bold"),spacing1=11,spacing3=6),
                "h3":dict(font=(family,12,"bold"),spacing1=8,spacing3=4),
                "bold":dict(font=(family,11,"bold")), "italic":dict(font=(family,11,"italic")), "underline":dict(underline=True),
                "code":dict(font="TkFixedFont",background="#eeeeee",lmargin1=22,lmargin2=22,spacing1=4,spacing3=4),
                "quote":dict(lmargin1=28,lmargin2=28,foreground="#444444",font=(family,11,"italic")),
                "warning":dict(background="#fff2cc",foreground="#7a4b00",lmargin1=12,lmargin2=12),
                "critical":dict(background="#ffd6d6",foreground="#8b0000",lmargin1=12,lmargin2=12),
                "high":dict(background="#ffe2cc",foreground="#9c3d00",lmargin1=12,lmargin2=12),
                "medium":dict(background="#fff2cc",foreground="#7a4b00",lmargin1=12,lmargin2=12),
                "low":dict(background="#d9eaf7",foreground="#154360",lmargin1=12,lmargin2=12),
                "evidence":dict(background="#fff5cc",lmargin1=12,lmargin2=12,spacing1=4,spacing3=4),
                "align_center":dict(justify="center"), "align_right":dict(justify="right"), "indent":dict(lmargin1=36,lmargin2=36),
            }
            for tag,opts in tag_defs.items(): editor.tag_configure(tag,**opts)
            self._v90_editor=editor; self._v91_notes=notes; self._v91_preview=preview
            self._v90_case_vars=(case_id,title_var,author_var,template_var,case_status_var,classification_var); self._v90_current_path=None

            def mark_dirty(_e=None):
                if editor.edit_modified():
                    self._v91_dirty=True; editor.edit_modified(False); win.title(_tr('ui.source.professional.report.editor.v.p0.072b7f60',p0=APP_VERSION))
                    schedule_outline()
            editor.bind("<<Modified>>",mark_dirty)

            def selected_range():
                try: return editor.index("sel.first"),editor.index("sel.last")
                except Exception: return editor.index("insert linestart"),editor.index("insert lineend")
            def apply_tag(tag):
                a,b=selected_range(); editor.tag_add(tag,a,b); self._v91_dirty=True
            def clear_format():
                a,b=selected_range()
                for tag in tag_defs: editor.tag_remove(tag,a,b)
            def prefix_lines(prefix):
                try: a=editor.index("sel.first linestart"); b=editor.index("sel.last lineend")
                except Exception: a=editor.index("insert linestart"); b=editor.index("insert lineend")
                text=editor.get(a,b); editor.delete(a,b); editor.insert(a,"\n".join(prefix+x for x in text.splitlines()))
            def insert_table():
                rows=simpledialog.askinteger(_tr('ui.source.tabel.c1029fcd'),_tr('ui.source.aantal.rijen.inclusief.kop.e0438052'),initialvalue=4,minvalue=2,maxvalue=30,parent=win)
                cols=simpledialog.askinteger(_tr('ui.source.tabel.c1029fcd'),_tr('ui.source.aantal.kolommen.8a98cda4'),initialvalue=3,minvalue=1,maxvalue=12,parent=win)
                if not rows or not cols:return
                head="| "+" | ".join(f"Kolom {i+1}" for i in range(cols))+" |\n"
                sep="| "+" | ".join("---" for _ in range(cols))+" |\n"
                body="".join("| "+" | ".join("" for _ in range(cols))+" |\n" for _ in range(rows-1))
                editor.insert("insert","\n"+head+sep+body+"\n")
            def insert_image():
                p=filedialog.askopenfilename(parent=win,title=_tr('ui.source.afbeelding.invoegen.8b16721e'),filetypes=[(_tr('ui.source.afbeeldingen.26d068ed'),"*.png *.jpg *.jpeg *.gif"),(_tr('ui.source.alle.bestanden.3b98611e'),"*.*")])
                if not p:return
                self._v91_images.append(p)
                editor.insert("insert",f"\n![Afbeelding {len(self._v91_images)}]({p})\n_Bijschrift: vul hier een beschrijving in._\n")
                content_now=editor.get("1.0",END)
                self._v91_image_refs, missing=insert_inline_images(editor,content_now,getattr(self,"_v90_current_path",None),max_width=max(700,editor.winfo_width()-120))
                self._v91_dirty=True
            def insert_page_break(): editor.insert("insert","\n\n--- PAGINAEINDE ---\n\n")
            component_blocks={
                "Tekst":"\nNieuwe tekstsectie.\n",
                "Managementsamenvatting":"\n## Managementsamenvatting\n\nBeschrijf kernbevindingen, impact en hoofdadvies.\n",
                "Finding":"\n### Finding — [titel]\n\n**Ernst:** Medium  \n**CWE:** -  \n**OWASP:** -  \n**Status:** Open\n\n**Beschrijving**\n\n**Bewijs**\n\n**Impact**\n\n**Aanbeveling**\n",
                "Evidenceblok":"\n### Evidence-item\n\n- Evidence ID: -\n- Bron: -\n- SHA-256: -\n- Verkrijgingsdatum: -\n- Integriteitsstatus: Niet gecontroleerd\n",
                "Risicomatrix":"\n## Risicomatrix\n\n| Risico | Kans | Impact | Score | Prioriteit |\n| --- | --- | --- | --- | --- |\n| | | | | |\n",
                "Tijdlijn":"\n## Onderzoekstijdlijn\n\n| Datum/tijd | Bron | Gebeurtenis | Betekenis |\n| --- | --- | --- | --- |\n| | | | |\n",
                "Hostoverzicht":"\n## Hostoverzicht\n\n| Host | OS | IP | Rol | Status |\n| --- | --- | --- | --- | --- |\n| | | | |\n",
                "VM-imageoverzicht":"\n## VM-imageoverzicht\n\n- Image: -\n- Formaat: -\n- Grootte: -\n- SHA-256: -\n- Read-only gekoppeld: Ja/Nee\n",
                "Memoryanalyse":"\n## Memoryanalyse\n\n- Proces/PID: -\n- Guard pages: -\n- RWX-regio's: -\n- Stackkandidaten: -\n- Geladen modules: -\n- Conclusie: -\n",
                "Compliance-matrix":"\n## Compliance-matrix\n\n| Norm | Eis | Bewijs | Status | Opmerking |\n| --- | --- | --- | --- | --- |\n| | | | Niet gecontroleerd | |\n",
                "Aanbevelingen":"\n## Aanbevelingen\n\n1. \n2. \n3. \n",
                "Conclusie":"\n## Conclusie\n\nBeschrijf de beantwoording van de onderzoeksvragen en de resterende onzekerheden.\n",
                "Handtekening":"\n## Goedkeuring\n\nOnderzoeker: ____________________  Datum: __________\n\nReviewer: _______________________  Datum: __________\n"
            }
            def insert_component(name, index="insert"):
                block=component_blocks.get(name,component_blocks["Tekst"])
                editor.insert(index,block)
                self._v91_dirty=True
                update_outline()
                editor.focus_set()

            def generate_toc():
                headings=[]
                for n,line in enumerate(editor.get("1.0","end-1c").splitlines(),1):
                    if line.startswith("### "): headings.append((3,line[4:].strip()))
                    elif line.startswith("## "): headings.append((2,line[3:].strip()))
                    elif line.startswith("# "): headings.append((1,line[2:].strip()))
                toc=["## Inhoudsopgave",""]
                for level,text in headings:
                    if text.lower()=="inhoudsopgave": continue
                    toc.append("  "*(level-1)+"- "+text)
                editor.insert("insert","\n"+"\n".join(toc)+"\n")
                self._v91_dirty=True

            def redact_selection():
                try: a,b=editor.index("sel.first"),editor.index("sel.last")
                except Exception:
                    messagebox.showwarning(_tr('ui.source.redactie.34da3d89'),_tr('ui.source.selecteer.eerst.tekst.die.gemaskeerd.moet.word.9b3438c6'),parent=win); return
                original=editor.get(a,b)
                editor.delete(a,b); editor.insert(a,"█"*max(4,len(original)))
                editor.tag_add("critical",a,f"{a}+{max(4,len(original))}c")
                self._v91_dirty=True

            drag_state={"kind":None,"value":None,"label":None}
            def begin_drag(kind,value,event):
                drag_state.update(kind=kind,value=value)
                try:
                    lbl=tk.Label(win,text=_tr('ui.source.p0.e26b4fb9',p0=value),bg="#f4c542",fg="#202020",relief="solid",bd=1)
                    lbl.place(x=event.x_root-win.winfo_rootx()+8,y=event.y_root-win.winfo_rooty()+8)
                    drag_state["label"]=lbl
                except Exception: drag_state["label"]=None
            def move_drag(event):
                lbl=drag_state.get("label")
                if lbl:
                    lbl.place(x=event.x_root-win.winfo_rootx()+8,y=event.y_root-win.winfo_rooty()+8)
            def end_drag(event):
                lbl=drag_state.get("label")
                if lbl:
                    try: lbl.destroy()
                    except Exception: pass
                kind,value=drag_state.get("kind"),drag_state.get("value")
                drag_state.update(kind=None,value=None,label=None)
                if not kind:return
                ex,ey=editor.winfo_rootx(),editor.winfo_rooty()
                if not (ex <= event.x_root <= ex+editor.winfo_width() and ey <= event.y_root <= ey+editor.winfo_height()): return
                index=editor.index(f"@{event.x_root-ex},{event.y_root-ey}")
                editor.mark_set("insert",index)
                if kind=="tool": insert_component(value,index)
                elif kind=="evidence":
                    path=Path(value); block=self._v90_evidence_text(path)
                    if path.suffix.lower() in {".png",".jpg",".jpeg",".gif",".bmp"}:
                        self._v91_images.append(str(path)); block += f"\n![{path.name}]({path})\n"
                    start=editor.index(index); editor.insert(index,"\n"+block+"\n"); end=editor.index("insert")
                    editor.tag_add("evidence",start,end)
                    content_now=editor.get("1.0",END)
                    self._v91_image_refs, missing=insert_inline_images(editor,content_now,getattr(self,"_v90_current_path",None),max_width=max(700,editor.winfo_width()-120))
                    self._v91_dirty=True
                    self._v92_linked_sources.append({"path":str(path),"sha256":hashlib.sha256(path.read_bytes()).hexdigest() if path.exists() else "","inserted_at":_dt.datetime.now().isoformat(timespec="seconds")})

            def toolbox_press(event):
                iid=toolbox.identify_row(event.y)
                if iid.startswith("tool_"):
                    begin_drag("tool",iid[5:],event)
            toolbox.bind("<ButtonPress-1>",toolbox_press,add="+")
            toolbox.bind("<B1-Motion>",move_drag,add="+")
            toolbox.bind("<ButtonRelease-1>",end_drag,add="+")
            toolbox.bind("<Double-1>",lambda e: insert_component(toolbox.selection()[0][5:]) if toolbox.selection() and toolbox.selection()[0].startswith("tool_") else None)

            self._v92_linked_sources=[]
            def replace_dialog():
                d=self._new_tool_window(parent=win); d.title(_tr('ui.source.zoeken.en.vervangen.66aa1cfa')); d.resizable(False,False); d.transient(win)
                f=ttk.Frame(d,padding=12); f.pack(); q=StringVar(); r=StringVar()
                ttk.Label(f,text=_tr('ui.source.zoeken.2d890f1f')).grid(row=0,column=0,sticky="w"); ttk.Entry(f,textvariable=q,width=38).grid(row=0,column=1,padx=6)
                ttk.Label(f,text=_tr('ui.source.vervangen.door.bd684131')).grid(row=1,column=0,sticky="w"); ttk.Entry(f,textvariable=r,width=38).grid(row=1,column=1,padx=6,pady=5)
                def repl(all_=False):
                    start="1.0" if all_ else editor.index("insert"); count=0
                    while True:
                        pos=editor.search(q.get(),start,stopindex=END,nocase=True)
                        if not pos:break
                        endp=f"{pos}+{len(q.get())}c"; editor.delete(pos,endp); editor.insert(pos,r.get()); count+=1; start=f"{pos}+{len(r.get())}c"
                        if not all_: editor.mark_set("insert",start); break
                    self._v90_status.set(_tr('ui.source.vervangen.p0.900d6a9d',p0=count))
                ttk.Button(f,text=_tr('ui.source.vervang.ad4447b2'),command=lambda:repl(False)).grid(row=2,column=0,pady=6); ttk.Button(f,text=_tr('ui.source.alles.vervangen.ec0b1fe6'),command=lambda:repl(True)).grid(row=2,column=1,pady=6)
            def update_preview():
                content=editor.get("1.0",END)
                preview.configure(state="normal")
                preview.delete("1.0",END)
                preview.insert("1.0",content)
                self._v90_apply_markdown_tags(preview)
                self._v91_preview_image_refs, missing=insert_inline_images(preview,content,getattr(self,"_v90_current_path",None),max_width=max(620,preview.winfo_width()-70))
                preview.configure(state="disabled")
                if missing: self._v90_status.set(_tr('ui.source.preview.p0.afbeelding.en.niet.gevonden.8f1310b9',p0=len(missing)))
                docs.select(preview_page)
            def update_outline():
                outline.delete(*outline.get_children())
                for n,line in enumerate(editor.get("1.0",END).splitlines(),1):
                    stripped=line.strip()
                    level=0; title=stripped
                    if stripped.startswith("### "): level=3; title=stripped[4:]
                    elif stripped.startswith("## "): level=2; title=stripped[3:]
                    elif stripped.startswith("# "): level=1; title=stripped[2:]
                    if level: outline.insert("","end",iid=f"line_{n}",text=("  "*(level-1))+title)
            outline_job=[None]
            def schedule_outline():
                if outline_job[0]:
                    try: win.after_cancel(outline_job[0])
                    except Exception: pass
                outline_job[0]=win.after(350,update_outline)
            def go_outline(_e=None):
                sel=outline.selection()
                if sel:
                    line=sel[0].split("_")[-1]; editor.mark_set("insert",f"{line}.0"); editor.see(f"{line}.0"); editor.focus_set()
            outline.bind("<Double-1>",go_outline)

            def apply_template():
                values={"title":title_var.get(),"case_id":case_id.get(),"author":author_var.get(),"date":_dt.datetime.now().strftime("%Y-%m-%d"),"project":project_name,"environment":f"Projectpad: {project_path or '-'}\nProjectManager-versie: {APP_VERSION}\nPlatform: {platform.platform()}"}
                body=self._v90_templates()[template_var.get()].format(**values)
                net_block=self._v90_network_scan_report_block()
                if net_block:
                    body += net_block
                if editor.get("1.0",END).strip() and not messagebox.askyesno(_tr('ui.source.sjabloon.toepassen.c9a19d74'),_tr('ui.source.bestaande.inhoud.vervangen.6ede8b4f'),parent=win): return
                editor.delete("1.0",END); editor.insert("1.0",body); self._v90_apply_markdown_tags(editor); update_outline(); self._v91_dirty=True
            ttk.Button(left,text=_tr('ui.source.sjabloon.toepassen.c9a19d74'),command=apply_template).pack(fill=X,pady=(6,2))
            def insert_netmap_context():
                block=self._v90_network_scan_report_block()
                if not block:
                    messagebox.showinfo(_tr('ui.source.netmap.observaties.38758189'),_tr('ui.source.geen.actuele.network.mapper.context.gevonden.7336e9f0'),parent=win);return
                editor.insert("end",block);self._v90_apply_markdown_tags(editor);update_outline();self._v91_dirty=True
            ttk.Button(left,text=_tr('ui.source.netmap.observaties.invoegen.316184ce'),command=insert_netmap_context).pack(fill=X,pady=2)
            ttk.Button(left,text=_tr('ui.source.nieuw.leeg.rapport.bbd4b407'),command=lambda:(editor.delete("1.0",END),setattr(self,"_v90_current_path",None))).pack(fill=X)

            # Evidence Explorer
            ttk.Label(right,text=_tr('ui.source.evidence.explorer.d505f368'),style="Heading.TLabel").pack(anchor="w")
            filter_var=StringVar(); ttk.Entry(right,textvariable=filter_var).pack(fill=X,pady=(5,4))
            ev_tree=ttk.Treeview(right,columns=("path",),show="tree",selectmode="browse",height=25); ev_tree.pack(fill=BOTH,expand=True)
            evidence=[]
            def refresh_evidence(*_):
                nonlocal evidence
                evidence=self._v90_collect_evidence(project_path); ev_tree.delete(*ev_tree.get_children()); cats={}; query=filter_var.get().lower().strip()
                for i,item in enumerate(evidence):
                    if query and query not in item['name'].lower() and query not in item['category'].lower(): continue
                    cat=item['category']; parent=cats.get(cat)
                    if not parent: parent=ev_tree.insert("","end",text=cat,open=True); cats[cat]=parent
                    ev_tree.insert(parent,"end",iid=f"ev_{i}",text=_tr('ui.source.p0.p1.01674de8',p0=item['name'],p1=format_bytes(item['size'])),values=(item['path'],))
            filter_var.trace_add("write",refresh_evidence)
            def insert_evidence():
                sel=ev_tree.selection()
                if not sel or not sel[0].startswith("ev_"): messagebox.showwarning(_tr('ui.source.geen.bewijs.f4c1cda3'),_tr('ui.source.selecteer.een.bewijsbestand.7f6b0aae'),parent=win); return
                path=Path(ev_tree.item(sel[0],"values")[0]); block=self._v90_evidence_text(path)
                if path.suffix.lower() in {".png",".jpg",".jpeg",".gif",".bmp"}:
                    self._v91_images.append(str(path)); block += f"\n![{path.name}]({path})\n"
                start=editor.index("insert"); editor.insert("insert","\n"+block+"\n"); end=editor.index("insert"); editor.tag_add("evidence",start,end)
                content_now=editor.get("1.0",END)
                self._v91_image_refs, missing=insert_inline_images(editor,content_now,getattr(self,"_v90_current_path",None),max_width=max(700,editor.winfo_width()-120))
                self._v91_dirty=True
            ttk.Button(right,text=_tr('ui.source.voeg.bewijs.toe.dee186f5'),command=insert_evidence).pack(fill=X,pady=(5,2))
            ttk.Button(right,text=_tr('ui.source.open.bewijsbestand.5f1b8e84'),command=lambda:self._v90_open_selected_evidence(ev_tree,win)).pack(fill=X)
            ev_tree.bind("<Double-1>",lambda e:insert_evidence())
            def evidence_press(event):
                iid=ev_tree.identify_row(event.y)
                if iid.startswith("ev_"):
                    vals=ev_tree.item(iid,"values")
                    if vals: begin_drag("evidence",vals[0],event)
            ev_tree.bind("<ButtonPress-1>",evidence_press,add="+")
            ev_tree.bind("<B1-Motion>",move_drag,add="+")
            ev_tree.bind("<ButtonRelease-1>",end_drag,add="+")
            ttk.Label(right,text=_tr('ui.source.tip.sleep.evidence.rechtstreeks.naar.de.rappor.f898d291'),wraplength=240).pack(fill=X,pady=(4,6))
            ttk.Separator(right).pack(fill=X,pady=4)
            ttk.Label(right,text=_tr('ui.source.reviewpunten.52869c62'),style="Heading.TLabel").pack(anchor="w")
            review_tree=ttk.Treeview(right,columns=("status","reviewer"),show="tree headings",height=7,selectmode="browse")
            review_tree.heading("#0",text=_tr('ui.source.opmerking.6618f521')); review_tree.heading("status",text=_tr('ui.source.status.bae7d5be')); review_tree.heading("reviewer",text=_tr('ui.source.reviewer.a74f16c1'))
            review_tree.column("#0",width=170); review_tree.column("status",width=85); review_tree.column("reviewer",width=90)
            review_tree.pack(fill=X,pady=(4,2))
            self._v93_review_tree=review_tree
            def refresh_reviews():
                review_tree.delete(*review_tree.get_children())
                for i,item in enumerate(getattr(self,"_v93_reviews",[])):
                    text=str(item.get("comment", "")); text=(text[:52]+"…") if len(text)>52 else text
                    review_tree.insert("","end",iid=f"rev_{i}",text=text,values=(item.get("status","Open"),item.get("reviewer","")))
            self._v93_refresh_reviews=refresh_reviews
            def add_review():
                try:
                    a,b=editor.index("sel.first"),editor.index("sel.last"); selected=editor.get(a,b)
                except Exception:
                    a=b=editor.index("insert"); selected=""
                comment=simpledialog.askstring(_tr('ui.source.reviewopmerking.3553a87d'),_tr('ui.source.opmerking.of.wijzigingsvoorstel.78e58d08'),parent=win)
                if not comment:return
                reviewer=author_var.get() or os.environ.get("USERNAME","") or "Reviewer"
                item={"id":str(uuid.uuid4()),"status":"Open","reviewer":reviewer,"created_at":_dt.datetime.now().isoformat(timespec="seconds"),"range":[a,b],"selected_text":selected,"comment":comment}
                self._v93_reviews.append(item); self._v93_add_audit("Review toegevoegd",comment[:120]); refresh_reviews(); self._v91_dirty=True
                if selected:
                    editor.tag_configure("review_open",background="#d9ecff",underline=True); editor.tag_add("review_open",a,b)
            def resolve_review():
                sel=review_tree.selection()
                if not sel:return
                idx=int(sel[0].split("_")[-1]); item=self._v93_reviews[idx]
                item["status"]="Afgehandeld"; item["resolved_at"]=_dt.datetime.now().isoformat(timespec="seconds")
                self._v93_add_audit("Review afgehandeld",item.get("comment","")[:120]); refresh_reviews(); self._v91_dirty=True
            def delete_review():
                sel=review_tree.selection()
                if not sel:return
                idx=int(sel[0].split("_")[-1]); item=self._v93_reviews.pop(idx)
                self._v93_add_audit("Review verwijderd",item.get("comment","")[:120]); refresh_reviews(); self._v91_dirty=True
            rb=ttk.Frame(right); rb.pack(fill=X)
            ttk.Button(rb,text=_tr('ui.source.opmerking.4fe98edd'),command=add_review).pack(side=LEFT,fill=X,expand=True,padx=(0,2))
            ttk.Button(rb,text=_tr('ui.source.afhandelen.3bad8083'),command=resolve_review).pack(side=LEFT,fill=X,expand=True,padx=2)
            ttk.Button(rb,text=_tr('ui.source.text.6a4e6e72'),command=delete_review,width=3).pack(side=LEFT,padx=(2,0))
            refresh_evidence(); refresh_reviews()

            # Menu-opdrachten
            file_m.add_command(label=_tr('ui.source.nieuw.8762a532'),accelerator="Ctrl+N",command=lambda:(editor.delete("1.0",END),setattr(self,"_v90_current_path",None)))
            file_m.add_command(label=_tr('ui.source.openen.f00cfa12'),accelerator="Ctrl+O",command=self._open_report_from_menu)
            file_m.add_command(label=_tr('ui.source.opslaan.2b030208'),accelerator="Ctrl+S",command=lambda:self._v90_save_report(False)); file_m.add_command(label=_tr('ui.source.opslaan.als.801b04c4'),accelerator="Ctrl+Shift+S",command=lambda:self._v90_save_report(True))
            file_m.add_separator(); file_m.add_command(label=_tr('ui.source.export.html.f54ec593'),command=lambda:self._v90_export_report("html")); file_m.add_command(label=_tr('ui.source.export.pdf.3dd7d56a'),command=lambda:self._v90_export_report("pdf")); file_m.add_command(label=_tr('ui.source.export.word.rtf.136b6ccc'),command=lambda:self._v90_export_report("rtf")); file_m.add_command(label=_tr('ui.source.export.markdown.a8c58424'),command=lambda:self._v90_export_report("md")); file_m.add_separator(); file_m.add_command(label=_tr('ui.source.sluiten.fe55d210'),command=close_editor)
            edit_m.add_command(label=_tr('ui.source.ongedaan.maken.7066cd24'),accelerator="Ctrl+Z",command=lambda:editor.event_generate("<<Undo>>")); edit_m.add_command(label=_tr('ui.source.opnieuw.9c282fac'),accelerator="Ctrl+Y",command=lambda:editor.event_generate("<<Redo>>")); edit_m.add_separator(); edit_m.add_command(label=_tr('ui.source.knippen.891a8fd9'),command=lambda:editor.event_generate("<<Cut>>")); edit_m.add_command(label=_tr('ui.source.kopi.ren.6ebc5343'),command=lambda:editor.event_generate("<<Copy>>")); edit_m.add_command(label=_tr('ui.source.plakken.c746aeba'),command=lambda:editor.event_generate("<<Paste>>")); edit_m.add_command(label=_tr('ui.source.alles.selecteren.9aa05858'),accelerator="Ctrl+A",command=lambda:editor.tag_add("sel","1.0","end-1c"))
            search_m.add_command(label=_tr('ui.source.zoeken.2d890f1f'),accelerator="Ctrl+F",command=lambda:self._v90_find_text(win,editor)); search_m.add_command(label=_tr('ui.source.zoeken.en.vervangen.66aa1cfa'),accelerator="Ctrl+H",command=replace_dialog)
            for lab,cmd in (("Afbeelding...",insert_image),("Tabel...",insert_table),("Evidence",insert_evidence),("Paginabreak",insert_page_break),("Opsomming",lambda:prefix_lines("- ")),("Nummering",lambda:prefix_lines("1. "))): insert_m.add_command(label=lab,command=cmd)

            # Module Framework 2.0 — installed modules can contribute report sections.
            try:
                module_report_hooks=self._intelligence_module_manager().report_contributions()
            except Exception:
                module_report_hooks=[]
            if module_report_hooks:
                module_insert_m=Menu(insert_m,tearoff=False);insert_m.add_cascade(label=_tr('ui.source.camt.module.sectie.602a3945'),menu=module_insert_m)
                def insert_module_section(package_id,hook_id):
                    try:
                        block=self._intelligence_module_manager().render_report_section(package_id,hook_id,{
                            "app":self,"project_name":project_name,"project_path":str(project_path or ""),
                            "case_id":case_id.get(),"report_title":title_var.get(),"classification":classification_var.get(),
                            "current_report":editor.get("1.0","end-1c"),
                        })
                        if not block.strip():
                            return messagebox.showinfo(_tr('ui.source.camt.module.sectie.602a3945'),_tr('ui.source.de.module.leverde.geen.rapportsectie.op.b377c8cd'),parent=win)
                        editor.insert("insert","\n"+block.strip()+"\n");self._v90_apply_markdown_tags(editor);update_outline();self._v91_dirty=True
                    except Exception as exc:messagebox.showerror(_tr('ui.source.camt.module.sectie.602a3945'),str(exc),parent=win)
                for hook in module_report_hooks:
                    module_insert_m.add_command(label=str(hook.get("label") or hook.get("package_id")),command=lambda p=hook["package_id"],h=hook["id"]:insert_module_section(p,h))
            for lab,tag in (("Titel","title"),("Kop 1","h1"),("Kop 2","h2"),("Kop 3","h3"),("Vet","bold"),("Cursief","italic"),("Onderstrepen","underline"),("Code","code"),("Citaat","quote"),("Waarschuwing","warning"),("Finding Critical","critical"),("Finding High","high"),("Finding Medium","medium"),("Finding Low","low")): format_m.add_command(label=lab,command=lambda t=tag:apply_tag(t))
            format_m.add_separator(); format_m.add_command(label=_tr('ui.source.links.uitlijnen.c4111d98'),command=lambda:clear_format()); format_m.add_command(label=_tr('ui.source.centreren.ed0dd31e'),command=lambda:apply_tag("align_center")); format_m.add_command(label=_tr('ui.source.rechts.uitlijnen.66706f84'),command=lambda:apply_tag("align_right")); format_m.add_command(label=_tr('ui.source.inspringen.6aa555f9'),command=lambda:apply_tag("indent")); format_m.add_command(label=_tr('ui.source.opmaak.wissen.0019fcb9'),command=clear_format)
            view_m.add_command(label=_tr('ui.source.preview.vernieuwen.b7e79a1a'),command=update_preview); view_m.add_command(label=_tr('ui.source.documentstructuur.vernieuwen.1eb6c82c'),command=update_outline)
            report_m.add_command(label=_tr('ui.source.sjabloon.toepassen.c9a19d74'),command=apply_template)
            report_m.add_command(label=_tr('ui.source.inhoudsopgave.genereren.64c5109f'),command=generate_toc)
            report_m.add_command(label=_tr('ui.source.evidence.invoegen.554be4a1'),command=insert_evidence)
            report_m.add_command(label=_tr('ui.source.geselecteerde.tekst.redigeren.8459fcc9'),command=redact_selection)
            report_m.add_command(label=_tr('ui.source.versiesnapshot.opslaan.7281576d'),command=lambda:self._v92_save_version_snapshot())
            report_m.add_command(label=_tr('ui.source.rapportmetadata.ee2e514b'),command=lambda:messagebox.showinfo(_tr('ui.source.rapportmetadata.ee2e514b'),_tr('ui.source.case.p0.status.p1.classificatie.p2.titel.p3.on.e835fe05',p0=case_id.get(),p1=case_status_var.get(),p2=classification_var.get(),p3=title_var.get(),p4=author_var.get(),p5=project_name),parent=win))
            review_m.add_command(label=_tr('ui.source.reviewopmerking.toevoegen.5dc440d0'),command=add_review)
            review_m.add_command(label=_tr('ui.source.geselecteerde.review.afhandelen.b21fbb75'),command=resolve_review)
            review_m.add_separator()
            review_m.add_command(label=_tr('ui.source.open.reviewpunten.tonen.1db7fb38'),command=lambda:self._v93_show_reviews())
            review_m.add_command(label=_tr('ui.source.rapportvalidatie.4c830e5a'),command=lambda:self._v93_show_validation())
            review_m.add_command(label=_tr('ui.source.case.intelligence.dashboard.e0fc4ab3'),command=lambda:self._v93_case_dashboard())
            publish_m.add_command(label=_tr('ui.source.publication.center.3631a866'),command=lambda:self._v93_publication_center())
            publish_m.add_command(label=_tr('ui.source.evidence.manifest.genereren.e105247c'),command=lambda:self._v93_generate_manifest(show_message=True))
            publish_m.add_command(label=_tr('ui.source.volledig.casepakket.zip.990c73a0'),command=lambda:self._v93_build_case_package())
            publish_m.add_separator()
            publish_m.add_command(label=_tr('ui.source.export.docx.73c8f571'),command=lambda:self._v93_export_docx())
            publish_m.add_command(label="Export TXT",command=lambda:self._v90_export_report("txt"))
            publish_m.add_command(label=_tr('ui.source.interne.publicatie.export.a331ac55'),command=lambda:self._v93_publish_profile("Intern"))
            publish_m.add_command(label=_tr('ui.source.externe.geanonimiseerde.export.f4fe3693'),command=lambda:self._v93_publish_profile("Extern"))
            publish_m.add_separator()
            publish_m.add_command(label=_tr('ui.source.definitieve.versie.vergrendelen.0bad8ab1'),command=lambda:self._v93_lock_report())
            publish_m.add_command(label=_tr('ui.source.rapport.heropenen.47489e8b'),command=lambda:self._v93_unlock_report())
            help_m.add_command(label=_tr('ui.source.sneltoetsen.de3822ad'),command=lambda:messagebox.showinfo(_tr('ui.source.sneltoetsen.de3822ad'),_tr('ui.source.ctrl.s.opslaan.ctrl.shift.s.opslaan.als.ctrl.o.5d8ccdef'),parent=win))

            # Toolbar
            tb("Nieuw",lambda:(editor.delete("1.0",END),setattr(self,"_v90_current_path",None)),"Nieuw rapport")
            tb("Open",self._open_report_from_menu,"Rapport openen"); tb("Opslaan",lambda:self._v90_save_report(False),"Opslaan")
            ttk.Separator(toolbar,orient="vertical").pack(side=LEFT,fill=Y,padx=4)
            tb("↶",lambda:editor.event_generate("<<Undo>>"),"Ongedaan maken"); tb("↷",lambda:editor.event_generate("<<Redo>>"),"Opnieuw")
            tb("Knip",lambda:editor.event_generate("<<Cut>>"),"Knippen"); tb("Kopieer",lambda:editor.event_generate("<<Copy>>"),"Kopiëren"); tb("Plak",lambda:editor.event_generate("<<Paste>>"),"Plakken")
            ttk.Separator(toolbar,orient="vertical").pack(side=LEFT,fill=Y,padx=4)
            style_var=StringVar(value=_tr('ui.source.normale.tekst.fbaa5ce9')); style_box=ttk.Combobox(toolbar,textvariable=style_var,state="readonly",width=18,values=["Normale tekst","Titel","Kop 1","Kop 2","Kop 3","Code","Citaat","Waarschuwing","Finding Critical","Finding High","Finding Medium","Finding Low"]); style_box.pack(side=LEFT,padx=3)
            style_map={"Titel":"title","Kop 1":"h1","Kop 2":"h2","Kop 3":"h3","Code":"code","Citaat":"quote","Waarschuwing":"warning","Finding Critical":"critical","Finding High":"high","Finding Medium":"medium","Finding Low":"low"}
            style_box.bind("<<ComboboxSelected>>",lambda e:clear_format() if style_var.get()=="Normale tekst" else apply_tag(style_map[style_var.get()]))
            tb("B",lambda:apply_tag("bold"),"Vet"); tb("I",lambda:apply_tag("italic"),"Cursief"); tb("U",lambda:apply_tag("underline"),"Onderstrepen")
            tb("Lijst",lambda:prefix_lines("- "),"Opsomming"); tb("1.",lambda:prefix_lines("1. "),"Nummering"); tb("Tabel",insert_table,"Tabel invoegen"); tb("Afbeelding",insert_image,"Afbeelding invoegen"); tb("TOC",generate_toc,"Inhoudsopgave"); tb("█",redact_selection,"Redigeren"); tb("Zoek",lambda:self._v90_find_text(win,editor),"Zoeken"); tb("Preview",update_preview,"Preview")

            # Vaste status- en actiebalk
            bottom=ttk.Frame(win,padding=(10,6)); bottom.grid(row=3,column=0,sticky="ew")
            self._v91_wordcount=StringVar(value=_tr('ui.source.0.woorden.27a87b3d'))
            ttk.Label(bottom,textvariable=self._v91_wordcount).pack(side=LEFT)
            zoom=IntVar(value=100); self._v92_zoom_var=zoom; ttk.Label(bottom,text=_tr('ui.source.zoom.9b3cbed5')).pack(side=LEFT,padx=(20,4)); z=ttk.Scale(bottom,from_=75,to=150,variable=zoom,orient="horizontal",length=130); z.pack(side=LEFT)
            def apply_zoom(*_):
                size=max(8,int(11*zoom.get()/100)); editor.configure(font=(family,size)); self._v91_wordcount.set(f"{len(editor.get('1.0','end-1c').split())} woorden · Zoom {zoom.get()}%")
            zoom.trace_add("write",apply_zoom)
            ttk.Button(bottom,text="TXT",command=lambda:self._v90_export_report("txt")).pack(side=RIGHT,padx=2); ttk.Button(bottom,text="DOCX",command=lambda:self._v93_export_docx()).pack(side=RIGHT,padx=2); ttk.Button(bottom,text=_tr('ui.source.html.9f738ce8'),command=lambda:self._v90_export_report("html")).pack(side=RIGHT,padx=2); ttk.Button(bottom,text=_tr('ui.source.pdf.d613d88c'),command=lambda:self._v90_export_report("pdf")).pack(side=RIGHT,padx=2); ttk.Button(bottom,text="RTF",command=lambda:self._v90_export_report("rtf")).pack(side=RIGHT,padx=2); ttk.Button(bottom,text=_tr('ui.source.sluiten.fe55d210'),command=close_editor).pack(side=RIGHT,padx=(10,2))

            ttk.Separator(toolbar,orient="vertical").pack(side=LEFT,fill=Y,padx=4)
            tb("Review",add_review,"Reviewopmerking toevoegen")
            tb("✓ Valideer",lambda:self._v93_show_validation(),"Rapport valideren")
            tb("Publiceer",lambda:self._v93_publication_center(),"Publication Center")

            def autosave():
                try:
                    if self._v91_dirty and getattr(self,"_v90_current_path",None): self._v90_save_report(False,quiet=True)
                    elif self._v91_dirty:
                        auto=self._v90_home()/"autosave"; auto.mkdir(exist_ok=True); p=auto/(re.sub(r"[^A-Za-z0-9_.-]+","_",case_id.get())+".autosave.pmreport.json")
                        p.write_text(json.dumps(self._v90_report_payload(),indent=2,ensure_ascii=False),encoding="utf-8"); self._v90_status.set(_tr('ui.source.autosave.p0.8424d2e8',p0=p.name))
                except Exception: pass
                self._v91_autosave_id=win.after(60000,autosave)
            self._v91_autosave_id=win.after(60000,autosave)

            # Sneltoetsen
            bindings={"<Control-s>":lambda e:self._v90_save_report(False),"<Control-Shift-S>":lambda e:self._v90_save_report(True),"<Control-o>":lambda e:self._open_report_from_menu(),"<Control-f>":lambda e:self._v90_find_text(win,editor),"<Control-h>":lambda e:replace_dialog(),"<Control-b>":lambda e:apply_tag("bold"),"<Control-i>":lambda e:apply_tag("italic"),"<Control-u>":lambda e:apply_tag("underline"),"<Control-a>":lambda e:editor.tag_add("sel","1.0","end-1c")}
            for seq,fn in bindings.items(): editor.bind(seq,fn)

            if open_path: self._v90_load_into_editor(open_path)
            elif new_report or not editor.get("1.0",END).strip(): apply_template()
            update_outline(); apply_zoom(); editor.focus_set()
        def _v90_report_payload(self) -> dict:
            cid,title,author,template,case_status,classification=self._v90_case_vars
            editor=self._v90_editor
            formatting={}
            keep={"title","h1","h2","h3","bold","italic","underline","code","quote","warning","critical","high","medium","low","evidence","align_center","align_right","indent"}
            for tag in keep:
                ranges=list(editor.tag_ranges(tag))
                if ranges: formatting[tag]=[[str(ranges[i]),str(ranges[i+1])] for i in range(0,len(ranges),2)]
            return {"schema":"ProjectManager.ReportStudio.4","version":APP_VERSION,"case_id":cid.get(),"title":title.get(),"author":author.get(),"template":template.get(),"case_status":case_status.get(),"classification":classification.get(),"updated_at":_dt.datetime.now().isoformat(timespec="seconds"),"project":getattr(getattr(self,"selected_project",None),"name","") or "","project_path":str(getattr(getattr(self,"selected_project",None),"path","") or ""),"content":editor.get("1.0",END).rstrip()+"\n","notes":getattr(self,"_v91_notes",None).get("1.0",END).rstrip()+"\n" if getattr(self,"_v91_notes",None) else "","formatting":formatting,"images":list(getattr(self,"_v91_images",[])),"linked_sources":list(getattr(self,"_v92_linked_sources",[])),"reviews":list(getattr(self,"_v93_reviews",[])),"audit_log":list(getattr(self,"_v93_audit",[])),"locked":bool(getattr(self,"_v93_locked",False)),"publication_profile":getattr(self,"_v93_publication_profile","Intern"),"layout":{"page":"A4","orientation":"portrait","zoom":getattr(getattr(self,"_v92_zoom_var",None),"get",lambda:100)()}}
        def _v90_save_report(self, save_as: bool=False, quiet: bool=False) -> None:
            self._v93_add_audit("Rapport opgeslagen", "Opslaan als" if save_as else "Opslaan")
            payload=self._v90_report_payload(); case_dir=self._v90_case_dir(payload['case_id'])
            path=getattr(self,"_v90_current_path",None)
            if save_as or not path:
                default=re.sub(r"[^A-Za-z0-9_.-]+","_",payload['title'])[:80]+".pmreport.json"
                chosen=filedialog.asksaveasfilename(title=_tr('ui.source.rapport.opslaan.78b9f8ad'),initialdir=str(case_dir/'reports'),initialfile=default,defaultextension=".pmreport.json",filetypes=[(_tr('ui.source.report.studio.7d55a3c4'),"*.pmreport.json")])
                if not chosen:return
                path=Path(chosen)
            path.write_text(json.dumps(payload,indent=2,ensure_ascii=False),encoding="utf-8"); self._v90_current_path=path
            sha=hashlib.sha256(path.read_bytes()).hexdigest(); path.with_suffix(path.suffix+".sha256").write_text(f"{sha}  {path.name}\n",encoding="utf-8")
            self._v90_status.set(_tr('ui.source.opgeslagen.p0.c7da7e5b',p0=path))
            self._v91_dirty=False
            try: self._report_studio.title(_tr('ui.source.professional.report.editor.v.p0.59551f1c',p0=APP_VERSION))
            except Exception: pass
            if not quiet: messagebox.showinfo(_tr('ui.source.rapport.opgeslagen.c1c08c65'),_tr('ui.source.rapport.opgeslagen.p0.70696287',p0=path),parent=self._report_studio)
        def _v90_load_into_editor(self, path: Path) -> None:
            try:
                data={}; formatting={}
                if path.suffix.lower()==".json" or path.name.endswith(".pmreport.json"):
                    raw=path.read_text(encoding="utf-8-sig")
                    if not raw.strip():
                        raise ValueError("This report file is empty. Create or export the report again.")
                    try:
                        data=json.loads(raw)
                    except json.JSONDecodeError as exc:
                        raise ValueError(f"This is not a valid CAMT report project (JSON error at line {exc.lineno}, column {exc.colno}).") from None
                    if not isinstance(data,dict):
                        raise ValueError("This CAMT report does not contain a valid report object.")
                    content=str(data.get("content") or data.get("markdown") or data.get("report_markdown") or "")
                    if not content.strip():
                        raise ValueError("The selected JSON contains no report text. Open a .pmreport.json report project or create the report again from its source module.")
                    formatting=data.get("formatting",{}) or {}
                    cid,title,author,template,case_status,classification=self._v90_case_vars
                    cid.set(data.get("case_id",cid.get())); title.set(data.get("title",title.get())); author.set(data.get("author",author.get()))
                    case_status.set(data.get("case_status",case_status.get())); classification.set(data.get("classification",classification.get()))
                    if data.get("template") in self._v90_templates(): template.set(data['template'])
                else: content=path.read_text(encoding="utf-8",errors="ignore")
                ed=self._v90_editor; ed.delete("1.0",END); ed.insert("1.0",content); self._v90_apply_markdown_tags(ed)
                self._v91_image_refs, missing_images=insert_inline_images(ed,content,path,max_width=max(700,ed.winfo_width()-120))
                for tag,ranges in formatting.items():
                    for pair in ranges:
                        try: ed.tag_add(tag,pair[0],pair[1])
                        except Exception: pass
                if getattr(self,"_v91_notes",None):
                    self._v91_notes.delete("1.0",END); self._v91_notes.insert("1.0",data.get("notes",""))
                self._v91_images=list(data.get("images",[])); self._v92_linked_sources=list(data.get("linked_sources",[]))
                self._v93_reviews=list(data.get("reviews",[])); self._v93_audit=list(data.get("audit_log",[])); self._v93_locked=bool(data.get("locked",False)); self._v93_publication_profile=data.get("publication_profile","Intern")
                if getattr(self,"_v93_refresh_reviews",None): self._v93_refresh_reviews()
                try: ed.configure(state="disabled" if self._v93_locked else "normal")
                except Exception: pass
                self._v90_current_path=path; self._v91_dirty=False
                if missing_images:
                    self._v90_status.set(_tr('ui.source.geopend.p0.p1.afbeelding.en.niet.gevonden.6e5d77a5',p0=path,p1=len(missing_images)))
                else:
                    self._v90_status.set(_tr('ui.source.geopend.p0.p1.afbeelding.en.geladen.1946f6f9',p0=path,p1=len(self._v91_image_refs)))
                try: self._report_studio.title(_tr('ui.source.professional.report.editor.p0.e3c363ae',p0=path.name))
                except Exception: pass
            except Exception as exc: messagebox.showerror(_tr('ui.source.openen.mislukt.62fabf49'),str(exc),parent=self._report_studio)
        def _v90_export_report(self, kind: str) -> None:
            self._v93_add_audit("Rapport geëxporteerd", kind.upper())
            payload=self._v90_report_payload(); case_dir=self._v90_case_dir(payload['case_id'])/'exports'; case_dir.mkdir(parents=True,exist_ok=True)
            safe=re.sub(r"[^A-Za-z0-9_.-]+","_",payload['title'])[:80] or "rapport"
            ext={"html":".html","pdf":".pdf","rtf":".rtf","md":".md","txt":".txt"}[kind]
            chosen=filedialog.asksaveasfilename(title=_tr('ui.source.export.p0.5462bcff',p0=kind.upper()),initialdir=str(case_dir),initialfile=safe+ext,defaultextension=ext)
            if not chosen:return
            path=Path(chosen); content=payload['content']
            try:
                if kind in ("md","txt"): path.write_text(content,encoding="utf-8")
                elif kind=="html":
                    import shutil
                    source_base=Path(getattr(self,'_v90_current_path',path)).parent
                    export_assets=path.parent/(path.stem+'_assets'); export_assets.mkdir(parents=True,exist_ok=True)
                    html_content=content
                    for image in payload.get('images',[]):
                        src=(source_base/str(image)).resolve() if not Path(str(image)).is_absolute() else Path(str(image))
                        if src.exists():
                            dst=export_assets/src.name; shutil.copy2(src,dst)
                            html_content=html_content.replace(f']({image})',f']({export_assets.name}/{dst.name})')
                    body=self._v90_markdown_to_html(html_content)
                    html_doc = "<!doctype html><html><head><meta charset=\"utf-8\"><title>" + str(payload["title"]) + "</title><style>" + """
                    :root{--ink:#172536;--muted:#617083;--line:#dbe4ee;--accent:#245b88}
                    *{box-sizing:border-box}body{font-family:Segoe UI,Arial,sans-serif;max-width:1240px;margin:0 auto;padding:46px 54px 80px;line-height:1.55;color:var(--ink);background:#eef2f6}
                    body>h1:first-of-type{margin:-46px -54px 34px;padding:44px 54px 38px;background:linear-gradient(135deg,#17365d,#0f7182);color:white;font-size:30px;box-shadow:0 10px 28px rgba(20,45,70,.18)}
                    h1{color:#17365d}h2{color:#17365d;margin-top:34px;padding-bottom:8px;border-bottom:2px solid #d6e3ee}h3{color:#245b88}
                    p{background:white;margin:8px 0;padding:12px 15px;border-radius:8px}ul{background:white;padding:14px 20px 14px 40px;border-radius:8px}
                    .table-wrap{overflow-x:auto;margin:16px 0 24px;border-radius:10px;box-shadow:0 4px 18px rgba(26,54,80,.08);background:white}
                    table{width:100%;border-collapse:collapse;font-size:13px}thead{background:linear-gradient(90deg,#17365d,#245b88);color:white}th{padding:11px 12px;text-align:left}td{padding:10px 12px;border-bottom:1px solid var(--line);vertical-align:top}tbody tr:nth-child(even){background:#f6f9fc}
                    pre{background:#152331;color:#e8f0f6;padding:16px;border-radius:8px}.spacer{height:5px}
                    @media print{body{background:white;margin:0;padding:12mm}.table-wrap{box-shadow:none;page-break-inside:avoid}}
                    """ + "</style></head><body>" + body + "</body></html>"
                    path.write_text(html_doc,encoding="utf-8")
                elif kind=="pdf":
                    export_pdf(path,payload['title'],content,payload.get('images',[]),getattr(self,'_v90_current_path',None))
                elif kind=="rtf":
                    export_rtf(path,content,payload.get('images',[]),getattr(self,'_v90_current_path',None))
                sha=hashlib.sha256(path.read_bytes()).hexdigest(); path.with_suffix(path.suffix+".sha256").write_text(f"{sha}  {path.name}\n",encoding="utf-8")
                self._v90_status.set(_tr('ui.source.ge.xporteerd.p0.e2981a85',p0=path))
                messagebox.showinfo(_tr('ui.source.export.gereed.08ecb02d'),_tr('ui.source.rapport.ge.xporteerd.p0.sha.256.p1.880aa659',p0=path,p1=sha),parent=self._report_studio)
            except Exception as exc: messagebox.showerror(_tr('ui.source.export.mislukt.64f5bcf1'),str(exc),parent=self._report_studio)
        def _v93_validate_report(self) -> dict:
            payload=self._v90_report_payload(); text=payload.get("content",""); issues=[]; warnings=[]
            required=[("Managementsamenvatting","managementsamenvatting"),("Conclusie","conclusie"),("Aanbevelingen","aanbevel")]
            low=text.lower()
            for label,needle in required:
                if needle not in low: issues.append(f"Verplicht onderdeel ontbreekt: {label}.")
            if not payload.get("title","").strip(): issues.append("Rapporttitel ontbreekt.")
            if not payload.get("author","").strip(): issues.append("Auteur/onderzoeker ontbreekt.")
            if payload.get("classification") in {"","Concept"}: warnings.append("Classificatie is leeg of staat nog op Concept.")
            open_reviews=[r for r in payload.get("reviews",[]) if r.get("status","Open") not in {"Afgehandeld","Afgewezen"}]
            if open_reviews: issues.append(f"Er staan nog {len(open_reviews)} open reviewpunten.")
            missing=[]; changed=[]
            for src in payload.get("linked_sources",[]):
                path=Path(src.get("path", ""))
                if not path.exists(): missing.append(str(path)); continue
                expected=src.get("sha256","")
                if expected:
                    try:
                        current=hashlib.sha256(path.read_bytes()).hexdigest()
                        if current.lower()!=expected.lower(): changed.append(str(path))
                    except Exception: warnings.append(f"Hash kon niet worden gecontroleerd: {path}")
            if missing: issues.append(f"{len(missing)} gekoppelde evidencebestanden ontbreken.")
            if changed: issues.append(f"{len(changed)} evidencebestanden hebben een gewijzigde SHA-256.")
            placeholders=["vul hier","[titel]","nog invullen","niet gecontroleerd"]
            found=[p for p in placeholders if p in low]
            if found: warnings.append("Mogelijke concept-/placeholdertekst aanwezig: "+", ".join(found)+".")
            status="Publicatie toegestaan" if not issues and not warnings else ("Publicatie met waarschuwingen" if not issues else "Publicatie geblokkeerd")
            return {"status":status,"issues":issues,"warnings":warnings,"missing_evidence":missing,"changed_evidence":changed,"open_reviews":len(open_reviews)}
        def _v93_build_case_package(self) -> None:
            payload=self._v90_report_payload(); result=self._v93_validate_report()
            if result["issues"] and not messagebox.askyesno(_tr('ui.source.casepakket.met.blokkades.c608edee'),_tr('ui.source.het.rapport.bevat.publicatieblokkades.toch.een.d4c4352c'),parent=getattr(self,"_report_studio",self.root)): return
            case_dir=self._v90_case_dir(payload["case_id"]); self._v93_generate_manifest(False)
            package_dir=case_dir/"exports"; package_dir.mkdir(parents=True,exist_ok=True)
            path=package_dir/f"{payload['case_id']}_casepakket_{_dt.datetime.now().strftime('%Y%m%d_%H%M%S')}.zip"
            manifest=[]
            with zipfile.ZipFile(path,"w",zipfile.ZIP_DEFLATED) as zf:
                for file in case_dir.rglob("*"):
                    if not file.is_file() or file==path: continue
                    rel=file.relative_to(case_dir); zf.write(file,rel.as_posix())
                    try: manifest.append({"path":rel.as_posix(),"sha256":hashlib.sha256(file.read_bytes()).hexdigest(),"size":file.stat().st_size})
                    except Exception: pass
                case_json=json.dumps({"case_id":payload["case_id"],"title":payload["title"],"generated_at":_dt.datetime.now().isoformat(timespec="seconds"),"files":manifest},indent=2,ensure_ascii=False)
                zf.writestr("package_manifest.json",case_json)
            sha=hashlib.sha256(path.read_bytes()).hexdigest(); path.with_suffix(path.suffix+".sha256").write_text(f"{sha}  {path.name}\n",encoding="utf-8")
            self._v93_add_audit("Casepakket gemaakt",str(path)); messagebox.showinfo(_tr('ui.source.casepakket.8afedbd1'),_tr('ui.source.casepakket.opgeslagen.p0.bestanden.p1.2f3c9a67',p0=path,p1=len(manifest)),parent=getattr(self,"_report_studio",self.root))
        def _v93_lock_report(self) -> None:
            result=self._v93_validate_report()
            if result["issues"]:
                messagebox.showerror(_tr('ui.source.vergrendeling.geblokkeerd.5a7128d0'),_tr('ui.source.het.rapport.kan.niet.definitief.worden.vergren.79cdae4b'),parent=getattr(self,"_report_studio",self.root)); return
            if not messagebox.askyesno(_tr('ui.source.definitief.vergrendelen.1ef8c7b1'),_tr('ui.source.het.rapport.wordt.read.only.latere.wijzigingen.91150e64'),parent=getattr(self,"_report_studio",self.root)): return
            self._v93_locked=True; self._v93_add_audit("Rapport vergrendeld","Definitieve versie")
            try: self._v90_editor.configure(state="disabled")
            except Exception: pass
            self._v90_save_report(False)
        def _v93_unlock_report(self) -> None:
            if not getattr(self,"_v93_locked",False):
                messagebox.showinfo(_tr('ui.source.heropenen.26305ac0'),_tr('ui.source.rapport.is.niet.vergrendeld.cdcff43f'),parent=getattr(self,"_report_studio",self.root)); return
            reason=simpledialog.askstring(_tr('ui.source.rapport.heropenen.47489e8b'),_tr('ui.source.verplichte.reden.voor.heropening.344c9a3d'),parent=getattr(self,"_report_studio",self.root))
            if not reason:return
            self._v93_locked=False; self._v93_add_audit("Rapport heropend",reason)
            try: self._v90_editor.configure(state="normal")
            except Exception: pass
            self._v91_dirty=True
        def _v93_case_dashboard(self) -> None:
            payload=self._v90_report_payload(); val=self._v93_validate_report(); evidence=payload.get("linked_sources",[]); reviews=payload.get("reviews",[])
            lines=["CASE INTELLIGENCE DASHBOARD","",f"Case-ID: {payload['case_id']}",f"Titel: {payload['title']}",f"Status: {payload['case_status']}",f"Classificatie: {payload['classification']}",f"Vergrendeld: {'Ja' if payload.get('locked') else 'Nee'}",f"Publicatieprofiel: {payload.get('publication_profile','Intern')}","",f"Evidence-items: {len(evidence)}",f"Reviewpunten totaal: {len(reviews)}",f"Open reviewpunten: {val['open_reviews']}",f"Validatiestatus: {val['status']}",f"Blokkades: {len(val['issues'])}",f"Waarschuwingen: {len(val['warnings'])}",f"Auditregels: {len(payload.get('audit_log',[]))}"]
            self._show_large_text_window("Case Intelligence Dashboard","\n".join(lines))
