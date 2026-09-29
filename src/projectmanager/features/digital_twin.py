from __future__ import annotations
from projectmanager.i18n import tr as _tr
import math
import json
import ipaddress
from copy import deepcopy
from projectmanager.core.shared import *
from projectmanager.ui.device_icons import draw_device_icon
from projectmanager.assets import AssetRepository, NetworkAsset, AssetRelationship, AssetImport
from projectmanager.cti import CTIRepository
from projectmanager.scenario_engine import ScenarioEngineRepository, normalize_scenario, write_management_report, write_report_studio_document, validate_report_inputs
from projectmanager.simulation_lab import SimulationLabBridge


class DigitalTwinMixin:
    """Glossy live Network Digital Twin with CTI, risk and coverage overlays."""

    _DT = {"bg":"#06101d","panel":"#0b1928","panel2":"#10243a","line":"#294c68","text":"#edf8ff","muted":"#8eb4cf","cyan":"#31d7ff","violet":"#8a6cff","good":"#35dc91","warn":"#ffbf4d","bad":"#ff5973"}

    def _show_digital_twin(self, event=None):
        asset_repo=AssetRepository(get_app_home_dir()); scenario_repo=ScenarioEngineRepository(get_app_home_dir()); cti_repo=CTIRepository()
        actors=sorted(cti_repo.list('actors'),key=lambda a:a.name.lower())
        base_theme = self._current_theme() if hasattr(self, '_current_theme') else {}
        p={
            'bg':base_theme.get('bg',self._DT['bg']), 'panel':base_theme.get('panel',self._DT['panel']),
            'panel2':base_theme.get('panel2',self._DT['panel2']), 'line':base_theme.get('border',self._DT['line']),
            'text':base_theme.get('text',self._DT['text']), 'muted':base_theme.get('muted',self._DT['muted']),
            'cyan':base_theme.get('accent',self._DT['cyan']), 'violet':base_theme.get('accent',self._DT['violet']),
            'good':base_theme.get('ok',self._DT['good']), 'warn':base_theme.get('warning',self._DT['warn']),
            'bad':base_theme.get('danger',self._DT['bad'])}
        template_var=StringVar(value=self._theme_label(self.theme_var.get()) if hasattr(self,'_theme_label') else 'Hoofdtemplate')
        win=self._new_tool_window(); win.title(_tr('ui.source.p0.unified.visual.workspace.0d76e654',p0=APP_NAME)); win.geometry('1540x900'); win.minsize(1120,700); win.resizable(True,True); win.configure(bg=p['bg'])
        try:
            win.attributes('-toolwindow', False)
        except TclError:
            pass
        pending_telemetry=getattr(self,'_pending_telemetry_analysis',None) or {}
        status=StringVar(value=_tr('ui.source.digital.twin.laden.6c9f5a27')); import_var=StringVar(); actor_var=StringVar(value=_tr('ui.source.geen.actor.b71b1bc6')); overlay_var=StringVar(value=_tr('ui.source.basis.83d956f4')); auto_var=BooleanVar(value=True); search_var=StringVar(); filter_var=StringVar(value=_tr('ui.source.alle.assets.fec10f44')); compare_var=BooleanVar(value=False); node_size_var=StringVar(value=_tr('ui.source.auto.c614ba7c')); spacing_var=StringVar(value=_tr('ui.source.normaal.c7bf278c'))
        state={'assets':[],'rels':[],'imports':[],'positions':{},'manual_positions':set(),'asset_map':{},'signature':'','after':None,'scale':1.0,'offset':[0.0,0.0],'drag':None,'node_drag':None,'selected':'','pulse':0,'pulse_job':None,'mode':'empty','scenario':None,'all_assets':[],'all_rels':[],'design_assets':[],'design_rels':[],'baseline_import_id':'','connect_source':'','scan_assets':[],'scan_rels':[],'scenario_assets':[],'scenario_rels':[],'scenario_overlay_ids':set(),'scenario_asset_map':{},'active_path_ids':[],'active_path_name':''}

        shell=Frame(win,bg=p['bg']); shell.pack(fill=BOTH,expand=True)
        header=Frame(shell,bg=p['panel'],height=72); header.pack(fill=X); header.pack_propagate(False)
        Label(header,text=_tr('ui.source.network.digital.twin.3af7f1b6'),font=('Segoe UI Semibold',18),bg=p['panel'],fg=p['text']).pack(side=LEFT,padx=18,pady=(12,0),anchor='n')
        Label(header,textvariable=status,font=('Segoe UI',9),bg=p['panel'],fg=p['muted']).pack(side=RIGHT,padx=18)
        if hasattr(self,'_theme_choices'):
            template_box=ttk.Combobox(header,textvariable=template_var,values=[self._theme_label(x) for x in self._theme_choices()],state='readonly',width=18)
            template_box.pack(side=RIGHT,padx=6,pady=20)
            Label(header,text=_tr('ui.source.template.3ec1ae06'),font=('Segoe UI',9),bg=p['panel'],fg=p['muted']).pack(side=RIGHT,pady=20)
            def switch_template(_event=None):
                selected=self._theme_from_label(template_var.get())
                if selected==self.theme_var.get(): return
                self._set_theme(selected)
                win.destroy()
                self.root.after(50,self._show_digital_twin)
            template_box.bind('<<ComboboxSelected>>',switch_template)
        actions=Frame(shell,bg=p['panel'],height=54); actions.pack(fill=X,padx=14,pady=(10,0)); actions.pack_propagate(False)
        def action_button(text, command, accent=False):
            Button(actions,text=text,font=('Segoe UI Semibold',9),bd=0,padx=12,pady=7,
                   bg=p['cyan'] if accent else p['panel2'],fg='#06101d' if accent else p['text'],
                   activebackground=p['violet'],activeforeground='white',command=command).pack(side=LEFT,padx=3,pady=9)
        def clear_workspace():
            state.update(assets=[], rels=[], positions={}, manual_positions=set(), asset_map={}, selected='', scenario=None,
                         mode='empty', design_assets=[], design_rels=[], baseline_import_id='', connect_source='', scan_assets=[], scan_rels=[], scenario_assets=[], scenario_rels=[], active_path_ids=[], active_path_name='')
            compare_var.set(False); import_var.set('')
            asset_list.delete(0,END); detail.delete('1.0',END); canvas.delete('all'); mini.delete('all')
            for key in metric_labels if 'metric_labels' in locals() else ():
                metric_labels[key].configure(text=_tr('ui.source.text.1b93795b'))
            status.set(_tr('ui.source.lege.workspace.laad.een.scan.scenario.of.ontwe.1c722cb1'))

        def _ask_node(kind='node'):
            dlg=self._new_tool_window(parent=win); dlg.title(_tr('dt.dialog.add_intermediary') if kind=='intermediary' else _tr('dt.dialog.add_node')); dlg.geometry('460x520'); dlg.transient(win); dlg.grab_set(); dlg.configure(bg=p['bg'])
            vals={'name':StringVar(value=_tr('digital_twin.new_firewall') if kind=='intermediary' else _tr('digital_twin.new_asset')),
                  'type':StringVar(value='firewall' if kind=='intermediary' else 'server'),
                  'ip':StringVar(), 'zone':StringVar(value=_tr('ui.source.design.59b03536')), 'risk':StringVar(value=_tr('ui.source.20.91032ad7')),
                  'criticality':StringVar(value=_tr('ui.source.50.e1822db4')), 'services':StringVar(), 'notes':StringVar(value=_tr('ui.source.handmatig.toegevoegd.in.design.mode.f42b6da9'))}
            Label(dlg,text=_tr('ui.source.design.asset.0b85d768'),font=('Segoe UI Semibold',15),bg=p['bg'],fg=p['text']).pack(anchor='w',padx=18,pady=(16,10))
            form=Frame(dlg,bg=p['panel']); form.pack(fill=BOTH,expand=True,padx=18,pady=(0,12))
            fields=[('Naam','name'),('Type','type'),('IP / subnet','ip'),('Zone','zone'),('Risk 0-100','risk'),('Criticality 0-100','criticality'),('Services (80/http,443/https)','services'),('Notitie','notes')]
            entries={}
            for label,key in fields:
                Label(form,text=label,bg=p['panel'],fg=p['muted'],anchor='w').pack(fill=X,padx=12,pady=(9,2))
                e=Entry(form,textvariable=vals[key],bg=p['panel2'],fg=p['text'],insertbackground=p['cyan'],relief='flat'); e.pack(fill=X,padx=12,ipady=5); entries[key]=e
            def save_node():
                try:
                    risk=max(0,min(100,int(vals['risk'].get() or 0))); crit=max(0,min(100,int(vals['criticality'].get() or 50)))
                except ValueError:
                    messagebox.showwarning(_tr('ui.source.design.asset.770bfa48'),_tr('ui.source.risk.en.criticality.moeten.getallen.zijn.68a1e820'),parent=dlg); return
                services=[]
                from projectmanager.assets import NetworkService
                for item in vals['services'].get().split(','):
                    item=item.strip()
                    if not item: continue
                    parts=item.split('/',1)
                    try: port=int(parts[0])
                    except ValueError: continue
                    services.append(NetworkService(port=port,name=parts[1] if len(parts)>1 else 'unknown'))
                a=NetworkAsset(name=vals['name'].get().strip() or _tr('digital_twin.new_asset'),ip=vals['ip'].get().strip(),asset_type=vals['type'].get().strip().lower() or 'asset',role='Intermediary' if kind=='intermediary' else 'Design asset',zone=vals['zone'].get().strip() or 'Design',risk_score=risk,criticality=crit,services=services,notes=vals['notes'].get().strip(),source='Design',source_import_id='design-layer')
                state['design_assets'].append(a); state['mode']='design'; merge_design(); dlg.destroy(); fit_view(); status.set(_tr('ui.source.design.asset.toegevoegd.p0.1513e3f8',p0=a.name))
            Button(dlg,text=_tr('ui.source.toevoegen.4d20d218'),command=save_node,bg=p['cyan'],fg='#06101d',bd=0,padx=16,pady=8).pack(pady=(0,14))

        def merge_design():
            base=[a for a in state.get('assets',[]) if a.source!='Design']
            base_rels=[r for r in state.get('rels',[]) if r.source_import_id!='design-layer']
            state['assets']=base+list(state['design_assets']); state['rels']=base_rels+list(state['design_rels']); state['asset_map']={a.asset_id:a for a in state['assets']}
            asset_list.delete(0,END)
            for a in state['assets']: asset_list.insert(END,f'  {a.name or a.ip}   | {a.role} | R{a.risk_score}')

        def connect_nodes():
            aid=state.get('selected')
            if not aid:
                messagebox.showwarning(_tr('ui.source.verbinden.cd3336ed'),_tr('ui.source.selecteer.eerst.een.bronnode.in.de.kaart.of.as.ce6bffdb'),parent=win); return
            if not state.get('connect_source'):
                state['connect_source']=aid; status.set(_tr('ui.source.bron.geselecteerd.selecteer.doelnode.en.klik.o.796f97eb')); return
            source=state.pop('connect_source'); target=aid
            if source==target:
                status.set(_tr('ui.source.bron.en.doel.zijn.gelijk.verbinding.geannuleer.57c32979')); return
            rel=AssetRelationship(source_asset_id=source,target_asset_id=target,relationship_type='designed_route',label=_tr('ui.source.design.route.69b60c8a'),confidence=90,source_import_id='design-layer')
            state['design_rels'].append(rel); state['mode']='design'; merge_design(); draw(); status.set(_tr('ui.source.designverbinding.toegevoegd.41bd38a1'))

        def delete_selected():
            aid=state.get('selected')
            if not aid: messagebox.showwarning(_tr('ui.source.verwijderen.6bc766d0'),_tr('ui.source.selecteer.eerst.een.handmatig.toegevoegd.asset.6aed034a'),parent=win); return
            asset=next((a for a in state['design_assets'] if a.asset_id==aid),None)
            if not asset: messagebox.showwarning(_tr('ui.source.verwijderen.6bc766d0'),_tr('ui.source.alleen.handmatig.toegevoegde.design.assets.kun.fc8426e7'),parent=win); return
            state['design_assets']=[a for a in state['design_assets'] if a.asset_id!=aid]
            state['design_rels']=[r for r in state['design_rels'] if r.source_asset_id!=aid and r.target_asset_id!=aid]
            state['selected']=''; merge_design(); fit_view(); status.set(_tr('ui.source.design.asset.verwijderd.p0.d4d240ce',p0=asset.name))

        def save_design():
            if not state['design_assets']:
                messagebox.showwarning(_tr('ui.source.design.opslaan.1e5c6f21'),_tr('ui.source.er.zijn.geen.handmatig.toegevoegde.assets.a8716245'),parent=win); return
            assets,rels,imports=asset_repo.load()
            assets=[a for a in assets if a.source_import_id!='design-layer']+state['design_assets']
            rels=[r for r in rels if r.source_import_id!='design-layer']+state['design_rels']
            imports=[i for i in imports if i.import_id!='design-layer']+[AssetImport(import_id='design-layer',source='Design Workspace',asset_count=len(state['design_assets']),relationship_count=len(state['design_rels']))]
            asset_repo.save(assets,rels,imports); status.set(_tr('ui.source.designlaag.opgeslagen.in.asset.repository.e52f9a22'))

        def apply_scenario():
            if not state.get('assets'):
                messagebox.showwarning(_tr('ui.source.scenario.toepassen.0fa17298'),_tr('ui.source.laad.eerst.een.scan.of.bouw.een.design.baselin.14de0339'),parent=win); return
            load_scenario()
            if state.get('scenario'):
                activate_mode('compare'); compare_var.set(True); visualize(); status.set(_tr('ui.source.scenario.p0.toegepast.op.huidige.baseline.86bf8201',p0=state['scenario'].name))

        def analyse_design():
            if not state.get('assets'):
                messagebox.showwarning(_tr('ui.source.analyseren.130c8258'),_tr('ui.source.er.is.geen.baseline.of.design.om.te.analyseren.c952b92e'),parent=win); return
            avg=round(sum(a.risk_score for a in state['assets'])/max(1,len(state['assets'])))
            critical=sum(1 for a in state['assets'] if a.risk_score>=70)
            intermediaries=sum(1 for a in state['assets'] if (a.role or '').lower()=='intermediary')
            summary=(_tr('ui.source.assets.p0.intermediary.devices.p1.relaties.p2..c033cb14',p0=len(state['assets']),p1=intermediaries,p2=len(state['rels']),p3=avg,p4=critical))
            messagebox.showinfo(_tr('ui.source.what.if.analyse.192c0f67'),summary,parent=win)

        def scenario_graph(sc):
            """Build a standalone graph exclusively from scenario steps."""
            assets=[]; rels=[]; seen={}; ordered=[]
            for step in sorted(sc.steps,key=lambda item:item.order):
                aid=(step.asset_id or step.asset_name or f'scenario-{step.order}').strip()
                if not aid: continue
                if aid not in seen:
                    name=step.asset_name or step.asset_id or f'Asset {step.order}'
                    low=name.lower()
                    atype='plc' if 'plc' in low else 'camera' if 'camera' in low else 'firewall' if 'firewall' in low else 'router' if 'router' in low else 'switch' if 'switch' in low else 'database' if ('sql' in low or 'historian' in low) else 'server' if ('server' in low or 'scada' in low) else 'endpoint'
                    zone='OT' if any(x in low for x in ('plc','scada','historian','brug','sluis','tunnel','sensor')) else 'DMZ' if any(x in low for x in ('web','vpn','firewall')) else 'IT'
                    seen[aid]=NetworkAsset(asset_id=aid,name=name,asset_type=atype,role='Scenario asset',zone=zone,criticality=max(50,step.impact),risk_score=step.step_risk or round((step.likelihood+step.impact)/2),confidence=85,notes=step.action,source_import_id='scenario-only',source='Scenario',attack_techniques=[step.technique_id] if step.technique_id else [],recommendations=list(sc.recommendations))
                    assets.append(seen[aid])
                else:
                    a=seen[aid]; a.risk_score=max(a.risk_score,step.step_risk or round((step.likelihood+step.impact)/2))
                    if step.technique_id and step.technique_id not in a.attack_techniques:a.attack_techniques.append(step.technique_id)
                if not ordered or ordered[-1]!=aid: ordered.append(aid)
            for source,target in zip(ordered,ordered[1:]):
                rels.append(AssetRelationship(source_asset_id=source,target_asset_id=target,relationship_type='scenario_path',label=_tr('ui.source.scenario.step.9c07ff11'),confidence=85,source_import_id='scenario-only'))
            return assets,rels

        def build_scenario_overlay():
            """Return full baseline plus scenario enrichment and remapped scenario relations."""
            baseline=list(state.get('scan_assets') or [])
            scenario_assets=list(state.get('scenario_assets') or [])
            scenario_rels=list(state.get('scenario_rels') or [])

            # Without a loaded scan there is no baseline to preserve. In that case the
            # scenario graph remains usable, but it is explicitly a scenario-only fallback.
            if not baseline:
                ids={a.asset_id for a in scenario_assets}
                state['scenario_overlay_ids']=ids
                state['scenario_asset_map']={a.asset_id:a.asset_id for a in scenario_assets}
                return list(scenario_assets),list(scenario_rels)

            visual=[deepcopy(a) for a in baseline]
            by_id={a.asset_id:a for a in visual}
            by_ip={str(a.ip or '').strip().casefold():a for a in visual if str(a.ip or '').strip()}
            by_name={}
            for a in visual:
                for raw in (getattr(a,'name',''),getattr(a,'hostname','')):
                    key=str(raw or '').strip().casefold()
                    if key: by_name.setdefault(key,a)

            overlay_ids=set()
            scenario_map={}

            def match(sa):
                if sa.asset_id in by_id: return by_id[sa.asset_id]
                ip=str(getattr(sa,'ip','') or '').strip().casefold()
                if ip and ip in by_ip: return by_ip[ip]
                for raw in (getattr(sa,'name',''),getattr(sa,'hostname','')):
                    key=str(raw or '').strip().casefold()
                    if key and key in by_name: return by_name[key]
                return None

            for sa in scenario_assets:
                target=match(sa)
                if target is None:
                    target=deepcopy(sa)
                    visual.append(target)
                    by_id[target.asset_id]=target
                scenario_map[sa.asset_id]=target.asset_id
                overlay_ids.add(target.asset_id)

                # Enrich only the visual overlay copy. The stored live baseline remains unchanged.
                target.risk_score=max(int(getattr(target,'risk_score',0) or 0),int(getattr(sa,'risk_score',0) or 0))
                try:
                    target.criticality=max(int(getattr(target,'criticality',0) or 0),int(getattr(sa,'criticality',0) or 0))
                except (TypeError,ValueError):
                    pass
                target.attack_techniques=sorted(set((getattr(target,'attack_techniques',[]) or [])+(getattr(sa,'attack_techniques',[]) or [])))
                target.recommendations=list(dict.fromkeys((getattr(target,'recommendations',[]) or [])+(getattr(sa,'recommendations',[]) or [])))

            # Scenario steps can reference the real baseline directly even when no scenario
            # NetworkAsset was generated for that step.
            sc=state.get('scenario')
            if sc:
                for step in getattr(sc,'steps',[]) or []:
                    raw_id=str(getattr(step,'asset_id','') or '').strip()
                    raw_name=str(getattr(step,'asset_name','') or '').strip().casefold()
                    resolved=None
                    if raw_id in by_id: resolved=raw_id
                    elif raw_id in scenario_map: resolved=scenario_map[raw_id]
                    elif raw_name and raw_name in by_name: resolved=by_name[raw_name].asset_id
                    if resolved: overlay_ids.add(resolved)

            rels=list(state.get('scan_rels') or [])
            seen={(r.source_asset_id,r.target_asset_id,r.relationship_type) for r in rels}
            for rel in scenario_rels:
                clone=deepcopy(rel)
                clone.source_asset_id=scenario_map.get(clone.source_asset_id,clone.source_asset_id)
                clone.target_asset_id=scenario_map.get(clone.target_asset_id,clone.target_asset_id)
                if clone.source_asset_id not in by_id or clone.target_asset_id not in by_id:
                    continue
                sig=(clone.source_asset_id,clone.target_asset_id,clone.relationship_type)
                if sig not in seen:
                    rels.append(clone); seen.add(sig)

            state['scenario_overlay_ids']=overlay_ids
            state['scenario_asset_map']=scenario_map
            return visual,rels

        def activate_mode(mode):
            """Live=baseline; Scenario=baseline+overlay; Compare=baseline+scenario effect."""
            if mode=='live':
                state['assets']=list(state['scan_assets'])
                state['rels']=list(state['scan_rels'])
                state['scenario_overlay_ids']=set()
                state['scenario_asset_map']={}
                state['scenario']=None if not state.get('scenario_assets') else state.get('scenario')
                state['intelligence']=None
            elif mode in ('scenario','compare'):
                if not state.get('scenario_assets'):
                    raise ValueError('Laad eerst een scenario.')
                overlay_assets,overlay_rels=build_scenario_overlay()
                state['assets']=overlay_assets
                state['rels']=overlay_rels
            else:
                state['assets']=[]; state['rels']=[]
                state['scenario_overlay_ids']=set()
                state['scenario_asset_map']={}
            state['mode']=mode
            state['asset_map']={a.asset_id:a for a in state['assets']}
            merge_design()
            if 'import_box' in locals():
                import_box.configure(state='readonly' if mode in ('live','scenario','compare') else 'disabled')

        def new_scan():
            try:
                self._open_network_digital_twin()
                status.set(_tr('ui.source.netmap.scanner.geopend.publiceer.de.scan.en.ki.1f2b1c79'))
            except Exception as exc:
                messagebox.showerror(_tr('ui.source.nieuwe.scan.8b36b2ad'),_tr('ui.source.scanner.kon.niet.worden.geopend.p0.9ad85853',p0=exc),parent=win)
        def load_scan():
            compare_var.set(False); reload_data(True); activate_mode('live'); fit_view(); status.set(_tr('ui.source.live.scan.geladen.scenario.data.is.niet.actief.dd0bfe20'))
        def import_scenario():
            path=filedialog.askopenfilename(parent=win,title=_tr('ui.source.scenario.importeren.c223d20d'),filetypes=[(_tr('ui.source.scenario.json.67f4c144'),'*.json'),(_tr('ui.source.alle.bestanden.3b98611e'),'*.*')])
            if not path:return
            try:
                raw=json.loads(Path(path).read_text(encoding='utf-8'))
                candidates=raw.get('scenarios',[]) if isinstance(raw,dict) and 'scenarios' in raw else [raw]
                imported=[]
                for item in candidates:
                    if isinstance(item,dict):
                        sc=normalize_scenario(item); scenario_repo.upsert(sc); imported.append(sc)
                if not imported: raise ValueError('Geen geldig scenario met stappen gevonden.')
                state['scenario']=imported[-1]; state['scenario_assets'],state['scenario_rels']=scenario_graph(state['scenario']); activate_mode('scenario'); compare_var.set(False); status.set(_tr('ui.source.scenario.ge.mporteerd.p0.2ed0cacc',p0=state['scenario'].name)); visualize()
            except Exception as exc:
                messagebox.showerror(_tr('ui.source.scenario.import.6b60f8d7'),_tr('ui.source.import.mislukt.p0.8db063ac',p0=exc),parent=win)
        def load_scenario():
            scenarios=scenario_repo.load_all()
            if not scenarios:
                messagebox.showwarning(_tr('ui.source.scenario.laden.7e15928a'),_tr('ui.source.er.zijn.nog.geen.scenario.s.opgeslagen.9356fd9d'),parent=win); return
            picker=self._new_tool_window(parent=win); picker.title(_tr('ui.source.scenario.laden.7e15928a')); picker.geometry('620x420'); picker.transient(win); picker.grab_set(); picker.configure(bg=p['bg'])
            Label(picker,text=_tr('ui.source.kies.scenario.ca9abeec'),font=('Segoe UI Semibold',14),bg=p['bg'],fg=p['text']).pack(anchor='w',padx=14,pady=14)
            lb=Listbox(picker,bg=p['panel'],fg=p['text'],selectbackground=p['violet'],bd=0,font=('Segoe UI',10)); lb.pack(fill=BOTH,expand=True,padx=14,pady=(0,10))
            for sc in scenarios: lb.insert(END,f'{sc.name}  |  risk {sc.overall_risk}  |  {len(sc.steps)} stappen')
            def choose():
                sel=lb.curselection()
                if not sel:return
                chosen=scenarios[sel[0]]
                if not chosen.steps:
                    messagebox.showwarning(_tr('ui.source.scenario.laden.7e15928a'),_tr('ui.source.dit.scenario.bevat.geen.stappen.en.kan.niet.wo.8611b26b'),parent=picker); return
                state['scenario']=chosen; state['scenario_assets'],state['scenario_rels']=scenario_graph(chosen); activate_mode('scenario'); compare_var.set(False); picker.destroy(); visualize()
            Button(picker,text=_tr('ui.source.laden.en.visualiseren.b7dbec36'),command=choose,bg=p['cyan'],fg='#06101d',bd=0,padx=14,pady=8).pack(pady=(0,14))
            lb.bind('<Double-Button-1>',lambda e:choose())
        def visualize():
            mode=state.get('mode','live')
            if mode=='scenario' and not state.get('scenario'):
                messagebox.showwarning(_tr('ui.source.visualiseren.9052f06c'),_tr('ui.source.laad.eerst.een.scenario.89d4d962'),parent=win); return
            if mode=='compare' and (not state.get('scenario_assets') or not state.get('scan_assets')):
                messagebox.showwarning(_tr('ui.source.vergelijken.43116834'),_tr('ui.source.laad.eerst.een.scan.n.een.scenario.10d6f59c'),parent=win); return
            draw(); fit_view();
            sc=state.get('scenario'); status.set(_tr('ui.source.p0.gevisualiseerd.fb030efe',p0='Scenario: ' + sc.name if sc and mode != 'live' else 'Live Environment'))
        def set_mode(mode):
            try:
                if mode=='scenario' and not state.get('scenario_assets'): raise ValueError('Laad eerst een scenario.')
                if mode=='live' and not state.get('scan_assets'): raise ValueError('Laad eerst een scan.')
                if mode=='compare' and (not state.get('scan_assets') or not state.get('scenario_assets')): raise ValueError('Vergelijkmodus vereist een baseline én een scenario.')
                activate_mode(mode); compare_var.set(mode=='compare'); fit_view(); visualize()
            except ValueError as exc: messagebox.showwarning(_tr('ui.source.weergavemodus.4e9689c5'),str(exc),parent=win)
        def timeline():
            if not state.get('scenario'): messagebox.showwarning(_tr('ui.source.timeline.018514a3'),_tr('ui.source.laad.eerst.een.scenario.89d4d962'),parent=win); return
            activate_mode('scenario'); visualize(); status.set(_tr('ui.source.timeline.actief.selecteer.aanvalsstappen.in.de.28bd71cc'))
        def attack_path():
            if state.get('mode')=='empty' or not state.get('assets'):
                messagebox.showwarning(_tr('ui.source.attack.path.ff1e4d52'),_tr('ui.source.laad.eerst.een.scan.scenario.of.gecombineerd.m.9ee48853'),parent=win); return
            ids=scenario_path_ids()
            if len(ids)<2:
                messagebox.showwarning(_tr('ui.source.attack.path.ff1e4d52'),_tr('ui.source.er.kon.geen.aanvalspad.met.minimaal.twee.gekop.f7e62ceb'),parent=win); return
            state['active_path_ids']=ids
            overlay_var.set('Risk')
            draw(); start_playback()
            status.set(_tr('ui.source.attack.path.actief.p0.p1.assets.98010520',p0=state.get('active_path_name') or 'afgeleid pad',p1=len(ids)))
        def export_simulation_lab():
            assets=list(state.get('assets') or [])
            rels=list(state.get('rels') or [])
            if not assets:
                messagebox.showwarning(_tr('ui.source.simulation.lab.export.5f362e59'),_tr('ui.source.laad.of.genereer.eerst.een.netwerk.scenario.bdaa89aa'),parent=win); return
            sc=state.get('scenario')
            base_name=(getattr(sc,'name','') if sc else '') or 'CAMT_Network_Lab'
            safe=''.join(c if c.isalnum() or c in ('-','_') else '_' for c in base_name).strip('_') or 'CAMT_Network_Lab'
            path=filedialog.asksaveasfilename(
                parent=win,title=_tr('ui.source.simulation.lab.manifest.exporteren.1b3a4f88'),
                defaultextension='.camt-lab.json',
                filetypes=[(_tr('ui.source.camt.simulation.lab.manifest.e8c3ce8b'),'*.camt-lab.json'),(_tr('ui.source.json.031a4e76'),'*.json')],
                initialfile=safe+'.camt-lab.json')
            if not path:return
            try:
                result=SimulationLabBridge.write_manifest(
                    path,assets,rels,scenario=sc,mode=state.get('mode','analysis'),
                    source_context='Network Digital Twin / Scenario Analysis')
                status.set(_tr('ui.source.simulation.lab.manifest.gereed.p0.37f801df',p0=result))
                messagebox.showinfo(
                    _tr('ui.source.simulation.lab.export.5f362e59'),
                    _tr('ui.source.export.gereed.n.n.p0.assets.en.p1.relaties.zij.cad6894a',p0=len(assets),p1=len(rels)),
                    parent=win)
            except Exception as exc:
                messagebox.showerror(_tr('ui.source.simulation.lab.export.5f362e59'),str(exc),parent=win)

        def management_report():
            sc=state.get('scenario')
            errors=validate_report_inputs(sc,state.get('assets',[]),state.get('rels',[]))
            if errors:
                messagebox.showwarning(_tr('ui.source.managementrapport.18b7a1e4'),'\n'.join(errors),parent=win); return
            path=filedialog.asksaveasfilename(parent=win,title=_tr('ui.source.managementrapport.naar.report.studio.0c9a4b87'),defaultextension='.pmreport.json',filetypes=[(_tr('ui.source.report.studio.7d55a3c4'),'*.pmreport.json')],initialfile='Managementrapport_'+''.join(c if c.isalnum() else '_' for c in sc.name)+'.pmreport.json')
            if not path:return
            try:
                report_path=write_report_studio_document(path,sc,state['assets'],state['rels'],state.get('mode','scenario'),intelligence=state.get('intelligence'))
                status.set(_tr('ui.source.managementrapport.gereed.voor.report.studio.p0.d5463699',p0=report_path))
                self._show_report_studio(open_path=Path(report_path))
            except Exception as exc:
                messagebox.showerror(_tr('ui.source.managementrapport.18b7a1e4'),str(exc),parent=win)
        action_button(_tr('dt.new_empty'),clear_workspace)
        action_button(_tr('dt.new_scan'),new_scan)
        action_button(_tr('dt.load_scan'),load_scan)
        action_button(_tr('dt.scenario_import'),import_scenario)
        action_button(_tr('dt.load_scenario'),load_scenario)
        action_button(_tr('dt.visualize'),visualize,True)
        action_button('Live',lambda:set_mode('live'))
        action_button('Scenario',lambda:set_mode('scenario'))
        action_button(_tr('dt.compare'),lambda:set_mode('compare'))
        action_button('Timeline',timeline)
        action_button('Attack Path',attack_path)
        action_button('Simulation Lab Export',export_simulation_lab)
        action_button(_tr('dt.management_report'),management_report)
        designbar=Frame(shell,bg=p['panel'],height=46); designbar.pack(fill=X,padx=14,pady=(6,0)); designbar.pack_propagate(False)
        def design_button(text,command):
            Button(designbar,text=text,font=('Segoe UI Semibold',9),bd=0,padx=11,pady=6,bg=p['panel2'],fg=p['text'],activebackground=p['violet'],activeforeground='white',command=command).pack(side=LEFT,padx=3,pady=7)
        Label(designbar,text=_tr('ui.source.design.what.if.3840d55c'),font=('Segoe UI Semibold',9),bg=p['panel'],fg=p['violet']).pack(side=LEFT,padx=(10,8))
        design_button(_tr('dt.add_node'),lambda:_ask_node('node'))
        design_button(_tr('dt.add_intermediary'),lambda:_ask_node('intermediary'))
        design_button(_tr('dt.connect'),connect_nodes)
        design_button(_tr('dt.delete'),delete_selected)
        design_button(_tr('dt.save_design'),save_design)
        design_button(_tr('dt.apply_scenario'),apply_scenario)
        design_button(_tr('dt.analyze'),analyse_design)
        controls=Frame(shell,bg=p['panel2'],height=58); controls.pack(fill=X,padx=14,pady=(8,8)); controls.pack_propagate(False)
        def lab(text): Label(controls,text=text,font=('Segoe UI',9),bg=p['panel2'],fg=p['muted']).pack(side=LEFT,padx=(10,4))
        lab('NetMap'); import_box=ttk.Combobox(controls,textvariable=import_var,width=30,state='readonly'); import_box.pack(side=LEFT,pady=13)
        lab('Threat actor'); actor_box=ttk.Combobox(controls,textvariable=actor_var,values=[_tr('cyber_twin.no_actor')]+[a.name for a in actors],width=22,state='readonly'); actor_box.pack(side=LEFT,pady=13)
        lab('Overlay'); overlay_box=ttk.Combobox(controls,textvariable=overlay_var,values=(_tr('dt.overlay.basic'),'CTI','Heatmap','Risk','Coverage'),width=12,state='readonly'); overlay_box.pack(side=LEFT,pady=13)
        lab(_tr('common.search')); search_entry=ttk.Entry(controls,textvariable=search_var,width=17); search_entry.pack(side=LEFT,pady=13)
        filter_box=ttk.Combobox(controls,textvariable=filter_var,values=(_tr('dt.filter.all'),_tr('dt.filter.scenario'),_tr('dt.filter.critical'),_tr('dt.filter.vulnerable'),_tr('dt.filter.covered')),width=15,state='readonly'); filter_box.pack(side=LEFT,padx=6,pady=13)
        lab('Node'); node_size_box=ttk.Combobox(controls,textvariable=node_size_var,values=(_tr('ui.source.auto.c614ba7c'),_tr('dt.node.mini'),_tr('dt.node.small'),_tr('dt.node.normal'),_tr('dt.node.large')),state='readonly',width=9); node_size_box.pack(side=LEFT,padx=3)
        Checkbutton(controls,text=_tr('ui.source.live.65c821a5'),variable=auto_var,bg=p['panel2'],fg=p['text'],selectcolor=p['panel'],activebackground=p['panel2'],activeforeground=p['text'],bd=0).pack(side=RIGHT,padx=9)
        Checkbutton(controls,text=_tr('ui.source.live.projection.401d54ae'),variable=compare_var,bg=p['panel2'],fg=p['text'],selectcolor=p['panel'],activebackground=p['panel2'],activeforeground=p['text'],bd=0).pack(side=RIGHT,padx=5)
        spacing_box=ttk.Combobox(controls,textvariable=spacing_var,values=[_tr('dt.spacing.compact'),_tr('dt.spacing.normal'),_tr('dt.spacing.wide')],state='readonly',width=9)
        spacing_box.pack(side=RIGHT,padx=3)
        Label(controls,text=_tr('ui.source.spacing.2acbb307'),font=('Segoe UI',8),bg=p['panel2'],fg=p['muted']).pack(side=RIGHT,padx=(8,0))
        for txt,cmd in [('Fit',lambda:fit_view()),(_tr('dt.relayout'),lambda:relayout()),('+',lambda:zoom(1.18)),('−',lambda:zoom(.84)),(_tr('dt.refresh'),lambda:reload_data(True))]:
            Button(controls,text=txt,font=('Segoe UI Semibold',9),bd=0,padx=10,pady=5,bg=p['cyan'] if txt==_tr('dt.refresh') else p['panel'],fg='#06101d' if txt==_tr('dt.refresh') else p['text'],activebackground=p['violet'],activeforeground='white',command=cmd).pack(side=RIGHT,padx=2)

        metrics=Frame(shell,bg=p['bg'],height=104); metrics.pack(fill=X,padx=14); metrics.pack_propagate(False)
        metric_labels={}
        for key,title in [('assets','ASSETS'),('relations','RELATIONS'),('risk','AVG RISK'),('coverage','COVERAGE'),('mode','VIEW MODE')]:
            card=Frame(metrics,bg=p['panel'],highlightbackground=p['line'],highlightthickness=1); card.pack(side=LEFT,fill=BOTH,expand=True,padx=4,pady=5)
            Label(card,text=title,font=('Segoe UI Semibold',8),bg=p['panel'],fg=p['muted'],anchor='w').pack(fill=X,padx=12,pady=(11,2))
            metric_labels[key]=Label(card,text=_tr('ui.source.text.1b93795b'),font=('Segoe UI Semibold',20),bg=p['panel'],fg=p['text'],anchor='w'); metric_labels[key].pack(fill=X,padx=12)

        body=PanedWindow(shell,orient=HORIZONTAL,sashwidth=7,bg=p['bg'],bd=0); body.pack(fill=BOTH,expand=True,padx=14,pady=(4,10))
        left=Frame(body,bg=p['panel'],width=260); center=Frame(body,bg=p['panel2']); right=Frame(body,bg=p['panel'],width=330)
        body.add(left,minsize=220); body.add(center,minsize=610); body.add(right,minsize=280)
        Label(left,text=_tr('ui.source.asset.cards.3d148152'),font=('Segoe UI Semibold',10),bg=p['panel'],fg=p['text'],anchor='w').pack(fill=X,padx=13,pady=12)
        asset_list=Listbox(left,bg=p['panel'],fg=p['text'],selectbackground=p['violet'],selectforeground='white',bd=0,highlightthickness=0,font=('Segoe UI',9),activestyle='none'); asset_list.pack(fill=BOTH,expand=True,padx=8,pady=(0,8))
        map_header=Frame(center,bg=p['panel2'],height=38); map_header.pack(fill=X); map_header.pack_propagate(False)
        Label(map_header,text=_tr('ui.source.glossy.asset.graph.sleep.apparaat.verplaatsen..36d103b6'),font=('Segoe UI Semibold',9),bg=p['panel2'],fg=p['muted']).pack(side=LEFT,padx=12,pady=10)
        canvas=Canvas(center,bg=p['bg'],highlightthickness=0,cursor='fleur'); canvas.pack(fill=BOTH,expand=True)
        mini=Canvas(canvas,bg=p['panel'],highlightbackground=p['line'],highlightthickness=1,width=180,height=120); mini.place(relx=1.0,rely=1.0,x=-12,y=-12,anchor='se')
        Label(right,text=_tr('ui.source.inspector.fddc50c7'),font=('Segoe UI Semibold',10),bg=p['panel'],fg=p['text'],anchor='w').pack(fill=X,padx=13,pady=12)
        detail=Text(right,wrap='word',bg=p['panel'],fg=p['text'],insertbackground=p['cyan'],bd=0,highlightthickness=0,font=('Segoe UI',9),padx=13,pady=8); detail.pack(fill=BOTH,expand=True)
        Label(right,text=_tr('ui.source.cyan.selectie.rood.kritisch.amber.verhoogd.gro.14e774b5'),wraplength=290,font=('Segoe UI',8),bg=p['panel'],fg=p['muted'],justify='left').pack(fill=X,padx=13,pady=10)

        palette={'router':'#52a8ff','server':'#ff9855','client':'#45df91','iot':'#38d6c7','printer':'#ef7ec6','storage':'#ffd05b','firewall':'#8a6cff','cloud':'#65c8ff','database':'#ffbd4d','domain controller':'#ff5973','ot':'#b6e563','endpoint':'#45df91'}
        icons={'router':'RTR','server':'SRV','client':'PC','iot':'IOT','printer':'PRN','storage':'NAS','firewall':'FW','cloud':'CLD','database':'DB','domain controller':'DC','ot':'OT','endpoint':'END'}
        def coverage_map():
            result={}
            for s in scenario_repo.load_all():
                for st in s.steps:
                    vals=[q.coverage for q in st.detection_points]
                    if vals: result[st.asset_id]=max(result.get(st.asset_id,0),round(sum(vals)/len(vals)))
            return result
        def selected_actor(): return next((a for a in actors if a.name==actor_var.get()),None)
        def metric(a,cov):
            actor=selected_actor(); overlap=len(set(a.attack_techniques)&set(actor.techniques)) if actor else 0; mode=overlay_var.get()
            if mode=='Risk': return a.risk_score
            if mode=='Coverage': return cov.get(a.asset_id,0)
            if mode=='CTI': return min(100,overlap*24+(20 if actor and a.services else 0))
            if mode=='Heatmap': return min(100,round(a.risk_score*.55+(100-cov.get(a.asset_id,0))*.25+min(100,overlap*25)*.20))
            return a.risk_score
        def color(value,a,cov):
            if overlay_var.get() in ('Basis','Basic'): return palette.get((a.asset_type or a.role or '').lower(),p['cyan'])
            if overlay_var.get()=='Coverage': return p['good'] if value>=70 else p['warn'] if value>=40 else p['bad']
            return p['bad'] if value>=70 else p['warn'] if value>=40 else p['good']
        def _nonphysical_ip(value):
            ip=str(value or "").strip()
            if not ip:return False
            if ip=="255.255.255.255":return True
            try:
                addr=ipaddress.ip_address(ip)
                if addr.is_multicast or addr.is_unspecified:return True
            except ValueError:return False
            return ip.endswith(".255")

        def visible_rows():
            q=search_var.get().strip().lower(); cov=coverage_map(); rows=[]
            overlay_ids=set(state.get('scenario_overlay_ids') or ())
            for a in state['assets']:
                # Broadcast/multicast observations are telemetry/evidence, not physical Twin nodes.
                if _nonphysical_ip(getattr(a,'ip','')): continue
                if q and q not in ' '.join([a.name or '',a.ip or '',a.role or '',a.asset_type or '']).lower(): continue
                f=filter_var.get()
                if f=='Scenario-only' and a.asset_id not in overlay_ids: continue
                if f=='Critical only' and a.risk_score<70: continue
                if f=='Vulnerable only' and not (a.recommendations or a.risk_score>=40): continue
                if f=='Covered only' and cov.get(a.asset_id,0)<70: continue
                rows.append(a)
            return rows
        def world_to_screen(x,y): return x*state['scale']+state['offset'][0],y*state['scale']+state['offset'][1]
        def base_positions(rows,w,h,force=False):
            if not rows:return
            count=len(rows); cols=max(1,math.ceil(math.sqrt(count)))
            # Match topology spacing to the LOD choice. This matters as much as icon size
            # on 13–15 inch displays.
            choice=node_size_var.get()
            if choice=='Mini' or (choice=='Auto' and count>25): gapx,gapy=115,92
            elif choice=='Klein' or (choice=='Auto' and count>10): gapx,gapy=145,112
            elif choice in ('Normaal','Normal'): gapx,gapy=185,145
            else: gapx,gapy=210,160
            spacing={'Compact':0.82,'Normaal':1.0,'Normal':1.0,'Ruim':1.28,'Wide':1.28}.get(spacing_var.get(),1.0)
            gapx=int(gapx*spacing); gapy=int(gapy*spacing)
            rowsn=math.ceil(count/cols)
            visible_ids={a.asset_id for a in rows}
            state['positions']={aid:pos for aid,pos in state['positions'].items() if aid in visible_ids}
            state['manual_positions']={aid for aid in state.get('manual_positions',set()) if aid in visible_ids}
            for i,a in enumerate(rows):
                if a.asset_id not in state['positions'] or (force and a.asset_id not in state['manual_positions']):
                    state['positions'][a.asset_id]=(120+(i%cols)*gapx,95+(i//cols)*gapy)
        def hex_points(x,y,r): return [v for i in range(6) for v in (x+r*math.cos(math.pi/6+i*math.pi/3),y+r*math.sin(math.pi/6+i*math.pi/3))]
        def draw_minimap(rows):
            mini.delete('all');
            if not rows:return
            xs=[state['positions'][a.asset_id][0] for a in rows]; ys=[state['positions'][a.asset_id][1] for a in rows]; minx,maxx=min(xs),max(xs); miny,maxy=min(ys),max(ys)
            for a in rows:
                x,y=state['positions'][a.asset_id]; mx=12+(x-minx)/max(1,maxx-minx)*156; my=12+(y-miny)/max(1,maxy-miny)*96; mini.create_oval(mx-3,my-3,mx+3,my+3,fill=p['cyan'],outline='')
        def _resolve_asset_id(raw):
            if not raw:
                return ''
            if raw in state.get('asset_map', {}):
                return raw
            needle=str(raw).strip().casefold()
            for asset in state.get('assets', []):
                candidates=(asset.asset_id, asset.name, asset.ip, asset.role)
                if any(str(value or '').strip().casefold()==needle for value in candidates):
                    return asset.asset_id
            return ''

        def scenario_path_ids():
            intelligence=state.get('intelligence')
            if intelligence is not None and getattr(intelligence, 'analysis', None):
                paths=list(getattr(intelligence.analysis, 'attack_paths', []) or [])
                if paths:
                    selected=max(paths,key=lambda item:(item.risk_score,len(item.steps)))
                    ids=[]
                    for step in selected.steps:
                        for raw in (step.source_asset_id,step.target_asset_id):
                            aid=_resolve_asset_id(raw)
                            if aid and (not ids or ids[-1]!=aid):
                                ids.append(aid)
                    if ids:
                        state['active_path_name']=selected.name
                        return ids
            sc=state.get('scenario')
            ids=[]
            if sc:
                for step in sorted(sc.steps,key=lambda x:x.order):
                    aid=_resolve_asset_id(step.asset_id or step.asset_name)
                    if aid and (not ids or ids[-1]!=aid): ids.append(aid)
            if ids:
                state['active_path_name']=getattr(sc,'name','Scenario attack path')
                return ids
            # Last-resort path from the active graph, so scan/design modes can also show a path.
            adjacency={}
            for rel in state.get('rels',[]):
                adjacency.setdefault(rel.source_asset_id,[]).append(rel.target_asset_id)
            starts=[a.asset_id for a in state.get('assets',[]) if all(r.target_asset_id!=a.asset_id for r in state.get('rels',[]))]
            current=(starts or [a.asset_id for a in state.get('assets',[])])[:1]
            if not current:return []
            path=[current[0]]; seen=set(path)
            while adjacency.get(path[-1]):
                nxt=next((x for x in adjacency[path[-1]] if x not in seen),None)
                if not nxt:break
                path.append(nxt);seen.add(nxt)
            state['active_path_name']='Afgeleid actief pad'
            return path
        def start_playback():
            ids=scenario_path_ids()
            if not ids:return
            state['play_index']=0
            def tick():
                if not win.winfo_exists():return
                idx=state.get('play_index',0)
                if idx>=len(ids): status.set(_tr('ui.source.attack.path.playback.voltooid.1ba80c55')); return
                state['selected']=ids[idx]; state['active_path_ids']=ids; draw(); status.set(_tr('ui.source.attack.path.stap.p0.p1.p2.3d04dc4b',p0=idx + 1,p1=len(ids),p2=state.get('active_path_name', ''))); state['play_index']=idx+1
                win.after(850,tick)
            tick()
        def node_icon_scale(count):
            choice=node_size_var.get()
            if choice=='Mini': return .28
            if choice=='Klein': return .42
            if choice in ('Normaal','Normal'): return .60
            if choice=='Groot': return .82
            if count<=10:return .58
            if count<=25:return .42
            if count<=50:return .30
            if count<=100:return .26
            return .22

        def node_label_detail(count):
            choice=node_size_var.get()
            if choice in ('Normaal','Normal','Groot','Large'):return 2
            if choice=='Klein':return 1
            if choice=='Mini':return 0
            if count<=12:return 2
            if count<=25:return 1
            return 0

        def draw():
            rows=visible_rows(); canvas.delete('graph'); w=max(680,canvas.winfo_width()); h=max(480,canvas.winfo_height()); base_positions(rows,w,h); cov=coverage_map(); amap={a.asset_id:a for a in rows}
            for r in state['rels']:
                if r.source_asset_id not in amap or r.target_asset_id not in amap: continue
                x1,y1=world_to_screen(*state['positions'][r.source_asset_id]); x2,y2=world_to_screen(*state['positions'][r.target_asset_id]); bend=max(35,abs(x2-x1)*.18)
                canvas.create_line(x1,y1,x1+bend,y1,x2-bend,y2,x2,y2,smooth=True,splinesteps=24,fill=p['line'],width=max(1,2*state['scale']),arrow=LAST,arrowshape=(12,14,5),tags='graph')
            path_ids=[x for x in (state.get('active_path_ids') or scenario_path_ids()) if x in amap]
            for i in range(len(path_ids)-1):
                x1,y1=world_to_screen(*state['positions'][path_ids[i]]); x2,y2=world_to_screen(*state['positions'][path_ids[i+1]])
                bend=max(35,abs(x2-x1)*.18)
                canvas.create_line(x1,y1,x1+bend,y1,x2-bend,y2,x2,y2,smooth=True,splinesteps=28,fill=p['bad'],width=max(3,4*state['scale']),arrow=LAST,arrowshape=(14,16,6),tags='graph')
            for a in rows:
                wx,wy=state['positions'][a.asset_id]
                x,y=world_to_screen(wx,wy)
                val=metric(a,cov)
                affected=a.asset_id in set(state.get('scenario_overlay_ids') or ())
                tel_chain=set(pending_telemetry.get('asset_chain',[]) or [])
                tel_hit=bool((a.name and a.name in tel_chain) or (a.hostname and a.hostname in tel_chain) or (a.ip and any(a.ip in x for x in tel_chain)))
                affected=affected or tel_hit
                fill=color(val,a,cov)
                if state.get('mode') in ('scenario','compare') and not affected:
                    fill=p['muted']
                sel=a.asset_id==state['selected']
                dtype=a.asset_type or a.role or 'device'
                node_tag=('graph','node',a.asset_id)

                # Selection/risk halo only; the asset itself is a recognizable device icon.
                icon_scale=node_icon_scale(len(rows))
                detail=node_label_detail(len(rows))
                # Level-of-detail: at overview scales prioritize topology over text.
                if state['scale'] < .18:
                    detail=0
                elif state['scale'] < .35:
                    detail=min(detail,1)
                halo_r=int(30+12*icon_scale)
                if sel or affected or a.risk_score>=70:
                    canvas.create_oval(
                        x-halo_r,y-halo_r,x+halo_r,y+halo_r,
                        fill='',
                        outline=p['cyan'] if sel else (p['violet'] if affected else p['bad']),
                        width=3 if sel or affected else 2,
                        tags=node_tag,
                    )

                draw_device_icon(
                    canvas,x,y-4,dtype,
                    outline=p['cyan'] if sel else fill,
                    fill=p['panel2'],
                    accent=fill,
                    tag=node_tag,
                    scale=icon_scale,
                )

                label=(a.name or a.ip or 'Onbekend')
                if len(label)>22: label=label[:19]+'…'
                if detail>=1:
                    ly=y+21+20*icon_scale
                    canvas.create_text(x,ly,text=label,fill=p['text'],
                        font=('Segoe UI Semibold',7 if icon_scale<.6 else 8),width=112,tags=node_tag)
                if detail>=2:
                    ly=y+36+20*icon_scale
                    canvas.create_text(x,ly,text=_tr('ui.source.r.p0.c.p1.f806ede5',p0=a.risk_score,p1=cov.get(a.asset_id, 0)),
                        fill=p['muted'],font=('Segoe UI',6),tags=node_tag)
            draw_minimap(rows); update_metrics(rows,cov)
        def update_metrics(rows,cov):
            metric_labels['assets'].configure(text=str(len(rows))); metric_labels['relations'].configure(text=str(len(state['rels']))); metric_labels['risk'].configure(text=_tr('ui.source.p0.6c727a34',p0=round(sum((a.risk_score for a in rows)) / max(1, len(rows))))); metric_labels['coverage'].configure(text=_tr('ui.source.p0.6c727a34',p0=round(sum((cov.get(a.asset_id, 0) for a in rows)) / max(1, len(rows))))); metric_labels['mode'].configure(text=state.get('mode','empty').upper())
            overlay_count=len(set(state.get('scenario_overlay_ids') or ()) & {a.asset_id for a in rows})
            extra=f' | scenario-assets: {overlay_count}' if state.get('mode') in ('scenario','compare') else ''
            tel_extra=f" | Telemetry: {len(pending_telemetry.get('event_ids',[]))} events / {len(pending_telemetry.get('techniques',[]))} TTPs" if pending_telemetry else ""
            status.set(_tr('ui.source.p0.assets.p1.relaties.bron.p2.overlay.p3.p4.p5.58f30e46',p0=len(rows),p1=len(state['rels']),p2=state.get('mode', 'empty').upper(),p3=overlay_var.get(),p4=extra,p5=tel_extra))
        def show_asset(a):
            state['selected']=a.asset_id; cov=coverage_map(); actor=selected_actor(); overlap=sorted(set(a.attack_techniques)&set(actor.techniques)) if actor else []
            lines=[a.name or a.ip,'─'*34,f'Type: {a.asset_type}',f'Rol: {a.role}',f'IP: {a.ip or "-"}',f'Zone: {a.zone}',f'Criticality: {a.criticality}',f'Risk score: {a.risk_score}/100',f'Coverage: {cov.get(a.asset_id,0)}%',f'Status: {a.compromise_state}','','ATT&CK badges:',', '.join(a.attack_techniques) or 'Geen technieken','','Services:']+[f'• {s.port}/{s.protocol} {s.name}' for s in a.services]+['',f'CTI actor: {actor.name if actor else _tr('cyber_twin.no_actor')}',f'TTP-overlap: {", ".join(overlap) if overlap else "Geen directe overlap"}','','Aanbevelingen:']+[f'• {x}' for x in a.recommendations]
            detail.delete('1.0',END); detail.insert('1.0','\n'.join(lines)); draw()
        def reload_data(force=False):
            assets,rels,imports=asset_repo.load(); labels={f'{i.source} {i.imported_at} [{i.import_id[:8]}]':i.import_id for i in reversed(imports)}; old=import_var.get(); import_box['values']=list(labels)
            if old not in labels and labels: import_var.set(next(iter(labels)))
            iid=labels.get(import_var.get(),''); rows=[a for a in assets if not iid or a.source_import_id==iid]; rr=[r for r in rels if not iid or r.source_import_id==iid]
            sig='|'.join([iid,str(len(rows)),str(len(rr))]+[f'{a.asset_id}:{a.updated_at}:{a.risk_score}' for a in rows])
            if force or sig!=state['signature']:
                state.update(scan_assets=list(rows),scan_rels=list(rr),all_assets=assets,all_rels=rels,imports=imports,signature=sig,baseline_import_id=iid)
                if state.get('mode') in ('live','compare'):
                    activate_mode(state['mode']); fit_view()
            if auto_var.get() and state.get('mode') in ('live','compare') and win.winfo_exists(): state['after']=win.after(2500,reload_data)
        def fit_view():
            rows=visible_rows()
            w=max(680,canvas.winfo_width()); h=max(480,canvas.winfo_height())
            # Fit changes viewport only; it must not destroy user-moved node positions.
            base_positions(rows,w,h,force=False)
            if not rows:
                state['scale']=1.0; state['offset']=[0.0,0.0]; draw(); return
            xs=[state['positions'][a.asset_id][0] for a in rows]
            ys=[state['positions'][a.asset_id][1] for a in rows]
            world_w=max(xs)-min(xs)+260; world_h=max(ys)-min(ys)+210
            # Large-network Fit All: allow the complete topology to fit, even when
            # 100+ devices require substantially less than the old 25% minimum.
            fit_scale=min((w-50)/max(1,world_w),(h-50)/max(1,world_h))
            state['scale']=max(.05,min(1.25,fit_scale))
            state['offset']=[w/2-((min(xs)+max(xs))/2)*state['scale'], h/2-((min(ys)+max(ys))/2)*state['scale']]
            draw()
        def relayout():
            # Explicit action: reset manual layout and rebuild the grid.
            state['manual_positions'].clear()
            rows=visible_rows()
            base_positions(rows,max(680,canvas.winfo_width()),max(480,canvas.winfo_height()),force=True)
            fit_view()
            status.set(_tr('ui.source.layout.opnieuw.opgebouwd.p0.888f6349',p0=spacing_var.get()))

        def zoom(factor, anchor_x=None, anchor_y=None):
            old_scale=state['scale']
            new_scale=max(.05,min(3.0,old_scale*factor))
            if abs(new_scale-old_scale)<1e-9:
                return
            # Keep the world position underneath the cursor fixed while zooming.
            if anchor_x is None: anchor_x=max(1,canvas.winfo_width())/2
            if anchor_y is None: anchor_y=max(1,canvas.winfo_height())/2
            world_x=(anchor_x-state['offset'][0])/old_scale
            world_y=(anchor_y-state['offset'][1])/old_scale
            state['scale']=new_scale
            state['offset']=[anchor_x-world_x*new_scale,anchor_y-world_y*new_scale]
            draw()
        def wheel(e): zoom(1.12 if e.delta>0 else .89,e.x,e.y)
        def wheel_up(e): zoom(1.12,e.x,e.y)
        def wheel_down(e): zoom(.89,e.x,e.y)
        def press(e):
            items=canvas.find_overlapping(e.x,e.y,e.x,e.y); aid=None
            for item in reversed(items):
                tags=canvas.gettags(item)
                if 'node' in tags:
                    aid=next((t for t in tags if t not in ('graph','node')),None); break
            if aid in state['asset_map']:
                wx=(e.x-state['offset'][0])/state['scale']; wy=(e.y-state['offset'][1])/state['scale']
                px,py=state['positions'].get(aid,(wx,wy))
                state['node_drag']=(aid,wx-px,wy-py)
                state['drag']=None
            else:
                state['drag']=(e.x,e.y,state['offset'][0],state['offset'][1])
                state['node_drag']=None
        def drag(e):
            if state.get('node_drag'):
                aid,dx,dy=state['node_drag']
                wx=(e.x-state['offset'][0])/state['scale']; wy=(e.y-state['offset'][1])/state['scale']
                state['positions'][aid]=(wx-dx,wy-dy)
                state['manual_positions'].add(aid)
                draw()
            elif state['drag']:
                sx,sy,ox,oy=state['drag']; state['offset']=[ox+e.x-sx,oy+e.y-sy]; draw()
        def release(e):
            state['drag']=None; state['node_drag']=None
        def click(e):
            items=canvas.find_overlapping(e.x,e.y,e.x,e.y)
            for item in reversed(items):
                tags=canvas.gettags(item)
                if 'node' in tags:
                    aid=next((t for t in tags if t not in ('graph','node')),None)
                    if aid in state['asset_map']: show_asset(state['asset_map'][aid]); break
        def list_select(e=None):
            sel=asset_list.curselection(); rows=state['assets']
            if sel and sel[0]<len(rows): show_asset(rows[sel[0]])
        import_box.bind('<<ComboboxSelected>>',lambda e:reload_data(True)); actor_box.bind('<<ComboboxSelected>>',lambda e:draw()); overlay_box.bind('<<ComboboxSelected>>',lambda e:draw()); filter_box.bind('<<ComboboxSelected>>',lambda e:draw()); node_size_box.bind('<<ComboboxSelected>>',lambda e:draw()); spacing_box.bind('<<ComboboxSelected>>',lambda e:draw()); search_var.trace_add('write',lambda *_:draw()); compare_var.trace_add('write',lambda *_:draw())
        canvas.bind('<MouseWheel>',wheel); canvas.bind('<Button-4>',wheel_up); canvas.bind('<Button-5>',wheel_down); canvas.bind('<ButtonPress-1>',press); canvas.bind('<B1-Motion>',drag); canvas.bind('<ButtonRelease-1>',release); canvas.bind('<Double-Button-1>',click); canvas.bind('<Configure>',lambda e:draw()); asset_list.bind('<<ListboxSelect>>',list_select)
        def close():
            if state['after']:
                try: win.after_cancel(state['after'])
                except Exception: pass
            win.destroy()
        win.protocol('WM_DELETE_WINDOW',close)
        pending_assets=getattr(self,'_pending_digital_twin_assets',None)
        pending_scenario=getattr(self,'_pending_digital_twin_scenario',None)
        # Cross-workspace consistency: if Scenario Analysis has an active IncidentScenario
        # but no converted NDT payload yet, do not silently pretend no scenario exists.
        active_incident=self._get_active_scenario() if hasattr(self,"_get_active_scenario") else getattr(self,"_active_scenario",None)
        pending_intelligence=getattr(self,'_pending_scenario_intelligence_result',None)
        if pending_assets and pending_assets[0]:
            scenario_assets,scenario_rels=pending_assets
            # Preserve any already-loaded NetMap baseline and apply the pending scenario as overlay.
            if not state.get('scan_assets'):
                stored_assets,stored_rels,stored_imports=asset_repo.load()
                if stored_imports:
                    latest=stored_imports[-1]
                    state['scan_assets']=[a for a in stored_assets if a.source_import_id==latest.import_id]
                    state['scan_rels']=[r for r in stored_rels if r.source_import_id==latest.import_id]
                    state['baseline_import_id']=latest.import_id
            state.update(
                scenario_assets=list(scenario_assets),
                scenario_rels=list(scenario_rels),
                scenario=pending_scenario,
                mode='scenario',
                signature='scenario-intelligence',
                intelligence=pending_intelligence,
            )
            activate_mode('scenario')
            compare_var.set(False)
            auto_var.set(False)
            asset_list.delete(0,END)
            for asset in state['assets']:
                marker='●' if asset.asset_id in state.get('scenario_overlay_ids',set()) else '○'
                asset_list.insert(END,f' {marker} {asset.name or asset.ip}   | {asset.role} | R{asset.risk_score}')
            if pending_intelligence is not None:
                analysis=pending_intelligence.analysis
                status.set(_tr('ui.source.scenario.intelligence.actief.p0.assets.p1.rela.6ed3ee00',p0=len(scenario_assets),p1=len(scenario_rels),p2=len(analysis.attack_paths),p3=analysis.overall_risk_score))
                overlay_var.set('Risk')
            fit_view()
            for attr in ('_pending_digital_twin_assets','_pending_digital_twin_scenario','_pending_scenario_intelligence_result'):
                try: delattr(self,attr)
                except AttributeError: pass
        else:
            clear_workspace()
