from __future__ import annotations
from projectmanager.i18n import tr as _tr
from pathlib import Path
from datetime import datetime
import importlib.util, json, os, platform, shutil, sqlite3, sys, traceback

from projectmanager.core.shared import (
    APP_NAME, APP_VERSION, APP_BUILD_ID, APP_EDITION, APP_RELEASE_CHANNEL,
    get_app_home_dir, get_app_data_layout, get_runtime_resource_root,
)

SCHEMA_MANIFEST_VERSION=1


def detect_ropper() -> tuple[bool, str]:
    """Detect Ropper, preferring the bundled Python package over a PATH command."""
    try:
        import ropper  # noqa: F401 - import is the runtime capability probe
        return True, "Bundled"
    except Exception:
        pass

    path = shutil.which("ropper")
    if path:
        return True, path
    return False, "Missing"


def detect_checksec() -> tuple[bool, str]:
    """Use CAMT native PE security checks on Windows; external checksec on Linux/Unix."""
    if os.name == "nt":
        return True, "CAMT Native PE Security"

    path = shutil.which("checksec")
    if path:
        return True, path
    return False, "Missing"

def release_manifest() -> dict:
    return {
        "app":APP_NAME,
        "edition":APP_EDITION,
        "version":APP_VERSION,
        "build_id":APP_BUILD_ID,
        "channel":APP_RELEASE_CHANNEL,
        "python":sys.version.split()[0],
        "platform":platform.platform(),
        "frozen":bool(getattr(sys,"frozen",False)),
        "app_home":str(get_app_home_dir()),
        "schema_manifest_version":SCHEMA_MANIFEST_VERSION,
    }

def ensure_data_layout() -> dict[str,str]:
    return {k:str(v) for k,v in get_app_data_layout().items()}

def _migration_state_path() -> Path:
    return get_app_home_dir()/"config"/"migration_state.json"

def run_safe_migrations() -> dict:
    """Non-destructive startup migrations.

    Existing user databases are opened through their own repository classes so
    CREATE TABLE IF NOT EXISTS / additive migrations execute normally. No dataset
    is cleared, replaced or copied.
    """
    layout=get_app_data_layout()
    checks=[]
    def record(name,fn):
        try:
            value=fn()
            checks.append({"name":name,"ok":True,"detail":str(value or "OK")})
        except Exception as exc:
            checks.append({"name":name,"ok":False,"detail":str(exc)})

    def cti():
        from projectmanager.offline_intelligence.database import OfflineIntelligenceDatabase
        db=OfflineIntelligenceDatabase(layout["cti"]/"offline_intelligence.sqlite3")
        with db.connect() as conn:
            n=conn.execute("SELECT COUNT(*) FROM sqlite_master WHERE type='table'").fetchone()[0]
        return f"{n} tables"
    record("Offline Intelligence / CVE schema",cti)

    def modules():
        from projectmanager.intelligence_modules import IntelligenceModuleManager
        m=IntelligenceModuleManager(get_app_home_dir())
        return f"framework v{m.FRAMEWORK_VERSION}; {len(m.list_packages())} packages/modules"
    record("Intelligence Module Framework",modules)

    def team_local():
        from projectmanager.team import TeamService
        svc=TeamService(get_app_home_dir())
        # Merely constructing service initializes its local non-destructive schema.
        return str(svc.db_path)
    record("Team local schema",team_local)

    def assets():
        from projectmanager.assets import AssetRepository
        repo=AssetRepository(get_app_home_dir())
        a,r,i=repo.load_consistent()
        return f"{len(a)} assets; {len(r)} relations"
    record("Asset Repository",assets)

    def reports():
        p=layout["reports"]/"cases";p.mkdir(parents=True,exist_ok=True)
        return str(p)
    record("Report Studio storage",reports)

    state={"version":APP_VERSION,"build_id":APP_BUILD_ID,"ran_at":datetime.now().isoformat(timespec="seconds"),"checks":checks}
    path=_migration_state_path();path.parent.mkdir(parents=True,exist_ok=True)
    path.write_text(json.dumps(state,indent=2,ensure_ascii=False),encoding="utf-8")
    return state

def dependency_diagnostics() -> list[dict]:
    def locate(name,*candidates):
        found=shutil.which(name)
        if found:return found
        for value in candidates:
            p=Path(os.path.expandvars(value))
            if p.exists():return str(p)
        return None
    commands={
        "nmap":locate("nmap",r"%ProgramFiles%\Nmap\nmap.exe",r"%ProgramFiles(x86)%\Nmap\nmap.exe"),
        "git":locate("git",r"%ProgramFiles%\Git\cmd\git.exe",r"%ProgramFiles%\Git\bin\git.exe"),
    }
    rows=[]
    for name,path in commands.items():
        rows.append({"name":name,"status":"AVAILABLE" if path else "OPTIONAL / MISSING","path":path or ""})

    ropper_ok, ropper_detail = detect_ropper()
    rows.append({"name":"ropper","status":"AVAILABLE" if ropper_ok else "OPTIONAL / MISSING","path":ropper_detail})

    checksec_ok, checksec_detail = detect_checksec()
    rows.append({"name":"checksec","status":"AVAILABLE" if checksec_ok else "OPTIONAL / MISSING","path":checksec_detail})
    rows.append({"name":"psycopg","status":"AVAILABLE" if importlib.util.find_spec("psycopg") else "OPTIONAL / MISSING","path":"Python package; required only for PostgreSQL Team Server"})
    try:
        import tkinter
        rows.append({"name":"tkinter","status":"AVAILABLE","path":str(tkinter.TkVersion)})
    except Exception as exc:
        rows.append({"name":"tkinter","status":"MISSING","path":str(exc)})
    return rows

def resource_diagnostics(project_root:Path|None=None) -> list[dict]:
    if project_root is None:
        project_root=get_runtime_resource_root()
    candidates=[
        ("help_center",project_root/"src/projectmanager/help_center.py",True),
        ("intelligence framework",project_root/"src/projectmanager/intelligence_modules",True),
        ("example intelligence packs",project_root/"intelligence_module_examples",True),
        ("Team Server launcher",project_root/"run_team_server.bat",False),
        ("Team Server config example",project_root/"team_server_config.example.json",False),
    ]
    return [{"name":n,"required":req,"exists":p.exists(),"path":str(p)} for n,p,req in candidates]

def writable_diagnostics() -> list[dict]:
    rows=[]
    for name,path in get_app_data_layout().items():
        probe=path/".camt_write_probe"
        try:
            probe.write_text("ok",encoding="utf-8");probe.unlink()
            rows.append({"name":name,"ok":True,"path":str(path)})
        except Exception as exc:
            rows.append({"name":name,"ok":False,"path":str(path),"error":str(exc)})
    return rows

def run_readiness_checks(project_root:Path|None=None) -> dict:
    migrations=run_safe_migrations()
    deps=dependency_diagnostics()
    resources=resource_diagnostics(project_root)
    writable=writable_diagnostics()
    failed=[]
    failed += [f"migration:{x['name']}" for x in migrations["checks"] if not x["ok"]]
    failed += [f"resource:{x['name']}" for x in resources if x["required"] and not x["exists"]]
    failed += [f"writable:{x['name']}" for x in writable if not x["ok"]]
    # tkinter is the only dependency that is mandatory for GUI startup.
    failed += [f"dependency:{x['name']}" for x in deps if x["status"]=="MISSING"]
    return {
        "manifest":release_manifest(),
        "migrations":migrations,
        "dependencies":deps,
        "resources":resources,
        "writable":writable,
        "passed":not failed,
        "failures":failed,
        "checked_at":datetime.now().isoformat(timespec="seconds"),
    }

def install_global_exception_logging(root=None):
    log_dir=get_app_data_layout()["logs"]
    def write(kind,exc_type,exc_value,exc_tb):
        stamp=datetime.now().strftime("%Y%m%d")
        path=log_dir/f"camt_exceptions_{stamp}.log"
        with path.open("a",encoding="utf-8") as f:
            f.write("\n"+"="*80+"\n")
            f.write(f"{datetime.now().isoformat(timespec='seconds')} | {kind} | {APP_VERSION} | {APP_BUILD_ID}\n")
            traceback.print_exception(exc_type,exc_value,exc_tb,file=f)
        return path
    def hook(exc_type,exc_value,exc_tb):
        write("sys.excepthook",exc_type,exc_value,exc_tb)
        try:sys.__excepthook__(exc_type,exc_value,exc_tb)
        except Exception:pass
    sys.excepthook=hook
    try:
        import threading
        def thread_hook(args):
            write(f"thread:{getattr(args.thread,'name','')}",args.exc_type,args.exc_value,args.exc_traceback)
        threading.excepthook=thread_hook
    except Exception:pass
    if root is not None:
        def tk_hook(exc_type,exc_value,exc_tb):
            path=write("tkinter_callback",exc_type,exc_value,exc_tb)
            try:
                from tkinter import messagebox
                messagebox.showerror(_tr('ui.source.camt.onverwachte.fout.8911e445'),_tr('ui.source.de.fout.is.gelogd.in.p0.590a6f56',p0=path))
            except Exception:pass
        root.report_callback_exception=tk_hook

def first_run_state() -> dict:
    p=get_app_home_dir()/"config"/"first_run.json"
    try:return json.loads(p.read_text(encoding="utf-8"))
    except Exception:return {}

def save_first_run_state(data:dict):
    p=get_app_home_dir()/"config"/"first_run.json";p.parent.mkdir(parents=True,exist_ok=True)
    data=dict(data);data["completed_at"]=datetime.now().isoformat(timespec="seconds");data["version"]=APP_VERSION
    p.write_text(json.dumps(data,indent=2,ensure_ascii=False),encoding="utf-8")

def first_run_required() -> bool:
    return not bool(first_run_state().get("completed_at"))
