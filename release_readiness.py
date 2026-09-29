from __future__ import annotations
from pathlib import Path
import json, os, sys

ROOT=Path(__file__).resolve().parent
sys.path.insert(0,str(ROOT/"src"))

from projectmanager.core.release_hardening import run_readiness_checks

if __name__=="__main__":
    report=run_readiness_checks(ROOT)
    out=ROOT/"CAMT_Beta_Release_Readiness.json"
    out.write_text(json.dumps(report,indent=2,ensure_ascii=False),encoding="utf-8")
    print("="*78)
    print("CAMT 1.2.0 Beta 10 — Release Readiness")
    print("="*78)
    print("PASS" if report["passed"] else "ATTENTION REQUIRED")
    for failure in report["failures"]:
        print("FAIL:",failure)
    print("Report:",out)
    raise SystemExit(0 if report["passed"] else 2)
