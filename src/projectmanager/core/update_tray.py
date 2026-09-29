from __future__ import annotations

import json
import os
import re
import sys
import threading
import time
from pathlib import Path
from typing import Callable

from projectmanager.core.shared import APP_NAME, APP_VERSION, APP_BUILD_ID

UPDATE_URL = "https://raw.githubusercontent.com/cyberfirepulse/CAMT-Updates/main/update.json"


def _version_key(version: str, build: str = "") -> tuple[int, ...]:
    nums = [int(x) for x in re.findall(r"\d+", str(version))]
    nums = (nums + [0, 0, 0, 0])[:4]
    build_date = 0
    m = re.search(r"(20\d{6})", str(build))
    if m:
        build_date = int(m.group(1))
    return tuple(nums + [build_date])


def _fetch_manifest(timeout: float = 7.0) -> dict:
    # requests is part of the current CAMT runtime; urllib remains an independent fallback.
    try:
        import requests  # type: ignore
        r = requests.get(UPDATE_URL, timeout=timeout, headers={"User-Agent": f"CAMT/{APP_VERSION}"})
        r.raise_for_status()
        data = r.json()
        return data if isinstance(data, dict) else {}
    except Exception:
        pass
    try:
        import urllib.request
        req = urllib.request.Request(UPDATE_URL, headers={"User-Agent": f"CAMT/{APP_VERSION}"})
        with urllib.request.urlopen(req, timeout=timeout) as response:
            data = json.loads(response.read().decode("utf-8", errors="replace"))
            return data if isinstance(data, dict) else {}
    except Exception:
        return {}


class WindowsTrayUpdateNotifier:
    """Native Windows notification-area icon without an extra Python dependency.

    The tray component is intentionally Windows-only and guarded at runtime; the CAMT
    application itself remains cross-platform. Double-clicking the icon (or clicking
    an update balloon) invokes the supplied callback on Tk's main thread.
    """

    def __init__(self, root, on_activate: Callable[[], None] | None = None) -> None:
        self.root = root
        self.on_activate = on_activate
        self._thread: threading.Thread | None = None
        self._ready = threading.Event()
        self._hwnd = None
        self._nid = None
        self._wndproc = None

    def start(self) -> None:
        if not sys.platform.startswith("win") or self._thread is not None:
            return
        self._thread = threading.Thread(target=self._message_loop, name="CAMTTray", daemon=True)
        self._thread.start()
        threading.Thread(target=self._check_for_update, name="CAMTUpdateCheck", daemon=True).start()

    def _check_for_update(self) -> None:
        self._ready.wait(8.0)
        time.sleep(2.0)
        manifest = _fetch_manifest()
        if not manifest:
            return
        remote_version = str(manifest.get("version") or manifest.get("app_version") or "")
        remote_build = str(manifest.get("build") or manifest.get("build_id") or "")

        # release_seq is authoritative for the Beta channel when present.
        # Beta 9 must never announce Beta 9 again after the update completed.
        remote_seq = manifest.get("release_seq")
        local_beta = re.search(r"\bBeta\s+(\d+)\b", APP_VERSION, re.IGNORECASE)
        if remote_seq is not None and local_beta:
            try:
                if int(remote_seq) <= int(local_beta.group(1)):
                    return
            except (TypeError, ValueError):
                pass

        if (remote_version.strip().casefold() == APP_VERSION.strip().casefold() and
                remote_build.strip().casefold() == APP_BUILD_ID.strip().casefold()):
            return

        if _version_key(remote_version, remote_build) > _version_key(APP_VERSION, APP_BUILD_ID):
            version_text = remote_version or remote_build or "new version"
            self.notify(
                "CAMT update available",
                f"{version_text} is available. Double-click the CAMT tray icon to open Update Manager.",
            )

    def notify(self, title: str, message: str) -> None:
        if not self._ready.wait(3.0) or self._nid is None:
            return
        try:
            import ctypes
            from ctypes import wintypes
            NIM_MODIFY, NIF_INFO, NIIF_INFO = 0x1, 0x10, 0x1
            self._nid.uFlags |= NIF_INFO
            self._nid.szInfoTitle = str(title)[:63]
            self._nid.szInfo = str(message)[:255]
            self._nid.dwInfoFlags = NIIF_INFO
            ctypes.windll.shell32.Shell_NotifyIconW(NIM_MODIFY, ctypes.byref(self._nid))
        except Exception:
            pass

    def _activate(self) -> None:
        if not self.on_activate:
            return
        try:
            self.root.after(0, self.on_activate)
        except Exception:
            pass

    def stop(self) -> None:
        if self._hwnd and sys.platform.startswith("win"):
            try:
                import ctypes
                ctypes.windll.user32.PostMessageW(self._hwnd, 0x0010, 0, 0)  # WM_CLOSE
            except Exception:
                pass

    def _message_loop(self) -> None:
        try:
            import ctypes
            from ctypes import wintypes

            user32 = ctypes.windll.user32
            shell32 = ctypes.windll.shell32
            kernel32 = ctypes.windll.kernel32

            WM_APP = 0x8000
            WM_TRAY = WM_APP + 37
            WM_DESTROY = 0x0002
            WM_CLOSE = 0x0010
            WM_LBUTTONDBLCLK = 0x0203
            NIN_BALLOONUSERCLICK = 0x0405
            NIM_ADD, NIM_DELETE = 0x0, 0x2
            NIF_MESSAGE, NIF_ICON, NIF_TIP = 0x1, 0x2, 0x4
            IMAGE_ICON, LR_LOADFROMFILE, LR_DEFAULTSIZE = 1, 0x10, 0x40
            IDI_APPLICATION = 32512

            WNDPROC = ctypes.WINFUNCTYPE(ctypes.c_longlong, wintypes.HWND, wintypes.UINT, wintypes.WPARAM, wintypes.LPARAM)

            class WNDCLASSW(ctypes.Structure):
                _fields_ = [
                    ("style", wintypes.UINT), ("lpfnWndProc", WNDPROC), ("cbClsExtra", ctypes.c_int),
                    ("cbWndExtra", ctypes.c_int), ("hInstance", wintypes.HINSTANCE), ("hIcon", wintypes.HICON),
                    ("hCursor", wintypes.HANDLE), ("hbrBackground", wintypes.HBRUSH),
                    ("lpszMenuName", wintypes.LPCWSTR), ("lpszClassName", wintypes.LPCWSTR),
                ]

            class NOTIFYICONDATAW(ctypes.Structure):
                _fields_ = [
                    ("cbSize", wintypes.DWORD), ("hWnd", wintypes.HWND), ("uID", wintypes.UINT),
                    ("uFlags", wintypes.UINT), ("uCallbackMessage", wintypes.UINT), ("hIcon", wintypes.HICON),
                    ("szTip", wintypes.WCHAR * 128), ("dwState", wintypes.DWORD), ("dwStateMask", wintypes.DWORD),
                    ("szInfo", wintypes.WCHAR * 256), ("uTimeoutOrVersion", wintypes.UINT),
                    ("szInfoTitle", wintypes.WCHAR * 64), ("dwInfoFlags", wintypes.DWORD),
                    ("guidItem", ctypes.c_byte * 16), ("hBalloonIcon", wintypes.HICON),
                ]

            @WNDPROC
            def wndproc(hwnd, msg, wparam, lparam):
                if msg == WM_TRAY and int(lparam) in (WM_LBUTTONDBLCLK, NIN_BALLOONUSERCLICK):
                    self._activate()
                    return 0
                if msg == WM_CLOSE:
                    user32.DestroyWindow(hwnd)
                    return 0
                if msg == WM_DESTROY:
                    try:
                        if self._nid is not None:
                            shell32.Shell_NotifyIconW(NIM_DELETE, ctypes.byref(self._nid))
                    finally:
                        user32.PostQuitMessage(0)
                    return 0
                return user32.DefWindowProcW(hwnd, msg, wparam, lparam)

            self._wndproc = wndproc
            class_name = "CAMTUpdateTrayWindow"
            hinst = kernel32.GetModuleHandleW(None)
            wc = WNDCLASSW(0, wndproc, 0, 0, hinst, 0, 0, 0, None, class_name)
            user32.RegisterClassW(ctypes.byref(wc))
            hwnd = user32.CreateWindowExW(0, class_name, "CAMT Update Tray", 0, 0, 0, 0, 0, 0, 0, hinst, None)
            if not hwnd:
                return
            self._hwnd = hwnd

            icon = 0
            candidates = []
            try:
                candidates.append(Path(sys.executable).resolve().parent / "assets" / "icons" / "CAMT.ico")
            except Exception:
                pass
            candidates.append(Path(__file__).resolve().parents[3] / "CAMT.ico")
            for path in candidates:
                if path.exists():
                    icon = user32.LoadImageW(None, str(path), IMAGE_ICON, 0, 0, LR_LOADFROMFILE | LR_DEFAULTSIZE)
                    if icon:
                        break
            if not icon:
                icon = user32.LoadIconW(None, ctypes.c_void_p(IDI_APPLICATION))

            nid = NOTIFYICONDATAW()
            nid.cbSize = ctypes.sizeof(NOTIFYICONDATAW)
            nid.hWnd = hwnd
            nid.uID = 1
            nid.uFlags = NIF_MESSAGE | NIF_ICON | NIF_TIP
            nid.uCallbackMessage = WM_TRAY
            nid.hIcon = icon
            nid.szTip = f"{APP_NAME} {APP_VERSION}"[:127]
            self._nid = nid
            shell32.Shell_NotifyIconW(NIM_ADD, ctypes.byref(nid))
            self._ready.set()

            msg = wintypes.MSG()
            while user32.GetMessageW(ctypes.byref(msg), 0, 0, 0) > 0:
                user32.TranslateMessage(ctypes.byref(msg))
                user32.DispatchMessageW(ctypes.byref(msg))
        except Exception:
            self._ready.set()


def start_core_update_notifier(app) -> WindowsTrayUpdateNotifier | None:
    if not sys.platform.startswith("win"):
        return None

    def open_updates() -> None:
        # Update Manager is a runtime module. Open the module manager because it is the
        # stable core entry point and lets the installed Update Manager launch itself.
        callback = getattr(app, "_show_intelligence_module_manager", None)
        if callable(callback):
            callback()

    notifier = WindowsTrayUpdateNotifier(app.root, open_updates)
    notifier.start()
    try:
        app.root.bind("<Destroy>", lambda e: notifier.stop() if e.widget is app.root else None, add="+")
    except Exception:
        pass
    return notifier
