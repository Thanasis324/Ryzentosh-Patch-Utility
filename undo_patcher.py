#!/usr/bin/env python3
"""
Ryzentosh Undo Utility
----------------------
Takes advantage of patch_history.json to selectively or completely revert
patches applied to applications, games, and libraries.

Features:
- Reverts files from .bak backups or saved original bytes.
- Clears quarantine flags and re-signs binaries after restoration.
- Supports app-level rollback, file-level rollback, and batch rollback.
- Provides interactive menus when run without arguments.

Usage:
  ./undo.sh                         # Interactive menu
  ./undo.sh "Hearts of Iron IV"     # Undo specific app
  ./undo.sh --all                   # Undo all active patches
  ./undo.sh --list                  # List patch history
"""

import argparse
from datetime import datetime
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
from typing import Dict, List, Optional, Tuple

HISTORY_FILE_DEFAULT = Path(__file__).resolve().parent / "patch_history.json"
HISTORY_FILE = HISTORY_FILE_DEFAULT

def get_history_file() -> Path:
    """Returns a writable history file path, falling back to home dir if needed."""
    global HISTORY_FILE
    if HISTORY_FILE != HISTORY_FILE_DEFAULT:
        return HISTORY_FILE

    script_path_str = str(Path(__file__).resolve())
    if ".app/Contents" in script_path_str:
        app_support = Path.home() / "Library" / "Application Support" / "RyzentoshPatchUtility"
        try:
            app_support.mkdir(parents=True, exist_ok=True)
        except Exception:
            pass
        app_support_hist = app_support / "patch_history.json"
        if not app_support_hist.exists():
            legacy_home = Path.home() / ".ryzentosh_patch_history.json"
            if legacy_home.exists():
                try:
                    shutil.copy2(legacy_home, app_support_hist)
                except Exception:
                    pass
        return app_support_hist

    if HISTORY_FILE_DEFAULT.exists():
        return HISTORY_FILE_DEFAULT
    try:
        parent = HISTORY_FILE_DEFAULT.parent
        if os.access(parent, os.W_OK):
            return HISTORY_FILE_DEFAULT
    except Exception:
        pass
    fallback = Path.home() / ".ryzentosh_patch_history.json"
    return fallback



class Colors:
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    RED = "\033[91m"
    BLUE = "\033[94m"
    CYAN = "\033[96m"
    BOLD = "\033[1m"
    RESET = "\033[0m"


def cprint(color: str, text: str):
    print(f"{color}{text}{Colors.RESET}")


def load_history() -> List[Dict]:
    """Loads recorded patch operations from history file."""
    hist_file = get_history_file()
    if not hist_file.exists():
        return []
    try:
        with open(hist_file, "r", encoding="utf-8") as f:
            data = json.load(f)
            return data.get("records", [])
    except Exception:
        return []


def save_history(records: List[Dict]) -> bool:
    """Atomically saves records to history file."""
    hist_file = get_history_file()
    try:
        temp_file = hist_file.with_suffix(".json.tmp")
        with open(temp_file, "w", encoding="utf-8") as f:
            json.dump({"records": records}, f, indent=2)
        temp_file.replace(hist_file)
        if "SUDO_UID" in os.environ and "SUDO_GID" in os.environ:
            try:
                os.chown(hist_file, int(os.environ["SUDO_UID"]), int(os.environ["SUDO_GID"]))
            except Exception:
                pass
        try:
            os.chmod(hist_file, 0o666)
        except Exception:
            pass
        return True
    except Exception as e:
        cprint(Colors.YELLOW, f"Warning: Failed to save history to {hist_file}: {e}")
        return False


def is_root_required_for_path(path: Path) -> bool:
    """Checks if root privileges are required to modify or restore the target path."""
    try:
        resolved = path.resolve()
        resolved_str = str(resolved)
        root_prefixes = ["/Applications", "/Library", "/usr", "/System", "/opt"]
        for prefix in root_prefixes:
            if resolved_str.startswith(prefix):
                return True
        if os.geteuid() == 0:
            return False
        check_p = resolved if resolved.exists() else resolved.parent
        if not os.access(check_p, os.W_OK):
            return True
        if resolved.exists() and not os.access(resolved.parent, os.W_OK):
            return True
    except Exception:
        pass
    return False


def restore_file_ownership(file_path: Path):
    """If running under sudo and file is in a user home directory or owned by non-root, chown to SUDO_UID."""
    if os.geteuid() == 0 and "SUDO_UID" in os.environ and "SUDO_GID" in os.environ:
        try:
            sudo_uid = int(os.environ["SUDO_UID"])
            sudo_gid = int(os.environ["SUDO_GID"])
            resolved = str(file_path.resolve())
            if resolved.startswith("/Users/") or not is_root_required_for_path(file_path):
                if file_path.exists():
                    os.chown(file_path, sudo_uid, sudo_gid)
                bak_p = file_path.with_name(file_path.name + ".bak")
                if bak_p.exists():
                    os.chown(bak_p, sudo_uid, sudo_gid)
        except Exception:
            pass


def strip_quarantine(file_path: Path) -> bool:
    """Removes macOS quarantine extended attributes."""
    try:
        subprocess.run(["xattr", "-cr", str(file_path)], check=True, capture_output=True)
        return True
    except Exception:
        return False


def resign_binary(file_path: Path) -> bool:
    """Applies ad-hoc code signature to prevent macOS kernel SIGKILL."""
    try:
        subprocess.run(
            ["codesign", "--force", "--deep", "-s", "-", str(file_path)],
            check=True,
            capture_output=True,
            text=True
        )
        return True
    except Exception:
        return False


def verify_signature(file_path: Path) -> Tuple[bool, str]:
    """Verifies the code signature of the binary."""
    try:
        res = subprocess.run(
            ["codesign", "--verify", "--deep", "--strict", str(file_path)],
            capture_output=True,
            text=True
        )
        return res.returncode == 0, res.stderr.strip() or res.stdout.strip()
    except Exception as e:
        return False, str(e)


def list_history():
    """Prints a detailed report of all patch history records."""
    records = load_history()
    if not records:
        cprint(Colors.YELLOW, f"No patch history recorded in {HISTORY_FILE.name}.")
        return 0

    cprint(Colors.BOLD, "\n=======================================================")
    cprint(Colors.BOLD, "            Ryzentosh Patch History & Status           ")
    cprint(Colors.BOLD, "=======================================================")

    for rec in records:
        status = rec.get("status", "unknown")
        status_color = Colors.GREEN if status == "active" else Colors.YELLOW
        date_str = rec.get("timestamp", "")[:19].replace("T", " ")
        print(f"\n• ID: {Colors.CYAN}{rec.get('id')}{Colors.RESET} | Date: {date_str} | Status: {status_color}[{status.upper()}]{Colors.RESET}")
        print(f"  App Name: {Colors.BOLD}{rec.get('app_name')}{Colors.RESET}")
        print(f"  Target:   {rec.get('target_root')}")
        for f in rec.get("files", []):
            f_status = f.get("status", "active")
            f_color = Colors.GREEN if f_status == "active" else Colors.YELLOW
            print(f"  - File: {f.get('file_path')} {f_color}[{f_status.upper()}]{Colors.RESET}")
            for s in f.get("symbols", []):
                print(f"    Symbol: {s.get('symbol')} at offset 0x{s.get('offset', 0):X}")
    print()
    return 0


def revert_entry(f_entry: Dict, now_iso: str) -> bool:
    """Reverts a single file entry using its backup or original bytes."""
    f_path = Path(f_entry.get("file_path"))
    bak_path = Path(f_entry.get("backup_path")) if f_entry.get("backup_path") else None
    restored = False

    # Strategy 1: Restore from .bak file
    if bak_path and bak_path.exists():
        print(f"  Restoring {f_path.name} from backup {bak_path.name}...")
        try:
            shutil.copy2(bak_path, f_path)
            restored = True
        except Exception as e:
            cprint(Colors.RED, f"  Failed to restore from backup: {e}")

    # Strategy 2: Restore saved original bytes directly into file
    if not restored and f_path.exists():
        symbols = f_entry.get("symbols", [])
        if symbols:
            print(f"  Restoring original bytes into {f_path.name}...")
            try:
                with open(f_path, "r+b") as f:
                    for s in symbols:
                        orig_hex = s.get("original_bytes_hex")
                        off = s.get("offset")
                        if orig_hex and off is not None:
                            f.seek(off)
                            f.write(bytes.fromhex(orig_hex))
                restored = True
            except Exception as e:
                cprint(Colors.RED, f"  Failed to restore original bytes: {e}")

    if restored:
        strip_quarantine(f_path)
        resign_binary(f_path)
        restore_file_ownership(f_path)
        f_entry["status"] = "reverted"
        f_entry["reverted_at"] = now_iso
        cprint(Colors.GREEN, f"  Successfully reverted {f_path.name}")
        return True
    else:
        cprint(Colors.RED, f"  Could not restore {f_path}")
        return False


def undo_patches(
    app_query: Optional[str] = None,
    all_patches: bool = False,
    file_path: Optional[Path] = None,
    record_id: Optional[str] = None
) -> int:
    """Undoes patches based on query criteria."""
    records = load_history()
    if not records:
        cprint(Colors.YELLOW, f"No patch history found in {HISTORY_FILE.name}.")
        return 0

    active_records = [r for r in records if r.get("status") == "active"]
    if not active_records:
        cprint(Colors.GREEN, "No active patches to undo (all previously recorded patches are already reverted).")
        return 0

    to_undo = []
    choice_is_interactive = False
    interactive_selected_app = None
    is_all = False

    if all_patches:
        to_undo = active_records
        is_all = True
    elif record_id:
        req_id = record_id.strip()
        to_undo = [r for r in active_records if r.get("id") == req_id]
        if not to_undo:
            cprint(Colors.RED, f"Error: No active patch record with ID '{record_id}'.")
            return 1
    elif file_path:
        target_str = str(file_path.resolve()).lower()
        for r in active_records:
            if any(target_str == f.get("file_path", "").lower() for f in r.get("files", [])):
                to_undo.append(r)
        if not to_undo:
            cprint(Colors.RED, f"Error: No active patch found for file '{file_path}'.")
            return 1
    elif app_query:
        query = app_query.lower().strip()
        for r in active_records:
            if (query in r.get("app_name", "").lower() or
                query == r.get("id", "").lower() or
                query in r.get("target_root", "").lower() or
                any(query in f.get("file_path", "").lower() for f in r.get("files", []))):
                to_undo.append(r)
        if not to_undo:
            cprint(Colors.RED, f"Error: No active patch matches '{app_query}'.")
            return 1
    else:
        # Interactive picker: group active records by application name
        choice_is_interactive = True
        grouped: Dict[str, List[Dict]] = {}
        for r in active_records:
            name = r.get("app_name", "Unknown App")
            grouped.setdefault(name, []).append(r)

        cprint(Colors.BOLD, "\n========================================================================")
        cprint(Colors.BOLD, "                 Ryzentosh Undo / Rollback Menu                         ")
        cprint(Colors.BOLD, "========================================================================")
        cprint(Colors.CYAN, f"  Active Applications in Patch History: {len(grouped)}")
        cprint(Colors.BOLD, "------------------------------------------------------------------------")
        app_list = list(grouped.keys())
        for idx, app_name in enumerate(app_list, 1):
            app_recs = grouped[app_name]
            files_set = set()
            for r in app_recs:
                for f in r.get("files", []):
                    if f.get("status") == "active":
                        files_set.add(f.get("file_path"))
            latest_date = max(r.get("timestamp", "") for r in app_recs)[:19].replace("T", " ")
            file_count = len(files_set)
            item_needs_root = any(
                is_root_required_for_path(Path(fp))
                for fp in files_set
            )
            priv_badge = f"{Colors.YELLOW}[REQUIRES ROOT]{Colors.RESET} " if item_needs_root else f"{Colors.GREEN}[USER]{Colors.RESET} "
            print(f"  {Colors.BOLD}{idx:2d}){Colors.RESET} {Colors.GREEN}[ACTIVE]{Colors.RESET} {Colors.BOLD}{app_name}{Colors.RESET} -> {file_count} file(s) ({latest_date}) {priv_badge}")
        print(f"   A) {Colors.RED}[REVERT ALL]{Colors.RESET} Undo ALL active patches")
        print(f"   R) {Colors.RED}[RESET SWITCH]{Colors.RESET} Factory reset: Revert all patches & wipe history")
        print(f"   Q) {Colors.BOLD}[CANCEL]{Colors.RESET}     Exit without reverting\n")
        try:
            choice = input("Select an application to undo: ").strip()
            if choice.lower() == "q":
                print("Cancelled.")
                return 0
            elif choice.lower() == "r":
                return reset_all_patches()
            elif choice.lower() == "a":
                to_undo = active_records
                is_all = True
            elif choice.isdigit() and 1 <= int(choice) <= len(app_list):
                interactive_selected_app = app_list[int(choice) - 1]
                to_undo = grouped[interactive_selected_app]
            else:
                cprint(Colors.RED, "Invalid selection.")
                return 1
        except (KeyboardInterrupt, EOFError):
            print("\nCancelled.")
            return 0

    if os.geteuid() != 0:
        needs_root = any(
            is_root_required_for_path(Path(f_entry.get("file_path")))
            for rec in to_undo
            for f_entry in rec.get("files", [])
        )
        if needs_root:
            cprint(Colors.YELLOW, "\n[!] Root privileges required to restore application(s) in /Applications.")
            cprint(Colors.YELLOW, "    Elevating with sudo (you may be prompted for your macOS password)...")
            script_path = str(Path(__file__).resolve())
            if all_patches or (choice_is_interactive and is_all):
                args = ["sudo", sys.executable, script_path, "--all"]
            elif record_id:
                args = ["sudo", sys.executable, script_path, "--id", record_id]
            elif file_path:
                args = ["sudo", sys.executable, script_path, "--file", str(file_path)]
            elif choice_is_interactive and interactive_selected_app:
                args = ["sudo", sys.executable, script_path, "--app", interactive_selected_app]
            elif app_query:
                args = ["sudo", sys.executable, script_path, "--app", app_query]
            else:
                args = ["sudo", sys.executable, script_path] + sys.argv[1:]
            try:
                res = subprocess.run(args)
                return res.returncode
            except Exception as e:
                cprint(Colors.RED, f"Failed to elevate with sudo: {e}")
                print(f"Please re-run this command with sudo:\n  sudo {' '.join(args[1:])}")
                return 1

    total_restored = 0
    now_iso = datetime.now().isoformat()

    for rec in to_undo:
        cprint(Colors.BOLD, f"\n==> Undoing patches for: {rec.get('app_name')} (ID: {rec.get('id')})")
        for f_entry in rec.get("files", []):
            if f_entry.get("status") == "reverted":
                continue
            if revert_entry(f_entry, now_iso):
                total_restored += 1

        # Check if all files in this record are reverted
        if all(f.get("status") == "reverted" for f in rec.get("files", [])):
            rec["status"] = "reverted"
            rec["reverted_at"] = now_iso

    save_history(records)
    cprint(Colors.BOLD, f"\n==> Undo complete: {total_restored} file(s) restored and marked reverted in history.")
    return 0


def wipe_all_history_ledgers():
    """Wipes all potential history files across repository, Application Support, and home."""
    targets = set()
    try:
        targets.add(get_history_file())
    except Exception:
        pass
    targets.add(HISTORY_FILE_DEFAULT)

    # Current user home
    targets.add(Path.home() / "Library" / "Application Support" / "RyzentoshPatchUtility" / "patch_history.json")
    targets.add(Path.home() / ".ryzentosh_patch_history.json")

    # If running under sudo, also check the original calling user's home
    if "SUDO_USER" in os.environ and os.environ["SUDO_USER"]:
        sudo_user_home = Path("/Users") / os.environ["SUDO_USER"]
        targets.add(sudo_user_home / "Library" / "Application Support" / "RyzentoshPatchUtility" / "patch_history.json")
        targets.add(sudo_user_home / ".ryzentosh_patch_history.json")

    empty_data = json.dumps({"records": []}, indent=2)
    for p in targets:
        try:
            if p.exists():
                p.write_text(empty_data, encoding="utf-8")
                if "SUDO_UID" in os.environ and "SUDO_GID" in os.environ:
                    try:
                        os.chown(p, int(os.environ["SUDO_UID"]), int(os.environ["SUDO_GID"]))
                    except Exception:
                        pass
        except Exception:
            pass


def reset_all_patches(force: bool = False) -> int:
    """
    Factory reset switch:
    1. Reverts all active patches across all apps and games.
    2. Cleans up leftover .bak backup files.
    3. Completely wipes the patch_history.json ledger.
    """
    records = load_history()
    active_records = [r for r in records if r.get("status") == "active"]

    if not force:
        try:
            cprint(Colors.RED, f"\n⚠️  WARNING: Factory Reset will revert all {len(active_records)} active patch(es), clean backups, and permanently wipe history.")
            confirm = input("Type 'yes' to confirm factory reset: ").strip().lower()
            if confirm != "yes":
                print("Factory reset cancelled.")
                return 0
        except (KeyboardInterrupt, EOFError):
            print("\nFactory reset cancelled.")
            return 0

    # Auto-elevate with sudo IF any active patch target requires root permissions
    if os.geteuid() != 0:
        needs_root = any(
            is_root_required_for_path(Path(f_entry.get("file_path")))
            for rec in active_records
            for f_entry in rec.get("files", [])
        )
        if needs_root:
            cprint(Colors.YELLOW, "\n[!] Root privileges required to restore application(s) in /Applications.")
            cprint(Colors.YELLOW, "    Elevating with sudo for Factory Reset...")
            script_path = str(Path(__file__).resolve())
            args = ["sudo", sys.executable, script_path, "--reset", "-f"]
            try:
                res = subprocess.run(args)
                return res.returncode
            except Exception as e:
                cprint(Colors.RED, f"Failed to elevate with sudo: {e}")
                return 1

    # Revert all active files
    now_iso = datetime.now().isoformat()
    total_restored = 0
    for rec in active_records:
        cprint(Colors.BOLD, f"\n==> Reverting: {rec.get('app_name')} (ID: {rec.get('id')})")
        for f_entry in rec.get("files", []):
            if f_entry.get("status") == "reverted":
                continue
            if revert_entry(f_entry, now_iso):
                total_restored += 1

    # Clean up all .bak backup files from all recorded apps/files
    cleaned_baks = 0
    for r in records:
        for f in r.get("files", []):
            bak_path_str = f.get("backup_path")
            if bak_path_str:
                bak_p = Path(bak_path_str)
                if bak_p.exists():
                    try:
                        bak_p.unlink()
                        cleaned_baks += 1
                    except Exception:
                        pass

    # Completely wipe all history ledgers
    wipe_all_history_ledgers()

    cprint(Colors.GREEN, f"\n✅ Factory reset complete!")
    print(f"  • Patches reverted:     {total_restored} file(s) restored")
    print(f"  • Backup files cleaned: {cleaned_baks} .bak file(s) removed")
    print(f"  • History ledger:       Completely wiped to 0 records\n")
    return 0


def main():
    parser = argparse.ArgumentParser(
        description="Ryzentosh Undo Utility: Revert binary patches using patch history."
    )
    parser.add_argument("app", nargs="?", default=None, help="Application name or search string to undo")
    parser.add_argument("-a", "--app", dest="app_flag", default=None, help="Application name or search string to undo")
    parser.add_argument("--id", dest="id_flag", default=None, help="Specific patch record ID to undo")
    parser.add_argument("--all", action="store_true", help="Undo all active patches")
    parser.add_argument("--file", type=Path, default=None, help="Specific file path to undo")
    parser.add_argument("--list", action="store_true", help="List all patch history records")
    parser.add_argument("--reset", action="store_true", help="Factory reset switch: Revert all patches, clean backups, and wipe history")
    parser.add_argument("-f", "--force", action="store_true", help="Force reset without confirmation prompt")

    args = parser.parse_args()

    if args.reset:
        return reset_all_patches(force=args.force)

    if args.list:
        return list_history()

    app_q = args.app_flag or args.app
    return undo_patches(
        app_query=app_q,
        all_patches=args.all,
        file_path=args.file,
        record_id=args.id_flag
    )


if __name__ == "__main__":
    sys.exit(main())
