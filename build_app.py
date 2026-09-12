#!/usr/bin/env python3
"""
Build & Packaging Script for Ryzentosh Patch Utility
Creates:
1. Self-contained macOS Application: /Applications/Ryzentosh Patch Utility.app
2. Drag-and-drop macOS DMG installer: Ryzentosh-Patch-Utility.dmg
3. ZIP archive: Ryzentosh-Patch-Utility-App.zip
"""

import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

REPO_DIR = Path(__file__).resolve().parent
APP_NAME = "Ryzentosh Patch Utility.app"
BUILD_DIR = Path.home() / "Ryzentosh-App-Build"
DMG_NAME = "Ryzentosh-Patch-Utility.dmg"
ZIP_NAME = "Ryzentosh-Patch-Utility-App.zip"


def generate_icns(png_path: Path, output_icns: Path) -> bool:
    """Generates Apple ICNS from PNG using sips and iconutil."""
    with tempfile.TemporaryDirectory() as td:
        iconset = Path(td) / "applogo.iconset"
        iconset.mkdir()
        sizes = [
            (16, "16x16"), (32, "16x16@2x"), (32, "32x32"), (64, "32x32@2x"),
            (128, "128x128"), (256, "128x128@2x"), (256, "256x256"), (512, "256x256@2x"),
            (512, "512x512"), (1024, "512x512@2x")
        ]
        for sz, name in sizes:
            subprocess.run(
                ["sips", "-z", str(sz), str(sz), str(png_path), "--out", str(iconset / f"icon_{name}.png")],
                check=True, capture_output=True
            )
        res = subprocess.run(
            ["iconutil", "-c", "icns", str(iconset), "-o", str(output_icns)],
            capture_output=True, text=True
        )
        return res.returncode == 0 and output_icns.exists()


def build():
    print("==> Packaging Ryzentosh Patch Utility as standalone macOS .app...")

    png_path = REPO_DIR / "applogo.png"
    icns_path = REPO_DIR / "applogo.icns"
    if not icns_path.exists() or icns_path.stat().st_mtime < png_path.stat().st_mtime:
        print("  • Generating Retina .icns icon...")
        if not generate_icns(png_path, icns_path):
            print("  [!] Failed to generate .icns, exiting.")
            return 1

    if BUILD_DIR.exists():
        shutil.rmtree(BUILD_DIR)
    BUILD_DIR.mkdir(parents=True)

    app_path = BUILD_DIR / APP_NAME
    contents = app_path / "Contents"
    macos = contents / "MacOS"
    resources = contents / "Resources"

    macos.mkdir(parents=True)
    resources.mkdir(parents=True)

    # 1. Assets & engine
    shutil.copy2(icns_path, resources / "applogo.icns")
    shutil.copy2(png_path, resources / "applogo.png")

    core_files = [
        "ryzentosh_patcher.py",
        "undo_patcher.py",
        "patch.sh",
        "undo.sh",
        "README.md",
        "instructions.txt"
    ]
    for cf in core_files:
        src = REPO_DIR / cf
        if src.exists():
            dst = resources / cf
            shutil.copy2(src, dst)
            if cf.endswith(".sh") or cf.endswith(".py"):
                dst.chmod(0o755)

    # Tests directory
    if (REPO_DIR / "tests").exists():
        shutil.copytree(
            REPO_DIR / "tests",
            resources / "tests",
            ignore=shutil.ignore_patterns("__pycache__", "*.pyc")
        )

    # 2. Info.plist
    plist_content = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundlePackageType</key>
    <string>APPL</string>
    <key>CFBundleInfoDictionaryVersion</key>
    <string>6.0</string>
    <key>CFBundleName</key>
    <string>Ryzentosh Patch Utility</string>
    <key>CFBundleDisplayName</key>
    <string>Ryzentosh Patch Utility</string>
    <key>CFBundleIdentifier</key>
    <string>com.ryzentosh.patchutility</string>
    <key>CFBundleVersion</key>
    <string>2.0</string>
    <key>CFBundleShortVersionString</key>
    <string>2.0</string>
    <key>CFBundleExecutable</key>
    <string>Ryzentosh Patch Utility</string>
    <key>CFBundleIconFile</key>
    <string>applogo</string>
    <key>LSMinimumSystemVersion</key>
    <string>10.13</string>
    <key>NSHighResolutionCapable</key>
    <true/>
</dict>
</plist>
"""
    (contents / "Info.plist").write_text(plist_content, encoding="utf-8")

    # 3. Native launcher executable
    launcher_content = """#!/bin/bash
# Self-contained launcher for Ryzentosh Patch Utility
DIR="$(cd "$(dirname "$0")/../Resources" && pwd)"

if [ "$#" -gt 0 ]; then
    # Direct CLI invocation with arguments
    exec python3 "$DIR/ryzentosh_patcher.py" "$@"
else
    # GUI double-click from Finder / Applications / Launchpad / Spotlight:
    # Launches interactive wizard in a dedicated Terminal session
    osascript <<EOF
tell application "Terminal"
    activate
    do script "cd '$DIR' && python3 ryzentosh_patcher.py"
end tell
EOF
fi
"""
    launcher_path = macos / "Ryzentosh Patch Utility"
    launcher_path.write_text(launcher_content, encoding="utf-8")
    launcher_path.chmod(0o755)

    # 4. Ad-hoc Codesign
    print("  • Applying ad-hoc code signature...")
    subprocess.run(["codesign", "--force", "--deep", "-s", "-", str(app_path)], check=True, capture_output=True)
    subprocess.run(["codesign", "--verify", "--deep", "--strict", str(app_path)], check=True, capture_output=True)
    print("  • Code signature verified successfully.")

    # 5. Install to /Applications
    sys_apps = Path("/Applications")
    installed_app = sys_apps / APP_NAME
    if sys_apps.exists() and os.access(sys_apps, os.W_OK):
        print(f"  • Installing directly into {installed_app}...")
        if installed_app.exists():
            shutil.rmtree(installed_app)
        shutil.copytree(app_path, installed_app, symlinks=True)
        subprocess.run(["touch", str(installed_app)], check=True)
        print(f"  ✅ Installed to /Applications/{APP_NAME}")

    # 6. Migrate persistent history to ~/Library/Application Support/RyzentoshPatchUtility
    app_support = Path.home() / "Library" / "Application Support" / "RyzentoshPatchUtility"
    app_support.mkdir(parents=True, exist_ok=True)
    active_hist = REPO_DIR / "patch_history.json"
    if active_hist.exists():
        shutil.copy2(active_hist, app_support / "patch_history.json")
        print(f"  • Linked persistent patch history ledger to {app_support / 'patch_history.json'}")

    # 7. Create DMG installer with drag-to-Applications symlink
    print("  • Creating drag-and-drop macOS DMG installer...")
    dmg_staging = BUILD_DIR / "dmg_root"
    dmg_staging.mkdir()
    shutil.copytree(app_path, dmg_staging / APP_NAME, symlinks=True)
    os.symlink("/Applications", str(dmg_staging / "Applications"))

    dmg_home = Path.home() / DMG_NAME
    dmg_repo = REPO_DIR / DMG_NAME
    for p in (dmg_home, dmg_repo):
        if p.exists():
            p.unlink()

    res = subprocess.run([
        "hdiutil", "create",
        "-volname", "Ryzentosh Patch Utility",
        "-srcfolder", str(dmg_staging),
        "-ov",
        "-format", "UDZO",
        str(dmg_home)
    ], capture_output=True, text=True)
    if res.returncode == 0:
        shutil.copy2(dmg_home, dmg_repo)
        print(f"  ✅ DMG installer created: {dmg_repo.name} ({dmg_repo.stat().st_size / (1024*1024):.1f} MB)")
    else:
        print(f"  [!] Failed to create DMG: {res.stderr}")

    # 8. Create ZIP archive
    print("  • Creating standalone App ZIP archive...")
    zip_home = Path.home() / ZIP_NAME
    zip_repo = REPO_DIR / ZIP_NAME
    for p in (zip_home, zip_repo):
        if p.exists():
            p.unlink()

    subprocess.run(["zip", "-r", "-q", str(zip_home), APP_NAME], cwd=str(BUILD_DIR), check=True)
    shutil.copy2(zip_home, zip_repo)
    print(f"  ✅ App ZIP archive created: {zip_repo.name} ({zip_repo.stat().st_size / (1024*1024):.1f} MB)")

    print("\n========================================================")
    print("  🎉 Ryzentosh Patch Utility macOS Application Ready!   ")
    print("========================================================")
    print("  1. Installed in: /Applications/Ryzentosh Patch Utility.app")
    print("  2. Installer DMG: Ryzentosh-Patch-Utility.dmg")
    print("  3. App ZIP:       Ryzentosh-Patch-Utility-App.zip")
    print("========================================================\n")
    return 0


if __name__ == "__main__":
    sys.exit(build())
