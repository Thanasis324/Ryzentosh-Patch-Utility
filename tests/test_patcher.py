#!/usr/bin/env python3
"""
Unit and integration tests for Ryzentosh Patching Utility.
"""

import os
import shutil
import struct
import subprocess
import tempfile
import unittest
from pathlib import Path
import sys

# Add parent directory to path so we can import ryzentosh_patcher
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import ryzentosh_patcher as rp
import undo_patcher as up


class TestRyzentoshPatcher(unittest.TestCase):
    def setUp(self):
        self.test_dir = tempfile.mkdtemp(prefix="ryzentosh_test_")
        self.test_path = Path(self.test_dir)
        self.test_hist_file = self.test_path / "patch_history.json"
        self.orig_rp_hist = rp.HISTORY_FILE
        self.orig_up_hist = up.HISTORY_FILE
        rp.HISTORY_FILE = self.test_hist_file
        up.HISTORY_FILE = self.test_hist_file

    def tearDown(self):
        rp.HISTORY_FILE = self.orig_rp_hist
        up.HISTORY_FILE = self.orig_up_hist
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_payload_length_and_structure(self):
        """Verify the replacement payload conforms to System V AMD64 rep stosb requirements."""
        self.assertEqual(len(rp.PATCH_PAYLOAD), 16)
        expected = bytes([
            0x57,                    # push %rdi
            0x48, 0x89, 0xF0,        # mov %rsi, %rax
            0x48, 0x89, 0xD1,        # mov %rdx, %rcx
            0xF3, 0xAA,              # rep stosb
            0x58,                    # pop %rax
            0xC3,                    # ret
            0x90, 0x90, 0x90, 0x90, 0x90  # 5x nop padding
        ])
        self.assertEqual(rp.PATCH_PAYLOAD, expected)

    def test_symbol_patterns(self):
        """Verify regex targets Intel fast memset symbols across variations."""
        valid_symbols = [
            "__intel_fast_memset.A",
            "__intel_fast_memset.J",
            "__intel_fast_memset.B",
            "__intel_fast_memset",
            "_intel_fast_memset.A",
            "_intel_fast_memset"
        ]
        for sym in valid_symbols:
            self.assertTrue(
                any(p.match(sym) for p in rp.TARGET_SYMBOL_PATTERNS),
                f"Pattern should match {sym}"
            )

        invalid_symbols = [
            "memset",
            "__memset_chk",
            "__intel_fast_memcpy",
            "__intel_fast_memset_wrapper",
            "_other_symbol"
        ]
        for sym in invalid_symbols:
            self.assertFalse(
                any(p.match(sym) for p in rp.TARGET_SYMBOL_PATTERNS),
                f"Pattern should NOT match {sym}"
            )

    def test_is_macho_file(self):
        """Verify detection of Mach-O magic headers and rejection of non-Mach-O files."""
        # Non-macho text file
        txt_file = self.test_path / "test.txt"
        txt_file.write_text("Hello world")
        self.assertFalse(rp.is_macho_file(txt_file))

        # 64-bit Mach-O
        macho64 = self.test_path / "libdummy64.dylib"
        with open(macho64, "wb") as f:
            f.write(struct.pack(">I", rp.MH_MAGIC_64) + b"\x00" * 60)
        self.assertTrue(rp.is_macho_file(macho64))

        # Universal FAT Mach-O
        fat = self.test_path / "libfat.dylib"
        with open(fat, "wb") as f:
            f.write(struct.pack(">I", rp.FAT_MAGIC) + b"\x00" * 60)
        self.assertTrue(rp.is_macho_file(fat))

    def test_patch_status_check(self):
        """Verify check_patch_status accurately identifies PATCHED vs UNPATCHED states."""
        dummy_bin = self.test_path / "dummy.bin"
        with open(dummy_bin, "wb") as f:
            f.write(b"\x00" * 32)
            f.write(b"\x90" * 16)  # unpatched at offset 32

        status, data = rp.check_patch_status(dummy_bin, 32)
        self.assertEqual(status, "UNPATCHED")
        self.assertEqual(data, b"\x90" * 16)

        # Apply patch manually
        with open(dummy_bin, "r+b") as f:
            f.seek(32)
            f.write(rp.PATCH_PAYLOAD)

        status, data = rp.check_patch_status(dummy_bin, 32)
        self.assertEqual(status, "PATCHED")
        self.assertEqual(data, rp.PATCH_PAYLOAD)

    def test_backup_and_restore(self):
        """Verify automated backup and restore functionality."""
        target = self.test_path / "libsample.dylib"
        orig_content = b"ORIGINAL_BINARY_BYTES_" + b"\x00" * 100
        target.write_bytes(orig_content)

        bak_file = target.with_name(target.name + ".bak")
        self.assertFalse(bak_file.exists())

        # Simulate backup
        shutil.copy2(target, bak_file)
        self.assertTrue(bak_file.exists())

        # Overwrite target
        target.write_bytes(b"MODIFIED_BYTES____" + b"\x11" * 100)
        self.assertNotEqual(target.read_bytes(), orig_content)

        # Restore
        ret = rp.cmd_restore(target)
        self.assertEqual(ret, 0)
        self.assertEqual(target.read_bytes(), orig_content)

    def test_deep_candidate_discovery(self):
        """Verify candidate discovery locates arbitrary named libraries across deep directory trees."""
        # Create a deep directory hierarchy:
        # App.app/Contents/Frameworks/InternalEngine/deeply/nested/custom_name.dylib
        # App.app/Contents/Libraries/libanother_arbitrary.dylib
        # App.app/Contents/MacOS/app_executable
        nested_dir = self.test_path / "Game.app" / "Contents" / "Frameworks" / "InternalEngine" / "deeply" / "nested"
        nested_dir.mkdir(parents=True)
        other_dir = self.test_path / "Game.app" / "Contents" / "Libraries"
        other_dir.mkdir(parents=True)

        cand1 = nested_dir / "custom_name.dylib"
        with open(cand1, "wb") as f:
            f.write(struct.pack(">I", rp.MH_MAGIC_64))
            f.write(b"\x00" * 100)
            f.write(b"something___intel_fast_memset.A__something")

        cand2 = other_dir / "libmkl_rt.dylib"
        with open(cand2, "wb") as f:
            f.write(struct.pack(">I", rp.MH_MAGIC_64))
            f.write(b"\x00" * 100)
            f.write(b"something_mkl_serv_cpu_detect_something")

        non_cand = nested_dir / "regular_file.dylib"
        with open(non_cand, "wb") as f:
            f.write(struct.pack(">I", rp.MH_MAGIC_64))
            f.write(b"\x00" * 200)

        patch_cands, mkl_cands = rp.find_candidates_in_path(self.test_path / "Game.app")

        self.assertIn(cand1, patch_cands)
        self.assertIn(cand2, mkl_cands)
        self.assertNotIn(non_cand, patch_cands)
        self.assertNotIn(non_cand, mkl_cands)

    def test_end_to_end_macho_compilation_and_patch(self):
        """Compile a real x86_64 Mach-O dylib, resolve symbols, patch, verify signature, and restore."""
        c_code = """
        #include <stddef.h>
        void *__intel_fast_memset(void *dest, int c, size_t n) {
            char *d = (char *)dest;
            while (n--) *d++ = (char)c;
            return dest;
        }
        void *__intel_fast_memset_A(void *dest, int c, size_t n) __asm__("__intel_fast_memset.A");
        void *__intel_fast_memset_A(void *dest, int c, size_t n) {
            return __intel_fast_memset(dest, c, n);
        }
        """
        c_file = self.test_path / "intel_stub.c"
        c_file.write_text(c_code)
        dylib_file = self.test_path / "libintel_custom.dylib"

        # Compile x86_64 dylib
        compile_cmd = [
            "clang", "-shared", "-arch", "x86_64",
            str(c_file), "-o", str(dylib_file)
        ]
        res = subprocess.run(compile_cmd, capture_output=True, text=True)
        self.assertEqual(res.returncode, 0, f"Compilation failed: {res.stderr}")
        self.assertTrue(rp.is_macho_file(dylib_file))

        # 1. Discover symbols
        symbols = rp.resolve_symbol_offsets(dylib_file)
        sym_names = [s.name for s in symbols]
        self.assertTrue(
            "__intel_fast_memset.A" in sym_names or "__intel_fast_memset" in sym_names,
            f"Expected Intel memset symbols, got: {sym_names}"
        )

        # 2. Check initial unpatched status
        for sym in symbols:
            status, cur_bytes = rp.check_patch_status(dylib_file, sym.file_offset)
            self.assertEqual(status, "UNPATCHED")
            self.assertNotEqual(cur_bytes, rp.PATCH_PAYLOAD)

        # 3. Patch the dylib
        patch_res = rp.cmd_patch(dylib_file)
        self.assertEqual(patch_res, 0)

        # 4. Verify patched bytes
        for sym in symbols:
            status, cur_bytes = rp.check_patch_status(dylib_file, sym.file_offset)
            self.assertEqual(status, "PATCHED")
            self.assertEqual(cur_bytes, rp.PATCH_PAYLOAD)

        # 5. Verify code signature
        valid, msg = rp.verify_signature(dylib_file)
        self.assertTrue(valid, f"Code signature verification failed: {msg}")

        # 6. Verify backup was created
        bak_file = dylib_file.with_name(dylib_file.name + ".bak")
        self.assertTrue(bak_file.exists())

        # 7. Verify running patch again detects already patched
        patch_res2 = rp.cmd_patch(dylib_file)
        self.assertEqual(patch_res2, 0)

        # 8. Restore from backup
        restore_res = rp.cmd_restore(dylib_file)
        self.assertEqual(restore_res, 0)
        status_after_restore, _ = rp.check_patch_status(dylib_file, symbols[0].file_offset)
        self.assertEqual(status_after_restore, "UNPATCHED")

    def test_detect_app_name(self):
        """Verify app name inference across .app bundles, Steam directories, and folders."""
        steam_path = Path("/Users/test/Library/Application Support/Steam/steamapps/common/Hearts of Iron IV/libtbb.dylib")
        self.assertEqual(rp.detect_app_name(steam_path.parent, steam_path), "Hearts of Iron IV")

        app_path = Path("/Applications/DaVinci Resolve/DaVinci Resolve.app/Contents/Libraries/libfoo.dylib")
        self.assertEqual(rp.detect_app_name(app_path.parent, app_path), "DaVinci Resolve")

        folder_path = Path("/Games/EuropaUniversalisIV")
        self.assertEqual(rp.detect_app_name(folder_path), "EuropaUniversalisIV")

    def test_history_recording_and_undo_workflow(self):
        """Verify history persistence and undo rollback via undo_patcher."""
        # Create a mock game app bundle
        game_dir = self.test_path / "Civilization.app" / "Contents" / "Libraries"
        game_dir.mkdir(parents=True)
        c_file = self.test_path / "civ_stub.c"
        c_file.write_text("""
        void *__intel_fast_memset(void *d, int c, unsigned long n) __asm__("__intel_fast_memset.A");
        void *__intel_fast_memset(void *d, int c, unsigned long n) { return d; }
        """)
        dylib = game_dir / "libengine.dylib"
        res = subprocess.run(["clang", "-shared", "-arch", "x86_64", str(c_file), "-o", str(dylib)], capture_output=True)
        self.assertEqual(res.returncode, 0)

        # 1. Patch the game
        patch_ret = rp.cmd_patch(self.test_path / "Civilization.app")
        self.assertEqual(patch_ret, 0)

        # 2. Check history file exists and has active record
        self.assertTrue(self.test_hist_file.exists())
        records = up.load_history()
        self.assertEqual(len(records), 1)
        rec = records[0]
        self.assertEqual(rec["app_name"], "Civilization")
        self.assertEqual(rec["status"], "active")
        self.assertEqual(len(rec["files"]), 1)
        self.assertEqual(rec["files"][0]["status"], "active")
        self.assertTrue("original_bytes_hex" in rec["files"][0]["symbols"][0])

        # 3. Undo by app name
        undo_ret = up.undo_patches(app_query="Civilization")
        self.assertEqual(undo_ret, 0)

        # Verify file is restored
        syms = rp.resolve_symbol_offsets(dylib)
        status, _ = rp.check_patch_status(dylib, syms[0].file_offset)
        self.assertEqual(status, "UNPATCHED")

        # Verify history record is marked reverted
        updated_records = up.load_history()
        self.assertEqual(updated_records[0]["status"], "reverted")
        self.assertEqual(updated_records[0]["files"][0]["status"], "reverted")

        # 4. Test fallback to original bytes when .bak is deleted
        # Re-patch
        rp.cmd_patch(self.test_path / "Civilization.app")
        # Delete .bak
        bak_file = dylib.with_name(dylib.name + ".bak")
        self.assertTrue(bak_file.exists())
        bak_file.unlink()
        self.assertFalse(bak_file.exists())

        # Undo should succeed using original_bytes_hex fallback!
        undo_ret2 = up.undo_patches(app_query="Civilization")
        self.assertEqual(undo_ret2, 0)
        status2, _ = rp.check_patch_status(dylib, syms[0].file_offset)
        self.assertEqual(status2, "UNPATCHED")

    def test_steam_game_discovery_and_patching(self):
        """Verify automatic discovery, manifest parsing, and patching of Steam games."""
        # Create mock Steam library
        steam_lib = self.test_path / "MockSteam" / "steamapps"
        common_dir = steam_lib / "common"
        hoi4_dir = common_dir / "Hearts of Iron IV"
        hoi4_dir.mkdir(parents=True)

        stellaris_dir = common_dir / "Stellaris"
        stellaris_dir.mkdir(parents=True)

        # Write ACF manifests
        acf_hoi4 = steam_lib / "appmanifest_394360.acf"
        acf_hoi4.write_text("""
        "AppState"
        {
            "appid" "394360"
            "name" "Hearts of Iron IV"
            "installdir" "Hearts of Iron IV"
        }
        """)

        acf_stellaris = steam_lib / "appmanifest_281990.acf"
        acf_stellaris.write_text("""
        "AppState"
        {
            "appid" "281990"
            "name" "Stellaris"
            "installdir" "Stellaris"
        }
        """)

        # Compile a mock dylib inside Hearts of Iron IV
        c_file = self.test_path / "hoi4_tbb.c"
        c_file.write_text("""
        void *__intel_fast_memset(void *d, int c, unsigned long n) __asm__("__intel_fast_memset.A");
        void *__intel_fast_memset(void *d, int c, unsigned long n) { return d; }
        """)
        hoi4_tbb = hoi4_dir / "libtbb.dylib"
        res = subprocess.run(["clang", "-shared", "-arch", "x86_64", str(c_file), "-o", str(hoi4_tbb)], capture_output=True)
        self.assertEqual(res.returncode, 0)

        # Mock get_steam_library_folders to return our mock library
        orig_get_libs = rp.get_steam_library_folders
        rp.get_steam_library_folders = lambda: [steam_lib]

        try:
            games = rp.discover_steam_games()
            self.assertEqual(len(games), 2)
            game_names = [g.name for g in games]
            self.assertIn("Hearts of Iron IV", game_names)
            self.assertIn("Stellaris", game_names)

            hoi4_game = next(g for g in games if g.name == "Hearts of Iron IV")
            self.assertEqual(hoi4_game.appid, "394360")
            self.assertEqual(hoi4_game.install_path, hoi4_dir)

            # Patch Hearts of Iron IV via steam command
            ret = rp.cmd_steam(game_query="Hearts of Iron IV", patch_mode=True)
            self.assertEqual(ret, 0)

            # Verify libtbb.dylib was patched
            syms = rp.resolve_symbol_offsets(hoi4_tbb)
            st, cur_bytes = rp.check_patch_status(hoi4_tbb, syms[0].file_offset)
            self.assertEqual(st, "PATCHED")
            self.assertEqual(cur_bytes, rp.PATCH_PAYLOAD)

            # Verify codesign
            valid, _ = rp.verify_signature(hoi4_tbb)
            self.assertTrue(valid)

            # Verify undo by steam game name works
            undo_ret = up.undo_patches(app_query="Hearts of Iron IV")
            self.assertEqual(undo_ret, 0)
            st_after, _ = rp.check_patch_status(hoi4_tbb, syms[0].file_offset)
            self.assertEqual(st_after, "UNPATCHED")

            # Test cmd_debug on the game
            debug_ret = rp.cmd_debug("Hearts of Iron IV")
            self.assertEqual(debug_ret, 0)

        finally:
            rp.get_steam_library_folders = orig_get_libs

    def test_user_intel_name_patterns(self):
        """Verify user glob name patterns across all Intel library families."""
        # TBB & OpenMP
        self.assertTrue(rp.matches_intel_name_pattern("libtbb.dylib"))
        self.assertTrue(rp.matches_intel_name_pattern("libtbbmalloc.dylib"))
        self.assertTrue(rp.matches_intel_name_pattern("libiomp5.dylib"))
        self.assertTrue(rp.matches_intel_name_pattern("libomp.dylib"))
        # MKL & IPP
        self.assertTrue(rp.matches_intel_name_pattern("libmkl_core.dylib"))
        self.assertTrue(rp.matches_intel_name_pattern("libipp_core.dylib"))
        # Compiler runtimes
        self.assertTrue(rp.matches_intel_name_pattern("libimf.dylib"))
        self.assertTrue(rp.matches_intel_name_pattern("libsvml.dylib"))
        self.assertTrue(rp.matches_intel_name_pattern("libcilkrts.5.dylib"))
        # Ray tracing / AI / Encoders
        self.assertTrue(rp.matches_intel_name_pattern("libembree3.dylib"))
        self.assertTrue(rp.matches_intel_name_pattern("liboidn.dylib"))
        self.assertTrue(rp.matches_intel_name_pattern("libSvtAv1Enc.dylib"))
        self.assertTrue(rp.matches_intel_name_pattern("libonedal.dylib"))
        self.assertTrue(rp.matches_intel_name_pattern("libdnnl.2.dylib"))
        # Adobe & DaVinci / MainConcept
        self.assertTrue(rp.matches_intel_name_pattern("MMXCore.plugin"))
        self.assertTrue(rp.matches_intel_name_pattern("FastCore"))
        self.assertTrue(rp.matches_intel_name_pattern("TextModel.framework"))
        self.assertTrue(rp.matches_intel_name_pattern("MultiProcessor Support.plugin"))
        self.assertTrue(rp.matches_intel_name_pattern("libsavcempc.dylib"))
        # Negative tests
        self.assertFalse(rp.matches_intel_name_pattern("libunrelated.dylib"))
        self.assertFalse(rp.matches_intel_name_pattern("libsqlite3.dylib"))
        self.assertFalse(rp.matches_intel_name_pattern("libcurl.4.dylib"))


    def test_installed_apps_discovery_and_mass_patch(self):
        """Verify discovery of installed applications and mass-patching with rollback."""
        mock_apps = self.test_path / "MockApplications"
        mock_apps.mkdir()

        # App 1: Clean App
        app1 = mock_apps / "CleanApp.app"
        (app1 / "Contents/MacOS").mkdir(parents=True)

        # App 2: PhotoEditor.app with libtbb.dylib
        app2 = mock_apps / "PhotoEditor.app"
        (app2 / "Contents/Frameworks").mkdir(parents=True)
        c_src2 = self.test_path / "tbb.c"
        c_src2.write_text("void *__intel_fast_memset_A(void *d, int c, unsigned long n) __asm__(\"___intel_fast_memset.A\");\nvoid *__intel_fast_memset_A(void *d, int c, unsigned long n) { return d; }")
        tbb_dylib = app2 / "Contents/Frameworks/libtbb.dylib"
        res = subprocess.run(["clang", "-shared", "-arch", "x86_64", str(c_src2), "-o", str(tbb_dylib)], capture_output=True)
        self.assertEqual(res.returncode, 0)

        # App 3: Suite/VideoEditor.app with libintel.dylib in nested folder
        app3_dir = mock_apps / "VideoSuite" / "VideoEditor.app"
        (app3_dir / "Contents/Libraries").mkdir(parents=True)
        c_src3 = self.test_path / "intel.c"
        c_src3.write_text("void *__intel_fast_memset(void *d, int c, unsigned long n); void *__intel_fast_memset(void *d, int c, unsigned long n) { return d; }")
        intel_dylib = app3_dir / "Contents/Libraries/libintel.dylib"
        res = subprocess.run(["clang", "-shared", "-arch", "x86_64", str(c_src3), "-o", str(intel_dylib)], capture_output=True)
        self.assertEqual(res.returncode, 0)

        # Mock get_installed_app_folders
        orig_get_folders = rp.get_installed_app_folders
        rp.get_installed_app_folders = lambda: [mock_apps]

        try:
            discovered = rp.discover_installed_apps()
            names = [a.name for a in discovered]
            self.assertIn("CleanApp", names)
            self.assertIn("PhotoEditor", names)
            self.assertIn("VideoEditor", names)

            # Test inspect mode
            ret_inspect = rp.cmd_apps(patch_mode=False)
            self.assertEqual(ret_inspect, 0)

            # Test mass-patch all apps needing patch
            ret_patch = rp.cmd_apps(patch_mode=True, all_apps=True)
            self.assertEqual(ret_patch, 0)

            # Verify PhotoEditor patched
            syms2 = rp.resolve_symbol_offsets(tbb_dylib)
            st2, b2 = rp.check_patch_status(tbb_dylib, syms2[0].file_offset)
            self.assertEqual(st2, "PATCHED")
            self.assertEqual(b2, rp.PATCH_PAYLOAD)

            # Verify VideoEditor patched
            syms3 = rp.resolve_symbol_offsets(intel_dylib)
            st3, b3 = rp.check_patch_status(intel_dylib, syms3[0].file_offset)
            self.assertEqual(st3, "PATCHED")
            self.assertEqual(b3, rp.PATCH_PAYLOAD)

            # Verify undo single app by name
            undo_ret = up.undo_patches(app_query="PhotoEditor")
            self.assertEqual(undo_ret, 0)
            st2_after, _ = rp.check_patch_status(tbb_dylib, syms2[0].file_offset)
            self.assertEqual(st2_after, "UNPATCHED")

            # Verify undo remaining all active
            undo_all_ret = up.undo_patches(all_patches=True)
            self.assertEqual(undo_all_ret, 0)
            st3_after, _ = rp.check_patch_status(intel_dylib, syms3[0].file_offset)
            self.assertEqual(st3_after, "UNPATCHED")

        finally:
            rp.get_installed_app_folders = orig_get_folders

    def test_progress_bar(self):
        """Verify ProgressBar updates, ticks, and finishes cleanly without exceptions."""
        pbar = rp.ProgressBar(total=5, prefix="TestScan", bar_length=10)
        for i in range(1, 6):
            pbar.update(i, f"Item_{i}")
            pbar.tick(f"Item_{i}")
        pbar.finish(clear=True)

    def test_find_app_by_name_and_fast_lookup(self):
        """Verify fast direct app lookup bypassing full directory scan."""
        mock_apps = self.test_path / "FastLookupApps"
        mock_apps.mkdir()

        # Direct .app
        app1 = mock_apps / "TargetApp.app"
        (app1 / "Contents/MacOS").mkdir(parents=True)

        # Nested suite .app
        app2 = mock_apps / "VideoSuite" / "VideoEditor.app"
        (app2 / "Contents/MacOS").mkdir(parents=True)

        # 1. Test direct exact lookup
        found1 = rp.find_app_by_name("TargetApp", search_dirs=[mock_apps])
        self.assertIsNotNone(found1)
        self.assertEqual(found1.name, "TargetApp")
        self.assertEqual(found1.bundle_path, app1.resolve())

        # 2. Test subfolder lookup
        found2 = rp.find_app_by_name("VideoEditor", search_dirs=[mock_apps])
        self.assertIsNotNone(found2)
        self.assertEqual(found2.name, "VideoEditor")
        self.assertEqual(found2.bundle_path, app2.resolve())

        # 3. Test non-existent app returns None
        found_none = rp.find_app_by_name("NonExistentApp123", search_dirs=[mock_apps])
        self.assertIsNone(found_none)

    def test_is_root_required_for_path(self):
        """Verify root privilege detection distinguishes system vs user-space paths."""
        # User space / temp path does not need root
        user_file = self.test_path / "user_lib.dylib"
        user_file.write_bytes(b"test")
        self.assertFalse(rp.is_root_required_for_path(user_file))
        self.assertFalse(up.is_root_required_for_path(user_file))

        # System paths require root (e.g. /Applications, /Library)
        sys_path = Path("/Applications/SomeTestApp.app")
        # When not running as UID 0, should require root
        if os.geteuid() != 0:
            self.assertTrue(rp.is_root_required_for_path(sys_path))
            self.assertTrue(up.is_root_required_for_path(sys_path))

    def test_cmd_undo_delegation_to_undo_patcher(self):
        """Verify rp.cmd_undo seamlessly delegates to up.undo_patches with history persistence."""
        # Create and patch a mock app
        app_dir = self.test_path / "DelegationApp.app" / "Contents" / "Libraries"
        app_dir.mkdir(parents=True)
        c_file = self.test_path / "delegation_stub.c"
        c_file.write_text("""
        void *__intel_fast_memset(void *d, int c, unsigned long n) __asm__("__intel_fast_memset.A");
        void *__intel_fast_memset(void *d, int c, unsigned long n) { return d; }
        """)
        dylib = app_dir / "libtarget.dylib"
        res = subprocess.run(["clang", "-shared", "-arch", "x86_64", str(c_file), "-o", str(dylib)], capture_output=True)
        self.assertEqual(res.returncode, 0)

        patch_ret = rp.cmd_patch(self.test_path / "DelegationApp.app")
        self.assertEqual(patch_ret, 0)

        # Call rp.cmd_undo (which delegates to up.undo_patches)
        undo_ret = rp.cmd_undo(app_name="DelegationApp")
        self.assertEqual(undo_ret, 0)

        # Verify patch status is unpatched
        syms = rp.resolve_symbol_offsets(dylib)
        status, _ = rp.check_patch_status(dylib, syms[0].file_offset)
        self.assertEqual(status, "UNPATCHED")

        # Verify history saved as reverted
        recs = up.load_history()
        match = [r for r in recs if r.get("app_name") == "DelegationApp"]
        self.assertTrue(len(match) > 0)
        self.assertEqual(match[-1]["status"], "reverted")

    def test_check_updated_patches_detection(self):
        """Verify check_updated_patches accurately detects when an app update overwrites patched files."""
        # 1. Create a mock app and compile an Intel library
        app_dir = self.test_path / "UpdatableGame.app" / "Contents" / "Libraries"
        app_dir.mkdir(parents=True)
        c_file = self.test_path / "game_stub.c"
        c_file.write_text("""
        void *__intel_fast_memset(void *d, int c, unsigned long n) __asm__("__intel_fast_memset.A");
        void *__intel_fast_memset(void *d, int c, unsigned long n) { return d; }
        """)
        dylib = app_dir / "libgame.dylib"
        res = subprocess.run(["clang", "-shared", "-arch", "x86_64", str(c_file), "-o", str(dylib)], capture_output=True)
        self.assertEqual(res.returncode, 0)

        # 2. Patch the application
        patch_ret = rp.cmd_patch(self.test_path / "UpdatableGame.app")
        self.assertEqual(patch_ret, 0)

        # 3. Before any update, check_updated_patches should find 0 broken apps
        updates = rp.check_updated_patches()
        self.assertEqual(len(updates), 0)

        # 4. Simulate a game / app update by recompiling the unpatched dylib (overwriting it)
        res2 = subprocess.run(["clang", "-shared", "-arch", "x86_64", str(c_file), "-o", str(dylib)], capture_output=True)
        self.assertEqual(res2.returncode, 0)

        # 5. check_updated_patches must now detect that the patch was overwritten!
        updates_after = rp.check_updated_patches()
        self.assertEqual(len(updates_after), 1)
        self.assertEqual(updates_after[0]["app_name"], "UpdatableGame")
        self.assertTrue(dylib.resolve() in [f.resolve() for f in updates_after[0]["outdated_files"]])

        # 6. Repatch the application
        repatch_ret = rp.cmd_patch(self.test_path / "UpdatableGame.app")
        self.assertEqual(repatch_ret, 0)

        # 7. check_updated_patches should now be clean again
        updates_repatched = rp.check_updated_patches()
        self.assertEqual(len(updates_repatched), 0)

        # 8. Check that the older active record was superseded
        history = rp.load_history()
        game_records = [r for r in history if r.get("app_name") == "UpdatableGame"]
        self.assertEqual(len(game_records), 2)
        self.assertEqual(game_records[0]["status"], "superseded")
        self.assertEqual(game_records[1]["status"], "active")

    def test_fat_binary_slice_realignment_and_offset_sync(self):
        """Verify check_updated_patches handles shifted offsets in fat binaries and auto-syncs history."""
        # 1. Create a mock app and compile a dylib
        app_dir = self.test_path / "CK2Mock.app" / "Contents" / "Libraries"
        app_dir.mkdir(parents=True)
        c_file = self.test_path / "ck2_stub.c"
        c_file.write_text("""
        void *__intel_fast_memset(void *d, int c, unsigned long n) __asm__("__intel_fast_memset.A");
        void *__intel_fast_memset(void *d, int c, unsigned long n) { return d; }
        """)
        dylib = app_dir / "libtbb.dylib"
        res = subprocess.run(["clang", "-shared", "-arch", "x86_64", str(c_file), "-o", str(dylib)], capture_output=True)
        self.assertEqual(res.returncode, 0)

        # 2. Patch the application
        patch_ret = rp.cmd_patch(self.test_path / "CK2Mock.app")
        self.assertEqual(patch_ret, 0)

        # Retrieve the real resolved symbol offset
        syms = rp.resolve_symbol_offsets(dylib)
        self.assertTrue(len(syms) > 0)
        real_offset = syms[0].file_offset

        # 3. Simulate codesign slice shift / stale history offset (e.g. 368960 vs 409920)
        fake_stale_offset = real_offset - 128
        recs = rp.load_history()
        self.assertEqual(len(recs), 1)
        recs[0]["files"][0]["symbols"][0]["offset"] = fake_stale_offset
        rp.save_history(recs)

        # 4. check_updated_patches should NOT falsely flag CK2Mock as broken,
        # because dynamic Mach-O symbol resolution reveals the live symbol is PATCHED!
        updates = rp.check_updated_patches()
        self.assertEqual(len(updates), 0, "Patched binary with shifted history offset must not trigger false alarm")

        # 5. Verify the history record was auto-synced with the real live offset
        recs_after = rp.load_history()
        synced_offset = recs_after[0]["files"][0]["symbols"][0]["offset"]
        self.assertEqual(synced_offset, real_offset, "History offset should be auto-synced to real live symbol offset")

    def test_factory_reset_wipes_all_history_and_restores(self):
        """Verify reset_all_patches reverts patches, deletes .bak files, and wipes history ledger to 0."""
        app_dir = self.test_path / "ResetMock.app" / "Contents" / "Libraries"
        app_dir.mkdir(parents=True)
        c_file = self.test_path / "reset_stub.c"
        c_file.write_text("""
        void *__intel_fast_memset(void *d, int c, unsigned long n) __asm__("__intel_fast_memset.A");
        void *__intel_fast_memset(void *d, int c, unsigned long n) { return d; }
        """)
        dylib = app_dir / "libtarget.dylib"
        res = subprocess.run(["clang", "-shared", "-arch", "x86_64", str(c_file), "-o", str(dylib)], capture_output=True)
        self.assertEqual(res.returncode, 0)

        # 1. Patch the application
        patch_ret = rp.cmd_patch(self.test_path / "ResetMock.app")
        self.assertEqual(patch_ret, 0)

        # Verify active history exists and .bak exists
        recs = rp.load_history()
        self.assertEqual(len(recs), 1)
        self.assertEqual(recs[0]["status"], "active")
        bak_file = dylib.with_name(dylib.name + ".bak")
        self.assertTrue(bak_file.exists())

        # 2. Run Factory Reset
        reset_ret = up.reset_all_patches(force=True)
        self.assertEqual(reset_ret, 0)

        # 3. Verify history ledger is completely wiped to 0 records
        recs_after = rp.load_history()
        self.assertEqual(len(recs_after), 0, "History ledger must have 0 records after factory reset")

        # 4. Verify .bak file is deleted
        self.assertFalse(bak_file.exists(), "Backup .bak file must be removed after factory reset")

        # 5. Verify binary is reverted to UNPATCHED
        syms = rp.resolve_symbol_offsets(dylib)
        self.assertTrue(len(syms) > 0)
        status, _ = rp.check_patch_status(dylib, syms[0].file_offset)
        self.assertEqual(status, "UNPATCHED", "Binary must be unpatched after factory reset")

    def test_interactive_wizard_loop_and_screen_clear(self):
        """Verify interactive_wizard loops continuously, clears screen on each pick, and only exits via Exit option."""
        from unittest.mock import patch

        clears = []
        def mock_clear():
            clears.append(True)

        # Simulate user inputs: "8" (view history), "" (press Enter to return), "12" (exit)
        user_inputs = ["8", "", "12"]
        def mock_input(prompt=""):
            return user_inputs.pop(0)

        with patch.object(rp, "clear_screen", side_effect=mock_clear):
            with patch("builtins.input", side_effect=mock_input):
                with patch.object(rp, "prompt_repatch_updates") as mock_repatch:
                    ret = rp.interactive_wizard()
                    self.assertEqual(ret, 0)
                    mock_repatch.assert_called_once()
                    # clear_screen must be called multiple times:
                    # 1. Start of loop
                    # 2. When option 8 is picked
                    # 3. Next iteration of loop (returning to menu)
                    # 4. When option 12 (exit) is picked
                    self.assertGreaterEqual(len(clears), 4)


if __name__ == "__main__":
    unittest.main()





