#!/usr/bin/env python3
"""
Ryzentosh Patching Utility
--------------------------
Fixes Intel library crashes on AMD Hackintoshes / Ryzentosh systems.

Intel performance libraries (Intel TBB, MKL, IPP) crash on AMD CPUs because
their CPUID dispatchers hit invalid or recursive code paths when encountering
"AuthenticAMD". This tool dynamically locates target symbols (such as
__intel_fast_memset.A) and applies an in-place prologue patch with universal
x86_64 assembly (rep stosb), removes quarantine attributes, and re-signs binaries.

Usage:
  python3 ryzentosh_patcher.py patch <target> [--dry-run] [--no-backup]
  python3 ryzentosh_patcher.py scan <target>
  python3 ryzentosh_patcher.py restore <target>
  python3 ryzentosh_patcher.py mkl-info
"""

import argparse
from datetime import datetime
import json
import os
import re
import shutil
import struct
import subprocess
import sys
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

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


# Universal 16-byte rep stosb patch:
# push %rdi          (0x57)
# mov  %rsi, %rax    (0x48 0x89 0xF0)
# mov  %rdx, %rcx    (0x48 0x89 0xD1)
# rep  stosb         (0xF3 0xAA)
# pop  %rax          (0x58)
# ret                (0xC3)
# nop * 5            (0x90 0x90 0x90 0x90 0x90)
PATCH_PAYLOAD = bytes([
    0x57,
    0x48, 0x89, 0xF0,
    0x48, 0x89, 0xD1,
    0xF3, 0xAA,
    0x58,
    0xC3,
    0x90, 0x90, 0x90, 0x90, 0x90
])
assert len(PATCH_PAYLOAD) == 16, "Payload must be exactly 16 bytes"

# Mach-O Magic constants
MH_MAGIC_64 = 0xFEEDFACF
MH_CIGAM_64 = 0xCFFAEDFE
MH_MAGIC = 0xFEEDFACE
MH_CIGAM = 0xCEFAEDFE
FAT_MAGIC = 0xCAFEBABE
FAT_CIGAM = 0xBEBAFECA
FAT_MAGIC_64 = 0xCAFEBABF
FAT_CIGAM_64 = 0xBFBAFECA

TARGET_SYMBOL_PATTERNS = [
    re.compile(r"_{1,3}intel_fast_memset(\.[A-Za-z0-9_]+)?$"),
]


class Colors:
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    RED = "\033[91m"
    BLUE = "\033[94m"
    CYAN = "\033[96m"
    WHITE = "\033[97m"
    GRAY = "\033[90m"
    BOLD = "\033[1m"
    RESET = "\033[0m"

    @classmethod
    def strip(cls, text: str) -> str:
        return re.sub(r"\033\[[0-9;]*m", "", text)


def cprint(color: str, text: str):
    print(f"{color}{text}{Colors.RESET}", flush=True)


def clear_screen():
    """Clears the terminal screen and scrollback buffer so no previous leftovers are visible."""
    if os.environ.get("TERM"):
        try:
            os.system("clear")
        except Exception:
            pass
    sys.stdout.write("\033[H\033[2J\033[3J")
    sys.stdout.flush()


class ProgressBar:
    """An Apple-themed startup loading bar that updates in-place strictly on a single line."""

    def __init__(self, total: int, prefix: str = "Scanning", bar_length: int = 16):
        self.total = max(1, total)
        self.prefix = prefix
        self.bar_length = bar_length
        self.current = 0
        self.is_tty = sys.stdout.isatty()

    def update(self, current: int, item_name: str = ""):
        self.current = current
        percent = min(1.0, self.current / self.total)
        filled = int(round(self.bar_length * percent))
        empty = self.bar_length - filled

        # Apple startup loading bar: solid white fill on dark gray track
        white_bar = f"{Colors.BOLD}{Colors.WHITE}" + ("█" * filled) + f"{Colors.RESET}"
        gray_track = f"{Colors.GRAY}" + ("░" * empty) + f"{Colors.RESET}"
        bar_visual = f"{white_bar}{gray_track}"

        pct_text = f"{int(percent * 100):3d}%"
        count_text = f"({self.current}/{self.total})"

        # Dynamic terminal width detection to guarantee NO line wrapping
        try:
            cols = shutil.get_terminal_size((80, 24)).columns
        except Exception:
            cols = 80
        max_line_len = max(40, cols - 2)

        # Base prefix: ⚡  [████░░░░] 50% (20/41)
        base_prefix = f"  {Colors.BOLD}⚡{Colors.RESET}  [{bar_visual}] {pct_text} {Colors.BOLD}{count_text}{Colors.RESET} "
        visible_base_len = 5 + self.bar_length + 2 + len(pct_text) + 1 + len(count_text) + 1

        avail_for_item = max(8, max_line_len - visible_base_len)
        clean_item = item_name.strip()
        if len(clean_item) > avail_for_item:
            clean_item = clean_item[:avail_for_item - 3] + "..."

        # \r rewrites in-place on the same line, \033[K clears remaining characters
        print(f"\r{base_prefix}{clean_item}\033[K", end="", flush=True)

    def tick(self, item_name: str = ""):
        self.update(self.current, item_name)

    def finish(self, clear: bool = True):
        if clear:
            print("\r\033[K", end="", flush=True)
        else:
            print(flush=True)


class MachOSegment:
    def __init__(self, name: str, vmaddr: int, vmsize: int, fileoff: int, filesize: int):
        self.name = name
        self.vmaddr = vmaddr
        self.vmsize = vmsize
        self.fileoff = fileoff
        self.filesize = filesize

    def contains_vmaddr(self, addr: int) -> bool:
        return self.vmaddr <= addr < (self.vmaddr + self.vmsize)


class SymbolInfo:
    def __init__(self, name: str, vmaddr: int, segment_name: str, section_name: str, file_offset: int):
        self.name = name
        self.vmaddr = vmaddr
        self.segment_name = segment_name
        self.section_name = section_name
        self.file_offset = file_offset


SKIP_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".icns", ".car", ".pdf",
    ".json", ".xml", ".plist", ".html", ".css", ".js", ".ts", ".txt", ".md", ".rtf",
    ".strings", ".nib", ".storyboardc", ".pak", ".dat", ".wav", ".mp3", ".ogg",
    ".ttf", ".otf", ".py", ".pyc", ".h", ".c", ".cpp", ".m", ".mm", ".o",
    ".zip", ".tar", ".gz", ".bz2", ".xz", ".7z", ".jar", ".vdf", ".acf"
}


def is_macho_file(file_path: Path) -> bool:
    """Quickly checks whether the given file has a Mach-O magic header."""
    if not file_path.is_file() or file_path.is_symlink():
        return False
    if file_path.suffix.lower() in SKIP_EXTENSIONS:
        return False
    try:
        with open(file_path, "rb") as f:
            magic = f.read(4)
            if len(magic) < 4:
                return False
            magic_num = struct.unpack(">I", magic)[0]
            return magic_num in (
                MH_MAGIC, MH_CIGAM, MH_MAGIC_64, MH_CIGAM_64,
                FAT_MAGIC, FAT_CIGAM, FAT_MAGIC_64, FAT_CIGAM_64
            )
    except (PermissionError, OSError):
        return False


def get_macho_slices(file_path: Path) -> List[Tuple[str, int, int]]:
    """
    Returns a list of (arch_name, offset, size) for each slice in a Mach-O binary.
    For thin binaries, returns [('x86_64' or other, 0, filesize)].
    """
    slices = []
    file_size = file_path.stat().st_size
    try:
        with open(file_path, "rb") as f:
            magic_bytes = f.read(4)
            if len(magic_bytes) < 4:
                return slices
            magic = struct.unpack(">I", magic_bytes)[0]

            if magic in (FAT_MAGIC, FAT_CIGAM):
                is_be = (magic == FAT_MAGIC)
                fmt = ">II" if is_be else "<II"
                nfat_bytes = f.read(4)
                if len(nfat_bytes) < 4:
                    return slices
                nfat_arch = struct.unpack(">I" if is_be else "<I", nfat_bytes)[0]

                for _ in range(nfat_arch):
                    arch_bytes = f.read(20)
                    if len(arch_bytes) < 20:
                        break
                    cputype, cpusubtype, offset, size, align = struct.unpack(
                        ">iiIII" if is_be else "<iiIII", arch_bytes
                    )
                    arch = "x86_64" if cputype == 0x01000007 else (
                        "arm64" if cputype == 0x0100000c else f"cpu_0x{cputype:x}"
                    )
                    slices.append((arch, offset, size))
            elif magic in (MH_MAGIC_64, MH_CIGAM_64):
                slices.append(("x86_64", 0, file_size))
            elif magic in (MH_MAGIC, MH_CIGAM):
                slices.append(("i386", 0, file_size))
    except Exception:
        pass
    return slices


def get_segments(file_path: Path, arch: Optional[str] = None) -> List[MachOSegment]:
    """Uses otool -l to parse Mach-O segment headers."""
    cmd = ["otool", "-l"]
    if arch:
        cmd.extend(["-arch", arch])
    cmd.append(str(file_path))

    segments = []
    try:
        res = subprocess.run(cmd, capture_output=True, text=True, check=True)
        lines = res.stdout.splitlines()
        i = 0
        while i < len(lines):
            line = lines[i].strip()
            if line in ("cmd LC_SEGMENT_64", "cmd LC_SEGMENT"):
                segname = ""
                vmaddr = 0
                vmsize = 0
                fileoff = 0
                filesize = 0
                while i < len(lines) and not (lines[i].strip().startswith("cmd ") and lines[i].strip() not in ("cmd LC_SEGMENT_64", "cmd LC_SEGMENT") and segname != ""):
                    sub = lines[i].strip()
                    if sub.startswith("segname "):
                        segname = sub.split()[1]
                    elif sub.startswith("vmaddr "):
                        vmaddr = int(sub.split()[1], 16)
                    elif sub.startswith("vmsize "):
                        vmsize = int(sub.split()[1], 16)
                    elif sub.startswith("fileoff "):
                        fileoff = int(sub.split()[1])
                    elif sub.startswith("filesize "):
                        filesize = int(sub.split()[1])
                    i += 1
                    if sub.startswith("initprot "):
                        break
                if segname:
                    segments.append(MachOSegment(segname, vmaddr, vmsize, fileoff, filesize))
            else:
                i += 1
    except Exception:
        segments.append(MachOSegment("__TEXT", 0x0, 0x10000000, 0, 0x10000000))
    return segments


def parse_symbols_nm(file_path: Path, arch: str = "x86_64") -> List[Tuple[str, int, str, str]]:
    """
    Runs nm -m to find defined symbols in the specified architecture slice.
    Returns: List of (symbol_name, vmaddr, segment_name, section_name)
    """
    cmd = ["nm", "-m", "-arch", arch, str(file_path)]
    symbols = []
    try:
        res = subprocess.run(cmd, capture_output=True, text=True, check=True)
        # Matches any defined symbol line, accommodating all attribute variations:
        # e.g.: 0000000000035400 (__TEXT,__text) non-external (was a private external) __intel_fast_memset.A
        # e.g.: 0000000100000000 (__TEXT,__text) [referenced dynamically] external __mh_execute_header
        nm_re = re.compile(r"^([0-9a-fA-F]+)\s+\(([^,]+),([^)]+)\)\s+.*?\s+(\S+)$")
        for line in res.stdout.splitlines():
            line = line.strip()
            m = nm_re.match(line)
            if m:
                addr_hex, seg, sec, sym = m.groups()
                addr = int(addr_hex, 16)
                symbols.append((sym, addr, seg, sec))
    except Exception:
        pass
    return symbols


def resolve_symbol_offsets(file_path: Path) -> List[SymbolInfo]:
    """
    Finds target Intel symbols in the binary and computes their exact file offsets.
    Handles fat binary slices and Mach-O segment translations.
    """
    slices = get_macho_slices(file_path)
    x86_slice = None
    for s_arch, s_offset, s_size in slices:
        if s_arch == "x86_64":
            x86_slice = (s_arch, s_offset, s_size)
            break

    slice_offset = x86_slice[1] if x86_slice else 0
    segments = get_segments(file_path, arch="x86_64" if x86_slice else None)
    nm_symbols = parse_symbols_nm(file_path, arch="x86_64" if x86_slice else "x86_64")

    resolved = []
    for sym_name, vmaddr, seg_name, sec_name in nm_symbols:
        is_target = any(pat.match(sym_name) for pat in TARGET_SYMBOL_PATTERNS)
        if not is_target:
            continue

        matched_seg = None
        for seg in segments:
            if seg.contains_vmaddr(vmaddr):
                matched_seg = seg
                break
        if not matched_seg:
            for seg in segments:
                if seg.name == seg_name:
                    matched_seg = seg
                    break

        if matched_seg:
            file_off = slice_offset + (vmaddr - matched_seg.vmaddr + matched_seg.fileoff)
        else:
            file_off = slice_offset + vmaddr

        resolved.append(SymbolInfo(sym_name, vmaddr, seg_name, sec_name, file_off))

    # Fallback for known libtbb.dylib offset if symbols were stripped
    if not resolved and ("tbb" in file_path.name.lower() or "memset" in file_path.name.lower()):
        try:
            file_size = file_path.stat().st_size
            if file_size > 0x35410:
                with open(file_path, "rb") as f:
                    f.seek(0x35400)
                    sig = f.read(8)
                    # Check for push %rsi; callq +0x4a; pop %rcx; retq OR already patched
                    if sig == b"\x56\xe8\x4a\x00\x00\x00\x59\xc3" or sig == PATCH_PAYLOAD[:8]:
                        resolved.append(SymbolInfo("__intel_fast_memset.A", 0x35400, "__TEXT", "__text", 0x35400))
        except Exception:
            pass

    return resolved


def fast_contains_intel_symbols(file_path: Path) -> bool:
    """Fast raw byte search for Intel symbol names."""
    try:
        with open(file_path, "rb") as f:
            chunk = f.read(50 * 1024 * 1024)
            if b"intel_fast_memset" in chunk:
                return True
            if f.tell() < file_path.stat().st_size:
                f.seek(-min(50 * 1024 * 1024, file_path.stat().st_size), os.SEEK_END)
                end_chunk = f.read()
                if b"intel_fast_memset" in end_chunk:
                    return True
    except Exception:
        pass
    return False


def fast_contains_mkl(file_path: Path) -> bool:
    """Checks if binary is related to Intel MKL."""
    name = file_path.name.lower()
    if "libmkl" in name or "mkl_" in name:
        return True
    try:
        with open(file_path, "rb") as f:
            chunk = f.read(10 * 1024 * 1024)
            if b"mkl_serv_cpu_detect" in chunk or b"MKL_DEBUG_CPU_TYPE" in chunk:
                return True
    except Exception:
        pass
    return False


USER_INTEL_NAME_PATTERNS = [
    # Intel Threading Building Blocks (TBB)
    re.compile(r".*tbb.*", re.IGNORECASE),
    # Intel OpenMP Runtimes
    re.compile(r".*iomp.*", re.IGNORECASE),
    re.compile(r".*openmp.*", re.IGNORECASE),
    re.compile(r".*libomp.*", re.IGNORECASE),
    # Intel Math Kernel Library (MKL)
    re.compile(r".*mkl.*", re.IGNORECASE),
    # Intel Integrated Performance Primitives (IPP)
    re.compile(r".*ipp.*", re.IGNORECASE),
    # Intel Compiler Runtimes (ICC / oneAPI / DPC++)
    re.compile(r".*libimf.*", re.IGNORECASE),
    re.compile(r".*libsvml.*", re.IGNORECASE),
    re.compile(r".*libirng.*", re.IGNORECASE),
    re.compile(r".*libintlc.*", re.IGNORECASE),
    re.compile(r".*cilkrts.*", re.IGNORECASE),
    re.compile(r".*liboffload.*", re.IGNORECASE),
    re.compile(r".*istrconv.*", re.IGNORECASE),
    # Intel Ray Tracing, AI & Rendering Engines
    re.compile(r".*embree.*", re.IGNORECASE),
    re.compile(r".*openvkl.*", re.IGNORECASE),
    re.compile(r".*ospray.*", re.IGNORECASE),
    re.compile(r".*oidn.*", re.IGNORECASE),
    re.compile(r".*openimagedenoise.*", re.IGNORECASE),
    # Intel SVT Video Encoders & Decoders
    re.compile(r".*svt.*", re.IGNORECASE),
    re.compile(r".*svtav1.*", re.IGNORECASE),
    re.compile(r".*svthevc.*", re.IGNORECASE),
    re.compile(r".*svtvp9.*", re.IGNORECASE),
    # Intel Data Analytics Acceleration Library (DAAL / oneDAL)
    re.compile(r".*daal.*", re.IGNORECASE),
    re.compile(r".*onedal.*", re.IGNORECASE),
    # Intel Deep Learning / Neural Networks (oneDNN / MKL-DNN)
    re.compile(r".*dnnl.*", re.IGNORECASE),
    re.compile(r".*mkldnn.*", re.IGNORECASE),
    # Adobe Performance Plugins & Frameworks (ICC/IPP-compiled)
    re.compile(r"^MMXCore.*", re.IGNORECASE),
    re.compile(r"^FastCore.*", re.IGNORECASE),
    re.compile(r"^TextModel.*", re.IGNORECASE),
    re.compile(r".*MultiProcessor Support.*", re.IGNORECASE),
    re.compile(r".*HalideRuntime.*", re.IGNORECASE),
    # DaVinci Resolve / Blackmagic / MainConcept ICC-compiled video modules
    re.compile(r".*savce.*", re.IGNORECASE),
    re.compile(r".*smpc.*", re.IGNORECASE),
    re.compile(r".*mainconcept.*", re.IGNORECASE),
    # Generic Intel CPUID dispatchers & routines
    re.compile(r".*intel_fast.*", re.IGNORECASE),
    re.compile(r".*intel_memset.*", re.IGNORECASE),
    re.compile(r".*intel_memcpy.*", re.IGNORECASE),
    re.compile(r".*intel_cpu.*", re.IGNORECASE),
]

def matches_intel_name_pattern(name: str) -> bool:
    """Checks if filename matches any of the common Intel performance library patterns."""
    return any(pat.match(name) for pat in USER_INTEL_NAME_PATTERNS)


def get_linked_executable_path_libs(macho_binary: Path) -> List[Path]:
    """Inspects otool -L to resolve any @executable_path relative libraries."""
    linked = []
    try:
        res = subprocess.run(["otool", "-L", str(macho_binary)], capture_output=True, text=True, check=True)
        for line in res.stdout.splitlines()[1:]:
            parts = line.strip().split()
            if not parts:
                continue
            lib_ref = parts[0]
            if lib_ref.startswith("@executable_path/"):
                rel_sub = lib_ref[len("@executable_path/"):]
                resolved = (macho_binary.parent / rel_sub).resolve()
                if resolved.exists() and resolved not in linked:
                    linked.append(resolved)
    except Exception:
        pass
    return linked


def find_candidates_in_path(root_path: Path, max_depth: int = 10) -> Tuple[List[Path], List[Path]]:
    """
    Recursively scans a path for:
    1. Mach-O files matching Intel library name patterns (*tbb*, *iomp*, *mkl*, *ipp*, MMXCore*, FastCore*, TextModel*).
    2. Mach-O files containing crashing Intel memset symbols.
    3. Resolves @executable_path linked libraries from Mach-O executables.
    """
    patch_candidates: List[Path] = []
    mkl_candidates: List[Path] = []
    seen: Set[Path] = set()

    def add_candidate(cand: Path):
        resolved = cand.resolve()
        if resolved in seen:
            return
        seen.add(resolved)
        name_lower = cand.name.lower()
        if "mkl" in name_lower:
            mkl_candidates.append(cand)
        else:
            patch_candidates.append(cand)

    # 1. Direct file target
    if root_path.is_file():
        if is_macho_file(root_path):
            if matches_intel_name_pattern(root_path.name) or fast_contains_intel_symbols(root_path) or fast_contains_mkl(root_path):
                add_candidate(root_path)
            for linked in get_linked_executable_path_libs(root_path):
                if is_macho_file(linked) and (matches_intel_name_pattern(linked.name) or fast_contains_intel_symbols(linked)):
                    add_candidate(linked)
        return patch_candidates, mkl_candidates

    # 2. Directory or .app walk
    root_depth = len(root_path.parts)
    for dirpath, dirnames, filenames in os.walk(root_path):
        dirnames[:] = [d for d in dirnames if not d.startswith(".") and d != "__pycache__" and d != "Resources"]
        current_depth = len(Path(dirpath).parts) - root_depth
        if current_depth > max_depth:
            continue

        for filename in filenames:
            if filename.endswith(".bak"):
                continue
            file_path = Path(dirpath) / filename
            if not is_macho_file(file_path):
                continue

            # Only check linked libraries on executable Mach-O binaries (skip dylibs/bundles)
            if not (filename.endswith(".dylib") or filename.endswith(".so") or filename.endswith(".bundle")):
                for linked in get_linked_executable_path_libs(file_path):
                    if is_macho_file(linked) and (matches_intel_name_pattern(linked.name) or fast_contains_intel_symbols(linked)):
                        add_candidate(linked)

            if matches_intel_name_pattern(filename):
                add_candidate(file_path)
            elif fast_contains_intel_symbols(file_path):
                add_candidate(file_path)
            elif fast_contains_mkl(file_path):
                add_candidate(file_path)

    # 3. If root_path is an .app bundle in a subfolder (e.g. game or suite), check parent directory for companion dylibs
    if root_path.suffix == ".app":
        parent_dir = root_path.parent
        if parent_dir.name not in ("Applications", "System"):
            try:
                for fname in os.listdir(parent_dir):
                    p = parent_dir / fname
                    if p.is_file() and not fname.endswith(".bak") and is_macho_file(p):
                        if matches_intel_name_pattern(fname) or fast_contains_intel_symbols(p):
                            add_candidate(p)
            except Exception:
                pass

    return patch_candidates, mkl_candidates


def check_patch_status(file_path: Path, offset: int) -> Tuple[str, bytes]:
    """Reads 16 bytes at offset and checks if patched."""
    try:
        with open(file_path, "rb") as f:
            f.seek(offset)
            data = f.read(16)
            if data == PATCH_PAYLOAD:
                return "PATCHED", data
            else:
                return "UNPATCHED", data
    except Exception:
        return "ERROR", b""


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


# =====================================================================
# History & Metadata Tracking
# =====================================================================

def detect_app_name(target_path: Path, file_path: Optional[Path] = None) -> str:
    """
    Infers a human-readable application or game name from directory paths.
    Recognizes .app bundles, Steam directories, and common game structures.
    """
    check_paths = []
    if file_path:
        check_paths.append(file_path.resolve())
    check_paths.append(target_path.resolve())

    for p in check_paths:
        for part in reversed(p.parts):
            if part.endswith(".app"):
                return part[:-4]
        parts = list(p.parts)
        if "common" in parts:
            idx = parts.index("common")
            if idx + 1 < len(parts):
                return parts[idx + 1]

    if target_path.is_dir():
        return target_path.name
    return target_path.stem


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
    """Checks if root privileges are required to modify the target path or its contents."""
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


def ensure_root(reason: str = "This operation requires root privileges.") -> bool:
    """
    Checks if running as root (UID 0). If not, elevates via sudo by re-executing
    the current command with sudo and replacing the current process.
    """
    if os.geteuid() == 0:
        return True

    cprint(Colors.YELLOW, f"\n[!] {reason}")
    cprint(Colors.YELLOW, "    Elevating with sudo (you may be prompted for your macOS password)...")
    args = ["sudo", sys.executable] + sys.argv
    try:
        os.execvp("sudo", args)
    except Exception as e:
        cprint(Colors.RED, f"Failed to elevate with sudo: {e}")
        print(f"Please re-run this command with sudo:\n  sudo {' '.join(args[1:])}")
        return False


def record_patches(app_name: str, target_root: Path, file_entries: List[Dict]):
    """Records a patch operation into history."""
    if not file_entries:
        return
    records = load_history()
    entry_id = f"{datetime.now().strftime('%Y%m%d-%H%M%S')}-{os.urandom(3).hex()}"
    resolved_root = str(target_root.resolve())
    now_iso = datetime.now().isoformat()
    # Mark prior active records for this app/target as superseded
    for r in records:
        if r.get("status") == "active":
            if r.get("app_name") == app_name or r.get("target_root") == resolved_root:
                r["status"] = "superseded"
                r["superseded_at"] = now_iso
    new_record = {
        "id": entry_id,
        "timestamp": now_iso,
        "app_name": app_name,
        "target_root": resolved_root,
        "status": "active",
        "files": file_entries
    }
    records.append(new_record)
    save_history(records)


def mark_history_reverted(file_path: Path):
    """Marks entries for a specific file path as reverted in history."""
    resolved_path = str(file_path.resolve())
    records = load_history()
    modified = False
    now_iso = datetime.now().isoformat()
    for rec in records:
        all_reverted = True
        for f in rec.get("files", []):
            if f.get("file_path") == resolved_path:
                f["status"] = "reverted"
                f["reverted_at"] = now_iso
                modified = True
            if f.get("status") != "reverted":
                all_reverted = False
        if all_reverted:
            rec["status"] = "reverted"
            rec["reverted_at"] = now_iso
    if modified:
        save_history(records)


# =====================================================================
# Commands
# =====================================================================

def cmd_scan(target: Path, verbose: bool = False) -> int:
    """Scans and inspects candidates without modifying anything."""
    cprint(Colors.BOLD, f"\n==> Scanning target: {target}")
    if not target.exists():
        cprint(Colors.RED, f"Error: Target path '{target}' does not exist.")
        return 1

    patch_candidates, mkl_candidates = find_candidates_in_path(target)

    if not patch_candidates and not mkl_candidates:
        cprint(Colors.YELLOW, "No Intel performance libraries (TBB / MKL) found in target path.")
        return 0

    if patch_candidates:
        cprint(Colors.CYAN, f"\nFound {len(patch_candidates)} candidate binary(ies) with Intel symbols:")
        for cand in patch_candidates:
            print(f"\n  • {Colors.BOLD}{cand}{Colors.RESET}")
            symbols = resolve_symbol_offsets(cand)
            if not symbols:
                print(f"    {Colors.YELLOW}Contains Intel strings, but no defined memset symbols resolved via symbol table.{Colors.RESET}")
                continue

            for sym in symbols:
                status, cur_bytes = check_patch_status(cand, sym.file_offset)
                status_color = Colors.GREEN if status == "PATCHED" else Colors.YELLOW
                hex_preview = " ".join(f"{b:02X}" for b in cur_bytes)
                print(f"    - Symbol: {Colors.BOLD}{sym.name}{Colors.RESET}")
                print(f"      Offset: 0x{sym.file_offset:X} (VM: 0x{sym.vmaddr:X}, {sym.segment_name},{sym.section_name})")
                print(f"      Status: {status_color}[{status}]{Colors.RESET}")
                print(f"      Bytes:  {hex_preview}")

    if mkl_candidates:
        cprint(Colors.CYAN, f"\nFound {len(mkl_candidates)} Intel MKL library(ies):")
        for mkl in mkl_candidates:
            print(f"  • {mkl}")
        cprint(Colors.YELLOW, "\nTip: Intel MKL requires runtime environment override:")
        print(f"     MKL_DEBUG_CPU_TYPE=5")
        print(f"  Run 'python3 ryzentosh_patcher.py mkl-info' for full details.")


def cmd_debug(target_input: str) -> int:
    """Performs deep diagnostic inspection of candidate libraries, symbols, Mach-O offsets, and signatures."""
    target_path = Path(target_input).expanduser()
    resolved_target = None
    if target_path.exists():
        resolved_target = target_path
    else:
        # Check Steam games
        for g in discover_steam_games():
            if target_input.lower().strip() in g.name.lower() or target_input.strip() == g.appid:
                resolved_target = g.install_path
                cprint(Colors.CYAN, f"Matched Steam Game: {g.name} (AppID: {g.appid})")
                break

        if not resolved_target:
            # Check Installed macOS Applications
            for a in discover_installed_apps():
                if target_input.lower().strip() in a.name.lower() or (a.bundle_id and target_input.lower().strip() in a.bundle_id.lower()):
                    resolved_target = a.bundle_path
                    cprint(Colors.CYAN, f"Matched Installed Application: {a.name}")
                    break

    if not resolved_target or not resolved_target.exists():
        cprint(Colors.RED, f"Error: Target '{target_input}' not found as a path, installed Steam game, or application.")
        return 1

    cprint(Colors.BOLD, f"\n=======================================================")
    cprint(Colors.BOLD, f"           Ryzentosh Deep Diagnostic Debug Trace       ")
    cprint(Colors.BOLD, f"=======================================================")
    print(f"Target: {resolved_target}")

    patch_candidates, mkl_candidates = find_candidates_in_path(resolved_target)
    print(f"Total Patch Candidates: {len(patch_candidates)}")
    print(f"Total MKL Candidates:   {len(mkl_candidates)}")

    if not patch_candidates and not mkl_candidates:
        cprint(Colors.YELLOW, "\nNo candidate libraries found matching Intel patterns or symbols.")
        return 0

    for cand in patch_candidates:
        cprint(Colors.BOLD, f"\n-------------------------------------------------------")
        cprint(Colors.BOLD, f"Candidate: {cand}")
        cprint(Colors.BOLD, f"-------------------------------------------------------")
        print(f"  File Size: {cand.stat().st_size} bytes")

        # Mach-O Slices
        slices = get_macho_slices(cand)
        slice_desc = ", ".join(f"{arch} (offset 0x{off:X}, size {sz})" for arch, off, sz in slices)
        print(f"  Mach-O Slices: {slice_desc if slices else 'Non-Mach-O or empty'}")

        # Segments
        segments = get_segments(cand)
        print(f"  Segments ({len(segments)}):")
        for seg in segments:
            print(f"    - {seg.name:<16} VM: 0x{seg.vmaddr:X}-0x{seg.vmaddr+seg.vmsize:X}  FileOff: 0x{seg.fileoff:X} (size 0x{seg.filesize:X})")

        # Raw nm -m output for target symbols
        raw_nm = parse_symbols_nm(cand)
        print(f"\n  Defined Symbols in Symbol Table ({len(raw_nm)} total):")
        matched_nm = []
        for sym_name, vmaddr, seg_name, sec_name in raw_nm:
            if any(pat.match(sym_name) for pat in TARGET_SYMBOL_PATTERNS) or "memset" in sym_name.lower():
                matched_nm.append((sym_name, vmaddr, seg_name, sec_name))
                print(f"    * {sym_name} (VM: 0x{vmaddr:X}, {seg_name},{sec_name})")

        if not matched_nm:
            cprint(Colors.YELLOW, "    No memset symbols matched in symbol table.")

        # Resolved SymbolInfo
        symbols = resolve_symbol_offsets(cand)
        print(f"\n  Resolved Target Symbol Offsets ({len(symbols)}):")
        for s in symbols:
            status, cur_bytes = check_patch_status(cand, s.file_offset)
            status_color = Colors.GREEN if status == "PATCHED" else Colors.YELLOW
            hex_str = " ".join(f"{b:02X}" for b in cur_bytes)

            explanation = ""
            if cur_bytes[:8] == b"\x56\xe8\x4a\x00\x00\x00\x59\xc3":
                explanation = "-> Intel CPUID recursive dispatch prologue (triggers crash loop on AMD)"
            elif cur_bytes == PATCH_PAYLOAD:
                explanation = "-> Universal rep stosb patch payload (Active & safe)"
            elif status == "PATCHED":
                explanation = "-> Already patched"
            else:
                explanation = "-> Unpatched"

            print(f"    • Symbol: {Colors.BOLD}{s.name}{Colors.RESET}")
            print(f"      Virtual Address:      0x{s.vmaddr:X} ({s.segment_name},{s.section_name})")
            print(f"      Computed File Offset: 0x{s.file_offset:X} ({s.file_offset})")
            print(f"      Current Bytes:        {hex_str}")
            print(f"      Status:               {status_color}[{status}]{Colors.RESET} {explanation}")

        # Security attributes
        print(f"\n  Security & Gatekeeper Status:")
        try:
            xattr_res = subprocess.run(["xattr", "-p", "com.apple.quarantine", str(cand)], capture_output=True, text=True)
            if xattr_res.returncode == 0 and xattr_res.stdout.strip():
                print(f"    Quarantine:     {Colors.YELLOW}[QUARANTINED] ({xattr_res.stdout.strip()}){Colors.RESET}")
            else:
                print(f"    Quarantine:     {Colors.GREEN}[CLEAN] (No com.apple.quarantine attribute){Colors.RESET}")
        except Exception:
            print("    Quarantine:     Unknown")

        try:
            cs_res = subprocess.run(["codesign", "-dvvv", str(cand)], capture_output=True, text=True)
            cs_out = (cs_res.stderr or "") + (cs_res.stdout or "")
            if "code object is not signed" in cs_out.lower():
                print(f"    Code Signature: {Colors.YELLOW}[UNSIGNED]{Colors.RESET}")
            else:
                id_line = next((l.strip() for l in cs_out.splitlines() if "Identifier=" in l), "Signed")
                valid, msg = verify_signature(cand)
                cs_status = f"{Colors.GREEN}[VALID]{Colors.RESET}" if valid else f"{Colors.YELLOW}[INVALID/ADHOC]{Colors.RESET}"
                print(f"    Code Signature: {cs_status} ({id_line})")
        except Exception:
            print("    Code Signature: Unknown")

    if mkl_candidates:
        cprint(Colors.BOLD, f"\n-------------------------------------------------------")
        cprint(Colors.BOLD, f"Intel MKL Libraries Found ({len(mkl_candidates)}):")
        cprint(Colors.BOLD, f"-------------------------------------------------------")
        for mkl in mkl_candidates:
            print(f"  • {mkl}")
        cprint(Colors.CYAN, "\nMKL Launch Option:")
        print("  /usr/bin/env MKL_DEBUG_CPU_TYPE=5 %command%")

    print()
    return 0



def cmd_patch(target: Path, dry_run: bool = False, no_backup: bool = False, verbose: bool = False) -> int:
    """Patches candidate binaries in target path and records history."""
    cprint(Colors.BOLD, f"\n==> Starting Ryzentosh patch for target: {target}")
    if not target.exists():
        cprint(Colors.RED, f"Error: Target path '{target}' does not exist.")
        return 1

    patch_candidates, mkl_candidates = find_candidates_in_path(target)
    if not patch_candidates:
        cprint(Colors.YELLOW, "No Intel memset libraries found to patch.")
        if mkl_candidates:
            cprint(Colors.CYAN, "Found Intel MKL libraries. Use 'mkl-info' command for launch configurations.")
        return 0

    if not dry_run and os.geteuid() != 0:
        if is_root_required_for_path(target) or any(is_root_required_for_path(c) for c in patch_candidates):
            ensure_root(f"Root privileges required to modify files in {target.name}")

    success_count = 0
    skipped_count = 0
    file_history_entries = []

    for cand in patch_candidates:
        print(f"\nProcessing: {Colors.BOLD}{cand}{Colors.RESET}")
        symbols = resolve_symbol_offsets(cand)
        if not symbols:
            cprint(Colors.YELLOW, "  No target memset symbols defined in symbol table.")
            continue

        backup_created = False
        target_needs_patch = False

        for sym in symbols:
            status, cur_bytes = check_patch_status(cand, sym.file_offset)
            if status == "PATCHED":
                print(f"  Symbol {Colors.CYAN}{sym.name}{Colors.RESET} at 0x{sym.file_offset:X}: {Colors.GREEN}[ALREADY PATCHED]{Colors.RESET}")
            else:
                target_needs_patch = True
                print(f"  Symbol {Colors.CYAN}{sym.name}{Colors.RESET} at 0x{sym.file_offset:X}: {Colors.YELLOW}[NEEDS PATCH]{Colors.RESET}")

        if not target_needs_patch:
            cprint(Colors.GREEN, "  All symbols already patched! Skipping file.")
            skipped_count += 1
            try:
                hist_recs = load_history()
                h_mod = False
                cand_resolved = str(cand.resolve())
                for r in hist_recs:
                    if r.get("status") == "active":
                        for f in r.get("files", []):
                            if f.get("file_path") == cand_resolved:
                                sym_map = {s.name: s.file_offset for s in symbols}
                                for s_ent in f.get("symbols", []):
                                    s_n = s_ent.get("symbol")
                                    if s_n in sym_map and s_ent.get("offset") != sym_map[s_n]:
                                        s_ent["offset"] = sym_map[s_n]
                                        h_mod = True
                if h_mod:
                    save_history(hist_recs)
            except Exception:
                pass
            continue

        if dry_run:
            cprint(Colors.CYAN, "  [DRY-RUN] Would create backup and write 16-byte rep stosb patch.")
            success_count += 1
            continue

        bak_file = cand.with_name(cand.name + ".bak")
        if not no_backup and not bak_file.exists():
            print(f"  Creating backup: {bak_file.name}")
            try:
                shutil.copy2(cand, bak_file)
                backup_created = True
            except Exception as e:
                cprint(Colors.RED, f"  Failed to create backup: {e}")
                return 1

        patched_syms_info = []
        try:
            with open(cand, "r+b") as f:
                for sym in symbols:
                    status, _ = check_patch_status(cand, sym.file_offset)
                    if status == "PATCHED":
                        continue
                    f.seek(sym.file_offset)
                    orig_bytes = f.read(16)
                    f.seek(sym.file_offset)
                    f.write(PATCH_PAYLOAD)
                    patched_syms_info.append({
                        "symbol": sym.name,
                        "offset": sym.file_offset,
                        "vmaddr": sym.vmaddr,
                        "original_bytes_hex": orig_bytes.hex()
                    })
                    print(f"  Patched {Colors.CYAN}{sym.name}{Colors.RESET} at 0x{sym.file_offset:X}")
            f.close()
        except Exception as e:
            cprint(Colors.RED, f"  Error writing patch: {e}")
            if backup_created and bak_file.exists():
                shutil.copy2(bak_file, cand)
                cprint(Colors.YELLOW, "  Restored original file from backup.")
            return 1

        print("  Clearing quarantine attributes (xattr -cr)...")
        strip_quarantine(cand)

        print("  Re-signing binary with ad-hoc signature (codesign)...")
        if resign_binary(cand):
            valid, msg = verify_signature(cand)
            if valid:
                cprint(Colors.GREEN, "  Code signature verified successfully.")
            else:
                cprint(Colors.YELLOW, f"  Signature applied with notice: {msg}")
        else:
            cprint(Colors.RED, "  Warning: codesign failed. Process might be terminated by Gatekeeper.")

        # Re-resolve symbol offsets after codesign in case slices in fat binaries shifted
        try:
            post_syms = resolve_symbol_offsets(cand)
            if post_syms:
                post_map = {s.name: s.file_offset for s in post_syms}
                for entry in patched_syms_info:
                    if entry.get("symbol") in post_map:
                        entry["offset"] = post_map[entry["symbol"]]
        except Exception:
            pass

        cprint(Colors.GREEN, f"  Successfully patched {cand.name}!")
        restore_file_ownership(cand)
        success_count += 1

        file_history_entries.append({
            "file_path": str(cand.resolve()),
            "backup_path": str(bak_file.resolve()) if bak_file.exists() else None,
            "symbols": patched_syms_info,
            "patched_at": datetime.now().isoformat(),
            "status": "active"
        })

    if file_history_entries and not dry_run:
        app_name = detect_app_name(target, patch_candidates[0] if patch_candidates else None)
        record_patches(app_name, target, file_history_entries)
        cprint(Colors.CYAN, f"\nSaved patch history: App '{app_name}' ({len(file_history_entries)} file(s)) -> {HISTORY_FILE.name}")

    cprint(Colors.BOLD, f"\n==> Patching summary: {success_count} patched, {skipped_count} already patched.")
    if mkl_candidates:
        cprint(Colors.CYAN, "\nNote: Target uses Intel MKL. Please configure the launch environment:")
        print("  /usr/bin/env MKL_DEBUG_CPU_TYPE=5 %command%")

    return 0


def cmd_restore(target: Path) -> int:
    """Restores files from .bak backups."""
    cprint(Colors.BOLD, f"\n==> Restoring target: {target}")
    if not target.exists():
        cprint(Colors.RED, f"Error: Target path '{target}' does not exist.")
        return 1

    if is_root_required_for_path(target) and os.geteuid() != 0:
        ensure_root(f"Root privileges required to restore: {target}")

    restored = 0
    if target.is_file():
        bak_file = target.with_name(target.name + ".bak")
        if not bak_file.exists() and target.name.endswith(".bak"):
            bak_file = target
            target = target.with_name(target.name[:-4])

        if bak_file.exists():
            print(f"Restoring {target.name} from {bak_file.name}...")
            shutil.copy2(bak_file, target)
            strip_quarantine(target)
            resign_binary(target)
            restore_file_ownership(target)
            mark_history_reverted(target)
            cprint(Colors.GREEN, f"Restored {target.name}")
            restored += 1
        else:
            cprint(Colors.YELLOW, f"No backup found ({bak_file.name}).")
    else:
        for dirpath, _, filenames in os.walk(target):
            for filename in filenames:
                if filename.endswith(".bak"):
                    bak_file = Path(dirpath) / filename
                    orig_file = Path(dirpath) / filename[:-4]
                    print(f"Restoring {orig_file.name} from {bak_file.name}...")
                    shutil.copy2(bak_file, orig_file)
                    strip_quarantine(orig_file)
                    resign_binary(orig_file)
                    restore_file_ownership(orig_file)
                    mark_history_reverted(orig_file)
                    cprint(Colors.GREEN, f"Restored {orig_file.name}")
                    restored += 1

    cprint(Colors.BOLD, f"\n==> Restore complete: {restored} file(s) restored.")
    return 0


def cmd_history() -> int:
    """Lists recorded patch history."""
    records = load_history()
    if not records:
        cprint(Colors.YELLOW, f"No patch history recorded in {HISTORY_FILE.name}.")
        return 0

    cprint(Colors.BOLD, f"\n=======================================================")
    cprint(Colors.BOLD, f"               Ryzentosh Patch History                 ")
    cprint(Colors.BOLD, f"=======================================================")

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
            f_path = f.get("file_path", "")
            print(f"  - File: {f_path} {f_color}[{f_status.upper()}]{Colors.RESET}")
            for s in f.get("symbols", []):
                print(f"    Symbol: {s.get('symbol')} at offset 0x{s.get('offset', 0):X}")
    print()
    return 0


def cmd_undo(app_name: Optional[str] = None, all_patches: bool = False, record_id: Optional[str] = None) -> int:
    """Undoes patches using recorded history."""
    import undo_patcher
    return undo_patcher.undo_patches(app_query=app_name, all_patches=all_patches, record_id=record_id)


def generate_icns_from_png(png_path: Path, output_icns: Path) -> bool:
    """Converts a PNG image to Apple ICNS format using macOS native sips and iconutil."""
    import tempfile
    try:
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
    except Exception as e:
        cprint(Colors.YELLOW, f"Warning: Failed to convert {png_path.name} to .icns: {e}")
        return False


def cmd_create_alias(dest_dir: Optional[Path] = None) -> int:
    """
    Creates a macOS Application bundle / shortcut in /Applications named
    'Ryzentosh patch Utility' using applogo.png from the script directory.
    """
    script_dir = Path(__file__).resolve().parent
    png_path = script_dir / "applogo.png"

    cprint(Colors.BOLD, "\n========================================================================")
    cprint(Colors.BOLD, "          Create Ryzentosh Patch Utility Application Shortcut           ")
    cprint(Colors.BOLD, "========================================================================")

    if not png_path.exists():
        candidates = list(script_dir.glob("*logo*.png"))
        if candidates:
            png_path = candidates[0]
        else:
            cprint(Colors.RED, f"Error: 'applogo.png' not found in {script_dir}")
            return 1

    print(f"  • Source Directory: {Colors.CYAN}{script_dir}{Colors.RESET}")
    print(f"  • Using Logo:       {Colors.GREEN}{png_path.name}{Colors.RESET}")

    if dest_dir:
        target_dir = dest_dir.expanduser().resolve()
    else:
        sys_apps = Path("/Applications")
        user_apps = Path.home() / "Applications"
        if os.access(sys_apps, os.W_OK) or os.geteuid() == 0:
            target_dir = sys_apps
        else:
            try:
                user_apps.mkdir(parents=True, exist_ok=True)
                target_dir = user_apps
            except Exception:
                target_dir = sys_apps

    app_name = "Ryzentosh patch Utility.app"
    app_bundle = target_dir / app_name
    print(f"  • Target Location:  {Colors.BOLD}{app_bundle}{Colors.RESET}")

    if not os.access(target_dir, os.W_OK) and os.geteuid() != 0:
        cprint(Colors.YELLOW, f"\n[!] Root privileges required to write to {target_dir}")
        cprint(Colors.YELLOW, "    Elevating with sudo...")
        try:
            res = subprocess.run(["sudo", sys.executable, str(Path(__file__).resolve()), "create-alias"])
            return res.returncode
        except Exception as e:
            cprint(Colors.RED, f"Failed to elevate with sudo: {e}")
            return 1

    # 1. Generate or load .icns
    icns_path = script_dir / "applogo.icns"
    if not icns_path.exists() or icns_path.stat().st_mtime < png_path.stat().st_mtime:
        print("  • Generating high-resolution Retina .icns from applogo.png...")
        if not generate_icns_from_png(png_path, icns_path):
            cprint(Colors.YELLOW, "  Warning: Could not build .icns; proceeding with standard bundle.")

    # 2. Build .app bundle hierarchy
    contents_dir = app_bundle / "Contents"
    macos_dir = contents_dir / "MacOS"
    resources_dir = contents_dir / "Resources"

    try:
        macos_dir.mkdir(parents=True, exist_ok=True)
        resources_dir.mkdir(parents=True, exist_ok=True)

        if icns_path.exists():
            shutil.copy2(icns_path, resources_dir / "applogo.icns")

        # 3. Create Info.plist
        plist_content = f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundlePackageType</key>
    <string>APPL</string>
    <key>CFBundleInfoDictionaryVersion</key>
    <string>6.0</string>
    <key>CFBundleName</key>
    <string>Ryzentosh patch Utility</string>
    <key>CFBundleDisplayName</key>
    <string>Ryzentosh patch Utility</string>
    <key>CFBundleIdentifier</key>
    <string>com.ryzentosh.patchutility</string>
    <key>CFBundleVersion</key>
    <string>1.0</string>
    <key>CFBundleShortVersionString</key>
    <string>1.0</string>
    <key>CFBundleExecutable</key>
    <string>Ryzentosh patch Utility</string>
    <key>CFBundleIconFile</key>
    <string>applogo</string>
    <key>LSMinimumSystemVersion</key>
    <string>10.13</string>
    <key>NSHighResolutionCapable</key>
    <true/>
</dict>
</plist>
"""
        (contents_dir / "Info.plist").write_text(plist_content, encoding="utf-8")

        # 4. Create launcher script
        launcher_bin = macos_dir / "Ryzentosh patch Utility"
        launcher_code = f"""#!/bin/bash
# Launcher script for Ryzentosh patch Utility
SCRIPT_DIR="{script_dir}"

osascript <<EOF
tell application "Terminal"
    activate
    do script "cd '$SCRIPT_DIR' && ./patch.sh"
end tell
EOF
"""
        launcher_bin.write_text(launcher_code, encoding="utf-8")
        launcher_bin.chmod(0o755)

        # 5. Ad-hoc codesign
        try:
            subprocess.run(["codesign", "--force", "--deep", "-s", "-", str(app_bundle)], check=True, capture_output=True)
        except Exception:
            pass

        # 6. Touch to refresh Finder & LaunchServices cache
        try:
            subprocess.run(["touch", str(app_bundle)], capture_output=True)
        except Exception:
            pass

        restore_file_ownership(app_bundle)

        cprint(Colors.GREEN, f"\n✅ Successfully created application shortcut: '{app_bundle.name}'!")
        print(f"  Installed at: {Colors.BOLD}{app_bundle}{Colors.RESET}")
        print("  You can now launch it directly from:")
        print("   • Applications folder in Finder")
        print("   • Spotlight Search (Cmd + Space -> 'Ryzentosh patch Utility')")
        print("   • Launchpad or Dock\n")
        return 0

    except Exception as e:
        cprint(Colors.RED, f"Failed to create application shortcut: {e}")
        return 1


def cmd_reset(force: bool = False) -> int:
    """
    Factory reset switch:
    1. Reverts all active patches across all applications and Steam games.
    2. Cleans up leftover .bak backup files.
    3. Completely wipes the patch_history.json ledger.
    """
    import undo_patcher
    return undo_patcher.reset_all_patches(force=force)



# =====================================================================
# Steam Games Integration
# =====================================================================

class SteamGame:
    def __init__(self, appid: str, name: str, install_path: Path, library_path: Path):
        self.appid = appid
        self.name = name
        self.install_path = install_path
        self.library_path = library_path

    def __repr__(self):
        return f"<SteamGame {self.name} (AppID: {self.appid}) at {self.install_path}>"


def get_steam_library_folders() -> List[Path]:
    """
    Discovers all Steam library folders across the system by checking
    default macOS locations, mounted external volumes, and parsing libraryfolders.vdf.
    """
    libraries: List[Path] = []
    primary_roots = [
        Path.home() / "Library/Application Support/Steam",
        Path.home() / "Library/Application Support/Steam/Steam.AppBundle/Steam",
        Path("/Library/Application Support/Steam"),
    ]

    for root in primary_roots:
        if not root.exists():
            continue
        steamapps = root / "steamapps"
        if steamapps.exists() and steamapps not in libraries:
            libraries.append(steamapps)

        vdf_path = steamapps / "libraryfolders.vdf"
        if vdf_path.exists():
            try:
                content = vdf_path.read_text(encoding="utf-8", errors="ignore")
                paths = re.findall(r'"path"\s+"([^"]+)"', content, re.IGNORECASE)
                for p_str in paths:
                    lib_p = Path(p_str) / "steamapps"
                    if lib_p.exists() and lib_p not in libraries:
                        libraries.append(lib_p)
            except Exception:
                pass

    # Scan /Volumes for external SSD libraries
    volumes = Path("/Volumes")
    if volumes.exists():
        try:
            for vol in volumes.iterdir():
                if vol.is_dir():
                    for sub in ["SteamLibrary/steamapps", "steamapps"]:
                        ext_p = vol / sub
                        if ext_p.exists() and ext_p not in libraries:
                            libraries.append(ext_p)
        except Exception:
            pass

    return libraries


def discover_steam_games() -> List[SteamGame]:
    """
    Finds all installed Steam games by parsing appmanifest_*.acf files and
    scanning steamapps/common across all discovered library locations.
    """
    games: Dict[str, SteamGame] = {}
    libraries = get_steam_library_folders()

    for lib in libraries:
        # 1. Parse appmanifest_*.acf
        try:
            for manifest in lib.glob("appmanifest_*.acf"):
                try:
                    content = manifest.read_text(encoding="utf-8", errors="ignore")
                    pattern = re.compile(r'"([^"]+)"\s+"([^"]+)"')
                    kv = {k.lower(): v for k, v in pattern.findall(content)}
                    name = kv.get("name")
                    installdir = kv.get("installdir")
                    appid = kv.get("appid", "")
                    if name and installdir:
                        game_path = lib / "common" / installdir
                        if game_path.exists():
                            games[str(game_path.resolve())] = SteamGame(appid, name, game_path, lib)
                except Exception:
                    continue
        except Exception:
            pass

        # 2. Check common/ subdirectories directly as fallback
        common_dir = lib / "common"
        if common_dir.exists() and common_dir.is_dir():
            try:
                for child in common_dir.iterdir():
                    if child.is_dir() and not child.name.startswith("."):
                        resolved = str(child.resolve())
                        if resolved not in games:
                            games[resolved] = SteamGame("", child.name, child, lib)
            except Exception:
                pass

    return sorted(list(games.values()), key=lambda g: g.name.lower())


def cmd_steam(game_query: Optional[str] = None, patch_mode: bool = False, all_games: bool = False, dry_run: bool = False, no_backup: bool = False) -> int:
    """Discovers, inspects, and patches installed Steam games."""
    cprint(Colors.BOLD, "\n==> Scanning for Installed Steam Games...")
    libraries = get_steam_library_folders()
    if not libraries:
        cprint(Colors.YELLOW, "No Steam libraries found in default macOS locations or mounted volumes.")
        print("Tip: If Steam is installed in a custom directory, you can run:")
        print("  ./patch.sh scan \"/path/to/SteamLibrary/steamapps/common/GameName\"")
        return 1

    games = discover_steam_games()
    if not games:
        cprint(Colors.YELLOW, f"Found {len(libraries)} Steam library folder(s), but no installed games were detected.")
        for lib in libraries:
            print(f"  • {lib}")
        return 0

    # Filter by query if supplied
    if game_query:
        q = game_query.lower().strip()
        filtered = [g for g in games if q in g.name.lower() or q == g.appid]
        if not filtered:
            cprint(Colors.RED, f"Error: No installed Steam game matches '{game_query}'.")
            print(f"Available games ({len(games)}):")
            for g in games:
                print(f"  • {g.name}")
            return 1
        games = filtered

    cprint(Colors.CYAN, f"\nFound {len(games)} installed Steam game(s):")

    pbar = ProgressBar(len(games), bar_length=16)
    game_statuses = []
    for idx, g in enumerate(games, 1):
        pbar.update(idx, g.name)
        patch_cands, mkl_cands = find_candidates_in_path(g.install_path, max_depth=6)
        needs_patch = False
        already_patched = False
        has_symbols = False

        for cand in patch_cands:
            syms = resolve_symbol_offsets(cand)
            if syms:
                has_symbols = True
                for s in syms:
                    st, _ = check_patch_status(cand, s.file_offset)
                    if st == "PATCHED":
                        already_patched = True
                    else:
                        needs_patch = True

        status_label = ""
        if needs_patch:
            status_label = f"{Colors.YELLOW}[NEEDS PATCH]{Colors.RESET}"
        elif already_patched:
            status_label = f"{Colors.GREEN}[PATCHED]{Colors.RESET}"
        elif has_symbols:
            status_label = f"{Colors.YELLOW}[SYMBOLS DETECTED]{Colors.RESET}"
        elif mkl_cands:
            status_label = f"{Colors.CYAN}[MKL ONLY]{Colors.RESET}"
        else:
            status_label = f"{Colors.GREEN}[CLEAN]{Colors.RESET}"

        if mkl_cands:
            status_label += f" {Colors.CYAN}(MKL){Colors.RESET}"

        game_statuses.append((g, patch_cands, mkl_cands, needs_patch, status_label))

    pbar.finish(clear=True)
    print()

    # Display list
    for idx, (g, patch_cands, mkl_cands, needs_patch, status_label) in enumerate(game_statuses, 1):
        appid_str = f" (AppID: {g.appid})" if g.appid else ""
        print(f"  {idx:2d}) {Colors.BOLD}{g.name}{Colors.RESET}{appid_str} -> {status_label}")
        print(f"      Path: {g.install_path}")
        if patch_cands:
            for cand in patch_cands:
                print(f"      - Library: {cand.name}")

    # Patch mode logic
    if not patch_mode:
        print(f"\nRun with {Colors.YELLOW}--patch{Colors.RESET} to apply patches:")
        print(f"  ./patch.sh steam \"Game Name\" --patch")
        print(f"  ./patch.sh steam --patch")
        return 0

    # Filter to games that can be patched
    games_needing_patch = [item for item in game_statuses if item[3]]  # needs_patch
    if not games_needing_patch:
        cprint(Colors.GREEN, "\nAll detected Steam games are already patched or clean! Nothing to patch.")
        return 0

    to_patch = []
    if all_games:
        to_patch = games_needing_patch
    elif len(games_needing_patch) == 1 and game_query:
        to_patch = games_needing_patch
    else:
        cprint(Colors.BOLD, "\nSteam games requiring patches:")
        for idx, (g, patch_cands, mkl_cands, _, _) in enumerate(games_needing_patch, 1):
            cand_count = len(patch_cands)
            print(f"  {idx}) {Colors.BOLD}{g.name}{Colors.RESET} ({cand_count} candidate file(s))")
        print(f"  A) All of the above")
        print(f"  Q) Cancel\n")
        try:
            choice = input("Enter choice: ").strip().lower()
            if choice == "q":
                print("Cancelled.")
                return 0
            elif choice in ("a", "all"):
                to_patch = games_needing_patch
            elif choice.isdigit() and 1 <= int(choice) <= len(games_needing_patch):
                to_patch = [games_needing_patch[int(choice) - 1]]
            else:
                cprint(Colors.RED, "Invalid selection.")
                return 1
        except (KeyboardInterrupt, EOFError):
            print("\nCancelled.")
            return 0

    if not to_patch:
        cprint(Colors.YELLOW, "No games selected to patch.")
        return 0

    total_patched_games = 0
    for g, patch_cands, mkl_cands, needs_patch, _ in to_patch:
        cprint(Colors.BOLD, f"\n==> Patching Steam Game: {g.name}")
        ret = cmd_patch(g.install_path, dry_run=dry_run, no_backup=no_backup)
        if ret == 0:
            total_patched_games += 1

        if mkl_cands:
            cprint(Colors.CYAN, f"\n[!] Notice for {g.name}:")
            print("  This game utilizes Intel MKL. In Steam, configure its launch option:")
            print(f"  {Colors.YELLOW}/usr/bin/env MKL_DEBUG_CPU_TYPE=5 %command%{Colors.RESET}")

    cprint(Colors.BOLD, f"\n==> Steam patching complete: {total_patched_games} game(s) processed.")
    return 0


# =====================================================================
# Installed macOS Applications Integration
# =====================================================================

class InstalledApp:
    def __init__(self, name: str, bundle_path: Path, bundle_id: str = ""):
        self.name = name
        self.bundle_path = bundle_path
        self.bundle_id = bundle_id
        self.patch_candidates: List[Path] = []
        self.mkl_candidates: List[Path] = []
        self.needs_patch: bool = False
        self.already_patched: bool = False
        self.status_label: str = ""

    def __repr__(self):
        return f"<InstalledApp {self.name} at {self.bundle_path}>"


def get_installed_app_folders() -> List[Path]:
    """Returns standard macOS application root directories."""
    roots = [
        Path("/Applications"),
        Path.home() / "Applications",
        Path("/Users/Shared/Applications"),
    ]
    return [r for r in roots if r.exists()]


def discover_installed_apps(search_dirs: Optional[List[Path]] = None) -> List[InstalledApp]:
    """
    Finds all installed .app bundles across standard application directories.
    Handles subdirectories (e.g. /Applications/DaVinci Resolve/DaVinci Resolve.app).
    """
    if search_dirs is None:
        search_dirs = get_installed_app_folders()

    apps: Dict[str, InstalledApp] = {}

    for sdir in search_dirs:
        for root, dirs, files in os.walk(sdir):
            rel_depth = len(Path(root).parts) - len(sdir.parts)
            if rel_depth > 3:
                dirs.clear()
                continue

            for d in list(dirs):
                if d.endswith(".app"):
                    app_path = Path(root) / d
                    dirs.remove(d)  # Don't recurse inside the .app bundle during top-level discovery
                    app_name = app_path.stem
                    bundle_id = ""
                    plist_p = app_path / "Contents" / "Info.plist"
                    if plist_p.exists():
                        try:
                            import plistlib
                            with open(plist_p, "rb") as pf:
                                pl = plistlib.load(pf)
                                app_name = pl.get("CFBundleDisplayName") or pl.get("CFBundleName") or app_name
                                bundle_id = pl.get("CFBundleIdentifier", "")
                        except Exception:
                            pass
                    apps[str(app_path.resolve())] = InstalledApp(str(app_name), app_path, str(bundle_id))

    return sorted(list(apps.values()), key=lambda a: a.name.lower())


def find_app_by_name(app_query: str, search_dirs: Optional[List[Path]] = None) -> Optional[InstalledApp]:
    """
    Fast direct lookup for an installed application by name or bundle ID.
    Bypasses scanning all installed applications when the user passes --app <name>.
    Performs targeted checks in /Applications and common subdirectories in < 10ms.
    """
    if not app_query:
        return None

    if search_dirs is None:
        search_dirs = get_installed_app_folders()

    q_raw = app_query.strip().strip("'\"")
    q = q_raw.lower()
    q_name = q[:-4] if q.endswith(".app") else q

    def make_installed_app(app_path: Path) -> InstalledApp:
        app_name = app_path.stem
        bundle_id = ""
        plist_p = app_path / "Contents" / "Info.plist"
        if plist_p.exists():
            try:
                import plistlib
                with open(plist_p, "rb") as pf:
                    pl = plistlib.load(pf)
                    app_name = pl.get("CFBundleDisplayName") or pl.get("CFBundleName") or app_name
                    bundle_id = pl.get("CFBundleIdentifier", "")
            except Exception:
                pass
        return InstalledApp(str(app_name), app_path.resolve(), str(bundle_id))

    # 1. Direct path check if path exists
    cand_p = Path(q_raw).expanduser()
    if cand_p.exists() and cand_p.suffix == ".app":
        return make_installed_app(cand_p)

    # 2. Fast check in root folders with raw query casing (e.g. /Applications/DaVinci Resolve/DaVinci Resolve.app)
    raw_name = q_raw[:-4] if q_raw.endswith(".app") else q_raw
    for sdir in search_dirs:
        if not sdir.exists():
            continue
        direct_raw = sdir / f"{raw_name}.app"
        if direct_raw.exists():
            return make_installed_app(direct_raw)
        sub_raw = sdir / raw_name / f"{raw_name}.app"
        if sub_raw.exists():
            return make_installed_app(sub_raw)
        sub_any = sdir / raw_name
        if sub_any.is_dir():
            for child in sub_any.glob("*.app"):
                if q in child.name.lower():
                    return make_installed_app(child)

    # 3. Fast scandir: search immediate entries of search_dirs (depth <= 2)
    matches: List[InstalledApp] = []
    for sdir in search_dirs:
        if not sdir.exists():
            continue
        try:
            with os.scandir(sdir) as it:
                for entry in it:
                    if not entry.is_dir(follow_symlinks=False):
                        continue
                    ename = entry.name
                    ename_lower = ename.lower()
                    if ename_lower.endswith(".app"):
                        stem = ename_lower[:-4]
                        if stem == q_name:
                            return make_installed_app(Path(entry.path))
                        if q_name in stem:
                            matches.append(make_installed_app(Path(entry.path)))
                    else:
                        # Check inside folder (e.g. /Applications/DaVinci Resolve/*.app)
                        try:
                            with os.scandir(entry.path) as sub_it:
                                for subentry in sub_it:
                                    if subentry.is_dir(follow_symlinks=False) and subentry.name.lower().endswith(".app"):
                                        sub_stem = subentry.name.lower()[:-4]
                                        if sub_stem == q_name:
                                            return make_installed_app(Path(subentry.path))
                                        if q_name in sub_stem or q_name in ename_lower:
                                            matches.append(make_installed_app(Path(subentry.path)))
                        except Exception:
                            pass
        except Exception:
            pass

    if matches:
        for m in matches:
            if m.name.lower() == q_name or m.bundle_id.lower() == q:
                return m
        return matches[0]

    # 4. Fallback: discover_installed_apps()
    all_apps = discover_installed_apps(search_dirs)
    for a in all_apps:
        if a.name.lower() == q_name or a.bundle_id.lower() == q:
            return a
    for a in all_apps:
        if q_name in a.name.lower() or q in a.bundle_id.lower() or q in str(a.bundle_path).lower():
            return a

    return None


def cmd_apps(
    app_query: Optional[str] = None,
    patch_mode: bool = False,
    all_apps: bool = False,
    dry_run: bool = False,
    no_backup: bool = False
) -> int:
    """Discovers, inspects, and mass-patches installed macOS applications."""
    if app_query:
        cprint(Colors.BOLD, f"\n==> Locating Installed Application: '{app_query}'...")
        target_app = find_app_by_name(app_query)
        if not target_app:
            cprint(Colors.RED, f"Error: No installed application matches '{app_query}'.")
            return 1
        apps = [target_app]
        cprint(Colors.GREEN, f"Found: {target_app.name} -> {target_app.bundle_path}")
    else:
        cprint(Colors.BOLD, "\n==> Scanning for Installed macOS Applications...")
        all_discovered = discover_installed_apps()
        if not all_discovered:
            cprint(Colors.YELLOW, "No applications found in /Applications or ~/Applications.")
            return 0
        apps = all_discovered

    cprint(Colors.CYAN, f"Scanning {len(apps)} installed application(s) for Intel performance components...")

    pbar = ProgressBar(len(apps), bar_length=16)
    app_statuses: List[InstalledApp] = []
    for idx, app in enumerate(apps, 1):
        pbar.update(idx, app.name)
        patch_cands, mkl_cands = find_candidates_in_path(app.bundle_path, max_depth=6)
        if not patch_cands and not mkl_cands:
            continue

        app.patch_candidates = patch_cands
        app.mkl_candidates = mkl_cands
        needs_patch = False
        already_patched = False
        has_symbols = False

        for cand in patch_cands:
            syms = resolve_symbol_offsets(cand)
            if syms:
                has_symbols = True
                for s in syms:
                    st, _ = check_patch_status(cand, s.file_offset)
                    if st == "PATCHED":
                        already_patched = True
                    else:
                        needs_patch = True

        app.needs_patch = needs_patch
        app.already_patched = already_patched

        if needs_patch:
            app.status_label = f"{Colors.YELLOW}[NEEDS PATCH]{Colors.RESET}"
        elif already_patched:
            app.status_label = f"{Colors.GREEN}[PATCHED]{Colors.RESET}"
        elif has_symbols:
            app.status_label = f"{Colors.YELLOW}[SYMBOLS DETECTED]{Colors.RESET}"
        elif mkl_cands:
            app.status_label = f"{Colors.CYAN}[MKL ONLY]{Colors.RESET}"
        else:
            app.status_label = f"{Colors.GREEN}[CLEAN]{Colors.RESET}"

        if mkl_cands:
            app.status_label += f" {Colors.CYAN}(MKL){Colors.RESET}"

        app_statuses.append(app)

    pbar.finish(clear=True)

    if not app_statuses:
        cprint(Colors.GREEN, "\nNo installed applications found with Intel performance components!")
        return 0

    cprint(Colors.BOLD, f"\nFound {len(app_statuses)} application(s) with Intel components:")
    for idx, app in enumerate(app_statuses, 1):
        print(f"  {idx:2d}) {Colors.BOLD}{app.name}{Colors.RESET} -> {app.status_label}")
        print(f"      Path: {app.bundle_path}")
        for cand in app.patch_candidates:
            print(f"      - Library: {cand.name}")

    if not patch_mode:
        print(f"\nRun with {Colors.YELLOW}--patch{Colors.RESET} to apply patches:")
        print(f"  ./patch.sh apps \"App Name\" --patch")
        print(f"  ./patch.sh apps --patch")
        print(f"  ./patch.sh apps --all --patch")
        return 0

    # Filter to applications that can be patched
    apps_needing_patch = [app for app in app_statuses if app.needs_patch]
    if not apps_needing_patch:
        cprint(Colors.GREEN, "\nAll detected applications are already patched or clean! Nothing to patch.")
        return 0

    # Ensure root if any application in apps_needing_patch requires root
    if not dry_run and os.geteuid() != 0:
        needs_root = any(is_root_required_for_path(app.bundle_path) for app in apps_needing_patch)
        if needs_root:
            ensure_root("Root privileges required to patch application(s) in /Applications.")

    to_patch = []
    if all_apps:
        to_patch = apps_needing_patch
    elif len(apps_needing_patch) == 1 and app_query:
        to_patch = apps_needing_patch
    else:
        cprint(Colors.BOLD, "\nApplications requiring patches:")
        for idx, app in enumerate(apps_needing_patch, 1):
            cand_count = len(app.patch_candidates)
            print(f"  {idx}) {Colors.BOLD}{app.name}{Colors.RESET} ({cand_count} candidate file(s))")
        print(f"  A) All of the above")
        print(f"  Q) Cancel\n")

        try:
            choice = input("Enter choice: ").strip().lower()
            if choice == "q":
                print("Cancelled.")
                return 0
            elif choice in ("a", "all"):
                to_patch = apps_needing_patch
            elif choice.isdigit() and 1 <= int(choice) <= len(apps_needing_patch):
                to_patch = [apps_needing_patch[int(choice) - 1]]
            else:
                cprint(Colors.RED, "Invalid selection.")
                return 1
        except (KeyboardInterrupt, EOFError):
            print("\nCancelled.")
            return 0

    if not to_patch:
        cprint(Colors.YELLOW, "No applications selected to patch.")
        return 0

    total_patched_apps = 0
    for app in to_patch:
        cprint(Colors.BOLD, f"\n==> Patching Application: {app.name}")
        ret = cmd_patch(app.bundle_path, dry_run=dry_run, no_backup=no_backup)
        if ret == 0:
            total_patched_apps += 1

        if app.mkl_candidates:
            cprint(Colors.CYAN, f"\n[!] Notice for {app.name}:")
            print("  This application utilizes Intel MKL. Set environment variable before launching:")
            print(f"  {Colors.YELLOW}export MKL_DEBUG_CPU_TYPE=5{Colors.RESET}")

    cprint(Colors.BOLD, f"\n==> Applications patching complete: {total_patched_apps} application(s) processed.")
    return 0


def cmd_mkl_info():
    """Displays instructions for configuring Intel MKL runtime overrides."""
    print(f"""
{Colors.BOLD}{Colors.CYAN}Intel MKL (Math Kernel Library) Configuration Guide for Ryzentosh{Colors.RESET}
==================================================================

{Colors.BOLD}The Issue:{Colors.RESET}
Intel MKL performs runtime CPUID checks. When run on an AMD processor,
MKL falls back to slow generic routines or fails with:
  "Intel MKL FATAL ERROR: Cannot load ... or illegal instruction"

{Colors.BOLD}The Fix:{Colors.RESET}
Set the environment variable {Colors.GREEN}MKL_DEBUG_CPU_TYPE=5{Colors.RESET}
This forces MKL to execute AVX2 / SSE optimized pathways regardless of CPU vendor.

{Colors.BOLD}Steam Games Launch Option:{Colors.RESET}
1. Open Steam -> Right-click your game -> Properties...
2. In the "General" tab, look for "Launch Options".
3. Paste the following:
   {Colors.YELLOW}/usr/bin/env MKL_DEBUG_CPU_TYPE=5 %command%{Colors.RESET}

{Colors.BOLD}Terminal / Shell Usage:{Colors.RESET}
Export the variable before launching your game or binary:
   {Colors.YELLOW}export MKL_DEBUG_CPU_TYPE=5
   ./YourGameApp/Contents/MacOS/YourGame{Colors.RESET}
""")
    return 0


def get_menu_indicators() -> Dict[str, str]:
    """Computes dynamic status indicators for the interactive menu."""
    indicators = {
        "active_count": 0,
        "total_records": 0,
        "active_badge": f"{Colors.GREEN}[0 active]{Colors.RESET}",
        "history_badge": f"{Colors.CYAN}[0 recorded]{Colors.RESET}",
        "steam_badge": f"{Colors.BLUE}[Steam: Ready]{Colors.RESET}",
        "apps_badge": f"{Colors.CYAN}[/Applications: Ready]{Colors.RESET}",
        "privilege_badge": f"{Colors.GREEN}Root{Colors.RESET}" if os.geteuid() == 0 else f"{Colors.YELLOW}Standard (Auto-sudo){Colors.RESET}",
    }
    try:
        records = load_history()
        total = len(records)
        active = sum(1 for r in records if r.get("status") == "active")
        indicators["active_count"] = active
        indicators["total_records"] = total
        if active > 0:
            indicators["active_badge"] = f"{Colors.YELLOW}[{active} active]{Colors.RESET}"
        else:
            indicators["active_badge"] = f"{Colors.GREEN}[0 active]{Colors.RESET}"
        indicators["history_badge"] = f"{Colors.CYAN}[{total} recorded]{Colors.RESET}"
    except Exception:
        pass

    try:
        steam_libs = get_steam_library_folders()
        if steam_libs:
            indicators["steam_badge"] = f"{Colors.GREEN}[{len(steam_libs)} lib detected]{Colors.RESET}"
        else:
            indicators["steam_badge"] = f"{Colors.YELLOW}[Not found]{Colors.RESET}"
    except Exception:
        pass

    return indicators


def check_updated_patches() -> List[Dict]:
    """
    Scans all active history records to detect if an application update,
    file replacement, or Steam game file verification has overwritten
    previously patched libraries with unpatched originals.

    Returns a list of dicts:
    [{
        'app_name': str,
        'target_root': Path,
        'records': List[Dict],
        'outdated_files': List[Path]
    }]
    """
    records = load_history()
    active_records = [r for r in records if r.get("status") == "active"]
    if not active_records:
        return []

    history_modified = False
    grouped: Dict[str, Dict] = {}
    for r in active_records:
        app_name = r.get("app_name", "Unknown App")
        target_root_str = r.get("target_root")
        if not target_root_str:
            continue
        target_root = Path(target_root_str)
        if not target_root.exists():
            continue

        outdated_for_rec = []
        for f_entry in r.get("files", []):
            if f_entry.get("status") == "reverted":
                continue
            f_path = Path(f_entry.get("file_path"))
            if not f_path.exists():
                continue

            is_broken = False
            # Dynamic symbols are the primary ground truth for Mach-O binaries.
            # This correctly handles slice realignment from codesign in universal/fat binaries.
            resolved_syms = []
            try:
                resolved_syms = resolve_symbol_offsets(f_path)
            except Exception:
                resolved_syms = []

            if resolved_syms:
                sym_map = {s.name: s.file_offset for s in resolved_syms}
                for sym in resolved_syms:
                    st, _ = check_patch_status(f_path, sym.file_offset)
                    if st == "UNPATCHED":
                        is_broken = True
                        break
                # If binary is fully patched, auto-sync any stale history offsets
                if not is_broken:
                    for s_ent in f_entry.get("symbols", []):
                        s_name = s_ent.get("symbol")
                        if s_name in sym_map and s_ent.get("offset") != sym_map[s_name]:
                            s_ent["offset"] = sym_map[s_name]
                            history_modified = True
            else:
                # Fallback for stripped binaries where nm cannot discover symbols
                symbols = f_entry.get("symbols", [])
                for s in symbols:
                    off = s.get("offset")
                    if off is not None:
                        status, _ = check_patch_status(f_path, off)
                        if status == "UNPATCHED":
                            is_broken = True
                            break

            if is_broken:
                outdated_for_rec.append(f_path)

        if outdated_for_rec:
            if app_name not in grouped:
                grouped[app_name] = {
                    "app_name": app_name,
                    "target_root": target_root,
                    "records": [r],
                    "outdated_files": list(set(outdated_for_rec))
                }
            else:
                grouped[app_name]["records"].append(r)
                for of in outdated_for_rec:
                    if of not in grouped[app_name]["outdated_files"]:
                        grouped[app_name]["outdated_files"].append(of)

    if history_modified:
        try:
            save_history(records)
        except Exception:
            pass

    return list(grouped.values())


def prompt_repatch_updates():
    """
    Runs at startup before the interactive menu. If any active patched applications
    have been reverted by an update, prompts the user to repatch them.
    """
    updates = check_updated_patches()
    if not updates:
        return

    cprint(Colors.BOLD, "\n========================================================================")
    cprint(Colors.YELLOW, "  ⚠️  UPDATE DETECTED: Previously Patched App(s) Were Overwritten       ")
    cprint(Colors.BOLD, "========================================================================")
    print("  The following application(s) were previously patched, but an update or")
    print("  file verification replaced their libraries with unpatched Intel binaries:\n")
    for u in updates:
        file_count = len(u["outdated_files"])
        print(f"  • {Colors.BOLD}{u['app_name']}{Colors.RESET} ({file_count} library/libraries need repatching)")
        print(f"    Path: {u['target_root']}")
    cprint(Colors.BOLD, "------------------------------------------------------------------------\n")

    for u in updates:
        app_name = u["app_name"]
        target_root = u["target_root"]
        try:
            ans = input(f"Would you like to repatch '{Colors.BOLD}{app_name}{Colors.RESET}' now? (Y/n): ").strip().lower()
        except (KeyboardInterrupt, EOFError):
            print("\nSkipping repatch check.")
            return

        if ans in ("", "y", "yes"):
            cprint(Colors.BOLD, f"\n==> Repatching updated application: {app_name}")
            if is_root_required_for_path(target_root) and os.geteuid() != 0:
                cprint(Colors.YELLOW, f"\n[!] Root privileges required to patch: {target_root}")
                cprint(Colors.YELLOW, "    Elevating with sudo (you may be prompted for your macOS password)...")
                try:
                    res = subprocess.run(["sudo", sys.executable, str(Path(__file__).resolve()), "patch", str(target_root)])
                    if res.returncode == 0:
                        cprint(Colors.GREEN, f"\n✅ Successfully repatched {app_name}!\n")
                    else:
                        cprint(Colors.RED, f"\n❌ Failed to repatch {app_name}.\n")
                except Exception as e:
                    cprint(Colors.RED, f"Failed to elevate with sudo: {e}")
            else:
                ret = cmd_patch(target_root)
                if ret == 0:
                    cprint(Colors.GREEN, f"\n✅ Successfully repatched {app_name}!\n")
                else:
                    cprint(Colors.RED, f"\n❌ Failed to repatch {app_name}.\n")
        else:
            print(f"Skipping {app_name}.\n")


def interactive_wizard():
    """Interactive mode when run without arguments."""
    # Check if any previously patched applications have been overwritten by updates (once at startup)
    prompt_repatch_updates()

    while True:
        clear_screen()
        ind = get_menu_indicators()

        cprint(Colors.BOLD, "\n========================================================================")
        cprint(Colors.BOLD, "                   Ryzentosh Patching Utility Wizard                    ")
        cprint(Colors.CYAN, "       Fix Intel performance library crashes on AMD macOS (SIGILL)      ")
        cprint(Colors.BOLD, "========================================================================")
        print(f"  {Colors.BOLD}System:{Colors.RESET} macOS x86_64 Ryzentosh  |  {Colors.BOLD}Privileges:{Colors.RESET} {ind['privilege_badge']}  |  {Colors.BOLD}Ledger:{Colors.RESET} {ind['active_badge']}")
        cprint(Colors.BOLD, "------------------------------------------------------------------------")
        print(f"  {Colors.BOLD} 1){Colors.RESET} {Colors.GREEN}[⚡ PATCH]{Colors.RESET}    Apply patch to target file, .app, or game folder")
        print(f"  {Colors.BOLD} 2){Colors.RESET} {Colors.CYAN}[🍎 APPS]{Colors.RESET}     Detect & mass-patch installed macOS apps {ind['apps_badge']}")
        print(f"  {Colors.BOLD} 3){Colors.RESET} {Colors.BLUE}[🎮 STEAM]{Colors.RESET}    Detect & patch installed Steam games {ind['steam_badge']}")
        print(f"  {Colors.BOLD} 4){Colors.RESET} {Colors.CYAN}[🔍 SCAN]{Colors.RESET}     Scan path for Intel libraries & symbols (Read-Only)")
        print(f"  {Colors.BOLD} 5){Colors.RESET} {Colors.YELLOW}[🔬 DEBUG]{Colors.RESET}    Deep diagnostic trace (Mach-O, symbols, offsets, codesign)")
        print(f"  {Colors.BOLD} 6){Colors.RESET} {Colors.YELLOW}[⏪ UNDO]{Colors.RESET}     Revert patches by application name {ind['active_badge']}")
        print(f"  {Colors.BOLD} 7){Colors.RESET} {Colors.BLUE}[🔄 RESTORE]{Colors.RESET}  Restore original file(s) from .bak backup directly")
        print(f"  {Colors.BOLD} 8){Colors.RESET} {Colors.CYAN}[📜 HISTORY]{Colors.RESET}  View patch history ledger {ind['history_badge']}")
        print(f"  {Colors.BOLD} 9){Colors.RESET} {Colors.YELLOW}[ℹ️  MKL]{Colors.RESET}      Intel MKL configuration guide & launch parameters")
        print(f"  {Colors.BOLD}10){Colors.RESET} {Colors.GREEN}[🚀 SHORTCUT]{Colors.RESET} Create 'Ryzentosh patch Utility' in /Applications with logo")
        print(f"  {Colors.BOLD}11){Colors.RESET} {Colors.RED}[💥 RESET]{Colors.RESET}    Factory Reset Switch: Revert all patches & clear saved data")
        print(f"  {Colors.BOLD}12){Colors.RESET} {Colors.BOLD}[🚪 EXIT]{Colors.RESET}     Exit utility")
        cprint(Colors.BOLD, "========================================================================\n")

        try:
            raw_choice = input("Select an option (1-12): ").strip()
        except (KeyboardInterrupt, EOFError):
            clear_screen()
            cprint(Colors.BOLD, "\n========================================================================")
            cprint(Colors.BOLD, "                   Ryzentosh Patching Utility                           ")
            cprint(Colors.BOLD, "========================================================================\n")
            cprint(Colors.GREEN, "  Exiting Ryzentosh Patch Utility. Goodbye!\n")
            return 0

        choice = raw_choice.lower()
        if not choice:
            continue

        if choice in ("12", "exit", "q", "quit"):
            clear_screen()
            cprint(Colors.BOLD, "\n========================================================================")
            cprint(Colors.BOLD, "                   Ryzentosh Patching Utility                           ")
            cprint(Colors.BOLD, "========================================================================\n")
            cprint(Colors.GREEN, "  Exiting Ryzentosh Patch Utility. Goodbye!\n")
            return 0

        elif choice in ("1", "patch"):
            clear_screen()
            cprint(Colors.BOLD, "\n========================================================================")
            cprint(Colors.BOLD, "                      [1] Apply Patch to Target                         ")
            cprint(Colors.BOLD, "========================================================================\n")
            try:
                path_str = input("Enter path to file, folder, or .app (or press Enter to cancel): ").strip().strip("'\"")
                if not path_str:
                    continue
                target_p = Path(path_str).expanduser()
                if is_root_required_for_path(target_p) and os.geteuid() != 0:
                    cprint(Colors.YELLOW, f"\n[!] Root privileges required to patch: {target_p}")
                    cprint(Colors.YELLOW, "    Elevating with sudo (you may be prompted for your macOS password)...")
                    try:
                        subprocess.run(["sudo", sys.executable, str(Path(__file__).resolve()), "patch", str(target_p)])
                    except Exception as e:
                        cprint(Colors.RED, f"Failed to elevate with sudo: {e}")
                else:
                    cmd_patch(target_p)
            except (KeyboardInterrupt, EOFError):
                print("\nOperation cancelled.")

        elif choice in ("2", "apps"):
            clear_screen()
            cprint(Colors.BOLD, "\n========================================================================")
            cprint(Colors.BOLD, "             [2] Detect & Mass-Patch Installed macOS Apps               ")
            cprint(Colors.BOLD, "========================================================================\n")
            try:
                if os.geteuid() != 0:
                    cprint(Colors.YELLOW, "[!] Root privileges required to patch applications in /Applications.")
                    cprint(Colors.YELLOW, "    Elevating with sudo (you may be prompted for your macOS password)...")
                    try:
                        subprocess.run(["sudo", sys.executable, str(Path(__file__).resolve()), "apps", "--patch"])
                    except Exception as e:
                        cprint(Colors.RED, f"Failed to elevate with sudo: {e}")
                else:
                    cmd_apps(patch_mode=True)
            except (KeyboardInterrupt, EOFError):
                print("\nOperation cancelled.")

        elif choice in ("3", "steam"):
            clear_screen()
            cprint(Colors.BOLD, "\n========================================================================")
            cprint(Colors.BOLD, "              [3] Detect & Patch Installed Steam Games                  ")
            cprint(Colors.BOLD, "========================================================================\n")
            try:
                cmd_steam(patch_mode=True)
            except (KeyboardInterrupt, EOFError):
                print("\nOperation cancelled.")

        elif choice in ("4", "scan"):
            clear_screen()
            cprint(Colors.BOLD, "\n========================================================================")
            cprint(Colors.BOLD, "                     [4] Scan Path (Read-Only)                          ")
            cprint(Colors.BOLD, "========================================================================\n")
            try:
                path_str = input("Enter path to file, folder, or .app (or press Enter to cancel): ").strip().strip("'\"")
                if not path_str:
                    continue
                cmd_scan(Path(path_str).expanduser())
            except (KeyboardInterrupt, EOFError):
                print("\nOperation cancelled.")

        elif choice in ("5", "debug"):
            clear_screen()
            cprint(Colors.BOLD, "\n========================================================================")
            cprint(Colors.BOLD, "                     [5] Deep Diagnostic Trace                          ")
            cprint(Colors.BOLD, "========================================================================\n")
            try:
                target_str = input("Enter path to .app, folder, dylib, Steam game, or app name (or press Enter to cancel): ").strip().strip("'\"")
                if not target_str:
                    continue
                cmd_debug(target_str)
            except (KeyboardInterrupt, EOFError):
                print("\nOperation cancelled.")

        elif choice in ("6", "undo"):
            clear_screen()
            try:
                cmd_undo()
            except (KeyboardInterrupt, EOFError):
                print("\nOperation cancelled.")

        elif choice in ("7", "restore"):
            clear_screen()
            cprint(Colors.BOLD, "\n========================================================================")
            cprint(Colors.BOLD, "                 [7] Restore Original File(s) from .bak                 ")
            cprint(Colors.BOLD, "========================================================================\n")
            try:
                path_str = input("Enter path to file, folder, or .app (or press Enter to cancel): ").strip().strip("'\"")
                if not path_str:
                    continue
                target_p = Path(path_str).expanduser()
                if is_root_required_for_path(target_p) and os.geteuid() != 0:
                    cprint(Colors.YELLOW, f"\n[!] Root privileges required to restore: {target_p}")
                    cprint(Colors.YELLOW, "    Elevating with sudo (you may be prompted for your macOS password)...")
                    try:
                        subprocess.run(["sudo", sys.executable, str(Path(__file__).resolve()), "restore", str(target_p)])
                    except Exception as e:
                        cprint(Colors.RED, f"Failed to elevate with sudo: {e}")
                else:
                    cmd_restore(target_p)
            except (KeyboardInterrupt, EOFError):
                print("\nOperation cancelled.")

        elif choice in ("8", "history"):
            clear_screen()
            cprint(Colors.BOLD, "\n========================================================================")
            cprint(Colors.BOLD, "                     [8] Patch History Ledger                           ")
            cprint(Colors.BOLD, "========================================================================\n")
            try:
                cmd_history()
            except (KeyboardInterrupt, EOFError):
                print("\nOperation cancelled.")

        elif choice in ("9", "mkl", "mkl-info"):
            clear_screen()
            try:
                cmd_mkl_info()
            except (KeyboardInterrupt, EOFError):
                print("\nOperation cancelled.")

        elif choice in ("10", "shortcut", "alias", "create-alias"):
            clear_screen()
            try:
                cmd_create_alias()
            except (KeyboardInterrupt, EOFError):
                print("\nOperation cancelled.")

        elif choice in ("11", "reset", "reset-switch"):
            clear_screen()
            try:
                cmd_reset()
            except (KeyboardInterrupt, EOFError):
                print("\nOperation cancelled.")

        else:
            clear_screen()
            cprint(Colors.RED, f"\n  Invalid choice: '{raw_choice}'. Please enter a number between 1 and 12.")

        try:
            input(f"\n{Colors.CYAN}Press Enter to return to the main menu...{Colors.RESET}")
        except (KeyboardInterrupt, EOFError):
            pass


def main():
    parser = argparse.ArgumentParser(
        description="Ryzentosh Patching Utility: Fix Intel TBB / MKL crashes on AMD macOS."
    )
    # Global / top-level flags allowing advanced users to skip wizard and direct-target
    parser.add_argument("-a", "--app", dest="app_flag", default=None, help="Directly target an installed macOS application by name (skips full scan)")
    parser.add_argument("-g", "--game", dest="game_flag", default=None, help="Directly target an installed Steam game by name")
    parser.add_argument("-p", "--patch", action="store_true", help="Apply patches directly")
    parser.add_argument("--dry-run", action="store_true", help="Simulate patch without writing")
    parser.add_argument("--no-backup", action="store_true", help="Skip creating .bak backup")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output")
    parser.add_argument("--check-updates", action="store_true", help="Check if updates overwrote any patched applications")
    parser.add_argument("--create-alias", "--alias", dest="alias_flag", action="store_true", help="Create 'Ryzentosh patch Utility' in /Applications with applogo.png")
    parser.add_argument("--reset", dest="reset_flag", action="store_true", help="Factory reset switch: Revert all patches, clean backups, and wipe history")
    parser.add_argument("-f", "--force", action="store_true", help="Force reset without confirmation prompt")

    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    p_patch = subparsers.add_parser("patch", help="Apply universal rep stosb patch to target")
    p_patch.add_argument("target", nargs="?", default=None, type=Path, help="File, folder, or .app to patch")
    p_patch.add_argument("-a", "--app", dest="app_flag", default=None, help="Directly target an installed application by name")
    p_patch.add_argument("-g", "--game", dest="game_flag", default=None, help="Directly target an installed Steam game by name")
    p_patch.add_argument("--dry-run", action="store_true", help="Simulate patch without writing")
    p_patch.add_argument("--no-backup", action="store_true", help="Skip creating .bak backup")
    p_patch.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output")

    p_scan = subparsers.add_parser("scan", help="Scan target for Intel symbols and report status")
    p_scan.add_argument("target", nargs="?", default=None, type=Path, help="File, folder, or .app to scan")
    p_scan.add_argument("-a", "--app", dest="app_flag", default=None, help="Directly target an installed application by name")
    p_scan.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output")

    p_debug = subparsers.add_parser("debug", help="Deep diagnostic inspection of candidate libraries, symbols, and offsets")
    p_debug.add_argument("target", nargs="?", default=None, help="File, folder, .app, Steam game name, or app name to debug")
    p_debug.add_argument("-a", "--app", dest="app_flag", default=None, help="Directly target an installed application by name")
    p_debug.add_argument("-g", "--game", dest="game_flag", default=None, help="Directly target a Steam game by name")

    p_apps = subparsers.add_parser("apps", help="Detect, inspect, and mass-patch installed macOS applications")
    p_apps.add_argument("app", nargs="?", default=None, help="Application name or bundle ID to inspect/patch")
    p_apps.add_argument("-a", "--app", dest="app_flag", default=None, help="Application name or bundle ID (skips full scan)")
    p_apps.add_argument("-p", "--patch", action="store_true", help="Apply patch to detected application(s)")
    p_apps.add_argument("--all", action="store_true", help="Patch all detected applications needing patch")
    p_apps.add_argument("--dry-run", action="store_true", help="Simulate patch without writing")
    p_apps.add_argument("--no-backup", action="store_true", help="Skip creating .bak backup")

    p_steam = subparsers.add_parser("steam", help="Detect, inspect, and patch installed Steam games")
    p_steam.add_argument("game", nargs="?", default=None, help="Game name or search term to inspect/patch")
    p_steam.add_argument("-g", "--game", dest="game_flag", default=None, help="Steam game name to inspect/patch")
    p_steam.add_argument("-p", "--patch", action="store_true", help="Apply patch to detected game(s)")
    p_steam.add_argument("--all", action="store_true", help="Patch all detected Steam games needing patch")
    p_steam.add_argument("--dry-run", action="store_true", help="Simulate patch without writing")
    p_steam.add_argument("--no-backup", action="store_true", help="Skip creating .bak backup")

    p_restore = subparsers.add_parser("restore", help="Restore target from .bak backup")
    p_restore.add_argument("target", type=Path, help="File, folder, or .app to restore")

    p_undo = subparsers.add_parser("undo", help="Undo patches by application name using history")
    p_undo.add_argument("app", nargs="?", default=None, help="Application name or search string to undo")
    p_undo.add_argument("-a", "--app", dest="app_flag", default=None, help="Application name to undo")
    p_undo.add_argument("--id", dest="id_flag", default=None, help="Specific patch record ID to undo")
    p_undo.add_argument("--all", action="store_true", help="Undo all active patches")

    subparsers.add_parser("history", help="Show history of patched applications and files")
    subparsers.add_parser("mkl-info", help="Show Intel MKL launch option instructions")
    subparsers.add_parser("check-updates", help="Check if app updates overwrote any patched applications")
    subparsers.add_parser("create-alias", help="Create 'Ryzentosh patch Utility' in /Applications with logo")
    subparsers.add_parser("alias", help="Create 'Ryzentosh patch Utility' in /Applications with logo")
    p_reset = subparsers.add_parser("reset", help="Factory reset switch: Revert all patches and wipe history")
    p_reset.add_argument("-f", "--force", action="store_true", help="Force reset without confirmation prompt")

    args = parser.parse_args()

    if not args.command:
        # Check if user specified top-level flags like --app, --game, or --check-updates
        if getattr(args, "check_updates", False):
            updates = check_updated_patches()
            if not updates:
                cprint(Colors.GREEN, "✅ All active patched applications are healthy and intact (no overwritten libraries detected).")
                return 0
            prompt_repatch_updates()
            return 0
        elif getattr(args, "alias_flag", False):
            return cmd_create_alias()
        elif getattr(args, "reset_flag", False):
            return cmd_reset(force=getattr(args, "force", False))
        elif getattr(args, "app_flag", None):
            return cmd_apps(
                app_query=args.app_flag,
                patch_mode=getattr(args, "patch", False),
                all_apps=False,
                dry_run=getattr(args, "dry_run", False),
                no_backup=getattr(args, "no_backup", False)
            )
        elif getattr(args, "game_flag", None):
            return cmd_steam(
                game_query=args.game_flag,
                patch_mode=getattr(args, "patch", False),
                all_games=False,
                dry_run=getattr(args, "dry_run", False),
                no_backup=getattr(args, "no_backup", False)
            )
        interactive_wizard()
        return 0

    if args.command == "check-updates":
        updates = check_updated_patches()
        if not updates:
            cprint(Colors.GREEN, "✅ All active patched applications are healthy and intact (no overwritten libraries detected).")
            return 0
        prompt_repatch_updates()
        return 0

    elif args.command in ("create-alias", "alias"):
        return cmd_create_alias()

    elif args.command == "reset":
        return cmd_reset(force=getattr(args, "force", False))

    elif args.command == "patch":
        target = args.target
        if getattr(args, "app_flag", None):
            app = find_app_by_name(args.app_flag)
            if not app:
                cprint(Colors.RED, f"Error: No installed application matches '{args.app_flag}'.")
                return 1
            target = app.bundle_path
        elif getattr(args, "game_flag", None):
            return cmd_steam(game_query=args.game_flag, patch_mode=True, dry_run=args.dry_run, no_backup=args.no_backup)

        if not target:
            cprint(Colors.RED, "Error: Must specify target file/folder or pass --app <name> / --game <name>.")
            return 1
        return cmd_patch(target.expanduser(), dry_run=args.dry_run, no_backup=args.no_backup, verbose=args.verbose)

    elif args.command == "scan":
        target = args.target
        if getattr(args, "app_flag", None):
            app = find_app_by_name(args.app_flag)
            if not app:
                cprint(Colors.RED, f"Error: No installed application matches '{args.app_flag}'.")
                return 1
            target = app.bundle_path
        if not target:
            cprint(Colors.RED, "Error: Must specify target file/folder or pass --app <name>.")
            return 1
        return cmd_scan(target.expanduser(), verbose=args.verbose)

    elif args.command == "debug":
        target = getattr(args, "app_flag", None) or getattr(args, "game_flag", None) or args.target
        if not target:
            cprint(Colors.RED, "Error: Must specify target or pass --app <name> / --game <name>.")
            return 1
        return cmd_debug(target)

    elif args.command == "apps":
        app_q = getattr(args, "app_flag", None) or args.app
        return cmd_apps(app_query=app_q, patch_mode=args.patch, all_apps=args.all, dry_run=args.dry_run, no_backup=args.no_backup)

    elif args.command == "steam":
        game_q = getattr(args, "game_flag", None) or args.game
        return cmd_steam(game_query=game_q, patch_mode=args.patch, all_games=args.all, dry_run=args.dry_run, no_backup=args.no_backup)

    elif args.command == "restore":
        return cmd_restore(args.target.expanduser())

    elif args.command == "undo":
        app_q = getattr(args, "app_flag", None) or args.app
        rec_id = getattr(args, "id_flag", None)
        return cmd_undo(app_name=app_q, all_patches=args.all, record_id=rec_id)

    elif args.command == "history":
        return cmd_history()

    elif args.command == "mkl-info":
        return cmd_mkl_info()

    return 0


if __name__ == "__main__":
    sys.exit(main())
