"""
Aetheris Standalone Windows Executable (.exe) Automated Build Script
Builds a standalone, zero-dependency Aetheris.exe utilizing PyInstaller.
"""

import os
import sys
import shutil
import subprocess
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent

def build_executable():
    print("=" * 70)
    print("  [BUILD] AETHERIS STANDALONE WINDOWS EXECUTABLE (.EXE)")
    print("=" * 70)

    try:
        import PyInstaller
        print(f" [+] PyInstaller detected: v{PyInstaller.__version__}")
    except ImportError:
        print(" [!] PyInstaller not found. Installing into environment...")
        subprocess.check_call([sys.executable, "-m", "pip", "install", "pyinstaller"])

    build_dir = BASE_DIR / "build"
    dist_dir = BASE_DIR / "dist"
    spec_file = BASE_DIR / "Aetheris.spec"

    if build_dir.exists():
        shutil.rmtree(build_dir, ignore_errors=True)

    if not spec_file.exists():
        print(f" [!] Spec file missing: {spec_file}")
        print(" [*] Generating default PyInstaller spec for Aetheris...")
        subprocess.check_call([
            sys.executable, "-m", "PyInstaller",
            "--noconfirm",
            "--onedir",
            "--name", "Aetheris",
            "main.py"
        ])
        spec_file = BASE_DIR / "Aetheris.spec"

    print(f" [+] Using PyInstaller spec: {spec_file}")
    cmd = [
        sys.executable,
        "-m", "PyInstaller",
        "--noconfirm",
        "--workpath", str(build_dir),
        "--distpath", str(dist_dir),
        str(spec_file)
    ]
    
    result = subprocess.run(cmd, cwd=str(BASE_DIR))
    if result.returncode != 0:
        print("\n [!] Build failed with compilation errors.")
        sys.exit(result.returncode)

    exe_path = dist_dir / "Aetheris" / "Aetheris.exe"
    if not exe_path.exists():
        exe_path = dist_dir / "Aetheris.exe"

    if exe_path.exists():
        size_mb = exe_path.stat().st_size / (1024 * 1024)
        print("\n" + "=" * 70)
        print("  [SUCCESS] BUILD COMPLETED SUCCESSFULLY!")
        print(f"  Target Executable: {exe_path}")
        print(f"  Binary File Size:  {size_mb:.2f} MB")
        print("=" * 70)
    else:
        print(f"\n [!] Expected binary not found under {dist_dir}")
        sys.exit(1)

if __name__ == "__main__":
    build_executable()