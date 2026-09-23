"""
Project AETHERIS - Codebase Header Enforcement Utility
Traverses the AST of all repository Python modules to detect and inject 
missing authoritative module-level docstrings.
"""
import os
import ast
from pathlib import Path

TARGET_DIR = Path(r"E:\Project_AETHERIS\aetheris")

# The authoritative AETHERIS template. The script will dynamically inject the filename.
HEADER_TEMPLATE = '"""\nProject AETHERIS - {filename}\n[Awaiting formal architectural description from Antigravity]\n"""\n\n'

def sweep_and_enforce_headers(directory: Path):
    missing_headers = []
    
    for py_file in directory.rglob("*.py"):
        if py_file.name == "__init__.py" or "venv" in py_file.parts:
            continue
            
        with open(py_file, "r", encoding="utf-8") as f:
            source = f.read()
            
        if not source.strip():
            continue # Skip completely empty files
            
        try:
            tree = ast.parse(source)
            docstring = ast.get_docstring(tree)
            
            if not docstring:
                missing_headers.append(py_file)
                inject_header(py_file, source)
        except SyntaxError:
            print(f"[!] AST Parse Failure: {py_file.name}")

    print(f"\n[+] AST Sweep Complete. {len(missing_headers)} modules lacked authoritative headers.")
    for f in missing_headers:
        print(f"  -> Injected template: {f.relative_to(TARGET_DIR.parent)}")

def inject_header(filepath: Path, original_source: str):
    module_name = filepath.stem.replace("_", " ").title()
    header = HEADER_TEMPLATE.format(filename=module_name)
    
    with open(filepath, "w", encoding="utf-8") as f:
        f.write(header + original_source)

if __name__ == "__main__":
    print("[+] Initializing Project AETHERIS AST Header Sweep...")
    sweep_and_enforce_headers(TARGET_DIR)