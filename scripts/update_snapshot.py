import os
from pathlib import Path
from typing import Set

def compile_repository_snapshot(target_directory: str = ".", output_matrix: str = "snapshot.txt") -> None:
    """
    Executes a deterministic filesystem traversal, mathematically pruning non-operational 
    virtual environments, compiled binaries, and caching layers from the index.
    """
    # Absolute isolation of hypervisor dependencies, binary staging trees, and LLM tensors
    exclusion_matrices: Set[str] = {
        "venv",
        ".venv",
        ".venv_wsl",
        ".pytest_cache",
        ".hypothesis",
        ".git",
        ".patch_archive",
        "build",
        "dist",
        "models",
        "__pycache__",
        ".venv",
        ".venv_wsl", 
        "build", 
        "dist", 
        ".hypothesis", 
        "models",
        ".git", 
        "__pycache__", 
        ".patch_archive"
    }
    
    with open(output_matrix, "w", encoding="utf-8") as snapshot_buffer:
        for root, dirs, files in os.walk(target_directory):
            # Mutate the directory list in-place to instantly kill recursive traversal into excluded nodes
            dirs[:] = [d for d in dirs if d not in exclusion_matrices]
            
            for file_node in sorted(files):
                # Prevent recursive self-indexing
                if file_node == output_matrix or file_node.endswith((".db", ".db-wal", ".db-shm", ".pyc", ".pyd", ".exe", ".dll", ".dat")):
                    continue
                    
                file_path = Path(root) / file_node
                relative_path = file_path.relative_to(target_directory)
                
                try:
                    # Enforce strict utf-8 decoding; drop hardware/binary blobs silently
                    with open(file_path, "r", encoding="utf-8", errors="ignore") as target_file:
                        loc_count = sum(1 for _ in target_file)
                    
                    snapshot_buffer.write(f"{relative_path}: {loc_count} LOC\n")
                except Exception as e:
                    snapshot_buffer.write(f"{relative_path}: [BINARY/UNREADABLE]\n")

if __name__ == "__main__":
    compile_repository_snapshot()