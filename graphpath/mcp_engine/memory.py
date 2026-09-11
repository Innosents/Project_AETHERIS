"""
Vector Search Memory Engine & Architectural Decision Record (ADR) Manager
Provides semantic discovery across project documentation, codebase architecture,
and decision records using an offline TF-IDF / N-Gram cosine vectorizer.
"""

import os
import re
import math
import json
import time
import threading
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

BASE_DIR = Path(__file__).resolve().parent.parent

class TextVectorizer:
    """
    Lightweight, deterministic N-Gram TF-IDF Vectorizer.
    Provides subword and token-level semantic cosine similarity with zero external API dependencies.
    """
    def __init__(self):
        self.stop_words = {
            "a", "an", "the", "and", "or", "in", "on", "at", "to", "for", "with", "by", "of",
            "is", "are", "was", "were", "be", "been", "this", "that", "it", "as", "from"
        }

    def tokenize(self, text: str) -> List[str]:
        """Extracts words and character 3-grams for robust subword matching."""
        clean = re.sub(r"[^a-zA-Z0-9_\-\.\/]", " ", text.lower())
        words = [w for w in clean.split() if w and w not in self.stop_words]
        
        tokens = list(words)
        # Add character tri-grams for words >= 4 chars to handle plurals, stems, and typos
        for w in words:
            if len(w) >= 4:
                for i in range(len(w) - 2):
                    tokens.append(f"ng:{w[i:i+3]}")
        return tokens

    def compute_tf(self, tokens: List[str]) -> Dict[str, float]:
        """Calculates term frequency vector."""
        tf: Dict[str, float] = {}
        for t in tokens:
            tf[t] = tf.get(t, 0.0) + 1.0
        total = max(1.0, float(len(tokens)))
        return {t: count / total for t, count in tf.items()}

    def cosine_similarity(self, vec1: Dict[str, float], vec2: Dict[str, float], idf: Dict[str, float]) -> float:
        """Computes TF-IDF weighted cosine similarity between two sparse vectors."""
        common_keys = set(vec1.keys()) & set(vec2.keys())
        if not common_keys:
            return 0.0

        dot_product = sum(vec1[k] * vec2[k] * (idf.get(k, 1.0) ** 2) for k in common_keys)
        
        mag1 = math.sqrt(sum((val * idf.get(k, 1.0)) ** 2 for k, val in vec1.items()))
        mag2 = math.sqrt(sum((val * idf.get(k, 1.0)) ** 2 for k, val in vec2.items()))

        if mag1 == 0.0 or mag2 == 0.0:
            return 0.0

        return dot_product / (mag1 * mag2)


class VectorMemoryEngine:
    _instance = None
    _lock = threading.RLock()

    def __new__(cls, *args, **kwargs):
        if not cls._instance:
            with cls._lock:
                if not cls._instance:
                    cls._instance = super(VectorMemoryEngine, cls).__new__(cls)
                    cls._instance._initialized = False
        return cls._instance

    def __init__(self, base_dir: Optional[Path] = None):
        if getattr(self, "_initialized", False):
            return

        self.base_dir = base_dir or BASE_DIR
        self.storage_dir = self.base_dir / "memory_store"
        self.storage_dir.mkdir(parents=True, exist_ok=True)
        
        self.memory_index_path = self.storage_dir / "project_memory_store.json"
        self.adr_path = self.storage_dir / "decision_records.json"

        self.vectorizer = TextVectorizer()
        self.chunks: List[Dict[str, Any]] = [] # list of {chunk_id, title, content, category, source_file, tf}
        self.idf: Dict[str, float] = {}
        self.decision_records: Dict[str, Dict[str, Any]] = {}

        self.load_decision_records()
        self.load_or_build_memory_index()
        self._initialized = True

    def load_decision_records(self) -> None:
        """Loads ADR records from disk."""
        with self._lock:
            if self.adr_path.exists():
                try:
                    with self.adr_path.open("r", encoding="utf-8") as f:
                        self.decision_records = json.load(f)
                except Exception:
                    self.decision_records = {}
            else:
                self.decision_records = {}
                self._seed_default_adrs()

    def save_decision_records(self) -> None:
        """Atomically persists decision records."""
        with self._lock:
            try:
                temp = self.adr_path.with_suffix(".tmp")
                with temp.open("w", encoding="utf-8") as f:
                    json.dump(self.decision_records, f, indent=2)
                temp.replace(self.adr_path)
            except Exception:
                pass

    def _seed_default_adrs(self) -> None:
        """Seeds initial architectural decisions for GraphPath."""
        self.decision_records = {
            "ADR-001-TESTBENCH-ISOLATION": {
                "record_id": "ADR-001-TESTBENCH-ISOLATION",
                "title": "Complete Isolation of Testbench from Core Discovery Pipeline",
                "decision": "All mock devices, gym environments, and simulation classes must reside exclusively in testbench/ and never be imported in production topology serialization.",
                "rationale": "Prevents artificial testbench containers from showing up as false positive assets on live home and enterprise network discovery scans.",
                "status": "accepted",
                "tags": ["architecture", "testbench", "isolation"],
                "affected_components": ["topology.serializer", "discovery.oid_library", "testbench"],
                "timestamp": "2026-08-30T16:00:00Z"
            },
            "ADR-002-INFRASTRUCTURE-PATHING": {
                "record_id": "ADR-002-INFRASTRUCTURE-PATHING",
                "title": "Automated Layer 2/3 Gateway and Intermediate Infrastructure Hierarchy",
                "decision": "Reconcile network topology from Gateway Router down to Wi-Fi Range Extenders and STBs, with Device Identity Profile (DIP) physical uplink pinning.",
                "rationale": "Overcomes flat Layer 2 broadcast domain limitations in consumer networks lacking enterprise SNMP bridge MIBs.",
                "status": "accepted",
                "tags": ["topology", "pathing", "routing", "dip"],
                "affected_components": ["topology.graph_store", "core.dip_manager", "ui.static.dashboard.js"],
                "timestamp": "2026-08-30T18:15:00Z"
            },
            "ADR-003-MCP-DUAL-MODE-ECOSYSTEM": {
                "record_id": "ADR-003-MCP-DUAL-MODE-ECOSYSTEM",
                "title": "Dual-Mode FastMCP and Universal JSON-RPC 2.0 STDIO Transport",
                "decision": "Implement all MCP servers (Discovery, Blackboard, Validation Guard, Vector Memory) with fallback to raw universal JSON-RPC 2.0 STDIO.",
                "rationale": "Guarantees 100% interoperability across AI agent clients (Antigravity, Claude Desktop, Cursor) with zero module import collision.",
                "status": "accepted",
                "tags": ["mcp", "agent", "json-rpc", "blackboard"],
                "affected_components": ["mcp_engine.server", "mcp_engine.tools", "mcp_engine.resources"],
                "timestamp": "2026-08-30T18:25:00Z"
            }
        }
        self.save_decision_records()

    def upsert_decision_record(
        self,
        record_id: str,
        title: str,
        decision: str,
        rationale: str,
        status: str = "accepted",
        tags: Optional[List[str]] = None,
        affected_components: Optional[List[str]] = None,
        context: str = ""
    ) -> Dict[str, Any]:
        """
        Logs or updates an Architectural Decision Record (ADR) and embeds it into vector memory.
        """
        with self._lock:
            now_iso = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
            record = {
                "record_id": record_id,
                "title": title,
                "decision": decision,
                "rationale": rationale,
                "status": status,
                "tags": tags or [],
                "affected_components": affected_components or [],
                "context": context,
                "updated_at": now_iso
            }
            if record_id not in self.decision_records:
                record["created_at"] = now_iso

            self.decision_records[record_id] = record
            self.save_decision_records()

            # Index into vector memory
            self._index_single_adr(record)
            self._recalculate_idf()
            self._save_memory_index()

            return {"status": "success", "record": record}

    def list_decision_records(self, status_filter: str = "", tag_filter: str = "") -> Dict[str, Any]:
        """Returns all decision records with optional filtering."""
        with self._lock:
            records = list(self.decision_records.values())
            if status_filter:
                sf = status_filter.strip().lower()
                records = [r for r in records if r.get("status", "").lower() == sf]
            if tag_filter:
                tf = tag_filter.strip().lower()
                records = [r for r in records if tf in [t.lower() for t in r.get("tags", [])]]

            return {
                "total_records": len(records),
                "decision_records": records
            }

    def load_or_build_memory_index(self) -> None:
        """Loads vector index from disk or builds it from project markdown files."""
        with self._lock:
            if self.memory_index_path.exists():
                try:
                    with self.memory_index_path.open("r", encoding="utf-8") as f:
                        data = json.load(f)
                        self.chunks = data.get("chunks", [])
                        self._recalculate_idf()
                        return
                except Exception:
                    pass

            self.index_project_documentation()

    def index_project_documentation(self, custom_paths: Optional[List[str]] = None) -> Dict[str, Any]:
        """
        Scans project documentation, architectural overviews, and ADRs into semantic chunks.
        """
        with self._lock:
            new_chunks: List[Dict[str, Any]] = []

            # 1. Index all Decision Records
            for adr in self.decision_records.values():
                content = f"Title: {adr['title']}\nDecision: {adr['decision']}\nRationale: {adr['rationale']}\nContext: {adr.get('context', '')}\nTags: {', '.join(adr.get('tags', []))}\nAffected Components: {', '.join(adr.get('affected_components', []))}"
                tokens = self.vectorizer.tokenize(content)
                new_chunks.append({
                    "chunk_id": f"adr_{adr['record_id']}",
                    "title": adr['title'],
                    "category": "decision_records",
                    "source_file": "decision_records.json",
                    "content": content,
                    "tokens_count": len(tokens),
                    "tf": self.vectorizer.compute_tf(tokens)
                })

            # 2. Discover markdown docs
            doc_files: List[Path] = []
            if custom_paths:
                for p in custom_paths:
                    path_obj = Path(p) if Path(p).is_absolute() else (self.base_dir / p)
                    if path_obj.exists():
                        doc_files.append(path_obj)
            else:
                # Target key project markdown files
                for pattern in ["*.md", "**/*.md"]:
                    for found in self.base_dir.glob(pattern):
                        if "venv" not in found.parts and ".git" not in found.parts:
                            doc_files.append(found)

            for doc_path in set(doc_files):
                try:
                    with doc_path.open("r", encoding="utf-8", errors="replace") as f:
                        text = f.read()
                    
                    file_rel = str(doc_path.relative_to(self.base_dir))
                    chunks_for_file = self._chunk_markdown(text, file_rel)
                    new_chunks.extend(chunks_for_file)
                except Exception:
                    pass

            self.chunks = new_chunks
            self._recalculate_idf()
            self._save_memory_index()

            return {
                "status": "indexed",
                "total_chunks_indexed": len(self.chunks),
                "total_documents_processed": len(set(doc_files))
            }

    def _chunk_markdown(self, text: str, source_file: str) -> List[Dict[str, Any]]:
        """Splits markdown text into semantic sections by header."""
        sections = re.split(r"(^#{1,3}\s+.+$)", text, flags=re.MULTILINE)
        chunks = []

        current_title = Path(source_file).stem.replace("_", " ").title()
        current_text = ""

        category = "architecture" if "overview" in source_file.lower() or "architecture" in source_file.lower() else "documentation"

        for part in sections:
            if part.startswith("#"):
                if current_text.strip():
                    tokens = self.vectorizer.tokenize(f"{current_title}\n{current_text}")
                    if tokens:
                        chunks.append({
                            "chunk_id": f"{source_file}_{len(chunks)}",
                            "title": current_title,
                            "category": category,
                            "source_file": source_file,
                            "content": current_text.strip()[:1000],
                            "tokens_count": len(tokens),
                            "tf": self.vectorizer.compute_tf(tokens)
                        })
                current_title = part.lstrip("#").strip()
                current_text = ""
            else:
                current_text += "\n" + part

        if current_text.strip():
            tokens = self.vectorizer.tokenize(f"{current_title}\n{current_text}")
            if tokens:
                chunks.append({
                    "chunk_id": f"{source_file}_{len(chunks)}",
                    "title": current_title,
                    "category": category,
                    "source_file": source_file,
                    "content": current_text.strip()[:1000],
                    "tokens_count": len(tokens),
                    "tf": self.vectorizer.compute_tf(tokens)
                })

        return chunks

    def _index_single_adr(self, adr: Dict[str, Any]) -> None:
        """Indexes a single ADR entry without full re-indexing."""
        chunk_id = f"adr_{adr['record_id']}"
        content = f"Title: {adr['title']}\nDecision: {adr['decision']}\nRationale: {adr['rationale']}\nContext: {adr.get('context', '')}\nTags: {', '.join(adr.get('tags', []))}"
        tokens = self.vectorizer.tokenize(content)
        
        # Remove existing chunk if present
        self.chunks = [c for c in self.chunks if c.get("chunk_id") != chunk_id]
        self.chunks.append({
            "chunk_id": chunk_id,
            "title": adr['title'],
            "category": "decision_records",
            "source_file": "decision_records.json",
            "content": content,
            "tokens_count": len(tokens),
            "tf": self.vectorizer.compute_tf(tokens)
        })

    def _recalculate_idf(self) -> None:
        """Calculates Inverse Document Frequency (IDF) table across all indexed chunks."""
        total_docs = max(1.0, float(len(self.chunks)))
        doc_freq: Dict[str, int] = {}
        for c in self.chunks:
            for term in c.get("tf", {}).keys():
                doc_freq[term] = doc_freq.get(term, 0) + 1

        self.idf = {
            term: math.log((total_docs + 1.0) / (df + 1.0)) + 1.0
            for term, df in doc_freq.items()
        }

    def _save_memory_index(self) -> None:
        """Saves compiled vector chunks to disk."""
        try:
            temp = self.memory_index_path.with_suffix(".tmp")
            with temp.open("w", encoding="utf-8") as f:
                json.dump({"chunks": self.chunks, "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}, f, indent=2)
            temp.replace(self.memory_index_path)
        except Exception:
            pass

    def search_project_memory(
        self,
        query: str,
        top_k: int = 5,
        category: str = "",
        min_score: float = 0.05
    ) -> Dict[str, Any]:
        """
        Executes semantic vector similarity search across all project chunks.
        """
        if not query:
            return {"error": "Missing search query."}

        with self._lock:
            q_tokens = self.vectorizer.tokenize(query)
            if not q_tokens:
                return {"query": query, "total_matches": 0, "results": []}

            q_tf = self.vectorizer.compute_tf(q_tokens)
            results = []

            for chunk in self.chunks:
                if category and chunk.get("category") != category:
                    continue

                sim = self.vectorizer.cosine_similarity(q_tf, chunk.get("tf", {}), self.idf)
                if sim >= min_score:
                    results.append({
                        "score": round(sim, 4),
                        "title": chunk.get("title"),
                        "category": chunk.get("category"),
                        "source_file": chunk.get("source_file"),
                        "excerpt": chunk.get("content", "")[:500]
                    })

            # Rank by cosine similarity descending
            results.sort(key=lambda x: x["score"], reverse=True)
            top_results = results[:top_k]

            return {
                "query": query,
                "total_matches": len(results),
                "returned_results": len(top_results),
                "results": top_results
            }

    def get_memory_stats(self) -> Dict[str, Any]:
        """Returns statistics on the indexed vector store."""
        with self._lock:
            categories: Dict[str, int] = {}
            for c in self.chunks:
                cat = c.get("category", "general")
                categories[cat] = categories.get(cat, 0) + 1

            return {
                "total_indexed_chunks": len(self.chunks),
                "total_vocabulary_terms": len(self.idf),
                "total_decision_records": len(self.decision_records),
                "category_distribution": categories,
                "last_indexed_iso": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
            }

