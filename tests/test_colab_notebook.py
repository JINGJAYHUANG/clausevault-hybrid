"""
Deterministic pytest verification for `HybridAI_Gemini_Cloud_Benchmark_Colab.ipynb`
and `firebase-hybrid-ai-v2` submission bundle integrity.
"""

from __future__ import annotations

import ast
import json
import re
from pathlib import Path

import pytest

ROOT_DIR = Path(__file__).resolve().parent.parent
NOTEBOOK_PATH = ROOT_DIR / "HybridAI_Gemini_Cloud_Benchmark_Colab.ipynb"
AT_CHAR = chr(64)


def _load_notebook() -> dict:
    assert NOTEBOOK_PATH.is_file(), f"Missing {NOTEBOOK_PATH}"
    return json.loads(NOTEBOOK_PATH.read_text(encoding="utf-8"))


def test_nbformat_v4_and_all_code_cells_parse_cleanly() -> None:
    nb = _load_notebook()
    assert nb["nbformat"] == 4
    assert nb["nbformat_minor"] >= 4
    code_cells = [c for c in nb["cells"] if c["cell_type"] == "code"]
    assert len(code_cells) >= 3
    for cell in code_cells:
        src = "".join(cell["source"])
        ast.parse(src, filename=cell.get("id", "notebook_cell"))


def test_colab_userdata_secret_isolation_and_runtime_unassign_in_finally() -> None:
    nb = _load_notebook()
    full_code = "\n".join("".join(c["source"]) for c in nb["cells"] if c["cell_type"] == "code")
    assert 'userdata.get("GEMINI_API_KEY")' in full_code
    assert "benchmark_receipt.json" in full_code

    tree = ast.parse(full_code)
    found_unassign_in_finally = False
    for node in ast.walk(tree):
        if isinstance(node, ast.Try) and node.finalbody:
            finally_src = ast.unparse(ast.Module(body=node.finalbody, type_ignores=[]))
            if "runtime.unassign()" in finally_src:
                found_unassign_in_finally = True
    assert found_unassign_in_finally, "Notebook MUST call runtime.unassign() inside a finally: block"


def test_notebook_local_sanitizer_and_window_truncation_harness_deterministic() -> None:
    nb = _load_notebook()
    code_cells = ["".join(c["source"]) for c in nb["cells"] if c["cell_type"] == "code"]
    ns: dict = {"__name__": "pytest_harness", "IN_COLAB": False}
    exec(code_cells[1], ns)  # cell-03-corpus-and-vault
    exec(code_cells[2], ns)  # cell-04-cloud-runner

    dry_summary = ns["evaluate_corpus_with_optional_gemini"](None)
    assert dry_summary["execution_mode"] == "DRY_RUN_NO_CLOUD_KEY"
    assert dry_summary["evaluated_cases"] == 4
    assert dry_summary["raw_pii_bytes_leaked_to_cloud"] == 0
    # Window-truncated local baseline misses late cross-clause contradictions in BENCH-02 (1 of 3 codes caught = 0.3333)
    assert dry_summary["local_truncated_window_recall"] == pytest.approx(0.3333, abs=1e-3)
    assert dry_summary["cloud_full_context_recall"] is None


def test_zero_plaintext_emails_or_tokens_in_notebook_and_docs() -> None:
    email_pat = re.compile(rf"[A-Za-z0-9._%+-]+{AT_CHAR}[A-Za-z0-9.-]+\.[A-Za-z]{{2,}}")
    token_pat = re.compile(r"\b(?:AIza[0-9A-Za-z_-]{30,}|sk-[0-9A-Za-z]{20,}|ghp_[0-9A-Za-z]{25,})\b")

    for path in ROOT_DIR.rglob("*"):
        if path.is_file() and path.suffix in {".ipynb", ".md", ".mjs", ".py", ".html", ".css", ".json"}:
            if "__pycache__" in path.parts or ".pytest_cache" in path.parts:
                continue
            content = path.read_text(encoding="utf-8")
            assert not email_pat.search(content), f"Plaintext email detected in {path.name}"
            assert not token_pat.search(content), f"Secret token detected in {path.name}"
