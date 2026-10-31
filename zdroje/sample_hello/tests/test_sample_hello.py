"""Testy vzorového nástroje – spustí ho stejně jako jádro (v odděleném procesu)."""

from pathlib import Path

from pycontrol.tools.executor import ToolExecutor
from pycontrol.tools.manifest import load_manifest

TOOL_DIR = Path(__file__).resolve().parents[1]


def _ctx():
    return {"task_id": "T-test", "cid": "c-test", "requester": "test", "requester_role": "operator",
            "source": "test", "config": {}}


def test_manifest_is_valid():
    m = load_manifest(TOOL_DIR)
    assert m.id == "sample.hello" and m.risk == "read"


def test_execute_greets():
    m = load_manifest(TOOL_DIR)
    res = ToolExecutor().run(m, "execute", {"jmeno": "Jan"}, _ctx(), timeout=10)
    assert res.ok, res.error
    assert res.data["pozdrav"].startswith("Ahoj, Jan")


def test_empty_name_is_tool_error():
    m = load_manifest(TOOL_DIR)
    res = ToolExecutor().run(m, "execute", {"jmeno": "  "}, _ctx(), timeout=10)
    assert res.status == "error" and res.error["code"] == "invalid_input"


def test_summary_and_version():
    m = load_manifest(TOOL_DIR)
    res = ToolExecutor().run(m, "execute", {"jmeno": "Jan"}, _ctx(), timeout=10)
    assert res.ok, res.error
    assert res.data["summary"] == res.data["pozdrav"]
    assert res.data["verze_nastroje"] == m.version
