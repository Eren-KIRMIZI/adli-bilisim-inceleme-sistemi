"""Unit tests for RegistryHiveParser, EventLogService, and WindowsArtifactParsers."""

import pytest
from src.registry_engine.hive_parser import RegistryHiveParser, create_synthetic_registry_hive
from src.registry_engine.windows_artifacts import WindowsArtifactParsers, create_synthetic_windows_artifacts
from src.eventlog_engine.evtx_service import EventLogService, create_synthetic_evtx_file


def test_synthetic_registry_hive_parser(tmp_path):
    hive_path = str(tmp_path / "SYSTEM.hiv")
    create_synthetic_registry_hive(hive_path)

    parser = RegistryHiveParser()
    res = parser.parse_hive_file(hive_path)
    assert res["total_keys_parsed"] >= 3
    root = res["root"]
    assert root["name"] == "ROOT_HIVE"
    child_names = {c["name"]: c for c in root["children"]}
    assert "CurrentControlSet" in child_names
    assert "AutorunEntries" in child_names

    ccs_vals = {v["name"]: v["value"] for v in child_names["CurrentControlSet"]["values"]}
    assert ccs_vals["ComputerName"] == "WIN-FORENSIC-01"


def test_synthetic_evtx_parser(tmp_path):
    evtx_path = str(tmp_path / "Security.evtx")
    create_synthetic_evtx_file(evtx_path)

    svc = EventLogService()
    res = svc.parse_evtx_file(evtx_path)
    events = res["events"]
    assert len(events) == 5

    ids = [e["event_id"] for e in events]
    assert 4624 in ids
    assert 4688 in ids
    assert 7045 in ids
    assert 1102 in ids

    cleared = [e for e in events if e["event_id"] == 1102][0]
    assert cleared["severity"] == "Kritik"


def test_windows_lnk_prefetch_recycle_parsers(tmp_path):
    paths = create_synthetic_windows_artifacts(str(tmp_path))

    lnk = WindowsArtifactParsers.parse_lnk(paths["lnk"])
    assert lnk["target_path"] == "E:\\Exfil\\musteri_listesi.zip"
    assert lnk["working_dir"] == "E:\\Exfil"
    assert lnk["target_file_size"] == 1048576

    pf = WindowsArtifactParsers.parse_prefetch(paths["pf"])
    assert pf["executable"] == "POWERSHELL.EXE"
    assert pf["run_count"] == 7
    assert pf["last_run"] is not None

    rb = WindowsArtifactParsers.parse_recycle_bin_i(paths["recycle"])
    assert rb["version"] == 2
    assert rb["original_size"] == 245760
    assert "gizli_maas_tablosu.xlsx" in rb["original_path"]


def test_corrupt_inputs_raise_explicitly(tmp_path):
    bad = tmp_path / "corrupt.bin"
    bad.write_bytes(b"NOT_A_VALID_FORENSIC_FILE")

    with pytest.raises(ValueError):
        RegistryHiveParser().parse_hive_file(str(bad))
    with pytest.raises(ValueError):
        EventLogService().parse_evtx_file(str(bad))
    with pytest.raises(ValueError):
        WindowsArtifactParsers.parse_lnk(str(bad))
