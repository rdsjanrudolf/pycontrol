"""Testy nástroje network.arp.

Nezávisí na skutečném Windows ani na právech účtu služby:
* Windows část (ctypes nad iphlpapi) se ověřuje proti podvrženému API, které vrací skutečné
  struktury MIB_IPNET_TABLE2 / MIB_IPFORWARD_TABLE2 v paměti,
* logika (filtry, zjištění, souhrn) proti podvrženému ``_read_raw``.
"""

import ctypes
import importlib.util
import ipaddress
import logging
import sys
from pathlib import Path

import pytest

from pycontrol.tools.manifest import load_manifest
from pycontrol.tools.sdk import ToolError

TOOL_DIR = Path(__file__).resolve().parents[1]


def _load_tool():
    spec = importlib.util.spec_from_file_location("network_arp_tool_under_test", TOOL_DIR / "tool.py")
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


tool = _load_tool()


class FakeCtx:
    def __init__(self, left=30.0):
        self.log = logging.getLogger("test.network.arp")
        self.config = {}
        self.sim_path = None
        self.requester = "test"
        self._left = left

    def time_left(self):
        return self._left


def mac(text):
    return bytes.fromhex(text.replace("-", "").replace(":", ""))


def nb(ip, mac_text, state=5, iface="Ethernet0", idx=4, router=False):
    return {"ip": ip, "mac": mac(mac_text) if mac_text else b"", "state": state, "if_index": idx,
            "interface": iface, "is_router": router}


GW_MAC = "90-6C-AC-11-22-33"


def raw_basic():
    return {
        "neighbors": [
            nb("192.168.1.1", GW_MAC, router=True),
            nb("192.168.1.20", "00-50-56-AA-BB-01"),
            nb("192.168.1.30", "00-15-5D-01-02-03", state=4),
            nb("192.168.1.40", None, state=1),
            nb("192.168.1.50", "00-11-22-33-44-55", state=6),
            nb("192.168.1.255", "FF-FF-FF-FF-FF-FF", state=6),
            nb("224.0.0.22", "01-00-5E-00-00-16", state=6),
            nb("10.0.0.5", "BC-24-11-00-00-01", iface="Ethernet1", idx=7),
        ],
        "gateways": [{"ip": "192.168.1.1", "interface": "Ethernet0", "if_index": 4, "metric": 25}],
        "gateway_error": None,
        "interfaces": {"Ethernet0": [ipaddress.IPv4Interface("192.168.1.10/24")],
                       "Ethernet1": [ipaddress.IPv4Interface("10.0.0.10/24")]},
    }


# --------------------------------------------------------------------------- manifest


def test_manifest_is_valid():
    m = load_manifest(TOOL_DIR)
    assert m.id == "network.arp"
    assert m.risk == "read"


# --------------------------------------------------------------------------- struktury Windows


def test_struct_layout_matches_windows_x64():
    # Velikosti podle Windows SDK (x64): chyba v rozložení by četla nesmysly.
    assert ctypes.sizeof(tool.SOCKADDR_INET) == 28
    assert ctypes.sizeof(tool.MIB_IPNET_ROW2) == 88
    assert tool.MIB_IPNET_ROW2.InterfaceLuid.offset == 32
    assert tool.MIB_IPNET_ROW2.PhysicalAddress.offset == 40
    assert tool.MIB_IPNET_ROW2.State.offset == 76
    assert tool.MIB_IPNET_ROW2.Flags.offset == 80
    assert tool.MIB_IPNET_TABLE2.Table.offset == 8
    assert ctypes.sizeof(tool.MIB_IPFORWARD_ROW2) == 104
    assert tool.MIB_IPFORWARD_ROW2.NextHop.offset == 44
    assert tool.MIB_IPFORWARD_ROW2.Metric.offset == 84
    assert tool.MIB_IPFORWARD_TABLE2.Table.offset == 8


def _sockaddr(ip):
    sa = tool.SOCKADDR_INET()
    sa.si_family = tool.AF_INET
    sa.Ipv4.sin_addr[:] = list(ipaddress.IPv4Address(ip).packed)
    return sa


class FakeIphlpapi:
    """Podvržené iphlpapi: alokuje skutečné tabulky MIB_* a vrací na ně ukazatel."""

    def __init__(self, neighbors=(), routes=(), net_rc=0, fwd_rc=0):
        self.neighbors, self.routes = list(neighbors), list(routes)
        self.net_rc, self.fwd_rc = net_rc, fwd_rc
        self.freed = []
        self._keep = []

    def _table(self, row_cls, table_cls, rows):
        n = max(1, len(rows))
        size = table_cls.Table.offset + ctypes.sizeof(row_cls) * n
        buf = ctypes.create_string_buffer(size)
        ctypes.c_uint32.from_buffer(buf).value = len(rows)
        arr = (row_cls * n).from_buffer(buf, table_cls.Table.offset)
        for i, r in enumerate(rows):
            arr[i] = r
        self._keep.append(buf)
        return ctypes.addressof(buf)

    def GetIpNetTable2(self, family, pptr):
        assert family == tool.AF_INET
        if self.net_rc:
            return self.net_rc
        rows = []
        for ip, mac_text, state, luid, idx, flags in self.neighbors:
            r = tool.MIB_IPNET_ROW2()
            r.Address = _sockaddr(ip)
            r.InterfaceIndex, r.InterfaceLuid, r.State, r.Flags = idx, luid, state, flags
            m = mac(mac_text) if mac_text else b""
            r.PhysicalAddress[:len(m)] = list(m)
            r.PhysicalAddressLength = len(m)
            rows.append(r)
        pptr.contents.value = self._table(tool.MIB_IPNET_ROW2, tool.MIB_IPNET_TABLE2, rows)
        return 0

    def GetIpForwardTable2(self, family, pptr):
        if self.fwd_rc:
            return self.fwd_rc
        rows = []
        for dest, plen, hop, luid, idx, metric in self.routes:
            r = tool.MIB_IPFORWARD_ROW2()
            r.DestinationPrefix.Prefix = _sockaddr(dest)
            r.DestinationPrefix.PrefixLength = plen
            r.NextHop = _sockaddr(hop)
            r.InterfaceLuid, r.InterfaceIndex, r.Metric = luid, idx, metric
            rows.append(r)
        pptr.contents.value = self._table(tool.MIB_IPFORWARD_ROW2, tool.MIB_IPFORWARD_TABLE2, rows)
        return 0

    def FreeMibTable(self, ptr):
        self.freed.append(ptr.value)

    def ConvertInterfaceLuidToAlias(self, pluid, buf, size):
        names = {100: "Ethernet0", 200: "Ethernet1"}
        if pluid.contents.value not in names:
            return 1168
        buf.value = names[pluid.contents.value]
        return 0


def test_windows_read_neighbors_and_gateways():
    api = FakeIphlpapi(
        neighbors=[("192.168.1.1", GW_MAC, 5, 100, 4, 1),
                   ("192.168.1.40", None, 1, 100, 4, 0),
                   ("10.0.0.5", "BC-24-11-00-00-01", 4, 300, 9, 0)],
        routes=[("0.0.0.0", 0, "192.168.1.1", 100, 4, 25),
                ("192.168.1.0", 24, "0.0.0.0", 100, 4, 256),
                ("0.0.0.0", 0, "0.0.0.0", 200, 7, 10)])
    aliases = {}
    nbs = tool._win_read_neighbors(api, aliases)
    assert [n["ip"] for n in nbs] == ["192.168.1.1", "192.168.1.40", "10.0.0.5"]
    assert nbs[0]["mac"] == mac(GW_MAC) and nbs[0]["is_router"] and nbs[0]["interface"] == "Ethernet0"
    assert nbs[1]["mac"] == b"" and nbs[1]["state"] == 1
    assert nbs[2]["interface"] == "rozhraní #9"  # alias nenalezen → číslo rozhraní
    gws = tool._win_read_gateways(api, aliases)
    assert gws == [{"ip": "192.168.1.1", "if_index": 4, "metric": 25, "interface": "Ethernet0"}]
    assert len(api.freed) == 2  # paměť Windows vždy uvolněna


def test_windows_empty_table_not_found():
    api = FakeIphlpapi(net_rc=tool.ERROR_NOT_FOUND)
    assert tool._win_read_neighbors(api, {}) == []


def test_windows_access_denied_is_explained():
    api = FakeIphlpapi(net_rc=tool.ERROR_ACCESS_DENIED)
    with pytest.raises(ToolError) as e:
        tool._win_read_neighbors(api, {})
    assert e.value.code == "access_denied"
    assert "kód 5" in str(e.value)


def test_windows_other_error_has_code():
    api = FakeIphlpapi(net_rc=tool.ERROR_NOT_ENOUGH_MEMORY)
    with pytest.raises(ToolError) as e:
        tool._win_read_neighbors(api, {})
    assert e.value.code == "win_error" and "0x00000008" in str(e.value)


def test_read_raw_survives_gateway_error(monkeypatch):
    api = FakeIphlpapi(neighbors=[("192.168.1.1", GW_MAC, 5, 100, 4, 0)], fwd_rc=tool.ERROR_ACCESS_DENIED)
    monkeypatch.setattr(tool, "_load_api", lambda: api)
    monkeypatch.setattr(tool, "_interface_addresses", lambda: {})
    raw = tool._read_raw(FakeCtx())
    assert len(raw["neighbors"]) == 1 and raw["gateways"] == []
    assert "přístup odepřen" in raw["gateway_error"]


# --------------------------------------------------------------------------- pomocné funkce


def test_mac_helpers():
    assert tool.format_mac(mac("00-50-56-aa-bb-01")) == "00-50-56-AA-BB-01"
    assert tool.format_mac(b"") is None and tool.format_mac(b"\x00" * 6) is None
    assert tool.mac_filter_hex("00:50:56") == "005056"
    assert tool.mac_filter_hex("aa-BB.cc dd") == "AABBCCDD"
    with pytest.raises(ToolError):
        tool.mac_filter_hex("zz-11")
    assert tool.vendor(mac("00-50-56-00-00-01")) == "VMware"
    assert tool.vendor(mac("BC-24-11-00-00-01")) == "Proxmox"
    assert "lokálně" in tool.vendor(mac("DA-11-22-33-44-55"))
    assert tool.vendor(mac("00-11-22-33-44-55")) is None


def test_ip_filter():
    assert tool.ip_filter_network("192.168.1.10").num_addresses == 1
    assert str(tool.ip_filter_network("192.168.1.7/24")) == "192.168.1.0/24"
    with pytest.raises(ToolError):
        tool.ip_filter_network("192.168.1.300")
    with pytest.raises(ToolError):
        tool.ip_filter_network("fe80::1")


def test_multicast_detection():
    assert tool.is_multicast("224.0.0.22", mac("01-00-5E-00-00-16"))
    assert tool.is_multicast("255.255.255.255", mac("FF-FF-FF-FF-FF-FF"))
    assert not tool.is_multicast("192.168.1.20", mac("00-50-56-AA-BB-01"))


# --------------------------------------------------------------------------- výsledek


def _ips(rep):
    return [r["address"] for r in rep["záznamy"]]


def test_report_default_hides_multicast_and_marks_gateway():
    rep = tool.build_report(raw_basic(), {})
    ips = _ips(rep)
    assert "224.0.0.22" not in ips and "192.168.1.255" not in ips
    t = rep["totals"]
    assert t["vícesměrové_skryté"] == 2 and t["total"] == 6
    assert t["statické"] == 1 and t["bez_odpovědi"] == 1
    gw = next(r for r in rep["záznamy"] if r["address"] == "192.168.1.1")
    assert gw["brána"] is True and gw["výrobce"] == "Fortinet" and gw["typ"] == "dynamický"
    assert rep["brány"][0]["state"] == "dosažitelný"
    assert rep["filters"] is None and rep["truncated"] is False
    # řazení: rozhraní, pak IP číselně
    assert ips[0] == "192.168.1.1" and ips[-1] == "10.0.0.5"


def test_row_fits_console_columns():
    # konzole ukáže nejvýš 8 sloupců – brána musí být mezi nimi, "warning" až deváté
    rep = tool.build_report(raw_basic(), {})
    row = rep["záznamy"][0]
    assert list(row)[:8] == ["address", "mac", "výrobce", "name", "typ", "state", "rozhraní", "brána"]
    assert len(row) == 8


def test_fortigate_vendor_from_test_server():
    assert tool.vendor(mac("AC-71-2E-FB-B3-B8")) == "Fortinet"


def test_report_include_multicast():
    rep = tool.build_report(raw_basic(), {"include_multicast": True})
    assert rep["totals"]["zobrazeno"] == 8
    assert {r["typ"] for r in rep["záznamy"] if r["address"] in ("224.0.0.22", "192.168.1.255")} == {"vícesměrový"}
    assert len(tool.build_report(raw_basic(), {"include_multicast": True, "state": "static"})["záznamy"]) == 1


def test_filters():
    raw = raw_basic()
    assert _ips(tool.build_report(raw, {"ip": "10.0.0.0/8"})) == ["10.0.0.5"]
    assert _ips(tool.build_report(raw, {"mac": "00:50:56"})) == ["192.168.1.20"]
    assert _ips(tool.build_report(raw, {"interface": "ethernet1"})) == ["10.0.0.5"]
    assert _ips(tool.build_report(raw, {"interface": "7"})) == ["10.0.0.5"]
    assert _ips(tool.build_report(raw, {"state": "static"})) == ["192.168.1.50"]
    assert _ips(tool.build_report(raw, {"state": "problem"})) == ["192.168.1.40"]
    assert len(tool.build_report(raw, {"state": "dynamic"})["záznamy"]) == 5
    rep = tool.build_report(raw, {"limit": 2})
    assert rep["truncated"] and rep["totals"]["zobrazeno"] == 2 and rep["totals"]["matched"] == 6
    rep = tool.build_report(raw, {"ip": "10.0.0.0/8", "state": "problem"})
    assert rep["filters"] == "adresa 10.0.0.0/8, bez odpovědi"


def test_finding_gateway_mac_shared_is_warning():
    raw = raw_basic()
    raw["neighbors"].append(nb("192.168.1.66", GW_MAC))
    rep = tool.build_report(raw, {})
    warns = [f["message"] for f in rep["findings"] if f["severity"] == "pozor"]
    assert any("ARP spoofing" in t and "192.168.1.66" in t for t in warns)
    marked = {r["address"]: r.get("warning") for r in rep["záznamy"]}
    assert marked["192.168.1.66"] and marked["192.168.1.1"] and not marked["192.168.1.20"]


def test_finding_shared_mac_without_gateway_is_info():
    raw = raw_basic()
    raw["neighbors"].append(nb("192.168.1.21", "00-50-56-AA-BB-01"))
    rep = tool.build_report(raw, {})
    infos = [f for f in rep["findings"] if "192.168.1.21" in f["message"]]
    assert infos and infos[0]["severity"] == "info"


def test_finding_gateway_unreachable_and_missing():
    raw = raw_basic()
    raw["neighbors"][0] = nb("192.168.1.1", None, state=0)
    rep = tool.build_report(raw, {})
    assert any(f["severity"] == "pozor" and "neodpovídá" in f["message"] for f in rep["findings"])
    assert next(r for r in rep["záznamy"] if r["address"] == "192.168.1.1")["warning"] == "brána neodpovídá"
    raw["neighbors"].pop(0)
    rep = tool.build_report(raw, {})
    assert any("zatím v ARP tabulce není" in f["message"] for f in rep["findings"])
    assert rep["brány"][0]["state"] == "není v ARP tabulce"


def test_finding_no_gateway_and_static_and_many_problems():
    raw = raw_basic()
    raw["gateways"] = []
    raw["neighbors"] += [nb(f"192.168.1.{100 + i}", None, state=1) for i in range(10)]
    texts = [f["message"] for f in tool.build_report(raw, {})["findings"]]
    assert any("nemá nastavenou výchozí bránu" in t for t in texts)
    assert any("Statické ARP záznamy (1): 192.168.1.50" in t for t in texts)
    assert any(t.startswith("11 záznamů bez odpovědi") for t in texts)


# --------------------------------------------------------------------------- execute


def _patch_execute(monkeypatch, raw, names=None):
    names = names or {}

    def fake_lookup(ip):
        if ip in names:
            return names[ip], [], [ip]
        raise OSError("nenalezeno")

    monkeypatch.setattr(tool, "require_windows", lambda ctx, name: None)
    monkeypatch.setattr(tool, "_read_raw", lambda ctx: raw)
    monkeypatch.setattr(tool.socket, "gethostbyaddr", fake_lookup)


def test_execute_with_dns_and_summary(monkeypatch):
    _patch_execute(monkeypatch, raw_basic(), {"192.168.1.1": "fw.firma.local", "192.168.1.20": "srv1.firma.local"})
    res = tool.execute(FakeCtx(), {})
    by = {r["address"]: r for r in res["záznamy"]}
    assert by["192.168.1.1"]["name"] == "fw.firma.local"
    assert by["192.168.1.30"]["name"] is None
    assert res["note"] is None
    assert res["summary"].startswith("ARP tabulka: záznamů 6 (dynamické 5, statické 1, bez odpovědi 1)")
    assert "brána 192.168.1.1 – dosažitelný, Fortinet" in res["summary"]
    assert "Pozor" not in res["summary"]


def test_execute_summary_mentions_warning(monkeypatch):
    raw = raw_basic()
    raw["neighbors"].append(nb("192.168.1.66", GW_MAC))
    _patch_execute(monkeypatch, raw)
    res = tool.execute(FakeCtx(), {"resolve_names": False})
    assert "Pozor: Stejnou MAC 90-6C-AC-11-22-33" in res["summary"]


def test_execute_without_dns(monkeypatch):
    _patch_execute(monkeypatch, raw_basic())
    monkeypatch.setattr(tool, "resolve_names", lambda *a: pytest.fail("DNS se nemá volat"))
    res = tool.execute(FakeCtx(), {"resolve_names": False})
    assert all(r["name"] is None for r in res["záznamy"])


def test_execute_dns_timeout_reported(monkeypatch):
    _patch_execute(monkeypatch, raw_basic())
    monkeypatch.setattr(tool, "resolve_names", lambda ips, s: ({}, False))
    res = tool.execute(FakeCtx(), {})
    assert res["note"]


def test_execute_without_deadline(monkeypatch):
    # ToolContext.time_left() vrací None, když jádro nezadá časový limit
    _patch_execute(monkeypatch, raw_basic())
    seen = {}
    monkeypatch.setattr(tool, "resolve_names", lambda ips, s: (seen.setdefault("s", s), ({}, True))[1])
    tool.execute(FakeCtx(left=None), {})
    assert seen["s"] == tool.DNS_MAX_SECONDS


def test_execute_invalid_input_before_windows(monkeypatch):
    monkeypatch.setattr(tool, "require_windows", lambda ctx, name: None)
    monkeypatch.setattr(tool, "_read_raw", lambda ctx: pytest.fail("Windows se nemá číst"))
    with pytest.raises(ToolError) as e:
        tool.execute(FakeCtx(), {"ip": "nesmysl"})
    assert e.value.code == "invalid_input"


def test_resolve_names_respects_deadline(monkeypatch):
    import time as _t
    monkeypatch.setattr(tool.socket, "gethostbyaddr", lambda ip: (_t.sleep(5), ("x", [], [ip]))[1])
    start = _t.monotonic()
    names, done = tool.resolve_names(["10.0.0.1", "10.0.0.2"], 0.3)
    assert not done and _t.monotonic() - start < 2


def test_output_size_within_limit():
    import json
    raw = raw_basic()
    raw["neighbors"] = [nb(f"10.{i // 250}.{i % 250}.1", f"00-50-56-00-{i // 256:02X}-{i % 256:02X}",
                           iface="Ethernet1") for i in range(600)]
    rep = tool.build_report(raw, {"limit": 500})
    assert len(json.dumps(rep, ensure_ascii=False).encode("utf-8")) < 200 * 1024
