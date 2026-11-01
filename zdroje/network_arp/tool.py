"""ARP tabulka serveru (sousedé IPv4) – obdoba ``arp -a`` bez práv správce.

Čtení:
* záznamy ARP přes ``GetIpNetTable2`` z ``iphlpapi`` (ctypes) – nezávisí na jazyku Windows,
* výchozí brány přes ``GetIpForwardTable2`` (cesty 0.0.0.0/0),
* názvy rozhraní přes ``ConvertInterfaceLuidToAlias``, adresy rozhraní přes psutil.

Obě funkce API čte i běžný uživatel, účet služby tedy žádné další právo nepotřebuje.
Windows část se testuje přes podvržené ``iphlpapi`` (viz ``tests``), logika nad daty přes
podvržené ``_read_raw``.
"""

import ctypes
import ipaddress
import queue
import socket
import threading
import time

from pycontrol.tools.sdk import ToolContext, ToolError, require_windows

TOOL_NAME = "ARP tabulka"
AF_INET = 2

NO_ERROR = 0
ERROR_ACCESS_DENIED = 5
ERROR_NOT_SUPPORTED = 50
ERROR_INVALID_PARAMETER = 87
ERROR_NOT_ENOUGH_MEMORY = 8
ERROR_NOT_FOUND = 1168

# ---------------------------------------------------------------------------
# Struktury Windows API (pevné šířky typů, aby šly ověřit i mimo Windows)
# ---------------------------------------------------------------------------


class SOCKADDR_IN(ctypes.Structure):
    _fields_ = [("sin_family", ctypes.c_uint16), ("sin_port", ctypes.c_uint16),
                ("sin_addr", ctypes.c_uint8 * 4), ("sin_zero", ctypes.c_uint8 * 8)]


class SOCKADDR_IN6(ctypes.Structure):
    _fields_ = [("sin6_family", ctypes.c_uint16), ("sin6_port", ctypes.c_uint16),
                ("sin6_flowinfo", ctypes.c_uint32), ("sin6_addr", ctypes.c_uint8 * 16),
                ("sin6_scope_id", ctypes.c_uint32)]


class SOCKADDR_INET(ctypes.Union):
    _fields_ = [("Ipv4", SOCKADDR_IN), ("Ipv6", SOCKADDR_IN6), ("si_family", ctypes.c_uint16)]


class MIB_IPNET_ROW2(ctypes.Structure):
    _fields_ = [("Address", SOCKADDR_INET),
                ("InterfaceIndex", ctypes.c_uint32),
                ("InterfaceLuid", ctypes.c_uint64),
                ("PhysicalAddress", ctypes.c_uint8 * 32),
                ("PhysicalAddressLength", ctypes.c_uint32),
                ("State", ctypes.c_int32),
                ("Flags", ctypes.c_uint8),          # bit 0 IsRouter, bit 1 IsUnreachable
                ("ReachabilityTime", ctypes.c_uint32)]


class MIB_IPNET_TABLE2(ctypes.Structure):
    _fields_ = [("NumEntries", ctypes.c_uint32), ("Table", MIB_IPNET_ROW2 * 1)]


class IP_ADDRESS_PREFIX(ctypes.Structure):
    _fields_ = [("Prefix", SOCKADDR_INET), ("PrefixLength", ctypes.c_uint8)]


class MIB_IPFORWARD_ROW2(ctypes.Structure):
    _fields_ = [("InterfaceLuid", ctypes.c_uint64),
                ("InterfaceIndex", ctypes.c_uint32),
                ("DestinationPrefix", IP_ADDRESS_PREFIX),
                ("NextHop", SOCKADDR_INET),
                ("SitePrefixLength", ctypes.c_uint8),
                ("ValidLifetime", ctypes.c_uint32),
                ("PreferredLifetime", ctypes.c_uint32),
                ("Metric", ctypes.c_uint32),
                ("Protocol", ctypes.c_int32),
                ("Loopback", ctypes.c_uint8),
                ("AutoconfigureAddress", ctypes.c_uint8),
                ("Publish", ctypes.c_uint8),
                ("Immortal", ctypes.c_uint8),
                ("Age", ctypes.c_uint32),
                ("Origin", ctypes.c_int32)]


class MIB_IPFORWARD_TABLE2(ctypes.Structure):
    _fields_ = [("NumEntries", ctypes.c_uint32), ("Table", MIB_IPFORWARD_ROW2 * 1)]


# NL_NEIGHBOR_STATE → (kód, český popis, typ záznamu)
STATES = {
    0: ("unreachable", "nedosažitelný", "dynamický"),
    1: ("incomplete", "neúplný (bez odpovědi)", "dynamický"),
    2: ("probe", "ověřuje se", "dynamický"),
    3: ("delay", "čeká na ověření", "dynamický"),
    4: ("stale", "platný, dlouho neověřený", "dynamický"),
    5: ("reachable", "dosažitelný", "dynamický"),
    6: ("permanent", "statický", "statický"),
}
PROBLEM_STATES = {"unreachable", "incomplete"}

# Orientační seznam výrobců podle prvních tří bajtů MAC (OUI). Úplná databáze IEEE se nebalí.
VENDORS = {
    "005056": "VMware", "000C29": "VMware", "000569": "VMware", "001C14": "VMware",
    "00155D": "Microsoft Hyper-V",
    "BC2411": "Proxmox", "525400": "QEMU/KVM",
    "080027": "VirtualBox", "0A0027": "VirtualBox (host-only)",
    "00163E": "Xen", "001C42": "Parallels",
    "00090F": "Fortinet", "906CAC": "Fortinet", "704CA5": "Fortinet", "085B0E": "Fortinet",
    "E81CBA": "Fortinet", "AC712E": "Fortinet",
    "00000C": "Cisco",
    "001132": "Synology",
    "245EBE": "QNAP", "00089B": "QNAP",
    "B827EB": "Raspberry Pi", "DCA632": "Raspberry Pi", "E45F01": "Raspberry Pi",
    "28CDC1": "Raspberry Pi", "D83ADD": "Raspberry Pi", "2CCF67": "Raspberry Pi",
    "24A43C": "Ubiquiti", "788A20": "Ubiquiti", "FCECDA": "Ubiquiti", "802AA8": "Ubiquiti",
    "F09FC2": "Ubiquiti", "7483C2": "Ubiquiti", "B4FBE4": "Ubiquiti", "E063DA": "Ubiquiti",
    "4C5E0C": "MikroTik", "6C3B6B": "MikroTik", "D4CA6D": "MikroTik", "E48D8C": "MikroTik",
    "488F5A": "MikroTik", "B869F4": "MikroTik", "CC2DE0": "MikroTik", "2CC81B": "MikroTik",
    "64D154": "MikroTik", "744D28": "MikroTik", "DC2C6E": "MikroTik", "18FD74": "MikroTik",
    "00C0B7": "APC (Schneider Electric)",
    "00E04C": "Realtek",
}

DNS_MAX_SECONDS = 8.0
DNS_WORKERS = 16
MANY_PROBLEMS = 10

# ---------------------------------------------------------------------------
# Čtení z Windows
# ---------------------------------------------------------------------------


def _load_api():
    """Načte iphlpapi s typy argumentů. Jen na Windows."""
    api = ctypes.WinDLL("iphlpapi")
    api.GetIpNetTable2.argtypes = [ctypes.c_uint16, ctypes.POINTER(ctypes.c_void_p)]
    api.GetIpNetTable2.restype = ctypes.c_uint32
    api.GetIpForwardTable2.argtypes = [ctypes.c_uint16, ctypes.POINTER(ctypes.c_void_p)]
    api.GetIpForwardTable2.restype = ctypes.c_uint32
    api.FreeMibTable.argtypes = [ctypes.c_void_p]
    api.FreeMibTable.restype = None
    api.ConvertInterfaceLuidToAlias.argtypes = [ctypes.POINTER(ctypes.c_uint64), ctypes.c_wchar_p, ctypes.c_size_t]
    api.ConvertInterfaceLuidToAlias.restype = ctypes.c_uint32
    return api


def _win_text(code: int) -> str:
    try:
        return ctypes.FormatError(code).strip()  # jen na Windows
    except Exception:  # noqa: BLE001
        return ""


def _api_error(what: str, code: int) -> ToolError:
    if code == ERROR_ACCESS_DENIED:
        return ToolError(f"{what}: přístup odepřen (kód 5, 0x00000005).", code="access_denied",
                         hint="Čtení ARP tabulky běžně nevyžaduje správce. Zkontrolujte, zda účet služby "
                              "NT SERVICE\\PyControl nemá odebraná práva skupinovou politikou nebo zda čtení "
                              "neblokuje bezpečnostní software (např. ESET HIPS).")
    if code == ERROR_NOT_SUPPORTED:
        return ToolError(f"{what}: protokol IPv4 není na serveru dostupný (kód 50).", code="not_supported",
                         hint="Ověřte, že je na síťovém adaptéru zapnutý protokol IPv4.")
    text = _win_text(code)
    return ToolError(f"{what} selhalo s chybou Windows {code} (0x{code:08X})" + (f": {text}" if text else "."),
                     code="win_error", hint="Zkuste akci zopakovat; při opakování pošlete chybu správci PyControlu.")


def _read_mib_table(api, func, table_cls, row_cls, what):
    """Zavolá Get*Table2 a vrátí kopie řádků (paměť Windows hned uvolní)."""
    ptr = ctypes.c_void_p()
    rc = func(AF_INET, ctypes.pointer(ptr))
    if rc == ERROR_NOT_FOUND:
        return []
    if rc != NO_ERROR:
        raise _api_error(what, rc)
    if not ptr.value:
        return []
    try:
        count = ctypes.c_uint32.from_address(ptr.value).value
        rows = (row_cls * count).from_address(ptr.value + table_cls.Table.offset)
        return [row_cls.from_buffer_copy(r) for r in rows]
    finally:
        api.FreeMibTable(ptr)


def _alias(api, luid: int, index: int, cache: dict) -> str:
    if luid in cache:
        return cache[luid]
    name = f"rozhraní #{index}"
    try:
        buf = ctypes.create_unicode_buffer(257)
        if api.ConvertInterfaceLuidToAlias(ctypes.pointer(ctypes.c_uint64(luid)), buf, 257) == NO_ERROR and buf.value:
            name = buf.value
    except Exception:  # noqa: BLE001 – název rozhraní je jen doplněk
        pass
    cache[luid] = name
    return name


def _ipv4(sa: SOCKADDR_INET) -> str:
    return str(ipaddress.IPv4Address(bytes(sa.Ipv4.sin_addr)))


def _win_read_neighbors(api, aliases: dict) -> list:
    out = []
    for r in _read_mib_table(api, api.GetIpNetTable2, MIB_IPNET_TABLE2, MIB_IPNET_ROW2, "Čtení ARP tabulky"):
        if r.Address.si_family != AF_INET:
            continue
        length = min(int(r.PhysicalAddressLength), 32)
        out.append({
            "ip": _ipv4(r.Address),
            "mac": bytes(r.PhysicalAddress[:length]),
            "state": int(r.State),
            "if_index": int(r.InterfaceIndex),
            "interface": _alias(api, int(r.InterfaceLuid), int(r.InterfaceIndex), aliases),
            "is_router": bool(r.Flags & 1),
        })
    return out


def _win_read_gateways(api, aliases: dict) -> list:
    out = []
    rows = _read_mib_table(api, api.GetIpForwardTable2, MIB_IPFORWARD_TABLE2, MIB_IPFORWARD_ROW2,
                           "Čtení směrovací tabulky")
    for r in rows:
        if r.DestinationPrefix.PrefixLength != 0 or r.NextHop.si_family != AF_INET:
            continue
        hop = _ipv4(r.NextHop)
        if hop == "0.0.0.0":
            continue
        out.append({"ip": hop, "if_index": int(r.InterfaceIndex), "metric": int(r.Metric),
                    "interface": _alias(api, int(r.InterfaceLuid), int(r.InterfaceIndex), aliases)})
    return out


def _interface_addresses() -> dict:
    """Název rozhraní → seznam IPv4 sítí serveru (psutil používá stejné názvy jako Windows)."""
    try:
        import psutil
        res = {}
        for name, addrs in psutil.net_if_addrs().items():
            nets = []
            for a in addrs:
                if a.family == socket.AF_INET and a.address:
                    try:
                        nets.append(ipaddress.IPv4Interface(f"{a.address}/{a.netmask or '255.255.255.255'}"))
                    except ValueError:
                        continue
            res[name] = nets
        return res
    except Exception:  # noqa: BLE001 – adresy rozhraní jsou jen doplněk
        return {}


def _read_raw(ctx) -> dict:
    """Vše, co nástroj potřebuje z Windows. Testy tuto funkci podvrhují."""
    api = _load_api()
    aliases: dict = {}
    neighbors = _win_read_neighbors(api, aliases)
    try:
        gateways = _win_read_gateways(api, aliases)
        gw_error = None
    except ToolError as e:  # brána je doplněk – výpis ARP nesmí kvůli ní selhat
        ctx.log.warning("Výchozí bránu se nepodařilo zjistit: %s", e)
        gateways, gw_error = [], str(e)
    return {"neighbors": neighbors, "gateways": gateways, "gateway_error": gw_error,
            "interfaces": _interface_addresses()}


# ---------------------------------------------------------------------------
# Pomocné funkce (bez Windows)
# ---------------------------------------------------------------------------


def format_mac(mac: bytes) -> str | None:
    if not mac or not any(mac):
        return None
    return "-".join(f"{b:02X}" for b in mac)


def mac_filter_hex(text: str) -> str:
    raw = "".join(ch for ch in text if ch not in "-:. ").upper()
    if not raw or any(ch not in "0123456789ABCDEF" for ch in raw):
        raise ToolError(f"„{text}“ není MAC adresa ani její část.", code="invalid_input",
                        hint="Zadejte šestnáctkové číslice, např. 00-50-56 nebo 00:50:56:ab:12:34.")
    return raw


def ip_filter_network(text: str) -> ipaddress.IPv4Network:
    try:
        net = ipaddress.ip_network(text.strip(), strict=False)
    except ValueError:
        raise ToolError(f"„{text}“ není platná IP adresa ani podsíť.", code="invalid_input",
                        hint="Příklad: 192.168.1.10 nebo 192.168.1.0/24.") from None
    if net.version != 4:
        raise ToolError("ARP tabulka obsahuje jen adresy IPv4.", code="invalid_input",
                        hint="Zadejte adresu IPv4, např. 192.168.1.10.")
    return net


def vendor(mac: bytes) -> str | None:
    if not mac or len(mac) < 3:
        return None
    name = VENDORS.get(mac[:3].hex().upper())
    if name:
        return name
    if mac[0] & 0x02:
        return "lokálně spravovaná MAC (náhodná nebo virtuální)"
    return None


def is_multicast(ip: str, mac: bytes) -> bool:
    addr = ipaddress.IPv4Address(ip)
    if addr.is_multicast or ip == "255.255.255.255":
        return True
    return bool(mac) and (mac == b"\xff" * len(mac) or bool(mac[0] & 0x01))


def _is_subnet_broadcast(ip: str, nets: list) -> bool:
    addr = ipaddress.IPv4Address(ip)
    return any(n.network.prefixlen < 31 and addr == n.network.broadcast_address for n in nets)


def resolve_names(ips: list, seconds: float) -> tuple[dict, bool]:
    """Reverzní DNS v daemon vláknech s celkovým časovým limitem. Vrací (výsledky, vše_dokončeno)."""
    results: dict = {}
    if not ips or seconds <= 0:
        return results, not ips
    jobs: queue.Queue = queue.Queue()
    for ip in ips:
        jobs.put(ip)
    lock = threading.Lock()

    def worker():
        while True:
            try:
                ip = jobs.get_nowait()
            except queue.Empty:
                return
            try:
                name = socket.gethostbyaddr(ip)[0]
            except (OSError, UnicodeError):
                name = None
            with lock:
                results[ip] = name

    threads = [threading.Thread(target=worker, daemon=True) for _ in range(min(DNS_WORKERS, len(ips)))]
    for t in threads:
        t.start()
    deadline = time.monotonic() + seconds
    for t in threads:
        t.join(max(0.0, deadline - time.monotonic()))
    with lock:
        done = len(results) == len(ips)
        return dict(results), done


def _ip_key(ip: str) -> int:
    return int(ipaddress.IPv4Address(ip))


# ---------------------------------------------------------------------------
# Hlavní logika
# ---------------------------------------------------------------------------


def build_report(raw: dict, inp: dict) -> dict:
    """Ze surových dat sestaví výsledek (bez DNS – ten doplní ``execute``).

    Klíče výstupu: kde konzole zná český popisek (``KEY_LABELS`` v jádře), použije se jeho klíč
    (summary, findings, address, name, state, totals, matched, truncated, filters, note); ostatní
    klíče jsou česky. Tabulka v konzoli ukáže nejvýš 8 sloupců – řádek záznamu má proto přesně 8 polí,
    případné ``warning`` je deváté (konzole podle něj řádek zvýrazní, ale sloupec nepřidá).
    """
    interfaces = raw.get("interfaces") or {}
    gateways = raw.get("gateways") or []
    gw_ips = {g["ip"] for g in gateways}

    ip_net = ip_filter_network(inp["ip"]) if inp.get("ip") else None
    mac_hex = mac_filter_hex(inp["mac"]) if inp.get("mac") else None
    iface = (inp.get("interface") or "").strip()
    state_filter = inp.get("state", "all")
    include_mc = bool(inp.get("include_multicast", False))
    limit = int(inp.get("limit", 200))

    entries = []
    for n in raw.get("neighbors") or []:
        mac = n.get("mac") or b""
        code, text, kind = STATES.get(n["state"], ("unknown", f"neznámý ({n['state']})", "dynamický"))
        nets = interfaces.get(n["interface"], [])
        multicast = is_multicast(n["ip"], mac) or _is_subnet_broadcast(n["ip"], nets)
        entries.append({"ip": n["ip"], "mac": format_mac(mac), "raw_mac": mac,
                        "vendor": None if multicast else vendor(mac), "kind": kind, "state": text,
                        "code": code, "interface": n["interface"], "if_index": n["if_index"],
                        "gateway": n["ip"] in gw_ips, "multicast": multicast})

    unicast = [e for e in entries if not e["multicast"]]
    findings, warn_ips = _findings(unicast, gateways, raw.get("gateway_error"))

    hidden_mc = 0
    selected = []
    for e in entries:
        if e["multicast"] and not include_mc:
            hidden_mc += 1
            continue
        if ip_net and ipaddress.IPv4Address(e["ip"]) not in ip_net:
            continue
        if mac_hex and (not e["mac"] or mac_hex not in e["raw_mac"].hex().upper()):
            continue
        if iface and iface.lower() not in e["interface"].lower() and iface != str(e["if_index"]):
            continue
        if state_filter == "dynamic" and (e["kind"] != "dynamický" or e["multicast"]):
            continue
        if state_filter == "static" and (e["kind"] != "statický" or e["multicast"]):
            continue
        if state_filter == "problem" and e["code"] not in PROBLEM_STATES:
            continue
        selected.append(e)
    selected.sort(key=lambda e: (e["interface"].lower(), _ip_key(e["ip"])))

    rows = []
    for e in selected[:limit]:
        row = {"address": e["ip"], "mac": e["mac"], "výrobce": e["vendor"], "name": None,
               "typ": "vícesměrový" if e["multicast"] else e["kind"], "state": e["state"],
               "rozhraní": e["interface"], "brána": e["gateway"]}
        if e["ip"] in warn_ips:
            row["warning"] = warn_ips[e["ip"]]
        rows.append(row)

    by_ip = {e["ip"]: e for e in unicast}
    gw_out = []
    for g in sorted(gateways, key=lambda g: g.get("metric", 0)):
        e = by_ip.get(g["ip"])
        gw_out.append({"address": g["ip"], "mac": e["mac"] if e else None, "výrobce": e["vendor"] if e else None,
                       "state": e["state"] if e else "není v ARP tabulce", "rozhraní": g["interface"]})

    filters = []
    if ip_net:
        filters.append(f"adresa {ip_net}")
    if mac_hex:
        filters.append(f"MAC {inp['mac'].strip()}")
    if iface:
        filters.append(f"rozhraní {iface}")
    if state_filter != "all":
        filters.append({"dynamic": "dynamické", "static": "statické", "problem": "bez odpovědi"}[state_filter])

    rep = {"summary": "", "filters": ", ".join(filters) or None, "truncated": len(selected) > len(rows),
           "note": None, "findings": findings, "brány": gw_out, "záznamy": rows}
    rep["totals"] = {
        "total": len(unicast),
        "dynamické": sum(1 for e in unicast if e["kind"] == "dynamický"),
        "statické": sum(1 for e in unicast if e["kind"] == "statický"),
        "bez_odpovědi": sum(1 for e in unicast if e["code"] in PROBLEM_STATES),
        "vícesměrové_skryté": hidden_mc,
        "matched": len(selected),
        "zobrazeno": len(rows),
    }
    return rep


def _findings(unicast: list, gateways: list, gw_error: str | None) -> tuple[list, dict]:
    """Vrací (zjištění, {ip: krátké varování pro zvýraznění řádku})."""
    out: list = []
    marks: dict = {}
    gw_ips = {g["ip"] for g in gateways}

    def add(severity, message):
        out.append({"severity": severity, "message": message})

    # Jedna MAC u více IP adres
    by_mac: dict = {}
    for e in unicast:
        if e["mac"] and e["code"] not in PROBLEM_STATES:
            by_mac.setdefault(e["mac"], []).append(e)
    for mac, group in sorted(by_mac.items()):
        if len(group) < 2:
            continue
        ips = sorted((e["ip"] for e in group), key=_ip_key)
        gw_in = [ip for ip in ips if ip in gw_ips]
        who = f" ({group[0]['vendor']})" if group[0]["vendor"] else ""
        if gw_in:
            others = [ip for ip in ips if ip not in gw_in]
            add("pozor", f"Stejnou MAC {mac}{who} jako výchozí brána {', '.join(gw_in)} má i: {', '.join(others)}. "
                         f"Může jít o proxy ARP nebo další adresy samotné brány (např. VIP na firewallu), ale také "
                         f"o ARP spoofing – útočník se vydává za bránu. Pokud to nečekáte, ověřte MAC brány přímo na "
                         f"bráně a najděte port na přepínači, kde se tato MAC učí.")
            for ip in ips:
                marks[ip] = "MAC brány u více IP"
        else:
            add("info", f"MAC {mac}{who} má více IP adres: {', '.join(ips)}. Obvykle jde o jedno zařízení "
                        f"s více adresami nebo proxy ARP; pokud to nečekáte, prověřte konflikt adres.")

    # Výchozí brána
    if gw_error:
        add("info", f"Výchozí bránu se nepodařilo zjistit: {gw_error}")
    elif not gateways:
        add("info", "Server nemá nastavenou výchozí bránu IPv4.")
    by_ip = {e["ip"]: e for e in unicast}
    for g in gateways:
        e = by_ip.get(g["ip"])
        if e is None:
            add("info", f"Výchozí brána {g['ip']} ({g['interface']}) zatím v ARP tabulce není – server s ní "
                        f"nedávno nekomunikoval. Ověřte síťovou dostupnost, např. nástrojem pro test sítě.")
        elif e["code"] in PROBLEM_STATES:
            add("pozor", f"Výchozí brána {g['ip']} ({g['interface']}) neodpovídá na ARP ({e['state']}). "
                         f"Server se pravděpodobně nedostane mimo svou podsíť – zkontrolujte bránu, kabel, "
                         f"VLAN a nastavení adresy brány.")
            marks[g["ip"]] = "brána neodpovídá"
        elif e["kind"] == "statický":
            add("info", f"Výchozí brána {g['ip']} má statický ARP záznam ({e['mac']}). Je to běžná ochrana "
                        f"proti ARP spoofingu, ale při výměně brány je nutné záznam změnit.")

    # Statické záznamy (mimo bránu)
    static = [e["ip"] for e in unicast if e["kind"] == "statický" and e["ip"] not in gw_ips]
    if static:
        shown = ", ".join(sorted(static, key=_ip_key)[:10]) + (" …" if len(static) > 10 else "")
        add("info", f"Statické ARP záznamy ({len(static)}): {shown}. Byly nastaveny ručně (arp -s / netsh); "
                    f"ověřte, že jsou záměrné a stále platné.")

    # Mnoho neúplných záznamů
    problems = [e for e in unicast if e["code"] in PROBLEM_STATES and e["ip"] not in gw_ips]
    if len(problems) >= MANY_PROBLEMS:
        add("pozor", f"{len(problems)} záznamů bez odpovědi (neúplné / nedosažitelné). Server se pokouší "
                     f"kontaktovat adresy, které v síti neodpovídají – vypnutá zařízení, chybná konfigurace "
                     f"(např. špatná maska), výpadek části sítě, nebo skenování sítě z tohoto serveru.")
    return out, marks


def _summary(rep: dict) -> str:
    t = rep["totals"]
    parts = [f"ARP tabulka: záznamů {t['total']} (dynamické {t['dynamické']}, statické {t['statické']}, "
             f"bez odpovědi {t['bez_odpovědi']})"]
    if rep["filters"]:
        parts.append(f"filtru odpovídá {t['matched']}")
    if rep["truncated"]:
        parts.append(f"zobrazeno {t['zobrazeno']}")
    if rep["brány"]:
        g = rep["brány"][0]
        who = f", {g['výrobce']}" if g.get("výrobce") else ""
        parts.append(f"brána {g['address']} – {g['state']}{who}")
    text = "; ".join(parts) + "."
    warn = [f["message"].split(". ")[0] for f in rep["findings"] if f["severity"] == "pozor"]
    if warn:
        text += " Pozor: " + "; ".join(warn[:2]) + "."
    return text


def execute(ctx: ToolContext, inp: dict) -> dict:
    require_windows(ctx, TOOL_NAME)
    # Vstup ověřit dřív, než se sáhne na Windows API.
    if inp.get("ip"):
        ip_filter_network(inp["ip"])
    if inp.get("mac"):
        mac_filter_hex(inp["mac"])

    ctx.log.info("Čtu ARP tabulku")
    rep = build_report(_read_raw(ctx), inp)

    rows = rep["záznamy"]
    if inp.get("resolve_names", True) and rows:
        ips = [r["address"] for r in rows if r["typ"] != "vícesměrový" and r["mac"]]
        left = ctx.time_left()
        seconds = DNS_MAX_SECONDS if left is None else min(DNS_MAX_SECONDS, left - 5.0)
        names, done = resolve_names(ips, seconds)
        for r in rows:
            r["name"] = names.get(r["address"])
        if not done:
            rep["note"] = "Reverzní DNS nestihl odpovědět u všech adres; chybějící názvy nejsou chyba záznamu."
    rep["summary"] = _summary(rep)
    ctx.log.info("ARP: %s záznamů, zobrazeno %s", rep["totals"]["total"], rep["totals"]["zobrazeno"])
    return rep
