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
    "E81CBA": "Fortinet",
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


def build_report(raw: dict, inp: dict, names: dict | None = None) -> dict:
    """Ze surových dat sestaví výsledek (bez DNS – ten doplní ``execute``)."""
    interfaces = raw.get("interfaces") or {}
    gateways = raw.get("gateways") or []
    gw_ips = {g["ip"] for g in gateways}

    ip_net = ip_filter_network(inp["ip"]) if inp.get("ip") else None
    mac_hex = mac_filter_hex(inp["mac"]) if inp.get("mac") else None
    iface = (inp.get("interface") or "").strip().lower()
    state_filter = inp.get("state", "all")
    include_mc = bool(inp.get("include_multicast", False))
    limit = int(inp.get("limit", 200))

    entries = []
    hidden_mc = 0
    for n in raw.get("neighbors") or []:
        mac = n.get("mac") or b""
        code, text, kind = STATES.get(n["state"], ("unknown", f"neznámý ({n['state']})", "dynamický"))
        nets = interfaces.get(n["interface"], [])
        multicast = is_multicast(n["ip"], mac) or _is_subnet_broadcast(n["ip"], nets)
        entries.append({
            "ip": n["ip"], "mac": format_mac(mac), "vendor": vendor(mac) if not multicast else None,
            "name": None, "type": kind, "state": text, "state_code": code,
            "interface": n["interface"], "if_index": n["if_index"],
            "is_gateway": n["ip"] in gw_ips, "is_router": bool(n.get("is_router")),
            "multicast": multicast, "_mac": mac,
        })

    unicast = [e for e in entries if not e["multicast"]]
    findings = _findings(unicast, gateways, raw.get("gateway_error"))

    selected = []
    for e in entries:
        if e["multicast"] and not include_mc:
            hidden_mc += 1
            continue
        if ip_net and ipaddress.IPv4Address(e["ip"]) not in ip_net:
            continue
        if mac_hex and (not e["mac"] or mac_hex not in e["_mac"].hex().upper()):
            continue
        if iface and iface not in e["interface"].lower() and iface != str(e["if_index"]):
            continue
        if state_filter == "dynamic" and e["type"] != "dynamický":
            continue
        if state_filter == "static" and e["type"] != "statický":
            continue
        if state_filter == "problem" and e["state_code"] not in PROBLEM_STATES:
            continue
        selected.append(e)

    selected.sort(key=lambda e: (e["interface"].lower(), _ip_key(e["ip"])))
    matched = len(selected)
    shown = selected[:limit]
    for e in shown:
        if names:
            e["name"] = names.get(e["ip"])
    rows = [{k: v for k, v in e.items() if not k.startswith("_") and k != "state_code"} for e in shown]

    gw_out = []
    by_ip = {e["ip"]: e for e in unicast}
    for g in sorted(gateways, key=lambda g: g.get("metric", 0)):
        e = by_ip.get(g["ip"])
        gw_out.append({"ip": g["ip"], "interface": g["interface"], "mac": e["mac"] if e else None,
                       "vendor": e["vendor"] if e else None,
                       "state": e["state"] if e else "není v ARP tabulce"})

    counts = {
        "total": len(unicast),
        "dynamic": sum(1 for e in unicast if e["type"] == "dynamický"),
        "static": sum(1 for e in unicast if e["type"] == "statický"),
        "problem": sum(1 for e in unicast if e["state_code"] in PROBLEM_STATES),
        "multicast_hidden": hidden_mc,
        "matched": matched,
        "shown": len(rows),
    }
    filtered = bool(ip_net or mac_hex or iface or state_filter != "all")
    return {"entries": rows, "gateways": gw_out, "findings": findings, "counts": counts,
            "truncated": matched > len(rows), "filtered": filtered}


def _findings(unicast: list, gateways: list, gw_error: str | None) -> list:
    out = []
    gw_ips = {g["ip"] for g in gateways}

    # Jedna MAC u více IP adres
    by_mac: dict = {}
    for e in unicast:
        if e["mac"] and e["state_code"] not in PROBLEM_STATES:
            by_mac.setdefault(e["mac"], []).append(e)
    for mac, group in sorted(by_mac.items()):
        if len(group) < 2:
            continue
        ips = sorted((e["ip"] for e in group), key=_ip_key)
        gw_in = [ip for ip in ips if ip in gw_ips]
        who = f" ({group[0]['vendor']})" if group[0]["vendor"] else ""
        if gw_in:
            out.append({"level": "varování", "text":
                        f"Stejnou MAC {mac}{who} jako výchozí brána {', '.join(gw_in)} má i: "
                        f"{', '.join(ip for ip in ips if ip not in gw_in)}. Může jít o proxy ARP nebo další "
                        f"adresy samotné brány (např. VIP na firewallu), ale také o ARP spoofing – útočník se "
                        f"vydává za bránu. Pokud to nečekáte, ověřte MAC brány přímo na bráně a najděte port "
                        f"na přepínači, kde se tato MAC učí."})
        else:
            out.append({"level": "informace", "text":
                        f"MAC {mac}{who} má více IP adres: {', '.join(ips)}. Obvykle jde o jedno zařízení "
                        f"s více adresami nebo proxy ARP; pokud to nečekáte, prověřte konflikt adres."})

    # Výchozí brána
    if gw_error:
        out.append({"level": "informace", "text": f"Výchozí bránu se nepodařilo zjistit: {gw_error}"})
    elif not gateways:
        out.append({"level": "informace", "text": "Server nemá nastavenou výchozí bránu IPv4."})
    by_ip = {e["ip"]: e for e in unicast}
    for g in gateways:
        e = by_ip.get(g["ip"])
        if e is None:
            out.append({"level": "informace", "text":
                        f"Výchozí brána {g['ip']} ({g['interface']}) zatím v ARP tabulce není – server s ní "
                        f"nedávno nekomunikoval. Ověřte síťovou dostupnost, např. nástrojem pro test sítě."})
        elif e["state_code"] in PROBLEM_STATES:
            out.append({"level": "varování", "text":
                        f"Výchozí brána {g['ip']} ({g['interface']}) neodpovídá na ARP ({e['state']}). "
                        f"Server se pravděpodobně nedostane mimo svou podsíť – zkontrolujte bránu, kabel, "
                        f"VLAN a nastavení adresy brány."})
        elif e["type"] == "statický":
            out.append({"level": "informace", "text":
                        f"Výchozí brána {g['ip']} má statický ARP záznam ({e['mac']}). Je to běžná ochrana "
                        f"proti ARP spoofingu, ale při výměně brány je nutné záznam změnit."})

    # Statické záznamy (mimo bránu)
    static = [e["ip"] for e in unicast if e["type"] == "statický" and e["ip"] not in gw_ips]
    if static:
        shown = ", ".join(sorted(static, key=_ip_key)[:10]) + (" …" if len(static) > 10 else "")
        out.append({"level": "informace", "text":
                    f"Statické ARP záznamy ({len(static)}): {shown}. Byly nastaveny ručně (arp -s / netsh); "
                    f"ověřte, že jsou záměrné a stále platné."})

    # Mnoho neúplných záznamů
    problems = [e for e in unicast if e["state_code"] in PROBLEM_STATES and e["ip"] not in gw_ips]
    if len(problems) >= MANY_PROBLEMS:
        out.append({"level": "varování", "text":
                    f"{len(problems)} záznamů bez odpovědi (neúplné / nedosažitelné). Server se pokouší "
                    f"kontaktovat adresy, které v síti neodpovídají – vypnutá zařízení, chybná konfigurace "
                    f"(např. špatná maska), výpadek části sítě, nebo skenování sítě z tohoto serveru."})
    return out


def _summary(rep: dict, inp: dict) -> str:
    c = rep["counts"]
    parts = [f"ARP tabulka: záznamů {c['total']} (dynamické {c['dynamic']}, statické {c['static']}, "
             f"bez odpovědi {c['problem']})"]
    if rep["filtered"]:
        parts.append(f"filtru odpovídá {c['matched']}")
    if rep["truncated"]:
        parts.append(f"zobrazeno {c['shown']}")
    gws = rep["gateways"]
    if gws:
        g = gws[0]
        who = f", {g['vendor']}" if g.get("vendor") else ""
        parts.append(f"brána {g['ip']} – {g['state']}{who}")
    text = "; ".join(parts) + "."
    warn = sum(1 for f in rep["findings"] if f["level"] == "varování")
    if warn:
        text += f" Varování: {warn}."
    return text


def execute(ctx: ToolContext, inp: dict) -> dict:
    require_windows(ctx, TOOL_NAME)
    # Vstup ověřit dřív, než se sáhne na Windows API.
    if inp.get("ip"):
        ip_filter_network(inp["ip"])
    if inp.get("mac"):
        mac_filter_hex(inp["mac"])

    ctx.log.info("Čtu ARP tabulku")
    raw = _read_raw(ctx)
    rep = build_report(raw, inp)

    dns_note = None
    if inp.get("resolve_names", True) and rep["entries"]:
        ips = [e["ip"] for e in rep["entries"] if not e["multicast"] and e["mac"]]
        try:
            left = float(ctx.time_left()) - 5.0
        except Exception:  # noqa: BLE001
            left = DNS_MAX_SECONDS
        names, done = resolve_names(ips, min(DNS_MAX_SECONDS, left))
        for e in rep["entries"]:
            e["name"] = names.get(e["ip"])
        if not done:
            dns_note = "Reverzní DNS nestihl odpovědět u všech adres; chybějící názvy nejsou chyba záznamu."
    rep["dns_note"] = dns_note
    rep["summary"] = _summary(rep, inp)
    ctx.log.info("ARP: %s záznamů, zobrazeno %s", rep["counts"]["total"], rep["counts"]["shown"])
    return rep
