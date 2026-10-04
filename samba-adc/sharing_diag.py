#!/usr/bin/python3
"""
File-sharing / network-discovery diagnostics for the Samba AD DC Cockpit module.

Reads one JSON request on stdin, writes one JSON response on stdout:
  {"cmd": "checks"}                                   -> list of check results
  {"cmd": "smb_test", "share": "x", "user": "u"}      -> sign-in test (password in the request's "pass" field)
Every check returns {id, status: ok|warn|fail|info, title, detail, fix?}.

The point of this tool: "the server shows up in Explorer but I can't open it" can
be caused by many different layers, so each is tested separately.
"""
import json
import os
import re
import shutil
import socket
import struct
import subprocess
import sys

TIMEOUT = 15


def sh(args, timeout=TIMEOUT, env=None, stdin=None):
    try:
        p = subprocess.run(args, capture_output=True, text=True, timeout=timeout,
                           env=dict(os.environ, **(env or {})), input=stdin)
        return p.returncode, (p.stdout or "") + (p.stderr or "")
    except FileNotFoundError:
        return 127, "%s: not found" % args[0]
    except subprocess.TimeoutExpired:
        return 124, "%s: timed out" % args[0]


def R(id_, status, title, detail="", fix=None):
    d = {"id": id_, "status": status, "title": title, "detail": detail}
    if fix:
        d["fix"] = fix
    return d


# ---------------------------------------------------------------- sockets
def _hex_addr(h, v6):
    a, p = h.split(":")
    port = int(p, 16)
    if v6:
        raw = bytes.fromhex(a)
        words = struct.unpack("<4I", raw)
        raw = b"".join(struct.pack(">I", w) for w in words)
        return socket.inet_ntop(socket.AF_INET6, raw), port
    return socket.inet_ntoa(struct.pack("<I", int(a, 16))), port


def listeners(proto, root="/proc/net"):
    """[(addr, port)] of listening TCP sockets / bound UDP sockets."""
    out = []
    for name, v6 in ((proto, False), (proto + "6", True)):
        try:
            with open("%s/%s" % (root, name)) as f:
                next(f)
                for line in f:
                    cols = line.split()
                    if proto == "tcp" and cols[3] != "0A":
                        continue
                    try:
                        out.append(_hex_addr(cols[1], v6))
                    except Exception:
                        pass
        except FileNotFoundError:
            pass
    return out


def listening_on(proto, port, **kw):
    return [a for a, p in listeners(proto, **kw) if p == port]


def is_wildcard(addrs):
    return any(a in ("0.0.0.0", "::") for a in addrs)


# ---------------------------------------------------------------- smb.conf
def testparm_dump():
    rc, out = sh(["testparm", "-s"])
    secs, cur = {}, None
    for line in out.splitlines():
        m = re.match(r"^\[(.+)\]\s*$", line)
        if m:
            cur = m.group(1)
            secs[cur] = {}
        elif cur and "=" in line:
            k, v = line.split("=", 1)
            secs[cur][k.strip().lower()] = v.strip()
    return secs


def host_ips():
    ips = []
    rc, out = sh(["hostname", "-I"])
    if rc == 0:
        ips = [i for i in out.split() if re.match(r"^\d+\.\d+\.\d+\.\d+$", i) and not i.startswith("127.")]
    return ips


# ---------------------------------------------------------------- DNS
def _read_name(data, p):
    labels, jumped, end = [], False, None
    while True:
        ln = data[p]
        if ln == 0:
            p += 1
            break
        if ln & 0xC0 == 0xC0:
            ptr = ((ln & 0x3F) << 8) | data[p + 1]
            if not jumped:
                end = p + 2
            jumped, p = True, ptr
            continue
        labels.append(data[p + 1:p + 1 + ln].decode("ascii", "replace"))
        p += 1 + ln
    return ".".join(labels), (end if jumped else p)


def dns_query(name, qtype, server="127.0.0.1", timeout=2.5):
    """Minimal DNS client. qtype 1=A, 33=SRV. Returns a list (A: ips, SRV: (prio, weight, port, target)) or None on error."""
    try:
        q = struct.pack(">HHHHHH", 0x5AD1, 0x0100, 1, 0, 0, 0)
        for lab in name.rstrip(".").split("."):
            q += bytes([len(lab)]) + lab.encode()
        q += b"\x00" + struct.pack(">HH", qtype, 1)
        s_ = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s_.settimeout(timeout)
        s_.sendto(q, (server, 53))
        data, _ = s_.recvfrom(4096)
        s_.close()
        _id, flags, qd, an, _ns, _ar = struct.unpack(">HHHHHH", data[:12])
        if flags & 0xF:
            return []
        pos = 12
        for _ in range(qd):
            _n, pos = _read_name(data, pos)
            pos += 4
        out = []
        for _ in range(an):
            _n, pos = _read_name(data, pos)
            typ, _cls, _ttl, rdlen = struct.unpack(">HHIH", data[pos:pos + 10])
            pos += 10
            if typ == 1 and qtype == 1 and rdlen == 4:
                out.append(socket.inet_ntoa(data[pos:pos + 4]))
            elif typ == 33 and qtype == 33:
                pr, wt, port = struct.unpack(">HHH", data[pos:pos + 6])
                tgt, _e = _read_name(data, pos + 6)
                out.append((pr, wt, port, tgt))
            pos += rdlen
        return out
    except Exception:
        return None


def dns_a(name, server="127.0.0.1", timeout=2.5):
    return dns_query(name, 1, server, timeout)


# ---------------------------------------------------------------- firewall parsing
def ports_in(text):
    return set(int(x) for x in re.findall(r"\b(\d{2,5})\b", text))


def port_ranges(text):
    """[(lo, hi)] for every 'a-b' / 'a:b' range in text."""
    return [(int(a), int(b)) for a, b in re.findall(r"\b(\d{2,5})\s*[-:]\s*(\d{2,5})\b", text)]


def parse_ufw(text):
    """-> (active, allowed). allowed holds (proto, port), ('range', proto, lo, hi) and application-profile names."""
    active = bool(re.search(r"^Status:\s*active", text, re.M | re.I))
    allowed = set()
    for line in text.splitlines():
        m = re.match(r"^(\S+?)(?:\s+\(v6\))?\s+ALLOW(?:\s+IN)?\s", line)
        if not m:
            continue
        spec = m.group(1)
        mm = re.match(r"^(\d+)(?::(\d+))?(?:/(tcp|udp))?$", spec)
        if mm:
            lo, hi, proto = int(mm.group(1)), int(mm.group(2) or mm.group(1)), mm.group(3) or "any"
            if hi == lo:
                allowed.add((proto, lo))
            else:
                allowed.add(("range", proto, lo, hi))
        else:
            allowed.add((spec.lower(), None))  # application profile, e.g. Samba
    return active, allowed


def ufw_allows(allowed, proto, port):
    if (proto, port) in allowed or ("any", port) in allowed:
        return True
    for e in allowed:
        if len(e) == 4 and e[0] == "range" and e[1] in (proto, "any") and e[2] <= port <= e[3]:
            return True
    if ("samba", None) in allowed and (proto, port) in (("tcp", 445), ("tcp", 139), ("udp", 137), ("udp", 138)):
        return True
    return False


def parse_nft(text):
    """-> (restrictive, ports). restrictive means some input hook has policy drop."""
    restrictive = False
    for m in re.finditer(r"chain\s+\S+\s*\{[^}]*?type\s+filter\s+hook\s+input[^;]*;\s*(?:priority[^;]*;)?\s*policy\s+(\w+)", text, re.S):
        if m.group(1) == "drop":
            restrictive = True
    return restrictive, ports_in(text)


def nft_allows(text, port):
    if port in ports_in(text):
        return True
    return any(lo <= port <= hi for lo, hi in port_ranges(text))


def parse_firewalld(zones_text, services_text, ports_text):
    svcs = set(services_text.split())
    ports = set()
    for tok in ports_text.split():
        m = re.match(r"^(\d+)(?:-(\d+))?/(tcp|udp)$", tok)
        if m:
            lo, hi = int(m.group(1)), int(m.group(2) or m.group(1))
            if hi - lo > 100:
                ports.add(("range", m.group(3), lo, hi))
            else:
                for p in range(lo, hi + 1):
                    ports.add((m.group(3), p))
    return svcs, ports


def firewalld_allows(svcs, ports, proto, port, kind):
    if (proto, port) in ports:
        return True
    if any(len(e) == 4 and e[1] == proto and e[2] <= port <= e[3] for e in ports):
        return True
    if "samba-dc" in svcs:  # firewalld's service that opens the whole AD DC port set
        return True
    names = {"smb": ("samba",), "dns": ("dns",), "kerberos": ("kerberos",), "ldap": ("ldap",), "ldaps": ("ldaps",),
             "rpc": ("samba",), "wsd": ("ws-discovery", "ws-discovery-tcp", "ws-discovery-udp"), "llmnr": ("llmnr",)}
    return any(n in svcs for n in names.get(kind, ()))


# ---------------------------------------------------------------- discovery implementation detection
WSD_UNITS = [("wsdd2.service", "wsdd2"), ("wsdd-server.service", "wsdd-server"), ("wsdd.service", "wsdd")]


def unit_info(unit):
    rc, out = sh(["systemctl", "show", "-p", "LoadState,ActiveState,UnitFileState,BindsTo,PartOf,After,MainPID", unit])
    if rc != 0:
        return None
    d = dict(l.split("=", 1) for l in out.splitlines() if "=" in l)
    return d


def check_discovery(service_unit, checks):
    found = []
    for unit, name in WSD_UNITS:
        info = unit_info(unit)
        if info and info.get("LoadState") not in (None, "not-found"):
            found.append((unit, name, info))
    have_systemd = shutil.which("systemctl") is not None
    if not have_systemd:
        checks.append(R("wsd_unit", "info", "Discovery daemon", "systemctl not available, so the discovery service state could not be inspected."))
        return None
    if not found:
        pkg = "wsdd2"
        checks.append(R("wsd_unit", "warn", "No WS-Discovery daemon installed",
                        "Windows 10/11 no longer use NetBIOS browsing, so without wsdd2 (or wsdd-server) this server will not appear under Network in File Explorer. It is still reachable by typing \\\\%s\\ in the address bar." % socket.gethostname(),
                        {"action": "install_discovery", "label": "Install and configure discovery"}))
        return None
    # prefer an active one
    found.sort(key=lambda f: f[2].get("ActiveState") != "active")
    unit, name, info = found[0]
    st = info.get("ActiveState")
    binds = info.get("BindsTo", "")
    problems = []
    if name == "wsdd2" and "smbd.service" in binds:
        rc, o = sh(["systemctl", "is-active", "smbd.service"])
        if o.strip() != "active":
            problems.append("wsdd2.service is bound to smbd.service (Debian's packaging for a plain file server), but this is an AD DC where smbd.service is disabled/masked and Samba runs as %s. systemd therefore refuses to keep wsdd2 running." % service_unit)
    if problems:
        checks.append(R("wsd_unit", "fail", "%s cannot run on an AD DC as packaged" % unit, " ".join(problems),
                        {"action": "fix_wsdd_binding", "label": "Bind %s to %s" % (unit, service_unit), "unit": unit}))
    elif st == "active":
        extra = "" if info.get("UnitFileState") == "enabled" else " (not enabled at boot)"
        checks.append(R("wsd_unit", "ok", "%s is running%s" % (unit, extra),
                        "Implementation: %s." % name, None if info.get("UnitFileState") == "enabled" else {"action": "enable_discovery", "label": "Enable at boot", "unit": unit}))
    else:
        checks.append(R("wsd_unit", "fail", "%s is installed but %s" % (unit, st),
                        "Windows will not see this server until it is started.", {"action": "enable_discovery", "label": "Start and enable", "unit": unit}))
    return name


# Ports a Windows client needs to reach a Samba AD DC (https://wiki.samba.org/index.php/Samba_AD_DC_Port_Usage)
AD_PORTS = [
    ("tcp", 53, "dns", "DNS"), ("udp", 53, "dns", "DNS"),
    ("tcp", 88, "kerberos", "Kerberos"), ("udp", 88, "kerberos", "Kerberos"),
    ("tcp", 135, "rpc", "RPC endpoint mapper"),
    ("udp", 137, "smb", "NetBIOS name service"), ("udp", 138, "smb", "NetBIOS datagram"), ("tcp", 139, "smb", "NetBIOS session"),
    ("tcp", 389, "ldap", "LDAP"), ("udp", 389, "ldap", "LDAP (CLDAP: the DC locator)"),
    ("tcp", 445, "smb", "SMB (SYSVOL, \\\\server, file shares)"),
    ("tcp", 464, "kerberos", "Kerberos password change"), ("udp", 464, "kerberos", "Kerberos password change"),
    ("tcp", 636, "ldaps", "LDAPS"), ("tcp", 3268, "ldap", "Global Catalog"), ("tcp", 3269, "ldaps", "Global Catalog (SSL)"),
    ("tcp", "49152-65535", "rpc", "dynamic RPC (Netlogon, SAMR, DRS ...)"),
]


def _need(impl):
    need = [(p, n, k, d) for p, n, k, d in AD_PORTS]
    if impl == "wsdd2":
        need += [("udp", 3702, "wsd", "WS-Discovery"), ("tcp", 3702, "wsd", "WS-Discovery metadata (wsdd2)"), ("udp", 5355, "llmnr", "LLMNR (wsdd2)")]
    elif impl in ("wsdd-server", "wsdd"):
        need += [("udp", 3702, "wsd", "WS-Discovery"), ("tcp", 5357, "wsd", "WS-Discovery metadata (wsdd)")]
    return need


def _probe(n):
    """a port number, or the first/middle of a range, for membership tests"""
    if isinstance(n, str):
        lo, hi = (int(x) for x in n.split("-"))
        return lo, hi
    return n, n


def check_firewall(impl, checks):
    need = _need(impl)
    engines = []
    if shutil.which("ufw"):
        rc, out = sh(["ufw", "status"])
        active, allowed = parse_ufw(out)
        if active:
            miss = [x for x in need if not all(ufw_allows(allowed, x[0], q) for q in set(_probe(x[1])))]
            engines.append(("ufw", miss))
    if shutil.which("firewall-cmd"):
        rc, out = sh(["firewall-cmd", "--state"])
        if rc == 0 and "running" in out:
            _, z = sh(["firewall-cmd", "--get-default-zone"])
            zone = z.strip().splitlines()[0] if z.strip() else "public"
            _, sv = sh(["firewall-cmd", "--zone=" + zone, "--list-services"])
            _, pt = sh(["firewall-cmd", "--zone=" + zone, "--list-ports"])
            svcs, ports = parse_firewalld("", sv, pt)
            miss = [x for x in need if not all(firewalld_allows(svcs, ports, x[0], q, x[2]) for q in set(_probe(x[1])))]
            engines.append(("firewalld", miss))
    if not engines and shutil.which("nft"):
        rc, out = sh(["nft", "list", "ruleset"])
        if rc == 0:
            restrictive, _ports = parse_nft(out)
            if restrictive:
                miss = [x for x in need if not all(nft_allows(out, q) for q in set(_probe(x[1])))]
                engines.append(("nftables", miss))
    if not engines:
        checks.append(R("firewall", "ok", "No restrictive host firewall detected",
                        "Checked ufw, firewalld and nftables. A firewall on your router or switches cannot be seen from here."))
        return
    for eng, miss in engines:
        if not miss:
            checks.append(R("firewall_" + eng, "ok", "%s allows the Active Directory, file-sharing and discovery ports" % eng))
            continue
        core = [x for x in miss if x[1] in (53, 88, 135, 389, 445, "49152-65535")]
        lst = ", ".join("%s/%s (%s)" % (p.upper(), n, d) for p, n, k, d in miss)
        detail = ("Windows needs these ports to find and talk to a domain controller. Blocking them gives: gpupdate \"lack of network connectivity to a domain controller\" (event 1129), "
                  "\"access denied\" on \\\\server, and failed domain logons. Discovery (UDP 3702) can keep working, so the computer still appears in Explorer.")
        checks.append(R("firewall_" + eng, "fail" if core else "warn", "%s is blocking %d port(s): %s" % (eng, len(miss), lst), detail,
                        {"action": "open_firewall", "label": "Open these ports", "engine": eng,
                         "ports": [[p, str(n)] for p, n, k, d in miss]}))


# ---------------------------------------------------------------- the checks
def run_checks(service_unit="samba-ad-dc.service"):
    checks = []
    parm = testparm_dump()
    g = parm.get("global", {})
    netbios = g.get("netbios name") or socket.gethostname().split(".")[0].upper()
    realm = g.get("realm", "")
    short = socket.gethostname().split(".")[0]
    rc, fq = sh(["hostname", "-f"])
    fqdn = fq.strip() if rc == 0 and "." in fq.strip() else (("%s.%s" % (short, realm.lower())) if realm else short)
    ips = host_ips()

    # 1. SMB listening
    smb = listening_on("tcp", 445)
    if not smb:
        checks.append(R("smb_listen", "fail", "Nothing is listening on TCP 445", "The Samba service is not serving SMB. Check that %s is running." % service_unit))
    elif not is_wildcard(smb) and not any(a in ips for a in smb):
        checks.append(R("smb_listen", "fail", "SMB only listens on %s" % ", ".join(sorted(set(smb))),
                        "Clients on the network cannot connect. Check 'interfaces' and 'bind interfaces only' in smb.conf (currently interfaces=%r, bind interfaces only=%r)." % (g.get("interfaces", ""), g.get("bind interfaces only", ""))))
    else:
        checks.append(R("smb_listen", "ok", "SMB is listening on TCP 445", "Bound to: %s." % ", ".join(sorted(set(smb)))))

    # 2. name consistency: what Explorer shows vs. what SMB/DNS know
    announced = short
    if announced.lower() != netbios.lower():
        checks.append(R("name_mismatch", "warn", "Hostname (%s) differs from the NetBIOS name (%s)" % (short, netbios),
                        "Network discovery announces the operating-system hostname, but Samba and DNS know the server as %s. Explorer then shows a name that clients cannot resolve. Make them identical (set the hostname with hostnamectl, or 'netbios name' in smb.conf)." % netbios))
    else:
        checks.append(R("name_mismatch", "ok", "Hostname and NetBIOS name match (%s)" % netbios))

    # 3. does the hostname resolve to a reachable address on this machine?
    try:
        res = sorted(set(a[4][0] for a in socket.getaddrinfo(fqdn, None, socket.AF_INET)))
    except Exception:
        res = []
    if not res:
        checks.append(R("host_resolve", "fail", "This server cannot resolve its own name (%s)" % fqdn,
                        "Add the server's real IP to /etc/hosts (\"<ip> %s %s\") or fix DNS." % (fqdn, short)))
    elif all(a.startswith("127.") for a in res):
        checks.append(R("host_resolve", "fail", "%s resolves to the loopback address %s" % (fqdn, ", ".join(res)),
                        "On Debian/Ubuntu /etc/hosts often maps the hostname to 127.0.1.1. Samba then hands out an address clients cannot reach. Replace it with the server's real IP (%s)." % (", ".join(ips) or "unknown")))
    else:
        checks.append(R("host_resolve", "ok", "%s resolves to %s" % (fqdn, ", ".join(res))))

    # 4. AD DNS has an A record for this host that matches one of our IPs
    if ips and realm:
        ans = dns_a(fqdn, "127.0.0.1")
        if ans is None:
            checks.append(R("dns_record", "warn", "Could not query the AD DNS server on this machine", "UDP 53 on 127.0.0.1 did not answer."))
        elif not ans:
            checks.append(R("dns_record", "fail", "No DNS A record for %s" % fqdn,
                            "Windows resolves \\\\%s through DNS. Without the record the computer shows up in Explorer but cannot be opened." % short,
                            {"action": "dns_update", "label": "Run samba_dnsupdate"}))
        elif not any(a in ips for a in ans):
            checks.append(R("dns_record", "fail", "DNS has %s for %s, but this machine's address is %s" % (", ".join(ans), fqdn, ", ".join(ips)),
                            "Stale record. Clients are being sent to the wrong address.", {"action": "dns_update", "label": "Run samba_dnsupdate"}))
        else:
            checks.append(R("dns_record", "ok", "DNS A record for %s is correct (%s)" % (fqdn, ", ".join(ans)),
                            "Clients must use this DC (or a DNS server that forwards the domain to it) for DNS, or they cannot resolve the name."))

    # 5. discovery daemon + its ports
    impl = check_discovery(service_unit, checks)
    udp3702 = listening_on("udp", 3702)
    if impl:
        if udp3702:
            checks.append(R("wsd_port", "ok", "WS-Discovery is listening on UDP 3702"))
        else:
            checks.append(R("wsd_port", "fail", "Nothing is listening on UDP 3702", "The discovery daemon is not announcing this server."))
        meta = 3702 if impl == "wsdd2" else 5357
        if udp3702 and not listening_on("tcp", meta):
            checks.append(R("wsd_meta", "fail", "Nothing is listening on TCP %d" % meta, "Windows needs this port to fetch the server's description after discovering it."))
        if impl == "wsdd2":
            checks.append(R("llmnr", "ok" if listening_on("udp", 5355) else "info", "LLMNR responder " + ("active on UDP 5355" if listening_on("udp", 5355) else "not detected"),
                            "wsdd2 also answers LLMNR, which lets Windows resolve \\\\%s even if the client does not use this DC for DNS." % short))
        else:
            checks.append(R("llmnr", "info", "No LLMNR responder with %s" % impl,
                            "Clients must resolve \\\\%s through DNS (use this DC as the client's DNS server). The Debian 13 'wsdd2' package adds LLMNR as a fallback." % short))

    # 6. firewall
    check_firewall(impl, checks)

    # 7. winbind (needed to evaluate group-based permissions)
    rc, out = sh(["wbinfo", "-p"])
    checks.append(R("winbind", "ok" if rc == 0 else "warn", "winbindd is responding" if rc == 0 else "winbindd is not responding",
                    "" if rc == 0 else "Group-based share permissions ('valid users = @DOMAIN\\group') cannot be evaluated. " + out.strip()[:200]))

    # 8. shares
    for name, p in parm.items():
        if name.lower() in ("global", "sysvol", "netlogon", "printers", "print$", "homes"):
            continue
        path = p.get("path", "")
        issues, notes = [], []
        if not path or not os.path.isdir(path):
            issues.append("path %r does not exist" % path)
        else:
            if "acl_xattr" in p.get("vfs objects", ""):
                try:
                    os.getxattr(path, "security.NTACL")
                except OSError:
                    notes.append("no Windows ACL set yet on the share root; access falls back to the Unix mode (%s)" % oct(os.stat(path).st_mode & 0o7777))
            st = os.stat(path)
            if not (st.st_mode & 0o005) and "acl_xattr" not in p.get("vfs objects", "") and not p.get("force user"):
                notes.append("directory mode %s gives 'others' no access; only the owner/group can enter" % oct(st.st_mode & 0o7777))
        if p.get("guest ok", "no").lower() in ("yes", "true", "1"):
            notes.append("guest access is enabled; Windows 11 24H2 and Windows Server 2025 refuse unauthenticated guest SMB by default")
        vu = p.get("valid users", "")
        for m in re.finditer(r'@"?([^",]+)"?', vu):
            grp = m.group(1).strip()
            rc, o = sh(["wbinfo", "-n", grp])
            if rc != 0:
                issues.append("group %r in 'valid users' cannot be resolved (%s)" % (grp, o.strip()[:80]))
        if issues:
            checks.append(R("share_" + name, "fail", "Share [%s]: %s" % (name, "; ".join(issues))))
        elif notes:
            checks.append(R("share_" + name, "warn", "Share [%s]" % name, "; ".join(notes) + "."))
        else:
            checks.append(R("share_" + name, "ok", "Share [%s] looks consistent" % name, "Path %s." % path))
    return checks


# ---------------------------------------------------------------- domain sign-in / Group Policy checks
def domain_checks(service_unit="samba-ad-dc.service"):
    checks = []
    parm = testparm_dump()
    g = parm.get("global", {})
    realm = g.get("realm", "")
    ips = host_ips()
    short = socket.gethostname().split(".")[0]
    netbios = (g.get("netbios name") or short).upper()
    fqdn = ("%s.%s" % (netbios.lower(), realm.lower())) if realm else short

    # 1. SYSVOL / NETLOGON shares
    for sec in ("sysvol", "netlogon"):
        p = parm.get(sec, {})
        path = p.get("path", "")
        if not p:
            checks.append(R("share_" + sec, "fail", "[%s] share is not defined in smb.conf" % sec,
                            "Windows reads Group Policy files and logon scripts through this share. Without it gpupdate fails."))
        elif not os.path.isdir(path):
            checks.append(R("share_" + sec, "fail", "[%s] path %s does not exist" % (sec, path)))
        else:
            checks.append(R("share_" + sec, "ok", "[%s] share is defined (%s)" % (sec, path)))

    # 2. Samba's own SYSVOL ACL consistency check
    if shutil.which("samba-tool"):
        rc, out = sh(["samba-tool", "ntacl", "sysvolcheck"], timeout=60)
        if rc == 0:
            checks.append(R("sysvol_acl", "ok", "SYSVOL permissions are consistent (samba-tool ntacl sysvolcheck)"))
        else:
            checks.append(R("sysvol_acl", "fail", "SYSVOL permissions are wrong", out.strip()[-500:] or "sysvolcheck reported errors.",
                            {"action": "sysvolreset", "label": "Reset SYSVOL permissions"}))

    # 3. SRV records Windows uses to find a DC
    if realm:
        for label, name in (("LDAP", "_ldap._tcp.%s" % realm.lower()), ("Kerberos", "_kerberos._tcp.%s" % realm.lower()),
                            ("LDAP (DC locator)", "_ldap._tcp.dc._msdcs.%s" % realm.lower())):
            ans = dns_query(name, 33)
            if ans is None:
                checks.append(R("srv_" + label, "warn", "Could not query %s" % name, "The AD DNS server on this machine did not answer."))
            elif not ans:
                checks.append(R("srv_" + label, "fail", "Missing DNS SRV record %s" % name,
                                "Windows cannot locate a domain controller, so gpupdate and domain logons fail.",
                                {"action": "dns_update", "label": "Run samba_dnsupdate"}))
            else:
                checks.append(R("srv_" + label, "ok", "SRV %s -> %s" % (name, ", ".join("%s:%d" % (t.rstrip("."), p_) for _pr, _w, p_, t in ans[:3]))))
        a_all = dns_query(fqdn, 1) or []
        if len(a_all) > 1:
            checks.append(R("dns_multi", "warn", "%s has %d A records (%s)" % (fqdn, len(a_all), ", ".join(a_all)),
                            "If one of these is not reachable from the clients (docker bridge, VPN, second NIC), Windows picks it some of the time and connections fail intermittently. Remove stale/unused addresses from DNS."))

    # 4. time (Kerberos allows 5 minutes of skew)
    synced = None
    if shutil.which("timedatectl"):
        rc, out = sh(["timedatectl", "show", "-p", "NTPSynchronized", "--value"])
        if rc == 0:
            synced = out.strip() == "yes"
    if synced is None and shutil.which("chronyc"):
        rc, out = sh(["chronyc", "tracking"])
        if rc == 0:
            synced = "Normal" in out
    if synced is True:
        checks.append(R("time", "ok", "System clock is synchronised"))
    elif synced is False:
        checks.append(R("time", "fail", "System clock is not synchronised",
                        "Kerberos rejects tickets when the DC and a client differ by more than 5 minutes. That produces \"access denied\" for \\\\server and gpupdate. Fix NTP on the DC (and make sure the client syncs from the domain)."))
    else:
        checks.append(R("time", "info", "Could not determine time synchronisation", "Neither timedatectl nor chronyc reported a state."))

    # 5. SPN for this DC (Kerberos to cifs/<name> uses HOST/)
    if shutil.which("samba-tool"):
        rc, out = sh(["samba-tool", "spn", "list", netbios + "$"])
        if rc == 0 and ("HOST/%s" % fqdn).lower() in out.lower():
            checks.append(R("spn", "ok", "Service principal names for %s are registered" % netbios))
        elif rc == 0:
            checks.append(R("spn", "fail", "HOST/%s is not registered for %s$" % (fqdn, netbios),
                            "Kerberos cannot authenticate SMB to %s, so Windows falls back to NTLM or is denied." % fqdn))

    # 6. authentication policy knobs that commonly cause "access denied"
    ntlm = g.get("ntlm auth", "ntlmv2-only")
    sign = g.get("server signing", "default")
    minp = g.get("server min protocol", "SMB2_02")
    notes = ["ntlm auth = %s" % ntlm, "server signing = %s" % sign, "server min protocol = %s" % minp]
    if ntlm.lower() == "disabled":
        checks.append(R("auth_policy", "fail", "NTLM authentication is disabled in smb.conf",
                        "Only Kerberos will work. Any client that reaches the server by IP address, by an alias, or from outside the domain gets \"access denied\". " + "; ".join(notes)))
    elif sign.lower() in ("disabled", "off", "no") and False:
        pass
    else:
        checks.append(R("auth_policy", "info", "Authentication settings", "; ".join(notes) + ". (An AD DC requires SMB signing by default; Windows 11 24H2 also requires it.)"))
    return checks


# ---------------------------------------------------------------- sign-in test
NT_HINTS = {
    "NT_STATUS_LOGON_FAILURE": ("auth", "Wrong user name or password."),
    "NT_STATUS_ACCOUNT_DISABLED": ("auth", "The account is disabled."),
    "NT_STATUS_ACCOUNT_LOCKED_OUT": ("auth", "The account is locked out."),
    "NT_STATUS_PASSWORD_EXPIRED": ("auth", "The password has expired."),
    "NT_STATUS_ACCESS_DENIED": ("acl", "Authentication worked but the share or folder permissions deny this user. Check the share's valid users and the Windows ACL."),
    "NT_STATUS_BAD_NETWORK_NAME": ("share", "The share name does not exist."),
    "NT_STATUS_CONNECTION_REFUSED": ("network", "Nothing is accepting SMB connections on that address (service down or firewall)."),
    "NT_STATUS_HOST_UNREACHABLE": ("network", "The address is unreachable."),
    "NT_STATUS_IO_TIMEOUT": ("network", "The connection timed out (firewall dropping packets?)."),
    "NT_STATUS_UNSUCCESSFUL": ("network", "Could not connect. Check the server name resolves and SMB is reachable."),
    "NT_STATUS_NOT_SUPPORTED": ("protocol", "Protocol/signing mismatch."),
}


def smb_test(share, user, host=None, pw=""):
    host = host or (host_ips() or ["127.0.0.1"])[0]
    if not share:  # what Explorer does when you open \\\\server
        rc, out = sh(["smbclient", "-L", "//%s" % host, "-U", user], timeout=20, env={"PASSWD": pw})
        if rc == 0:
            return {"ok": True, "layer": "none", "message": "Signed in to \\\\%s and listed its shares. Server-side authentication works for this account; if a Windows client still gets access denied, look at the client: is it joined to the domain and signed in with a domain account, does its DNS point at this DC, is its clock correct?" % host, "raw": out.strip()[-600:]}
        m = re.search(r"NT_STATUS_[A-Z_]+", out)
        code = m.group(0) if m else ""
        layer, msg = NT_HINTS.get(code, ("unknown", "The test failed."))
        return {"ok": False, "layer": layer, "code": code, "message": msg, "raw": out.strip()[-600:]}
    rc, out = sh(["smbclient", "//%s/%s" % (host, share), "-U", user, "-c", "ls"], timeout=20, env={"PASSWD": pw})
    if rc == 0:
        return {"ok": True, "layer": "none", "message": "Signed in to \\\\%s\\%s and listed the share. Server side is fine; if a client still cannot open it, the cause is on the client or between the client and this server (DNS name resolution, firewall, or guest/signing policy)." % (host, share), "raw": out.strip()[-600:]}
    m = re.search(r"NT_STATUS_[A-Z_]+", out)
    code = m.group(0) if m else ""
    layer, msg = NT_HINTS.get(code, ("unknown", "The test failed."))
    return {"ok": False, "layer": layer, "code": code, "message": msg, "raw": out.strip()[-600:]}


def main():
    try:
        req = json.loads(sys.stdin.read() or "{}")
        cmd = req.get("cmd")
        if cmd == "checks":
            data = run_checks(req.get("service") or "samba-ad-dc.service")
        elif cmd == "domain_checks":
            data = domain_checks(req.get("service") or "samba-ad-dc.service")
        elif cmd == "smb_test":
            if not re.match(r"^[\w.$ -]*$", req.get("share", "")) or not re.match(r"^[\w.\\@$ -]+$", req.get("user", "")):
                raise ValueError("Invalid share or user name")
            data = smb_test(req["share"], req["user"], req.get("host"), req.get("pass", ""))
        else:
            raise ValueError("Unknown command")
        print(json.dumps({"ok": True, "data": data}))
    except Exception as e:  # noqa: BLE001
        print(json.dumps({"ok": False, "error": "%s: %s" % (type(e).__name__, e)}))


if __name__ == "__main__":
    main()
