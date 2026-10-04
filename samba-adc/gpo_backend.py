#!/usr/bin/python3
"""
GPO backend for the Samba AD DC Cockpit module.

Reads one JSON request from stdin ({"cmd": ..., ...}) and writes one JSON
response to stdout ({"ok": true, "data": ...} or {"ok": false, "error": ...}).

It is run as root on the DC and mirrors what Samba's own `samba-tool gpo load`
does (samba/policies.py):
  * AD objects are read/written through the local sam.ldb with the system
    session, so all DSDB modules run (replication metadata etc.).
  * SYSVOL files are read/written over SMB (libsmb) using this DC's machine
    account, so path lookups are case-insensitive (Samba provisions MACHINE/USER
    in upper case) and new files get ACLs derived from the GPO's DS ACL.
  * Every write bumps GPT.INI + versionNumber and registers the client-side
    extension (CSE) GUIDs, otherwise Windows clients would ignore the change.
"""
import base64
import json
import os
import re
import shutil
import struct
import subprocess
import sys

import ldb
from samba.auth import system_session
from samba.dcerpc import security
from samba.ndr import ndr_unpack
from samba.auth_util import system_session_unix
from samba.ntacls import dsacl2fsacl, setntacl
from samba.param import LoadParm
from samba.samba3 import param as s3param, passdb
from samba.samdb import SamDB

POLICIES_ACL = "O:LAG:BAD:P(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;SO)(A;OICI;FA;;;SY)(A;OICI;0x1200a9;;;AU)(A;OICI;0x1301bf;;;PA)"
GUID_RE = re.compile(r"^\{[0-9A-Fa-f]{8}-([0-9A-Fa-f]{4}-){3}[0-9A-Fa-f]{12}\}$")
REG_SZ, REG_EXPAND_SZ, REG_BINARY, REG_DWORD, REG_MULTI_SZ, REG_QWORD = 1, 2, 3, 4, 7, 11


class Ctx:
    def __init__(self, server=None):
        self.lp = LoadParm()
        self.lp.load_default()
        self.realm = self.lp.get("realm")
        self.samdb = SamDB(url=self.lp.samdb_url(), session_info=system_session(self.lp), lp=self.lp)
        self.base_dn = self.samdb.get_default_basedn()
        self.domsid = security.dom_sid(self.samdb.get_domain_sid())
        self.sysvol = self.lp.get("path", "sysvol")
        self._passdb = None

    # ---- filesystem helpers (case-insensitive like SMB) ---------------
    @staticmethod
    def find(parent, name):
        try:
            for e in os.listdir(parent):
                if e.lower() == name.lower():
                    return e
        except FileNotFoundError:
            pass
        return None

    def policies_dir(self):
        d = self.find(self.sysvol, self.realm.lower())
        if d is None:
            raise RuntimeError("sysvol has no %s directory" % self.realm.lower())
        p = self.find(os.path.join(self.sysvol, d), "Policies")
        if p is None:
            raise RuntimeError("sysvol has no Policies directory")
        return os.path.join(self.sysvol, d, p)

    def base_for(self, root):
        if root == "policies":
            return self.policies_dir()
        if GUID_RE.match(root or ""):
            return os.path.join(self.policies_dir(), self.find(self.policies_dir(), root) or root.upper())
        raise ValueError("Invalid root")

    def resolve(self, root, rel, create=False):
        """Return (real_path, [newly created paths]). Matches existing names case-insensitively."""
        rel = (rel or "").replace("\\", "/").strip("/")
        parts = [x for x in rel.split("/") if x]
        if any(x in ("..", ".") for x in parts):
            raise ValueError("Invalid path")
        cur = self.base_for(root)
        created = []
        for i, part in enumerate(parts):
            hit = self.find(cur, part)
            if hit is None:
                if not create:
                    return None, created
                nxt = os.path.join(cur, part)
                if i < len(parts) - 1:
                    os.mkdir(nxt, 0o755)
                    created.append(nxt)
                cur = nxt
            else:
                cur = os.path.join(cur, hit)
        return cur, created

    # ---- GPO objects -------------------------------------------------
    def gpo_dn(self, guid):
        if not GUID_RE.match(guid or ""):
            raise ValueError("Invalid GPO GUID")
        dn = self.samdb.get_default_basedn()
        dn.add_child(ldb.Dn(self.samdb, "CN=Policies,CN=System"))
        dn.add_child(ldb.Dn(self.samdb, "CN=%s" % guid.upper()))
        return dn

    def gpo_msg(self, guid, attrs):
        res = self.samdb.search(base=self.gpo_dn(guid), scope=ldb.SCOPE_BASE, attrs=attrs)
        if not res:
            raise ValueError("GPO %s not found" % guid)
        return res[0]

    def fs_sddl(self, guid):
        msg = self.gpo_msg(guid, ["nTSecurityDescriptor"])
        ds = ndr_unpack(security.descriptor, msg["nTSecurityDescriptor"][0]).as_sddl()
        return dsacl2fsacl(ds, self.domsid)

    def passdb(self):
        if self._passdb is None:
            s3 = s3param.get_context()
            s3.load(self.lp.configfile)
            s3.set("passdb backend", "samba_dsdb:%s" % self.samdb.url)
            passdb.reload_static_pdb()
            self._passdb = passdb.PDB(s3.get("passdb backend"))
        return self._passdb

    def stamp_acl(self, guid, path):
        """Give a new file/dir the GPO's NT ACL (what `samba-tool ntacl sysvolreset` would do).
        guid=None means a file in the Policies folder itself (e.g. the ADMX Central Store)."""
        sddl = self.fs_sddl(guid) if guid else POLICIES_ACL
        setntacl(self.lp, path, sddl, str(self.domsid), system_session_unix(),
                 use_ntvfs=False, skip_invalid_chown=True, passdb=self.passdb(), service="sysvol")

    # ---- file operations ---------------------------------------------
    def load(self, root, rel):
        p, _ = self.resolve(root, rel)
        if p is None or not os.path.isfile(p):
            return None
        with open(p, "rb") as f:
            return f.read()

    def save(self, root, rel, data, guid=None, stamp=True):
        p, created = self.resolve(root, rel, create=True)
        existed = os.path.exists(p)
        tmp = p + ".tmp-gpoedit"
        with open(tmp, "wb") as f:
            f.write(data)
        os.chmod(tmp, 0o644)
        os.replace(tmp, p)
        if stamp:
            for c in created + [p]:
                self.stamp_acl(guid, c)
        return not existed

    def mkdirs(self, root, rel, guid=None):
        p, _ = self.resolve(root, rel + "/_", create=True)
        d = os.path.dirname(p)
        if not os.path.isdir(d):
            os.mkdir(d, 0o755)
            if guid:
                self.stamp_acl(guid, d)


# ---------------------------------------------------------------------
# Registry.pol (PReg) parser / writer
# ---------------------------------------------------------------------
def pol_parse(data):
    out = []
    if not data:
        return out
    if data[:4] != b"PReg":
        raise ValueError("Not a Registry.pol file (bad signature)")
    pos = 8
    n = len(data)

    def read_str(p):
        e = p
        while e + 1 < n and not (data[e] == 0 and data[e + 1] == 0):
            e += 2
        return data[p:e].decode("utf-16-le", "replace"), e + 2

    while pos + 2 <= n:
        if data[pos:pos + 2] != b"[\x00":
            break
        pos += 2
        key, pos = read_str(pos)
        pos += 2  # ;
        name, pos = read_str(pos)
        pos += 2
        typ = struct.unpack_from("<I", data, pos)[0]
        pos += 4 + 2
        size = struct.unpack_from("<I", data, pos)[0]
        pos += 4 + 2
        raw = data[pos:pos + size]
        pos += size
        if data[pos:pos + 2] == b"]\x00":
            pos += 2
        out.append({"key": key, "name": name, "type": typ, "data": decode_value(typ, raw)})
    return out


def decode_value(typ, raw):
    if typ in (REG_SZ, REG_EXPAND_SZ):
        return raw.decode("utf-16-le", "replace").rstrip("\x00")
    if typ == REG_DWORD and len(raw) >= 4:
        return struct.unpack("<I", raw[:4])[0]
    if typ == REG_QWORD and len(raw) >= 8:
        return struct.unpack("<Q", raw[:8])[0]
    if typ == REG_MULTI_SZ:
        s = raw.decode("utf-16-le", "replace")
        return [x for x in s.split("\x00") if x != ""]
    return raw.hex()


def encode_value(typ, val):
    if typ in (REG_SZ, REG_EXPAND_SZ):
        return (str(val) + "\x00").encode("utf-16-le")
    if typ == REG_DWORD:
        return struct.pack("<I", int(val) & 0xFFFFFFFF)
    if typ == REG_QWORD:
        return struct.pack("<Q", int(val))
    if typ == REG_MULTI_SZ:
        items = list(val) if isinstance(val, (list, tuple)) else [str(val)]
        return ("\x00".join(items) + "\x00\x00").encode("utf-16-le") if items else b"\x00\x00\x00\x00"
    return bytes.fromhex(val or "")


def pol_build(entries):
    out = bytearray(b"PReg" + struct.pack("<I", 1))
    semi = b";\x00"
    for e in entries:
        v = encode_value(int(e["type"]), e.get("data"))
        out += b"[\x00" + (e["key"] + "\x00").encode("utf-16-le") + semi
        out += (e["name"] + "\x00").encode("utf-16-le") + semi
        out += struct.pack("<I", int(e["type"])) + semi
        out += struct.pack("<I", len(v)) + semi + v + b"]\x00"
    return bytes(out)


# ---------------------------------------------------------------------
# Versioning / CSE registration
# ---------------------------------------------------------------------
def parse_exts(s):
    d = {}
    for m in re.finditer(r"\[((?:\{[0-9A-Fa-f-]+\})+)\]", s or ""):
        guids = re.findall(r"\{[0-9A-Fa-f-]+\}", m.group(1))
        d.setdefault(guids[0].upper(), [])
        for t in guids[1:]:
            if t.upper() not in d[guids[0].upper()]:
                d[guids[0].upper()].append(t.upper())
    return d


def build_exts(d):
    return "".join("[%s%s]" % (c, "".join(sorted(d[c]))) for c in sorted(d))


def commit(ctx, guid, machine=False, user=False, machine_exts=(), user_exts=()):
    """Bump GPT.INI + versionNumber and register CSE/tool GUID pairs."""
    raw = ctx.load(guid, "GPT.INI")
    text = raw.decode("utf-8", "replace") if raw else "[General]\r\nVersion=0\r\n"
    m = re.search(r"^Version\s*=\s*(\d+)", text, re.M | re.I)
    ver = int(m.group(1)) if m else 0
    mv, uv = ver & 0xFFFF, ver >> 16
    if machine:
        mv = (mv + 1) & 0xFFFF
    if user:
        uv = (uv + 1) & 0xFFFF
    newver = (uv << 16) | mv
    if m:
        text = text[:m.start()] + "Version=%d" % newver + text[m.end():]
    elif "[General]" in text:
        text = text.replace("[General]", "[General]\r\nVersion=%d" % newver, 1)
    else:
        text = "[General]\r\nVersion=%d\r\n" % newver + text
    ctx.save(guid, "GPT.INI", text.encode("utf-8"), guid)

    msg = ldb.Message()
    msg.dn = ctx.gpo_dn(guid)
    msg["versionNumber"] = ldb.MessageElement(str(newver), ldb.FLAG_MOD_REPLACE, "versionNumber")
    for attr, pairs in (("gPCMachineExtensionNames", machine_exts), ("gPCUserExtensionNames", user_exts)):
        if not pairs:
            continue
        cur = ctx.gpo_msg(guid, [attr])
        d = parse_exts(str(cur[attr][0]) if attr in cur else "")
        for cse, tool in pairs:
            d.setdefault(cse.upper(), [])
            if tool and tool.upper() not in d[cse.upper()]:
                d[cse.upper()].append(tool.upper())
        msg[attr] = ldb.MessageElement(build_exts(d), ldb.FLAG_MOD_REPLACE, attr)
    ctx.samdb.modify(msg)
    return {"version": newver, "machine": mv, "user": uv}


# ---------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------
def s(msg, attr, default=""):
    return str(msg[attr][0]) if attr in msg else default


def cmd_info(ctx, req):
    import samba
    return {"realm": ctx.realm, "domain": ctx.lp.get("workgroup"), "base_dn": str(ctx.base_dn),
            "samba_version": samba.version, "sysvol_policies": ctx.policies_dir()}


def cmd_list_gpos(ctx, req):
    base = ldb.Dn(ctx.samdb, "CN=Policies,CN=System," + str(ctx.base_dn))
    res = ctx.samdb.search(base=base, scope=ldb.SCOPE_ONELEVEL, expression="(objectClass=groupPolicyContainer)",
                           attrs=["cn", "displayName", "versionNumber", "flags", "whenCreated", "whenChanged",
                                  "gPCFileSysPath", "gPCMachineExtensionNames", "gPCUserExtensionNames", "description"])
    out = []
    for m in res:
        ver = int(s(m, "versionNumber", "0") or 0)
        out.append({"guid": s(m, "cn"), "name": s(m, "displayName"), "description": s(m, "description"),
                    "flags": int(s(m, "flags", "0") or 0), "version": ver,
                    "machine_version": ver & 0xFFFF, "user_version": ver >> 16,
                    "created": s(m, "whenCreated"), "changed": s(m, "whenChanged"),
                    "path": s(m, "gPCFileSysPath"),
                    "machine_exts": s(m, "gPCMachineExtensionNames"), "user_exts": s(m, "gPCUserExtensionNames")})
    out.sort(key=lambda g: g["name"].lower())
    return out


def parse_gplink(v):
    links = []
    for m in re.finditer(r"\[LDAP://([^;\]]*);(\d+)\]", v or "", re.I):
        g = re.search(r"CN=(\{[0-9A-Fa-f-]+\})", m.group(1), re.I)
        if g:
            links.append({"guid": g.group(1).upper(), "options": int(m.group(2))})
    # gPLink stores the lowest-precedence link first; GPMC "Link order 1" is the last entry.
    links.reverse()
    for i, l in enumerate(links):
        l["order"] = i + 1
        l["disabled"] = bool(l["options"] & 1)
        l["enforced"] = bool(l["options"] & 2)
    return links


def cmd_list_containers(ctx, req):
    """Domain root, OUs and sites with their GPO links."""
    out = []
    exprs = [(ctx.base_dn, "(|(objectClass=domainDNS)(objectClass=organizationalUnit))", "domain/ou")]
    for base, expr, _ in exprs:
        res = ctx.samdb.search(base=base, scope=ldb.SCOPE_SUBTREE, expression=expr,
                               attrs=["gPLink", "gPOptions", "name", "objectClass"])
        for m in res:
            classes = [str(c).lower() for c in m["objectClass"]]
            out.append({"dn": str(m.dn), "name": s(m, "name"),
                        "type": "domain" if "domaindns" in classes else "ou",
                        "links": parse_gplink(s(m, "gPLink")), "block_inheritance": s(m, "gPOptions", "0") == "1"})
    try:
        sites = ctx.samdb.search(base=ldb.Dn(ctx.samdb, "CN=Sites," + str(ctx.samdb.get_config_basedn())),
                                 scope=ldb.SCOPE_ONELEVEL, expression="(objectClass=site)",
                                 attrs=["gPLink", "gPOptions", "name"])
        for m in sites:
            out.append({"dn": str(m.dn), "name": s(m, "name"), "type": "site",
                        "links": parse_gplink(s(m, "gPLink")), "block_inheritance": False})
    except Exception:
        pass
    return out


def cmd_set_links(ctx, req):
    dn = ldb.Dn(ctx.samdb, req["dn"])
    links = sorted(req.get("links", []), key=lambda l: l["order"])
    parts = []
    for l in reversed(links):  # store lowest precedence first
        g = l["guid"].upper()
        if not GUID_RE.match(g):
            raise ValueError("Bad GUID")
        opts = (1 if l.get("disabled") else 0) | (2 if l.get("enforced") else 0)
        parts.append("[LDAP://CN=%s,CN=Policies,CN=System,%s;%d]" % (g, ctx.base_dn, opts))
    msg = ldb.Message()
    msg.dn = dn
    if parts:
        msg["gPLink"] = ldb.MessageElement("".join(parts), ldb.FLAG_MOD_REPLACE, "gPLink")
    else:
        existing = ctx.samdb.search(base=dn, scope=ldb.SCOPE_BASE, attrs=["gPLink"])
        if existing and "gPLink" in existing[0]:
            msg["gPLink"] = ldb.MessageElement([], ldb.FLAG_MOD_DELETE, "gPLink")
    if "block_inheritance" in req:
        existing = ctx.samdb.search(base=dn, scope=ldb.SCOPE_BASE, attrs=["gPOptions"])
        has = bool(existing) and "gPOptions" in existing[0]
        if req["block_inheritance"]:
            msg["gPOptions"] = ldb.MessageElement("1", ldb.FLAG_MOD_REPLACE, "gPOptions")
        elif has:
            msg["gPOptions"] = ldb.MessageElement([], ldb.FLAG_MOD_DELETE, "gPOptions")
    if len(msg) > 0:
        ctx.samdb.modify(msg)
    return True


def cmd_set_gpo_attr(ctx, req):
    msg = ldb.Message()
    msg.dn = ctx.gpo_dn(req["guid"])
    if "flags" in req:
        f = int(req["flags"])
        if f not in (0, 1, 2, 3):
            raise ValueError("flags must be 0-3")
        msg["flags"] = ldb.MessageElement(str(f), ldb.FLAG_MOD_REPLACE, "flags")
    if "name" in req:
        if not req["name"].strip():
            raise ValueError("Name required")
        msg["displayName"] = ldb.MessageElement(req["name"].strip(), ldb.FLAG_MOD_REPLACE, "displayName")
    ctx.samdb.modify(msg)
    return True


def cmd_read_file(ctx, req):
    d = ctx.load(req["root"], req["path"])
    return None if d is None else base64.b64encode(d).decode()


def cmd_write_file(ctx, req):
    guid = req["root"] if req["root"] != "policies" else None
    ctx.save(req["root"], req["path"], base64.b64decode(req["data"]), guid)
    return finish(ctx, req)


def cmd_read_files(ctx, req):
    """Read many files in one call. paths: explicit list, or dir + exts to read a whole folder."""
    out = {}
    paths = req.get("paths")
    if paths is None:
        d, _ = ctx.resolve(req["root"], req.get("dir", ""))
        exts = tuple(e.lower() for e in req.get("exts", []))
        paths = []
        if d and os.path.isdir(d):
            paths = [os.path.join(req.get("dir", ""), n) for n in sorted(os.listdir(d))
                     if os.path.isfile(os.path.join(d, n)) and (not exts or n.lower().endswith(exts))]
    for rel in paths:
        data = ctx.load(req["root"], rel)
        if data is not None:
            out[rel.replace("\\", "/")] = base64.b64encode(data).decode()
    return out


def cmd_write_files(ctx, req):
    guid = req["root"] if req["root"] != "policies" else None
    n = 0
    for f in req["files"]:
        ctx.save(req["root"], f["path"], base64.b64decode(f["data"]), guid)
        n += 1
    return finish(ctx, req) and n


def cmd_lookup_principals(ctx, req):
    """Resolve SIDs -> names and names -> SIDs through the directory."""
    out = {}
    for sid in req.get("sids", []):
        if not re.match(r"^S-1-\d+(-\d+)+$", str(sid)):
            continue  # never put unvalidated text into an LDAP filter
        try:
            res = ctx.samdb.search(base=ctx.base_dn, scope=ldb.SCOPE_SUBTREE,
                                   expression="(objectSid=%s)" % sid, attrs=["sAMAccountName", "objectClass"])
            if res:
                out[sid] = {"name": s(res[0], "sAMAccountName"), "type": "group" if b"group" in res[0]["objectClass"] else "user"}
        except Exception:
            pass
    for name in req.get("names", []):
        try:
            safe = re.sub(r"[()*\\\x00]", "", name)
            res = ctx.samdb.search(base=ctx.base_dn, scope=ldb.SCOPE_SUBTREE,
                                   expression="(sAMAccountName=%s)" % safe, attrs=["objectSid"])
            if res:
                out[name] = {"sid": str(ndr_unpack(security.dom_sid, res[0]["objectSid"][0]))}
        except Exception:
            pass
    return out


def cmd_search_principals(ctx, req):
    q = re.sub(r"[()*\\\x00]", "", req.get("q", ""))
    res = ctx.samdb.search(base=ctx.base_dn, scope=ldb.SCOPE_SUBTREE,
                           expression="(&(|(objectClass=user)(objectClass=group))(sAMAccountName=*%s*))" % q,
                           attrs=["sAMAccountName", "objectSid", "objectClass"])
    out = []
    for m in list(res)[:50]:
        out.append({"name": s(m, "sAMAccountName"), "sid": str(ndr_unpack(security.dom_sid, m["objectSid"][0])),
                    "type": "group" if b"group" in m["objectClass"] else "user"})
    return out


def cmd_delete_file(ctx, req):
    p, _ = ctx.resolve(req["root"], req["path"])
    if p is not None and os.path.isfile(p):
        os.unlink(p)
    elif p is not None and os.path.isdir(p) and req.get("recursive"):
        import shutil
        shutil.rmtree(p)
    return finish(ctx, req)


def cmd_list_dir(ctx, req):
    p, _ = ctx.resolve(req["root"], req.get("path", ""))
    if p is None or not os.path.isdir(p):
        return []
    out = []
    for n in sorted(os.listdir(p)):
        fp = os.path.join(p, n)
        out.append({"name": n, "dir": os.path.isdir(fp), "size": 0 if os.path.isdir(fp) else os.path.getsize(fp)})
    return out


def cmd_create_gpo(ctx, req):
    """Create a GPO exactly as `samba-tool gpo create` does, but without needing SMB credentials."""
    import uuid
    name = (req.get("name") or "").strip()
    if not name:
        raise ValueError("A display name is required")
    base = ldb.Dn(ctx.samdb, "CN=Policies,CN=System," + str(ctx.base_dn))
    for m in ctx.samdb.search(base=base, scope=ldb.SCOPE_ONELEVEL, attrs=["displayName"]):
        if s(m, "displayName").lower() == name.lower():
            raise ValueError("A GPO named '%s' already exists" % name)
    guid = "{%s}" % str(uuid.uuid4()).upper()
    dn = ctx.gpo_dn(guid)
    dns = ctx.realm.lower()
    unc = "\\\\%s\\sysvol\\%s\\Policies\\%s" % (dns, dns, guid)
    ctx.samdb.transaction_start()
    try:
        for d, cls in ((dn, "groupPolicyContainer"), (ldb.Dn(ctx.samdb, "CN=User,%s" % dn), "container"),
                       (ldb.Dn(ctx.samdb, "CN=Machine,%s" % dn), "container")):
            m = ldb.Message()
            m.dn = d
            m["a01"] = ldb.MessageElement(cls, ldb.FLAG_MOD_ADD, "objectClass")
            ctx.samdb.add(m)
        m = ldb.Message()
        m.dn = dn
        for k, v in (("displayName", name), ("gPCFileSysPath", unc), ("versionNumber", "0"),
                     ("gpcFunctionalityVersion", "2"), ("flags", "0")):
            m[k] = ldb.MessageElement(v, ldb.FLAG_MOD_REPLACE, k)
        ctx.samdb.modify(m, controls=["permissive_modify:0"])
        ctx.samdb.transaction_commit()
    except Exception:
        ctx.samdb.transaction_cancel()
        raise
    try:
        gdir = os.path.join(ctx.policies_dir(), guid)
        os.mkdir(gdir, 0o755)
        ctx.stamp_acl(guid, gdir)
        for sub in ("Machine", "User"):
            os.mkdir(os.path.join(gdir, sub), 0o755)
            ctx.stamp_acl(guid, os.path.join(gdir, sub))
        ctx.save(guid, "GPT.INI", b"[General]\r\nVersion=0\r\n", guid)
    except Exception:
        ctx.samdb.delete(dn, ["tree_delete:1"])  # do not leave a half-created GPO behind
        raise
    return guid


def cmd_delete_gpo(ctx, req):
    import shutil
    guid = req["guid"].upper()
    dn = ctx.gpo_dn(guid)
    # remove it from every container that links to it, so no dangling links remain
    for c in cmd_list_containers(ctx, {}):
        links = [l for l in c["links"] if l["guid"] != guid]
        if len(links) != len(c["links"]):
            cmd_set_links(ctx, {"dn": c["dn"], "links": links})
    ctx.samdb.delete(dn, ["tree_delete:1"])
    d = os.path.join(ctx.policies_dir(), ctx.find(ctx.policies_dir(), guid) or guid)
    if os.path.isdir(d):
        shutil.rmtree(d)
    return True


def cmd_install_samba_admx(ctx, req):
    """Copy Samba's bundled ADMX/ADML (samba.admx, GNOME_Settings.admx, ...) into the Central Store."""
    src = req.get("src") or "/usr/share/samba/admx"
    if not os.path.isdir(src):
        raise ValueError("%s not found (is the samba package with ADMX templates installed?)" % src)
    n = 0
    for dirpath, _dirs, files in os.walk(src):
        rel = os.path.relpath(dirpath, src)
        for f in files:
            if not f.lower().endswith((".admx", ".adml")):
                continue
            with open(os.path.join(dirpath, f), "rb") as fh:
                data = fh.read()
            ctx.save("policies", "PolicyDefinitions/" + (f if rel == "." else rel + "/" + f), data, None)
            n += 1
    return n


# ---------------------------------------------------------------------
# Health check + repair (the things that make Windows say "access denied" /
# 1058 / "no settings applied" even though the GPO exists in the console)
# ---------------------------------------------------------------------
CSE_FILES = [
    # (relative file, side, cse, tool)
    ("Machine/Registry.pol", "machine", "{35378EAC-683F-11D2-A89A-00C04FBBCFA2}", "{D02B1F72-3407-48AE-BA88-E8213C6761F1}"),
    ("User/Registry.pol", "user", "{35378EAC-683F-11D2-A89A-00C04FBBCFA2}", "{D02B1F73-3407-48AE-BA88-E8213C6761F1}"),
    ("Machine/Microsoft/Windows NT/SecEdit/GptTmpl.inf", "machine", "{827D319E-6EAC-11D2-A4EA-00C04F79F83A}", "{803E14A0-B4FB-11D0-A0D0-00A0C90F574B}"),
    ("Machine/Microsoft/Windows NT/Audit/audit.csv", "machine", "{F3CCC681-B74C-4060-9F26-CD84525DCA2A}", "{0F3F3735-573D-9804-99E4-AB2A69BA5FD4}"),
    ("Machine/Scripts/scripts.ini", "machine", "{42B5FAAE-6536-11D2-AE5A-0000F87571E3}", "{40B6664F-4972-11D1-A7CA-0000F87571E3}"),
    ("Machine/Scripts/psscripts.ini", "machine", "{42B5FAAE-6536-11D2-AE5A-0000F87571E3}", "{40B6664F-4972-11D1-A7CA-0000F87571E3}"),
    ("User/Scripts/scripts.ini", "user", "{42B5FAAE-6536-11D2-AE5A-0000F87571E3}", "{40B66650-4972-11D1-A7CA-0000F87571E3}"),
    ("User/Scripts/psscripts.ini", "user", "{42B5FAAE-6536-11D2-AE5A-0000F87571E3}", "{40B66650-4972-11D1-A7CA-0000F87571E3}"),
    ("User/Preferences/Drives/Drives.xml", "user", "{5794DAFD-BE60-433f-88A2-1A31939AC01F}", "{2EA1A81B-48E5-45E9-8BB7-A6E3AC170006}"),
    ("Machine/Preferences/Registry/Registry.xml", "machine", "{B087BE9D-ED37-454f-AF9C-04291E351182}", "{BEE07A6A-EC9F-4659-B8C9-0B1937907C83}"),
    ("User/Preferences/Registry/Registry.xml", "user", "{B087BE9D-ED37-454f-AF9C-04291E351182}", "{BEE07A6A-EC9F-4659-B8C9-0B1937907C83}"),
]


def has_ntacl(path):
    try:
        os.getxattr(path, "security.NTACL")
        return True
    except OSError:
        return False


def gpo_findings(ctx, g):
    """-> list of {level, msg, fix?} for one GPO dict from cmd_list_gpos."""
    out = []
    guid = g["guid"]
    gdir, _ = ctx.resolve(guid, "")
    if gdir is None or not os.path.isdir(gdir):
        out.append({"level": "fail", "msg": "The GPO exists in Active Directory but its SYSVOL folder is missing. Clients get \"cannot access gpt.ini\" (event 1058).", "fix": "repair"})
        return out
    gpt = ctx.load(guid, "GPT.INI")
    if gpt is None:
        out.append({"level": "fail", "msg": "GPT.INI is missing from the SYSVOL folder; Windows cannot read this GPO.", "fix": "repair"})
    else:
        m = re.search(r"^Version\s*=\s*(\d+)", gpt.decode("utf-8", "replace"), re.M | re.I)
        v = int(m.group(1)) if m else None
        if v is None:
            out.append({"level": "fail", "msg": "GPT.INI has no Version= line.", "fix": "repair"})
        elif v != g["version"]:
            out.append({"level": "warn", "msg": "Version mismatch: Active Directory says %d, GPT.INI says %d (GPMC shows this as AD/SYSVOL out of sync)." % (g["version"], v), "fix": "repair"})
    for sub in ("Machine", "User"):
        d, _ = ctx.resolve(guid, sub)
        if d is None:
            out.append({"level": "warn", "msg": "The %s folder is missing." % sub, "fix": "repair"})
    # NT ACLs: without them smbd falls back to POSIX bits and Windows clients can be denied
    if not has_ntacl(gdir):
        out.append({"level": "fail", "msg": "The GPO folder has no Windows (NT) ACL. Clients that are not root-mapped can be denied access.", "fix": "repair"})
    else:
        for rel, *_ in CSE_FILES:
            p, _c = ctx.resolve(guid, rel)
            if p and os.path.isfile(p) and not has_ntacl(p):
                out.append({"level": "fail", "msg": "%s has no Windows (NT) ACL." % rel, "fix": "repair"})
                break
    # settings that exist on disk but whose client-side extension is not registered are ignored by clients
    for rel, side, cse, tool in CSE_FILES:
        p, _c = ctx.resolve(guid, rel)
        if not (p and os.path.isfile(p)) or os.path.getsize(p) < 12 and rel.endswith("Registry.pol"):
            continue
        attr = g["machine_exts"] if side == "machine" else g["user_exts"]
        if cse.upper() not in parse_exts(attr):
            out.append({"level": "fail", "msg": "%s exists but its client-side extension %s is not registered on the GPO, so Windows ignores those settings." % (rel, cse), "fix": "repair"})
    flags = g["flags"]
    if flags:
        out.append({"level": "info", "msg": "GPO status is \"%s\"." % ["Enabled", "User configuration disabled", "Computer configuration disabled", "All settings disabled"][flags]})
    return out


def cmd_health(ctx, req):
    res = []
    for g in cmd_list_gpos(ctx, {}):
        try:
            f = gpo_findings(ctx, g)
        except Exception as e:  # noqa: BLE001
            f = [{"level": "fail", "msg": "Could not inspect: %s" % e}]
        res.append({"guid": g["guid"], "name": g["name"], "findings": f})
    # links that point at a GPO that no longer exists
    known = {g["guid"].upper() for g in cmd_list_gpos(ctx, {})}
    dangling = []
    for c in cmd_list_containers(ctx, {}):
        for l in c["links"]:
            if l["guid"].upper() not in known:
                dangling.append({"container": c["dn"], "guid": l["guid"]})
    return {"gpos": res, "dangling_links": dangling}


def cmd_repair_gpo(ctx, req):
    """Make the GPO consistent: folders, GPT.INI, NT ACLs on everything, CSE registration."""
    guid = req["guid"].upper()
    g = [x for x in cmd_list_gpos(ctx, {}) if x["guid"].upper() == guid]
    if not g:
        raise ValueError("GPO not found")
    g = g[0]
    done = []
    gdir = os.path.join(ctx.policies_dir(), ctx.find(ctx.policies_dir(), guid) or guid)
    if not os.path.isdir(gdir):
        os.mkdir(gdir, 0o755)
        done.append("created the SYSVOL folder")
    for sub in ("Machine", "User"):
        p, _ = ctx.resolve(guid, sub)
        if p is None:
            os.mkdir(os.path.join(gdir, sub), 0o755)
            done.append("created %s folder" % sub)
    gpt = ctx.load(guid, "GPT.INI")
    want = "[General]\r\nVersion=%d\r\n" % g["version"]
    if gpt is None:
        ctx.save(guid, "GPT.INI", want.encode(), None, stamp=False)
        done.append("recreated GPT.INI")
    else:
        t = gpt.decode("utf-8", "replace")
        m = re.search(r"^Version\s*=\s*(\d+)", t, re.M | re.I)
        if not m or int(m.group(1)) != g["version"]:
            t = (t[:m.start()] + "Version=%d" % g["version"] + t[m.end():]) if m else "[General]\r\nVersion=%d\r\n" % g["version"] + t
            ctx.save(guid, "GPT.INI", t.encode(), None, stamp=False)
            done.append("synchronised GPT.INI version with Active Directory (%d)" % g["version"])
    n = 0
    for dirpath, dirs, files in os.walk(gdir):
        for name in dirs + files:
            ctx.stamp_acl(guid, os.path.join(dirpath, name))
            n += 1
    ctx.stamp_acl(guid, gdir)
    done.append("applied the GPO's Windows ACL to %d files/folders" % (n + 1))
    me, ue = [], []
    for rel, side, cse, tool in CSE_FILES:
        p, _c = ctx.resolve(guid, rel)
        if p and os.path.isfile(p) and not (rel.endswith("Registry.pol") and os.path.getsize(p) < 12):
            cur = parse_exts(g["machine_exts"] if side == "machine" else g["user_exts"])
            if cse.upper() not in cur or tool.upper() not in cur.get(cse.upper(), []):
                (me if side == "machine" else ue).append((cse, tool))
    if me or ue:
        msg = ldb.Message()
        msg.dn = ctx.gpo_dn(guid)
        for attr, pairs, cur_s in (("gPCMachineExtensionNames", me, g["machine_exts"]), ("gPCUserExtensionNames", ue, g["user_exts"])):
            if pairs:
                d = parse_exts(cur_s)
                for cse, tool in pairs:
                    d.setdefault(cse.upper(), [])
                    if tool.upper() not in d[cse.upper()]:
                        d[cse.upper()].append(tool.upper())
                msg[attr] = ldb.MessageElement(build_exts(d), ldb.FLAG_MOD_REPLACE, attr)
        ctx.samdb.modify(msg)
        done.append("registered %d missing client-side extension(s)" % (len(me) + len(ue)))
    return done


# ---------------------------------------------------------------------
# Microsoft ADMX templates -> domain Central Store
# ---------------------------------------------------------------------
MS_ADMX_URL = "https://download.microsoft.com/download/9159cafd-e6a0-4053-bb43-289376d5f1a7/Administrative Templates (.admx) for Windows 11 Sep 2026 Update.msi"
LANG_RE = re.compile(r"^[a-z]{2,3}(-[A-Za-z0-9]{2,8})+$")


def cmd_admx_status(ctx, req):
    d, _ = ctx.resolve("policies", "PolicyDefinitions")
    out = {"exists": bool(d and os.path.isdir(d)), "admx": 0, "languages": {}, "msiextract": bool(shutil.which("msiextract")),
           "default_url": MS_ADMX_URL}
    if out["exists"]:
        for n in os.listdir(d):
            fp = os.path.join(d, n)
            if os.path.isfile(fp) and n.lower().endswith(".admx"):
                out["admx"] += 1
            elif os.path.isdir(fp) and LANG_RE.match(n):
                out["languages"][n] = len([x for x in os.listdir(fp) if x.lower().endswith(".adml")])
    return out


def _find_policy_definitions(root):
    best = None
    for dirpath, dirs, files in os.walk(root):
        if os.path.basename(dirpath).lower() == "policydefinitions" and any(f.lower().endswith(".admx") for f in files):
            n = len([f for f in files if f.lower().endswith(".admx")])
            if best is None or n > best[0]:
                best = (n, dirpath)
    return best[1] if best else None


def cmd_import_ms_admx(ctx, req):
    """Download (or open) Microsoft's Administrative Templates MSI and copy PolicyDefinitions into the Central Store."""
    import tempfile
    import urllib.parse
    import urllib.request
    langs = req.get("languages") or ["en-US"]
    work = tempfile.mkdtemp(prefix="sadc-admx-")
    try:
        msi = None
        if req.get("path"):
            msi = req["path"]
            if not os.path.isfile(msi) and not os.path.isdir(msi):
                raise ValueError("%s does not exist on this server" % msi)
        else:
            url = req.get("url") or MS_ADMX_URL
            u = urllib.parse.urlparse(url)
            if u.scheme != "https" or not (u.hostname or "").endswith(("download.microsoft.com", "microsoft.com")):
                raise ValueError("For safety only https://*.microsoft.com download links are accepted. Download the file yourself and use the 'file on this server' option.")
            safe = urllib.parse.urlunparse((u.scheme, u.netloc, urllib.parse.quote(u.path), "", u.query, ""))
            msi = os.path.join(work, "templates.msi")
            try:
                with urllib.request.urlopen(urllib.request.Request(safe, headers={"User-Agent": "samba-adc-cockpit"}), timeout=120) as r, open(msi, "wb") as f:
                    total = 0
                    while True:
                        chunk = r.read(1 << 20)
                        if not chunk:
                            break
                        total += len(chunk)
                        if total > 400 << 20:
                            raise ValueError("Download is unexpectedly large; aborting")
                        f.write(chunk)
            except Exception as e:
                raise ValueError("Could not download from Microsoft (%s). If this server has no internet access, download the MSI on another computer, copy it here, and use the 'file on this server' option." % e)
        if os.path.isdir(msi):
            pd = _find_policy_definitions(msi)
        else:
            if not shutil.which("msiextract"):
                raise ValueError("msiextract is not installed. Install the 'msitools' package (apt install msitools) and try again.")
            out = os.path.join(work, "x")
            os.mkdir(out)
            p = subprocess.run(["msiextract", "-C", out, msi], capture_output=True, text=True)
            if p.returncode != 0:
                raise ValueError("msiextract failed: %s" % (p.stderr or p.stdout)[-300:])
            pd = _find_policy_definitions(out)
        if not pd:
            raise ValueError("No PolicyDefinitions folder with .admx files was found in that package")
        n_admx = n_adml = 0
        for name in sorted(os.listdir(pd)):
            fp = os.path.join(pd, name)
            if os.path.isfile(fp) and name.lower().endswith(".admx"):
                with open(fp, "rb") as fh:
                    ctx.save("policies", "PolicyDefinitions/" + name, fh.read(), None)
                n_admx += 1
            elif os.path.isdir(fp) and LANG_RE.match(name) and (langs == ["*"] or name.lower() in [l.lower() for l in langs]):
                for f in sorted(os.listdir(fp)):
                    if f.lower().endswith(".adml"):
                        with open(os.path.join(fp, f), "rb") as fh:
                            ctx.save("policies", "PolicyDefinitions/%s/%s" % (name, f), fh.read(), None)
                        n_adml += 1
        if n_adml == 0:
            raise ValueError("The package has no .adml files for %s; the policy names would be unreadable." % ", ".join(langs))
        return {"admx": n_admx, "adml": n_adml, "languages": langs}
    finally:
        shutil.rmtree(work, ignore_errors=True)


def cmd_read_pol(ctx, req):
    cls = {"machine": "Machine", "user": "User"}[req["class"]]
    d = ctx.load(req["guid"], cls + "/Registry.pol")
    return pol_parse(d)


def cmd_write_pol(ctx, req):
    cls = {"machine": "Machine", "user": "User"}[req["class"]]
    ctx.save(req["guid"], cls + "/Registry.pol", pol_build(req["entries"]), req["guid"])
    cse = ("{35378EAC-683F-11D2-A89A-00C04FBBCFA2}",
           "{D02B1F72-3407-48AE-BA88-E8213C6761F1}" if cls == "Machine" else "{D02B1F73-3407-48AE-BA88-E8213C6761F1}")
    r = dict(req)
    r["bump"] = [req["class"]]
    r["exts"] = {req["class"]: [list(cse)]}
    return finish(ctx, r, guid=req["guid"])


def finish(ctx, req, guid=None):
    """Optional version bump + CSE registration shared by every write command."""
    guid = guid or (req["root"] if req.get("root") not in (None, "policies") else None)
    bump = req.get("bump") or []
    if not guid or not bump:
        return True
    exts = req.get("exts") or {}
    return commit(ctx, guid, machine="machine" in bump, user="user" in bump,
                  machine_exts=[tuple(x) for x in exts.get("machine", [])],
                  user_exts=[tuple(x) for x in exts.get("user", [])])


def cmd_commit(ctx, req):
    return finish(ctx, {"bump": req.get("bump"), "exts": req.get("exts")}, guid=req["guid"])


COMMANDS = {k[4:]: v for k, v in globals().items() if k.startswith("cmd_")}


def main():
    try:
        req = json.loads(sys.stdin.read() or "{}")
        fn = COMMANDS.get(req.get("cmd"))
        if not fn:
            raise ValueError("Unknown command %r" % req.get("cmd"))
        ctx = Ctx(req.get("server"))
        print(json.dumps({"ok": True, "data": fn(ctx, req)}))
    except Exception as e:  # noqa: BLE001
        print(json.dumps({"ok": False, "error": "%s: %s" % (type(e).__name__, e)}))


if __name__ == "__main__":
    main()
