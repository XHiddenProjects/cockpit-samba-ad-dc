#!/usr/bin/env python3
"""
Consistency checks for one extension directory. Run in CI and by `make check`.

  python3 scripts/check_package.py samba-adc            # verify
  python3 scripts/check_package.py samba-adc --files    # print the runtime file list (used by `make dist`)

Verifies that
  * manifest.json is valid JSON and its "name" equals the directory name,
  * every file the installer copies exists,
  * every asset the page loads (<script src>, <link href>, fetch("x.py")) is in the installer's list,
  * VERSION, package.json and the top CHANGELOG entry agree.
"""
import json
import os
import re
import sys


def main():
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    if len(args) != 1:
        sys.exit(__doc__)
    ext = args[0].rstrip("/")
    name = os.path.basename(os.path.abspath(ext))
    errors = []

    def p(*a):
        return os.path.join(ext, *a)

    inst = open(p("install.sh")).read()
    m = re.search(r"RUNTIME_FILES=\(\s*(.*?)\s*\)", inst, re.S)
    if not m:
        sys.exit("install.sh has no RUNTIME_FILES=( ... ) list")
    files = m.group(1).split()
    if "--files" in sys.argv:
        print("\n".join(files))
        return

    try:
        manifest = json.load(open(p("manifest.json")))
        if manifest.get("name") != name:
            errors.append('manifest.json "name" is %r but the directory is %r' % (manifest.get("name"), name))
    except Exception as e:  # noqa: BLE001
        errors.append("manifest.json: %s" % e)

    for f in files:
        if not os.path.isfile(p(f)):
            errors.append("installer lists %s but it does not exist" % f)

    refs = set()
    html = open(p("index.html")).read()
    refs.update(re.findall(r'(?:src|href)="([^"#:]+)"', html))
    for js in [f for f in files if f.endswith(".js") and os.path.isfile(p(f))]:
        refs.update(re.findall(r'fetch\(\s*"([^"]+\.(?:py|json|js|html|css))"', open(p(js)).read()))
        refs.update(re.findall(r'(?:py|backend\w*)\(\s*"([a-z_]+\.py)"', open(p(js)).read()))
    for r in sorted(refs):
        if r.startswith("../"):  # Cockpit's own base1/cockpit.js
            continue
        if r not in files:
            errors.append("the page loads %s but install.sh does not install it" % r)

    version = open(p("VERSION")).read().strip()
    if not re.fullmatch(r"\d+\.\d+\.\d+", version):
        errors.append("VERSION %r is not MAJOR.MINOR.PATCH" % version)
    if os.path.isfile(p("package.json")):
        pv = json.load(open(p("package.json"))).get("version")
        if pv != version:
            errors.append("package.json version %s != VERSION %s" % (pv, version))
    if os.path.isfile(p("CHANGELOG.md")):
        top = re.search(r"^## \[?v?(\d+\.\d+\.\d+)", open(p("CHANGELOG.md")).read(), re.M)
        if not top or top.group(1) != version:
            errors.append("top CHANGELOG.md entry (%s) != VERSION %s" % (top.group(1) if top else "none", version))
    else:
        errors.append("CHANGELOG.md is missing")

    if errors:
        print("%s: %d problem(s)" % (name, len(errors)))
        for e in errors:
            print("  - " + e)
        sys.exit(1)
    print("%s %s: package is consistent (%d runtime files, %d page references checked)" % (name, version, len(files), len(refs)))


if __name__ == "__main__":
    main()
