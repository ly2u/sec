"""Assertions for the live L2 container scan (see run.sh)."""

import json
import sys

report = json.load(open(sys.argv[1]))
executed = sys.argv[2] == "yes"
errors = []
l2 = {(f["package"], f["installed_version"]): f for f in report["findings"] if f.get("layer") == "L2"}
want = {("nginx", "1.28.0"): "1.30.6", ("OpenSSL", "1.1.1w"): "3.0.18", ("PHP", "8.3.10"): "8.3.36"}
for key, fix in want.items():
    f = l2.get(key)
    if not f:
        errors.append(f"missing L2 finding {key}; have {list(l2)}")
    elif f["fixed_version"] != fix or f["method"] != "baota" or f["status"] != "CONFIRMED_AFFECTED":
        errors.append(f"{key}: fix={f['fixed_version']} method={f['method']} status={f['status']}")
openssl = l2.get(("OpenSSL", "1.1.1w"))
if openssl and "编译进 nginx" not in openssl.get("guidance", ""):
    errors.append("bundled OpenSSL guidance must explain it is compiled into nginx")
redis = [i for i in report["l2"]["installs"] if i["product"] == "redis"]
if not redis or redis[0].get("version") or "root" not in redis[0].get("note", ""):
    errors.append(f"non-root-owned redis-server must be listed without a version: {redis}")
if executed:
    errors.append("SECURITY: the non-root-owned redis-server was executed")
for e in errors:
    print("  -", e)
sys.exit(1 if errors else 0)
