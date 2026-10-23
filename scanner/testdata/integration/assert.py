"""Assertions for one container scan (see run.sh)."""

import json
import sys

path, code, want, pkg = sys.argv[1], int(sys.argv[2]), sys.argv[3], sys.argv[4]
errors = []
try:
    report = json.load(open(path))
except Exception as exc:  # noqa: BLE001
    print(f"report is not valid JSON (exit code {code}): {exc}")
    print(open(path).read()[:600])
    sys.exit(1)

findings = {f["id"]: f for f in report["findings"]}
affected = findings.get("CVE-2099-1001")
if not affected:
    errors.append(f"CVE-2099-1001 not reported for {pkg}; findings: {list(findings)}")
else:
    if affected["status"] != want:
        errors.append(f"status {affected['status']}, want {want}")
    if affected["package"] != pkg:
        errors.append(f"package {affected['package']}, want {pkg}")
    if affected["priority"] != "P0":
        errors.append(f"KEV finding must be P0, got {affected['priority']}")
    if not affected["binaries"]:
        errors.append("no installed binaries attributed")
if "CVE-2099-1002" in findings:
    errors.append("CVE-2099-1002 is fixed by the installed version but was reported")
if report["summary"]["already_fixed"] < 1:
    errors.append("already_fixed must count CVE-2099-1002")
if report["summary"]["packages"] < 5:
    errors.append(f"too few packages read: {report['summary']['packages']}")
if code != 3:
    errors.append(f"exit code {code}, want 3 (P0 present)")

for e in errors:
    print("  -", e)
sys.exit(1 if errors else 0)
