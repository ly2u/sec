"""Verified OSV package naming and the explicitly supported standard channels."""

import re

BASES = {
    "Debian": "debian",
    "Ubuntu": "ubuntu",
    "Alpine": "alpine",
    "Rocky Linux": "rocky",
    "AlmaLinux": "alma",
}
RELEASES = {
    "debian": ["11", "12", "13"],
    "ubuntu": ["20.04", "22.04", "24.04"],
    "rocky": ["8", "9"],
    "alma": ["8", "9"],
    "alpine": ["3.22", "3.23", "3.24"],
}
PACKAGE_KEYS = {
    "debian": "source",
    "ubuntu": "source",
    "alpine": "origin",
    "rocky": "source",
    "alma": "binary",
}
PACKAGE_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9+_.-]{0,255}")
VERSION = re.compile(r"[A-Za-z0-9][A-Za-z0-9.+:~^_*_-]{0,255}")


def coordinate(ecosystem):
    base, separator, suffix = ecosystem.partition(":")
    if base not in BASES or not separator:
        return None
    distro = BASES[base]
    if distro == "ubuntu":
        match = re.fullmatch(r"(?:(Pro):)?(\d{2}\.\d{2}):LTS", suffix)
        if not match:
            return None  # FIPS/realtime channels must never masquerade as the standard kernel.
        release, subscription = match[2], bool(match[1])
    else:
        release = suffix.removeprefix("v") if distro == "alpine" else suffix
        subscription = False
    if release not in RELEASES[distro]:
        return None
    return distro, release, subscription
