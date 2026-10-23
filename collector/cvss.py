"""Retain all supplied assessments; select a primary without recomputing CVSS."""

import math

VERSIONS = {"cvssV3_1": "3.1", "cvssV4_0": "4.0", "cvssV3_0": "3.0", "cvssV2_0": "2.0"}
ORDER = [
    ("3.1", "cna"),
    ("3.1", "cisa-adp"),
    ("4.0", "cna"),
    ("4.0", "cisa-adp"),
    ("3.0", "cna"),
    ("3.0", "cisa-adp"),
    ("2.0", "cna"),
    ("2.0", "cisa-adp"),
]


def severity(score, version):
    if version == "2.0":
        return "HIGH" if score >= 7 else "MEDIUM" if score >= 4 else "LOW"
    if score == 0:
        return "NONE"
    return "CRITICAL" if score >= 9 else "HIGH" if score >= 7 else "MEDIUM" if score >= 4 else "LOW"


def assessments(cna, adps):
    metrics = []
    containers = [("cna", cna)]
    for container in adps:
        name = container.get("providerMetadata", {}).get("shortName", "")
        containers.append(
            ("cisa-adp" if name.upper().startswith("CISA") else "adp:" + name, container)
        )
    for source, container in containers:
        for metric in container.get("metrics", []):
            for key, version in VERSIONS.items():
                if key not in metric:
                    continue
                value = metric[key]
                score = float(value["baseScore"])
                if not math.isfinite(score) or not 0 <= score <= 10:
                    raise ValueError("Invalid CVSS base score")
                metrics.append(
                    {
                        "version": version,
                        "source": source,
                        "score": score,
                        "vector": value.get("vectorString"),
                        "metrics": value,
                    }
                )
    candidates = [value for value in metrics if (value["version"], value["source"]) in ORDER]
    primary = min(
        candidates, key=lambda value: ORDER.index((value["version"], value["source"])), default=None
    )
    return {
        "cvss_metrics": metrics,
        "cvss": primary["score"] if primary else None,
        "cvss_version": primary["version"] if primary else None,
        "cvss_vector": primary["vector"] if primary else None,
        "cvss_source": primary["source"] if primary else None,
        "severity": severity(primary["score"], primary["version"]) if primary else None,
    }
