"""Running the rules, scoring the result, and emitting SARIF.

Two decisions here are about being usable in CI rather than about detection.

**Findings are attributed to the stage that ships.** The rules already skip
builder stages; the scanner records which stage a finding came from so a
reviewer can see the reasoning rather than trusting it.

**Baselining is by finding identity, not by count.** "We had 12 findings and now
we have 12" passes a check while a critical replaces a low. A baseline here is
the set of accepted finding ids, so a *new* finding fails even when the total
did not move.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .dockerfile import Dockerfile
from .rules import (
    DEFAULT_APPROVED_BASES,
    DOCKERFILE_RULES,
    Finding,
    RuntimeConfig,
    Severity,
    check_runtime,
)

SEVERITY_WEIGHT = {
    Severity.CRITICAL: 25,
    Severity.HIGH: 10,
    Severity.MEDIUM: 4,
    Severity.LOW: 1,
}


@dataclass
class Report:
    findings: list[Finding] = field(default_factory=list)
    dockerfiles: list[str] = field(default_factory=list)
    runtimes: list[str] = field(default_factory=list)
    stages_scanned: int = 0

    @property
    def score(self) -> int:
        """0-100, where 100 is nothing found.

        Severity-weighted, so ten low findings never outweigh one critical.
        Reported next to the counts, never instead of them.
        """
        penalty = sum(SEVERITY_WEIGHT[f.severity] for f in self.findings)
        return max(0, 100 - penalty)

    @property
    def grade(self) -> str:
        for threshold, letter in ((90, "A"), (75, "B"), (60, "C"), (40, "D"), (20, "E")):
            if self.score >= threshold:
                return letter
        return "F"

    def by_severity(self) -> dict[Severity, int]:
        counts = {severity: 0 for severity in Severity}
        for finding in self.findings:
            counts[finding.severity] += 1
        return counts

    def worst(self) -> Severity | None:
        return max((f.severity for f in self.findings), key=lambda s: s.rank, default=None)

    def to_dict(self) -> dict[str, Any]:
        return {
            "score": self.score,
            "grade": self.grade,
            "dockerfiles": self.dockerfiles,
            "runtime_files": self.runtimes,
            "stages_scanned": self.stages_scanned,
            "counts": {s.value: n for s, n in self.by_severity().items()},
            "findings": [f.to_dict() for f in self.findings],
        }


def finding_id(finding: Finding) -> str:
    """A stable identity for baselining.

    Rule plus location plus stage — deliberately not the message text, so
    rewording a rule does not invalidate every baseline that referenced it.
    """
    return f"{finding.rule}:{finding.where or ''}:{finding.stage}:{finding.line}"


def scan_dockerfile(
    dockerfile: Dockerfile,
    *,
    approved: tuple[str, ...] = DEFAULT_APPROVED_BASES,
    skip: frozenset[str] = frozenset(),
) -> list[Finding]:
    """Run the Dockerfile rules against the stages that ship."""
    findings: list[Finding] = []
    for stage in dockerfile.shipping_stages():
        for rule in DOCKERFILE_RULES:
            if rule.id in skip:
                continue
            findings.extend(
                rule.check(rule, dockerfile, stage, approved=approved)
            )

    # HC008 (secrets) is the exception: a secret in a builder stage is still in
    # the build cache and in any pushed intermediate layer, so it is checked
    # against every stage rather than only the one that ships.
    if "HC008" not in skip:
        secrets_rule = next(r for r in DOCKERFILE_RULES if r.id == "HC008")
        shipping = {s.label for s in dockerfile.shipping_stages()}
        for stage in dockerfile.stages:
            if stage.label in shipping:
                continue
            findings.extend(secrets_rule.check(secrets_rule, dockerfile, stage))

    for finding in findings:
        object.__setattr__(finding, "where", dockerfile.path)
    return findings


def scan(
    dockerfiles: list[Dockerfile] | None = None,
    runtimes: list[RuntimeConfig] | None = None,
    *,
    approved: tuple[str, ...] = DEFAULT_APPROVED_BASES,
    skip: frozenset[str] = frozenset(),
    baseline: set[str] | None = None,
) -> Report:
    """Scan everything supplied and return one report."""
    report = Report()

    for dockerfile in dockerfiles or []:
        report.dockerfiles.append(dockerfile.path)
        report.stages_scanned += len(dockerfile.stages)
        report.findings.extend(scan_dockerfile(dockerfile, approved=approved, skip=skip))

    for config in runtimes or []:
        if config.source not in report.runtimes:
            report.runtimes.append(config.source)
        report.findings.extend(f for f in check_runtime(config) if f.rule not in skip)

    if baseline:
        report.findings = [f for f in report.findings if finding_id(f) not in baseline]

    report.findings.sort(
        key=lambda f: (-f.severity.rank, f.rule, f.where, f.stage)
    )
    return report


def write_baseline(report: Report, path: str | Path) -> Path:
    """Accept the current findings, so only new ones fail from now on."""
    out = Path(path)
    out.write_text(
        json.dumps(
            {
                "note": (
                    "Accepted findings. Identity is rule+file+stage+line, so a NEW "
                    "finding still fails even when the total count is unchanged."
                ),
                "accepted": sorted(finding_id(f) for f in report.findings),
            },
            indent=2,
        ),
        encoding="utf-8",
    )
    return out


def read_baseline(path: str | Path) -> set[str]:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    return set(data.get("accepted", []))


def to_sarif(report: Report) -> dict[str, Any]:
    """SARIF 2.1.0, so GitHub code scanning renders the findings inline.

    ``security-severity`` is the numeric field GitHub actually sorts on; a
    SARIF file without it shows every finding as a warning regardless of what
    the level says.
    """
    numeric = {
        Severity.CRITICAL: "9.5", Severity.HIGH: "8.0",
        Severity.MEDIUM: "5.0", Severity.LOW: "2.0",
    }
    level = {
        Severity.CRITICAL: "error", Severity.HIGH: "error",
        Severity.MEDIUM: "warning", Severity.LOW: "note",
    }

    seen: dict[str, Finding] = {}
    for finding in report.findings:
        seen.setdefault(finding.rule, finding)

    rules = [
        {
            "id": rule_id,
            "name": example.title.replace(" ", ""),
            "shortDescription": {"text": example.title},
            "fullDescription": {"text": example.detail},
            "help": {"text": example.fix},
            "defaultConfiguration": {"level": level[example.severity]},
            "properties": {
                "security-severity": numeric[example.severity],
                "tags": ["security", "container", *example.references],
            },
        }
        for rule_id, example in sorted(seen.items())
    ]

    results = []
    for finding in report.findings:
        start_line = 1
        if finding.line:
            try:
                start_line = int(str(finding.line).split("-")[0])
            except ValueError:
                start_line = 1
        results.append(
            {
                "ruleId": finding.rule,
                "level": level[finding.severity],
                "message": {"text": f"{finding.detail}. Fix: {finding.fix}"},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": finding.where or "Dockerfile"},
                            "region": {"startLine": start_line},
                        }
                    }
                ],
                "properties": {"stage": finding.stage},
            }
        )

    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "container-hardening-scanner",
                        "informationUri": (
                            "https://github.com/Vincent-P-essy/container-hardening-scanner"
                        ),
                        "rules": rules,
                    }
                },
                "results": results,
            }
        ],
    }
