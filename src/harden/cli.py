"""Command line interface."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from . import __version__
from .dockerfile import DockerfileError
from .dockerfile import load as load_dockerfile
from .rules import DEFAULT_APPROVED_BASES, DOCKERFILE_RULES, Severity
from .runtime import RuntimeError_
from .runtime import load as load_runtime
from .scanner import read_baseline, scan, to_sarif, write_baseline

SEVERITY_STYLE = {
    Severity.CRITICAL: "bright_red",
    Severity.HIGH: "red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "cyan",
}


def _discover(paths: list[str]) -> tuple[list[Path], list[Path]]:
    """Split the inputs into Dockerfiles and runtime manifests."""
    dockerfiles: list[Path] = []
    runtimes: list[Path] = []

    for raw in paths:
        path = Path(raw)
        candidates = (
            [p for p in sorted(path.rglob("*")) if p.is_file()]
            if path.is_dir()
            else [path]
        )
        for candidate in candidates:
            name = candidate.name.lower()
            if name.startswith("dockerfile") or name.endswith(".dockerfile"):
                dockerfiles.append(candidate)
            elif candidate.suffix in (".yaml", ".yml"):
                runtimes.append(candidate)
    return dockerfiles, runtimes


def cmd_scan(args: argparse.Namespace, console: Console) -> int:
    dockerfile_paths, runtime_paths = _discover(args.path)
    if not dockerfile_paths and not runtime_paths:
        console.print(
            "[red]nothing to scan[/] — pass a Dockerfile, a compose file, a "
            "Kubernetes manifest, or a directory containing them"
        )
        return 2

    dockerfiles = [load_dockerfile(p) for p in dockerfile_paths]
    runtimes = []
    for path in runtime_paths:
        try:
            runtimes.extend(load_runtime(path))
        except RuntimeError_:
            # A YAML file that is neither compose nor a workload is not an
            # error: directories are full of unrelated YAML.
            continue

    approved = (
        tuple(a.strip() for a in args.approved_bases.split(",") if a.strip())
        if args.approved_bases
        else DEFAULT_APPROVED_BASES
    )
    baseline = (
        read_baseline(args.baseline)
        if args.baseline and Path(args.baseline).exists()
        else None
    )

    report = scan(
        dockerfiles, runtimes,
        approved=approved,
        skip=frozenset(args.skip.split(",")) if args.skip else frozenset(),
        baseline=baseline,
    )

    if args.write_baseline:
        path = write_baseline(report, args.write_baseline)
        console.print(
            f"[green]wrote[/] {path} — {len(report.findings)} finding(s) accepted. "
            "A new finding will still fail even if the total does not change."
        )
        return 0

    if args.sarif:
        Path(args.sarif).write_text(json.dumps(to_sarif(report), indent=2), encoding="utf-8")
        console.print(f"[dim]wrote {args.sarif}[/]")
    if args.json:
        Path(args.json).write_text(json.dumps(report.to_dict(), indent=2), encoding="utf-8")
        console.print(f"[dim]wrote {args.json}[/]")

    _render(report, console, args)

    if args.fail_over:
        threshold = Severity(args.fail_over)
        breaching = [f for f in report.findings if f.severity.rank >= threshold.rank]
        if breaching:
            console.print(
                f"\n[bold red]FAIL[/] {len(breaching)} finding(s) at "
                f"{args.fail_over} or above"
            )
            return 1
    return 0


def _render(report, console: Console, args) -> None:
    counts = report.by_severity()
    header = Text()
    header.append(f"score {report.score}/100  ", style="bold")
    style = "green" if report.grade in "AB" else "yellow" if report.grade == "C" else "bright_red"
    header.append(f"grade {report.grade}\n", style=f"bold {style}")
    header.append(
        f"{len(report.dockerfiles)} Dockerfile(s), {report.stages_scanned} stage(s), "
        f"{len(report.runtimes)} runtime file(s)\n",
        style="dim",
    )
    for severity in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW):
        header.append(f"{counts[severity]} {severity.value}   ", style=SEVERITY_STYLE[severity])
    console.print(Panel(header, title="container hardening", border_style="blue", expand=False))

    if not report.findings:
        console.print("[bold green]nothing found.[/]")
        return

    table = Table(header_style="dim", show_lines=False)
    table.add_column("rule", style="bold")
    table.add_column("sev")
    table.add_column("where", style="cyan", overflow="fold")
    table.add_column("what is wrong", overflow="fold")
    table.add_column("fix", style="dim", overflow="fold")

    for finding in report.findings[: args.limit]:
        location = finding.where or ""
        if finding.line:
            location += f":{finding.line}"
        if finding.stage and len(report.dockerfiles) + len(report.runtimes) > 1:
            location += f" [{finding.stage}]"
        table.add_row(
            finding.rule,
            Text(finding.severity.value, style=SEVERITY_STYLE[finding.severity]),
            location,
            finding.detail,
            finding.fix,
        )
    console.print(table)
    if len(report.findings) > args.limit:
        console.print(f"[dim]... and {len(report.findings) - args.limit} more[/]")


def cmd_rules(args: argparse.Namespace, console: Console) -> int:
    from .rules import DANGEROUS_CAPABILITIES

    table = Table(title="Dockerfile rules", title_style="bold", header_style="dim")
    table.add_column("id", style="bold")
    table.add_column("sev")
    table.add_column("finds", overflow="fold")
    table.add_column("references", style="dim")
    for rule in DOCKERFILE_RULES:
        table.add_row(
            rule.id,
            Text(rule.severity.value, style=SEVERITY_STYLE[rule.severity]),
            rule.title,
            ", ".join(rule.references) or "—",
        )
    console.print(table)

    runtime_rules = [
        ("RT001", Severity.CRITICAL, "Container runs privileged"),
        ("RT002", Severity.CRITICAL, "Docker socket mounted into the container"),
        ("RT003", Severity.HIGH, "No non-root user set at runtime"),
        ("RT004", Severity.HIGH, "no-new-privileges is not set"),
        ("RT005", Severity.MEDIUM, "Default capability set retained"),
        ("RT006", Severity.CRITICAL, "Dangerous capability granted"),
        ("RT007", Severity.MEDIUM, "Root filesystem is writable"),
        ("RT008", Severity.CRITICAL, "Host PID namespace shared"),
        ("RT009", Severity.HIGH, "Host network namespace shared"),
        ("RT010", Severity.MEDIUM, "No memory limit"),
        ("RT011", Severity.HIGH, "seccomp disabled"),
        ("RT012", Severity.CRITICAL, "Sensitive host path mounted"),
    ]
    table = Table(
        title="Runtime rules — compose and Kubernetes",
        title_style="bold", header_style="dim",
    )
    table.add_column("id", style="bold")
    table.add_column("sev")
    table.add_column("finds", overflow="fold")
    for rule_id, severity, title in runtime_rules:
        table.add_row(rule_id, Text(severity.value, style=SEVERITY_STYLE[severity]), title)
    console.print(table)
    console.print(
        "\n[dim]None of the RT rules is expressible in a Dockerfile. A perfect "
        "Dockerfile still runs privileged if the deployment says so.[/]\n"
    )
    console.print(f"[dim]Capabilities treated as dangerous: "
                  f"{', '.join(sorted(DANGEROUS_CAPABILITIES))}[/]")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="harden",
        description="Container hardening for Dockerfiles and the runtime config around them.",
    )
    parser.add_argument("--version", action="version", version=f"harden {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("scan", help="scan Dockerfiles and runtime manifests")
    p.add_argument("path", nargs="+")
    p.add_argument("--approved-bases", help="comma-separated allowlist of base images")
    p.add_argument("--skip", help="comma-separated rule ids to ignore")
    p.add_argument("--baseline", help="accepted findings JSON")
    p.add_argument("--write-baseline", help="accept the current findings and write them here")
    p.add_argument("--sarif", help="write SARIF for GitHub code scanning")
    p.add_argument("--json", help="write the full report here")
    p.add_argument("--limit", type=int, default=25)
    p.add_argument(
        "--fail-over", choices=[s.value for s in Severity],
        help="exit 1 when a finding reaches this severity",
    )
    p.set_defaults(func=cmd_scan)

    p = sub.add_parser("rules", help="list every rule")
    p.set_defaults(func=cmd_rules)

    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    console = Console()
    try:
        return int(args.func(args, console))
    except (DockerfileError, RuntimeError_) as exc:
        console.print(f"[bold red]error:[/] {exc}")
        return 2
    except (OSError, ValueError) as exc:
        console.print(f"[bold red]error:[/] {exc}")
        return 2
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    sys.exit(main())
