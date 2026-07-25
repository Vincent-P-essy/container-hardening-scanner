"""The rules, and the runtime checks a Dockerfile linter cannot make.

Two things separate this from Hadolint, and both are about scope rather than
cleverness.

**Rules apply to the stage that ships.** A `USER root` in a builder stage is not
a finding — nothing from that stage reaches production. Reporting it is how a
linter earns the reputation that gets it removed from CI.

**Half the hardening is not in the Dockerfile at all.** `no-new-privileges`,
dropped capabilities, a read-only root filesystem, seccomp — none of these are
Dockerfile directives. A perfect Dockerfile still runs privileged if the
compose file or the pod spec says so, so the runtime configuration is checked
as a first-class input rather than assumed.

Each rule names the change to make, not the principle to consider. "Set a
non-root USER" is actionable; "follow least privilege" is not.
"""

from __future__ import annotations

import enum
import re
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from typing import Any

from .dockerfile import Dockerfile, Stage


class Severity(str, enum.Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"

    @property
    def rank(self) -> int:
        return ["low", "medium", "high", "critical"].index(self.value)


@dataclass(frozen=True)
class Finding:
    rule: str
    severity: Severity
    title: str
    detail: str
    fix: str
    where: str = ""
    line: str = ""
    stage: str = ""
    references: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule": self.rule,
            "severity": self.severity.value,
            "title": self.title,
            "detail": self.detail,
            "fix": self.fix,
            "where": self.where,
            "line": self.line,
            "stage": self.stage,
            "references": list(self.references),
        }


@dataclass(frozen=True)
class Rule:
    id: str
    severity: Severity
    title: str
    check: Callable[..., Iterator[Finding]]
    references: tuple[str, ...] = ()
    #: True when the rule reads runtime configuration rather than the Dockerfile.
    runtime: bool = False


#: Base images that are officially maintained and small enough that the CVE
#: surface is defensible. Not a security boundary - a starting point a team
#: overrides with its own approved registry.
DEFAULT_APPROVED_BASES = (
    "alpine", "debian", "ubuntu", "gcr.io/distroless", "cgr.dev/chainguard",
    "python", "node", "golang", "eclipse-temurin", "registry.access.redhat.com/ubi9",
    "scratch",
)

#: `\b` does not match between an underscore and a letter, so a naive
#: `\bpassword` misses `DATABASE_PASSWORD=` - which is how the variable is
#: actually spelled almost every time.
SECRET_PATTERNS = (
    (re.compile(r"(?i)[\w-]*(?:password|passwd|pwd)[\w-]*\s*=\s*\S+"), "a password"),
    (re.compile(r"(?i)[\w-]*(?:secret|token|api[_-]?key)[\w-]*\s*=\s*\S+"),
     "a secret or token"),
    (re.compile(r"AKIA[0-9A-Z]{16}"), "an AWS access key id"),
    (re.compile(r"(?i)-----BEGIN [A-Z ]*PRIVATE KEY-----"), "a private key"),
    (re.compile(r"(?i)\bghp_[A-Za-z0-9]{20,}"), "a GitHub token"),
)


def _f(
    rule: Rule, detail: str, fix: str, *, line: str = "", stage: str = "", where: str = ""
) -> Finding:
    return Finding(
        rule=rule.id, severity=rule.severity, title=rule.title, detail=detail,
        fix=fix, line=line, stage=stage, where=where, references=rule.references,
    )


# -- Dockerfile rules -------------------------------------------------------


def _check_user(rule: Rule, dockerfile: Dockerfile, stage: Stage, **_: Any):
    user = stage.last("USER")
    if user is None:
        if stage.is_scratch:
            return
        yield _f(
            rule,
            "the shipping stage declares no USER, so the container runs as root",
            "add a non-root USER as the last instruction before CMD, and chown "
            "anything it needs to write",
            stage=stage.label,
        )
        return
    name = (user.words() or [""])[0].split(":")[0]
    if name in ("root", "0"):
        yield _f(
            rule,
            f"the shipping stage ends as {name!r}",
            "switch to a non-root user. If a step needs root, do it earlier and "
            "put the USER instruction last",
            line=user.lines, stage=stage.label,
        )


def _check_tag(rule: Rule, dockerfile: Dockerfile, stage: Stage, **_: Any):
    if stage.is_scratch:
        return
    tag = stage.base_tag
    if not tag:
        yield _f(
            rule, f"{stage.base} has no tag, so it resolves to :latest",
            f"pin a version: FROM {stage.base}:<version>, or a digest for "
            "reproducibility",
            line=stage.instructions[0].lines, stage=stage.label,
        )
    elif tag == "latest":
        yield _f(
            rule, f"{stage.base} is pinned to :latest, which moves under you",
            "pin an explicit version; a rebuild months later should produce the "
            "same image",
            line=stage.instructions[0].lines, stage=stage.label,
        )


def _check_digest(rule: Rule, dockerfile: Dockerfile, stage: Stage, **_: Any):
    if stage.is_scratch or stage.pinned_by_digest:
        return
    yield _f(
        rule, f"{stage.base} is not pinned by digest",
        f"pin the digest: FROM {stage.base}@sha256:<digest>. A tag can be moved; "
        "a digest cannot",
        line=stage.instructions[0].lines, stage=stage.label,
    )


def _check_approved_base(rule: Rule, dockerfile: Dockerfile, stage: Stage,
                         approved: tuple[str, ...] = DEFAULT_APPROVED_BASES, **_: Any):
    if stage.is_scratch:
        return
    image = stage.base_image.lower()
    if any(image == a or image.startswith(a + "/") or image.startswith(a) for a in approved):
        return
    yield _f(
        rule, f"{stage.base_image} is not in the approved base-image list",
        f"use an approved base, or add {stage.base_image} to --approved-bases "
        "with a recorded reason",
        line=stage.instructions[0].lines, stage=stage.label,
    )


def _check_apt_recommends(rule: Rule, dockerfile: Dockerfile, stage: Stage, **_: Any):
    for instruction in stage.find("RUN"):
        for command in instruction.commands():
            if not re.search(r"\bapt-get\s+install\b", command):
                continue
            if "--no-install-recommends" in command:
                continue
            yield _f(
                rule,
                "apt-get install without --no-install-recommends pulls in "
                "packages nothing asked for",
                "add --no-install-recommends, and apt-get clean plus "
                "rm -rf /var/lib/apt/lists/* in the same RUN",
                line=instruction.lines, stage=stage.label,
            )


def _check_apt_cache(rule: Rule, dockerfile: Dockerfile, stage: Stage, **_: Any):
    for instruction in stage.find("RUN"):
        commands = instruction.commands()
        installs = any(re.search(r"\bapt-get\s+install\b", c) for c in commands)
        if not installs:
            continue
        cleaned = any(
            re.search(r"rm\s+-rf?\s+/var/lib/apt/lists", c) or "apt-get clean" in c
            for c in commands
        )
        if not cleaned:
            yield _f(
                rule,
                "the apt lists are left in the layer, adding tens of megabytes "
                "that cannot be removed later",
                "end the same RUN with: rm -rf /var/lib/apt/lists/*",
                line=instruction.lines, stage=stage.label,
            )


def _check_add(rule: Rule, dockerfile: Dockerfile, stage: Stage, **_: Any):
    for instruction in stage.find("ADD"):
        value = instruction.value
        if "--from=" in value:
            continue
        remote = re.search(r"https?://", value)
        archive = re.search(r"\.(?:tar|tgz|tar\.gz|tar\.bz2|tar\.xz|zip)\b", value)
        if remote:
            yield _f(
                rule,
                "ADD fetches a URL, with no checksum and no way to see what "
                "arrived",
                "use RUN curl -fsSL <url> -o file && echo '<sha256>  file' | "
                "sha256sum -c -, then extract",
                line=instruction.lines, stage=stage.label,
            )
        elif archive:
            yield _f(
                rule,
                "ADD silently extracts archives, so the layer contents depend on "
                "the archive rather than on the Dockerfile",
                "use COPY and extract explicitly with RUN tar",
                line=instruction.lines, stage=stage.label,
            )
        else:
            yield _f(
                rule, "ADD used where COPY would do",
                "use COPY: it does exactly one thing",
                line=instruction.lines, stage=stage.label,
            )


def _check_secrets(rule: Rule, dockerfile: Dockerfile, stage: Stage, **_: Any):
    # Every stage, not just the shipping one: a secret in a builder stage is
    # still in the build cache and in any pushed intermediate layer.
    for instruction in stage.instructions:
        if instruction.keyword not in ("ENV", "ARG", "RUN", "LABEL"):
            continue
        # A value that is obviously a placeholder or an injection point is not
        # a leaked secret. Flagging ARG API_TOKEN= or ENV PWD=${DB_PWD} trains
        # people to skip the rule that matters.
        if _is_placeholder(instruction.value):
            continue
        for pattern, what in SECRET_PATTERNS:
            if pattern.search(instruction.value):
                yield _f(
                    rule,
                    f"{instruction.keyword} on line {instruction.lines} appears to "
                    f"contain {what}",
                    "remove it and rotate it — it is in the image layers and the "
                    "build cache. Use a build secret (RUN --mount=type=secret) or "
                    "inject at runtime",
                    line=instruction.lines, stage=stage.label,
                )
                break


_PLACEHOLDER_VALUE = re.compile(
    r"=\s*(?:$|\"\"|\'\'|\$[\{(]|<[^>]*>|changeme\b|xxx+\b|\.\.\.)", re.IGNORECASE
)


def _is_placeholder(value: str) -> bool:
    """True when the assignment has no actual secret on the right of the `=`."""
    return bool(_PLACEHOLDER_VALUE.search(value))


def _check_healthcheck(rule: Rule, dockerfile: Dockerfile, stage: Stage, **_: Any):
    if not stage.find("HEALTHCHECK"):
        yield _f(
            rule, "no HEALTHCHECK, so the orchestrator cannot tell a wedged "
                  "container from a working one",
            "add a HEALTHCHECK that exercises the actual service, not just the "
            "process being alive",
            stage=stage.label,
        )


def _check_curl_bash(rule: Rule, dockerfile: Dockerfile, stage: Stage, **_: Any):
    for instruction in stage.find("RUN"):
        if re.search(r"(?:curl|wget)[^|]*\|\s*(?:ba)?sh", instruction.value):
            yield _f(
                rule,
                "a script is piped from the network straight into a shell — the "
                "build executes whatever that URL returns today",
                "download to a file, verify a checksum or signature, then run it",
                line=instruction.lines, stage=stage.label,
            )


def _check_sudo(rule: Rule, dockerfile: Dockerfile, stage: Stage, **_: Any):
    for instruction in stage.find("RUN"):
        if re.search(r"\bsudo\b", instruction.value):
            yield _f(
                rule, "sudo in a build step",
                "drop sudo: build steps that need root should run before the "
                "USER instruction",
                line=instruction.lines, stage=stage.label,
            )


def _check_root_writable(rule: Rule, dockerfile: Dockerfile, stage: Stage, **_: Any):
    for instruction in stage.find("RUN"):
        if re.search(r"chmod\s+(?:-R\s+)?(?:0?777|a\+rwx)", instruction.value):
            yield _f(
                rule, "chmod 777 makes the path writable by every process in the "
                      "container",
                "grant the narrowest mode that works, and chown to the runtime "
                "user instead",
                line=instruction.lines, stage=stage.label,
            )


def _check_multistage(rule: Rule, dockerfile: Dockerfile, stage: Stage, **_: Any):
    if dockerfile.multi_stage:
        return
    build_markers = ("go build", "mvn ", "gradle ", "npm run build", "cargo build",
                     "make ", "gcc ", "g++ ", "pip install --no-cache-dir -r")
    for instruction in stage.find("RUN"):
        if any(marker in instruction.value for marker in build_markers):
            yield _f(
                rule,
                "the image is built in one stage and contains the toolchain it "
                "compiled with",
                "split into a builder stage and a runtime stage, and COPY --from "
                "only the artefact",
                line=instruction.lines, stage=stage.label,
            )
            return


def _check_expose_privileged(rule: Rule, dockerfile: Dockerfile, stage: Stage, **_: Any):
    for instruction in stage.find("EXPOSE"):
        for word in instruction.words():
            port = word.split("/")[0]
            if port.isdigit() and int(port) < 1024:
                yield _f(
                    rule,
                    f"port {port} is privileged, so binding it needs root or "
                    "CAP_NET_BIND_SERVICE",
                    f"listen on a high port and map it: EXPOSE 8080 with "
                    f"-p {port}:8080",
                    line=instruction.lines, stage=stage.label,
                )


def _check_workdir(rule: Rule, dockerfile: Dockerfile, stage: Stage, **_: Any):
    for instruction in stage.find("RUN"):
        if re.search(r"\bcd\s+/", instruction.value) and not stage.find("WORKDIR"):
            yield _f(
                rule, "cd inside RUN instead of WORKDIR",
                "use WORKDIR: a cd does not persist to the next instruction",
                line=instruction.lines, stage=stage.label,
            )
            return


DOCKERFILE_RULES: tuple[Rule, ...] = (
    Rule("HC001", Severity.CRITICAL, "Container runs as root", _check_user,
         ("CIS Docker 4.1", "CWE-250")),
    Rule("HC002", Severity.MEDIUM, "Base image tag is floating", _check_tag,
         ("CIS Docker 4.2",)),
    Rule("HC003", Severity.LOW, "Base image not pinned by digest", _check_digest),
    Rule("HC004", Severity.MEDIUM, "Base image not approved", _check_approved_base),
    Rule("HC005", Severity.LOW, "apt-get install pulls recommended packages",
         _check_apt_recommends),
    Rule("HC006", Severity.LOW, "Package lists left in the layer", _check_apt_cache),
    Rule("HC007", Severity.MEDIUM, "ADD used instead of COPY", _check_add,
         ("CIS Docker 4.9",)),
    Rule("HC008", Severity.CRITICAL, "Secret material in the image", _check_secrets,
         ("CWE-798", "CIS Docker 4.10")),
    Rule("HC009", Severity.LOW, "No HEALTHCHECK", _check_healthcheck,
         ("CIS Docker 4.6",)),
    Rule("HC010", Severity.HIGH, "Remote script piped into a shell", _check_curl_bash,
         ("CWE-494",)),
    Rule("HC011", Severity.MEDIUM, "sudo in a build step", _check_sudo),
    Rule("HC012", Severity.HIGH, "World-writable path", _check_root_writable,
         ("CWE-732",)),
    Rule("HC013", Severity.MEDIUM, "Build toolchain shipped in the image",
         _check_multistage),
    Rule("HC014", Severity.LOW, "Privileged port exposed", _check_expose_privileged),
    Rule("HC015", Severity.LOW, "cd used instead of WORKDIR", _check_workdir),
)


# -- runtime rules ----------------------------------------------------------
#
# These read a compose file or a pod spec. They exist because a Dockerfile
# cannot express them, and a perfect Dockerfile still runs privileged if the
# deployment says so.


@dataclass
class RuntimeConfig:
    """Normalised runtime settings, from compose or a Kubernetes spec."""

    name: str
    source: str
    privileged: bool = False
    user: str = ""
    read_only_root: bool = False
    no_new_privileges: bool = False
    cap_add: tuple[str, ...] = ()
    cap_drop: tuple[str, ...] = ()
    pid_host: bool = False
    network_host: bool = False
    docker_socket_mounted: bool = False
    memory_limit: str = ""
    cpu_limit: str = ""
    seccomp: str = ""
    volumes: tuple[str, ...] = ()

    @property
    def drops_all(self) -> bool:
        return any(c.upper() == "ALL" for c in self.cap_drop)


DANGEROUS_CAPABILITIES = {
    "SYS_ADMIN": "effectively root: mount, namespaces, and most of the kernel API",
    "SYS_PTRACE": "read and write the memory of other processes",
    "SYS_MODULE": "load kernel modules — a full host compromise",
    "NET_ADMIN": "reconfigure the host network",
    "DAC_READ_SEARCH": "bypass file read permission checks",
    "SETUID": "become any user inside the container",
    "SYS_BOOT": "reboot the host",
}


def check_runtime(config: RuntimeConfig) -> list[Finding]:
    """Findings from the runtime configuration."""
    out: list[Finding] = []

    def add(rule: str, severity: Severity, title: str, detail: str, fix: str,
            references: tuple[str, ...] = ()) -> None:
        out.append(
            Finding(rule=rule, severity=severity, title=title, detail=detail,
                    fix=fix, where=config.source, stage=config.name,
                    references=references)
        )

    if config.privileged:
        add("RT001", Severity.CRITICAL, "Container runs privileged",
            "privileged disables every isolation mechanism at once: all "
            "capabilities, all devices, no seccomp, no AppArmor. It is "
            "equivalent to running on the host",
            "remove privileged: true and add only the capabilities actually "
            "needed",
            ("CIS Docker 5.4", "CWE-250"))

    if config.docker_socket_mounted:
        add("RT002", Severity.CRITICAL, "Docker socket mounted into the container",
            "/var/run/docker.sock is root on the host. Anything that can write "
            "to it can start a privileged container and escape",
            "remove the mount. If the workload genuinely needs to build images, "
            "use a rootless builder or a separate build service",
            ("CIS Docker 5.31",))

    if not config.user or config.user in ("root", "0"):
        add("RT003", Severity.HIGH, "No non-root user set at runtime",
            "the runtime configuration does not override the image's user, so "
            "an image that defaults to root runs as root",
            "set user: \"10001:10001\" (compose) or runAsNonRoot with runAsUser "
            "(Kubernetes)",
            ("CIS Docker 5.9",))

    if not config.no_new_privileges:
        add("RT004", Severity.HIGH, "no-new-privileges is not set",
            "without it, a setuid binary inside the container can still raise "
            "privileges — which defeats running as a non-root user",
            "add security_opt: [\"no-new-privileges:true\"], or "
            "allowPrivilegeEscalation: false",
            ("CIS Docker 5.25",))

    if not config.drops_all:
        add("RT005", Severity.MEDIUM, "Default capability set retained",
            "Docker grants 14 capabilities by default, including SETUID, "
            "CHOWN and NET_RAW. Almost no workload needs them",
            "cap_drop: [ALL], then cap_add only what breaks",
            ("CIS Docker 5.3",))

    for capability in config.cap_add:
        name = capability.upper().removeprefix("CAP_")
        if name in DANGEROUS_CAPABILITIES:
            add("RT006", Severity.CRITICAL, f"Dangerous capability {name} granted",
                f"{name} grants: {DANGEROUS_CAPABILITIES[name]}",
                f"remove {name}. If it is genuinely required, document why and "
                "isolate the workload",
                ("CWE-250",))

    if not config.read_only_root:
        add("RT007", Severity.MEDIUM, "Root filesystem is writable",
            "a writable root filesystem lets an attacker drop tooling and "
            "persist inside the container",
            "read_only: true, with tmpfs mounts for the paths that need writing",
            ("CIS Docker 5.12",))

    if config.pid_host:
        add("RT008", Severity.CRITICAL, "Host PID namespace shared",
            "the container sees and can signal every process on the host, "
            "including reading their memory",
            "remove pid: host",
            ("CIS Docker 5.15",))

    if config.network_host:
        add("RT009", Severity.HIGH, "Host network namespace shared",
            "the container binds host ports directly and can reach anything the "
            "host can, bypassing network policy",
            "use a bridge network and publish only the ports needed",
            ("CIS Docker 5.9",))

    if not config.memory_limit:
        add("RT010", Severity.MEDIUM, "No memory limit",
            "one container can exhaust host memory and take its neighbours with "
            "it — a denial of service that needs no attacker",
            "set a memory limit, and a CPU limit alongside it",
            ("CIS Docker 5.10",))

    if config.seccomp in ("unconfined", "false"):
        add("RT011", Severity.HIGH, "seccomp disabled",
            "the default seccomp profile blocks around 44 dangerous syscalls; "
            "unconfined restores all of them",
            "remove seccomp:unconfined, or supply a narrower custom profile",
            ("CIS Docker 5.21",))

    for volume in config.volumes:
        host_path = volume.split(":")[0]
        if host_path in ("/", "/etc", "/var/run", "/proc", "/sys", "/boot", "/dev"):
            add("RT012", Severity.CRITICAL, f"Sensitive host path {host_path} mounted",
                f"mounting {host_path} exposes host state the container can read "
                "and often write",
                f"remove the {host_path} mount, or narrow it to the specific file "
                "needed and mark it read-only",
                ("CIS Docker 5.5",))

    return out


def all_rules() -> tuple[Rule, ...]:
    return DOCKERFILE_RULES
