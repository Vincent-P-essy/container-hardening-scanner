"""Reading the runtime configuration: Docker Compose and Kubernetes.

The Dockerfile is half the story. `no-new-privileges`, dropped capabilities, a
read-only root filesystem, seccomp, resource limits — none of them are
Dockerfile directives, and a container built from an impeccable Dockerfile still
runs privileged if the compose file says `privileged: true`.

Both formats are normalised into one :class:`~harden.rules.RuntimeConfig` so a
single rule set covers them. The normalisation has to be careful in one place:
Kubernetes has **two** security contexts, one on the pod and one on each
container, and the container's wins where both are set. A checker that reads
only the pod-level context reports a hardened pod whose containers each override
it back to root.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from .rules import RuntimeConfig


class RuntimeError_(ValueError):
    """Raised when a runtime file cannot be read."""


def _as_list(value: Any) -> tuple[str, ...]:
    if value is None:
        return ()
    if isinstance(value, str):
        return (value,)
    return tuple(str(v) for v in value)


def from_compose(data: dict[str, Any], source: str = "compose.yaml") -> list[RuntimeConfig]:
    """Normalise every service in a Compose file."""
    services = data.get("services") or {}
    if not isinstance(services, dict):
        raise RuntimeError_(f"{source}: 'services' must be a mapping")

    out: list[RuntimeConfig] = []
    for name, service in services.items():
        if not isinstance(service, dict):
            continue

        security_opt = _as_list(service.get("security_opt"))
        seccomp = ""
        no_new_privileges = False
        for option in security_opt:
            lowered = option.lower().replace(" ", "")
            if lowered.startswith("no-new-privileges"):
                no_new_privileges = lowered.endswith(("true", ":1"))
            if lowered.startswith("seccomp"):
                seccomp = lowered.split(":", 1)[1] if ":" in lowered else ""

        volumes = _as_list(service.get("volumes"))
        # A long-form volume entry is a mapping, not a string.
        for entry in service.get("volumes") or []:
            if isinstance(entry, dict) and entry.get("source"):
                volumes = (*volumes, str(entry["source"]))

        deploy = service.get("deploy") or {}
        limits = (deploy.get("resources") or {}).get("limits") or {}

        out.append(
            RuntimeConfig(
                name=str(name),
                source=source,
                privileged=bool(service.get("privileged", False)),
                user=str(service.get("user", "")),
                read_only_root=bool(service.get("read_only", False)),
                no_new_privileges=no_new_privileges,
                cap_add=_as_list(service.get("cap_add")),
                cap_drop=_as_list(service.get("cap_drop")),
                pid_host=str(service.get("pid", "")) == "host",
                network_host=str(service.get("network_mode", "")) == "host",
                docker_socket_mounted=any("docker.sock" in v for v in volumes),
                memory_limit=str(service.get("mem_limit") or limits.get("memory") or ""),
                cpu_limit=str(service.get("cpus") or limits.get("cpus") or ""),
                seccomp=seccomp,
                volumes=volumes,
            )
        )
    return out


def from_kubernetes(data: dict[str, Any], source: str = "pod.yaml") -> list[RuntimeConfig]:
    """Normalise every container in a Pod, Deployment, StatefulSet or DaemonSet."""
    spec = data.get("spec") or {}
    # Workload controllers wrap the pod spec in .spec.template.spec.
    pod_spec = (spec.get("template") or {}).get("spec") or spec
    pod_security = pod_spec.get("securityContext") or {}
    volumes = pod_spec.get("volumes") or []

    host_paths: list[str] = []
    for volume in volumes:
        host_path = (volume or {}).get("hostPath") or {}
        if host_path.get("path"):
            host_paths.append(str(host_path["path"]))

    seccomp_profile = (pod_security.get("seccompProfile") or {}).get("type", "")

    out: list[RuntimeConfig] = []
    containers = (pod_spec.get("containers") or []) + (
        pod_spec.get("initContainers") or []
    )
    for container in containers:
        if not isinstance(container, dict):
            continue
        # The container's context wins where both are set. Reading only the pod
        # level reports a hardened pod whose containers override it back.
        context = {**pod_security, **(container.get("securityContext") or {})}
        capabilities = context.get("capabilities") or {}
        limits = (container.get("resources") or {}).get("limits") or {}

        run_as_user = context.get("runAsUser")
        user = str(run_as_user) if run_as_user is not None else ""
        if not user and context.get("runAsNonRoot") is True:
            user = "nonroot"

        container_seccomp = (
            (context.get("seccompProfile") or {}).get("type") or seccomp_profile
        )

        out.append(
            RuntimeConfig(
                name=str(container.get("name", "container")),
                source=source,
                privileged=bool(context.get("privileged", False)),
                user=user,
                read_only_root=bool(context.get("readOnlyRootFilesystem", False)),
                # Kubernetes expresses this as allowPrivilegeEscalation, which
                # is the inverse.
                no_new_privileges=context.get("allowPrivilegeEscalation") is False,
                cap_add=_as_list(capabilities.get("add")),
                cap_drop=_as_list(capabilities.get("drop")),
                pid_host=bool(pod_spec.get("hostPID", False)),
                network_host=bool(pod_spec.get("hostNetwork", False)),
                docker_socket_mounted=any("docker.sock" in p for p in host_paths),
                memory_limit=str(limits.get("memory", "")),
                cpu_limit=str(limits.get("cpu", "")),
                seccomp="unconfined" if container_seccomp == "Unconfined" else container_seccomp,
                volumes=tuple(host_paths),
            )
        )
    return out


def load(path: str | Path) -> list[RuntimeConfig]:
    """Read a compose file or a Kubernetes manifest, detecting which it is."""
    source = Path(path)
    if not source.exists():
        raise RuntimeError_(f"runtime file not found: {source}")

    try:
        documents = [d for d in yaml.safe_load_all(source.read_text(encoding="utf-8")) if d]
    except yaml.YAMLError as exc:
        raise RuntimeError_(f"{source.name}: invalid YAML: {exc}") from None

    out: list[RuntimeConfig] = []
    for document in documents:
        if not isinstance(document, dict):
            continue
        if "services" in document:
            out.extend(from_compose(document, str(source)))
        elif document.get("kind") in (
            "Pod", "Deployment", "StatefulSet", "DaemonSet", "Job", "CronJob", "ReplicaSet"
        ):
            out.extend(from_kubernetes(document, str(source)))

    if not out:
        raise RuntimeError_(
            f"{source.name}: no Compose services or Kubernetes workloads found. "
            "Expected a 'services:' key or a workload 'kind:'."
        )
    return out
