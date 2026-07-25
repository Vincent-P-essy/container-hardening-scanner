"""harden - container hardening for Dockerfiles and the runtime around them.

Multi-stage aware, so builder-stage findings do not drown the ones that ship,
and it reads the compose file or pod spec too - because no-new-privileges,
dropped capabilities and a read-only rootfs are not Dockerfile directives.
"""

__version__ = "1.0.0"
