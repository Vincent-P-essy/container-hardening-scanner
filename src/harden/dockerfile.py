"""Parsing a Dockerfile properly, because the parsing is where linters go wrong.

Most Dockerfile linters work line by line with regular expressions, which
produces two classes of wrong answer that matter.

**False negatives from multi-stage builds.** A `USER root` in a builder stage is
irrelevant — nothing from that stage ships. A `USER root` in the final stage is
the finding. A line-oriented scanner cannot tell them apart, so it either
reports both (noise) or neither (worse).

**False positives from line continuations.** A `RUN` spanning eight lines with
backslashes is one instruction. Scanning its lines individually reports the same
issue eight times, or reports `apt-get install` without seeing the
`--no-install-recommends` two lines below.

So this parses into instructions and then into stages, resolving `COPY --from`
so that a stage which nothing copies from can be recognised as build-only.
"""

from __future__ import annotations

import re
import shlex
from dataclasses import dataclass, field
from pathlib import Path


class DockerfileError(ValueError):
    pass


@dataclass(frozen=True)
class Instruction:
    """One logical instruction, with continuations already joined."""

    keyword: str
    value: str
    line: int
    #: The lines this instruction spans, for reporting.
    end_line: int = 0

    @property
    def lines(self) -> str:
        return (
            f"{self.line}" if self.end_line in (0, self.line)
            else f"{self.line}-{self.end_line}"
        )

    def words(self) -> list[str]:
        """Shell-split the value, tolerating anything that will not split."""
        try:
            return shlex.split(self.value)
        except ValueError:
            return self.value.split()

    def commands(self) -> list[str]:
        """A RUN split into the separate shell commands it actually runs.

        `RUN apt-get update && apt-get install -y curl` is two commands, and a
        rule about `apt-get install` flags needs to see the second one on its
        own rather than as a substring of a longer line.
        """
        if self.keyword != "RUN":
            return []
        parts = re.split(r"&&|\|\||;|\n", self.value)
        return [p.strip() for p in parts if p.strip()]


@dataclass
class Stage:
    """One build stage."""

    index: int
    base: str
    name: str = ""
    instructions: list[Instruction] = field(default_factory=list)
    #: Stage names or indices that COPY --from this stage.
    copied_from_by: set[str] = field(default_factory=set)

    @property
    def label(self) -> str:
        return self.name or f"stage {self.index}"

    @property
    def is_scratch(self) -> bool:
        return self.base.lower() == "scratch"

    def find(self, *keywords: str) -> list[Instruction]:
        wanted = {k.upper() for k in keywords}
        return [i for i in self.instructions if i.keyword in wanted]

    def last(self, keyword: str) -> Instruction | None:
        found = self.find(keyword)
        return found[-1] if found else None

    @property
    def base_image(self) -> str:
        return self.base.split("@")[0].split(":")[0]

    @property
    def base_tag(self) -> str:
        if "@" in self.base:
            return self.base.split("@", 1)[1]
        if ":" in self.base:
            return self.base.split(":", 1)[1]
        return ""

    @property
    def pinned_by_digest(self) -> bool:
        return "@sha256:" in self.base


@dataclass
class Dockerfile:
    path: str
    instructions: list[Instruction]
    stages: list[Stage]

    @property
    def final_stage(self) -> Stage | None:
        """The stage that actually ships.

        Everything else is scaffolding, and reporting findings against
        scaffolding is how a linter trains a team to ignore it.
        """
        return self.stages[-1] if self.stages else None

    def shipping_stages(self) -> list[Stage]:
        return [self.final_stage] if self.final_stage else []

    @property
    def multi_stage(self) -> bool:
        return len(self.stages) > 1


_KEYWORDS = {
    "FROM", "RUN", "CMD", "LABEL", "EXPOSE", "ENV", "ADD", "COPY", "ENTRYPOINT",
    "VOLUME", "USER", "WORKDIR", "ARG", "ONBUILD", "STOPSIGNAL", "HEALTHCHECK",
    "SHELL", "MAINTAINER",
}


def parse(text: str, path: str = "Dockerfile") -> Dockerfile:
    """Parse into logical instructions, then into stages."""
    instructions: list[Instruction] = []
    buffer: list[str] = []
    start_line = 0

    for number, raw in enumerate(text.splitlines(), start=1):
        line = raw.rstrip()
        stripped = line.strip()

        if not buffer and (not stripped or stripped.startswith("#")):
            continue

        if not buffer:
            start_line = number

        # A trailing backslash continues the instruction. Joining first is what
        # stops a rule seeing half of an apt-get invocation.
        if line.endswith("\\"):
            buffer.append(line[:-1].strip())
            continue

        buffer.append(stripped)
        joined = " ".join(part for part in buffer if part)
        buffer = []

        if not joined:
            continue

        keyword, _, value = joined.partition(" ")
        keyword = keyword.upper()
        if keyword not in _KEYWORDS:
            # Unknown directives are skipped rather than guessed at. A parser
            # that invents an interpretation produces findings nobody can act on.
            continue
        instructions.append(
            Instruction(keyword=keyword, value=value.strip(), line=start_line, end_line=number)
        )

    if buffer:
        joined = " ".join(part for part in buffer if part)
        keyword, _, value = joined.partition(" ")
        if keyword.upper() in _KEYWORDS:
            instructions.append(
                Instruction(keyword.upper(), value.strip(), start_line, start_line)
            )

    stages = _stages(instructions)
    return Dockerfile(path=path, instructions=instructions, stages=stages)


_FROM = re.compile(r"^(?P<image>\S+)(?:\s+[Aa][Ss]\s+(?P<name>\S+))?$")


def _stages(instructions: list[Instruction]) -> list[Stage]:
    stages: list[Stage] = []
    current: Stage | None = None

    for instruction in instructions:
        if instruction.keyword == "FROM":
            match = _FROM.match(instruction.value.strip())
            if match is None:
                raise DockerfileError(
                    f"line {instruction.line}: cannot parse FROM {instruction.value!r}"
                )
            current = Stage(
                index=len(stages),
                base=match.group("image"),
                name=(match.group("name") or "").lower(),
            )
            current.instructions.append(instruction)
            stages.append(current)
            continue
        if current is not None:
            current.instructions.append(instruction)

    # Resolve COPY --from so a stage nothing copies from is recognisably
    # build-only, and its contents can be ignored by the rules.
    by_name = {s.name: s for s in stages if s.name}
    by_index = {str(s.index): s for s in stages}
    for stage in stages:
        for instruction in stage.find("COPY", "ADD"):
            match = re.search(r"--from=(\S+)", instruction.value)
            if not match:
                continue
            source = match.group(1).lower()
            target = by_name.get(source) or by_index.get(source)
            if target is not None:
                target.copied_from_by.add(stage.label)

    return stages


def load(path: str | Path) -> Dockerfile:
    source = Path(path)
    if not source.exists():
        raise DockerfileError(f"Dockerfile not found: {source}")
    return parse(source.read_text(encoding="utf-8"), str(source))
