"""Java/Maven dependencies are scored against real Maven Central data (#77).

Regression tests for issue #77: ``db.py`` registered no ``"java"`` ecosystem, so
``get_similar()`` compared Java coordinates against an empty set and a Java
dependency could never be escalated or suggested.
"""

import json
import subprocess
import sys
from pathlib import Path

import pytest
from click.testing import CliRunner

from taintrace.cli import cli
from taintrace.db import KnownPackagesDB, UnknownEcosystemError
from taintrace.scorer import RiskLevel, RiskScorer
from taintrace.similarity import SimilarityEngine

DATA_FILE = Path(__file__).resolve().parents[1] / "src" / "taintrace" / "data" / "java_packages.txt"
GENERATOR = Path(__file__).resolve().parents[1] / "scripts" / "generate_java_packages.py"


# ── The java ecosystem is populated with real Maven coordinates ─────


@pytest.mark.parametrize("coordinate", [
    "com.google.guava:guava",
    "org.apache.commons:commons-lang3",
    "org.springframework:spring-core",
    "org.slf4j:slf4j-api",
    "junit:junit",
])
def test_common_maven_coordinates_are_known(coordinate):
    assert KnownPackagesDB().is_known(coordinate, "java")


def test_java_typosquat_coordinate_is_not_known():
    db = KnownPackagesDB()
    assert not db.is_known("com.google.guava:guavv", "java")
    assert not db.is_known("com.google.guava:guva", "java")


def test_java_database_is_not_empty():
    """The bug: an empty java set silently disabled similarity matching."""
    assert len(KnownPackagesDB()._packages["java"]) > 100


def test_java_similarity_finds_a_typosquat_coordinate():
    db = KnownPackagesDB()
    matches = {name: score for name, score in db.get_similar(
        "org.apache.commons:commons-lang", threshold=0.8, ecosystem="java")}
    assert "org.apache.commons:commons-lang3" in matches
    assert matches["org.apache.commons:commons-lang3"] >= 0.9


def test_java_similarity_stays_inside_the_java_ecosystem():
    db = KnownPackagesDB()
    java_matches = {name for name, _ in db.get_similar("org.apache.commons:commons-lang3", ecosystem="java")}
    assert java_matches
    assert java_matches <= set(db._packages["java"])
    # A Python/numpy package must never surface as a Java suggestion.
    assert db.get_similar("numpy", ecosystem="java") == []


def test_bare_artifact_id_is_known_without_a_group_prefix():
    """Gradle/Maven users think in artifactIds; those must resolve too."""
    db = KnownPackagesDB()
    assert db.is_known("guava", "java")
    assert db.is_known("spring-core", "java")
    assert not db.is_known("guavv", "java")


# ── Data provenance: real coordinates, never hand-typed guesses ─────


def test_data_file_records_its_provenance():
    header = DATA_FILE.read_text(encoding="utf-8").split("# ---")[0]
    assert "search.maven.org" in header or "central.sonatype.com" in header
    assert "Generated" in header
    assert "scripts/generate_java_packages.py" in header


def test_every_entry_is_a_full_group_and_artifact_coordinate():
    entries = _data_entries()
    assert entries
    for entry in entries:
        group, _, artifact = entry.partition(":")
        assert group and artifact, entry
        assert " " not in entry, entry
        assert not entry.startswith(":"), entry


def test_data_file_is_sorted_and_deduplicated():
    entries = _data_entries()
    assert entries == sorted(entries)
    assert len(entries) == len(set(entries))


def _data_entries():
    lines = DATA_FILE.read_text(encoding="utf-8").splitlines()
    return [line.strip() for line in lines
            if line.strip() and not line.startswith("#")]


# ── The generator is committed and self-checking ───────────────────


def test_generator_script_exists():
    assert GENERATOR.is_file(), "regeneration script must ship with the package"


def test_generator_offline_check_accepts_the_committed_data():
    """`--check` validates the committed file without hitting the network."""
    result = subprocess.run(
        [sys.executable, str(GENERATOR), "--check"],
        capture_output=True, text=True, timeout=120, check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr


# ── End-to-end: a Gradle build file is escalated correctly ─────────


def test_check_gradle_recognises_real_deps_and_flags_typosquats(tmp_path):
    lockfile = tmp_path / "build.gradle"
    lockfile.write_text(
        'dependencies {\n'
        '  implementation "com.google.guava:guava:33.0.0-jre"\n'
        '  implementation "org.slf4j:slf4j-api:2.0.9"\n'
        '  implementation "org.apache.commons:commons-lang:3.12.0"\n'
        '}\n', encoding="utf-8",
    )
    result = CliRunner().invoke(cli, ["check", str(lockfile), "--format", "json"])
    assert result.exit_code == 1, result.output
    output = json.loads(result.output)
    results = {item["package"]: item for item in output["results"]}
    assert results["com.google.guava:guava"]["risk_score"] == 0.0
    assert results["org.slf4j:slf4j-api"]["risk_score"] == 0.0
    typo = results["org.apache.commons:commons-lang"]
    assert typo["risk_level"] in ("HIGH", "CRITICAL")
    assert "org.apache.commons:commons-lang3" in typo["similar_to"]


def test_check_gradle_version_catalog_is_scored(tmp_path):
    catalog = tmp_path / "libs.versions.toml"
    catalog.write_text(
        '[versions]\nguava = "33.0.0-jre"\n'
        '[libraries]\n'
        'guava = { module = "com.google.guava:guava", version.ref = "guava" }\n'
        'guava-typo = { module = "com.google.guava:guav", version = "33.0.0-jre" }\n',
        encoding="utf-8",
    )
    result = CliRunner().invoke(cli, ["check", str(catalog), "--format", "json"])
    assert result.exit_code == 1, result.output
    results = {item["package"]: item for item in json.loads(result.output)["results"]}
    assert results["com.google.guava:guava"]["risk_score"] == 0.0
    assert "com.google.guava:guava" in results["com.google.guava:guav"]["similar_to"]


def test_score_command_accepts_the_java_ecosystem():
    result = CliRunner().invoke(cli, ["score", "com.google.guava:guav", "-e", "java"])
    assert result.exit_code == 0, result.output
    assert "com.google.guava:guava" in result.output


def test_java_dependency_is_escalated_by_the_scorer():
    result = RiskScorer().score("org.apache.commons:commons-lan", "java", 0.7)
    assert result.level in (RiskLevel.HIGH, RiskLevel.CRITICAL)
    assert result.similar_packages


def test_known_java_dependency_scores_clean():
    result = RiskScorer().score("org.springframework:spring-core", "java", 0.7)
    assert result.level == RiskLevel.LOW
    assert result.score == 0.0


# ── The silent-gap class of bug must not come back (#77) ───────────


def test_every_ecosystem_the_cli_offers_has_known_package_data():
    """A registered-but-empty ecosystem is the root cause of #77."""
    from taintrace.cli import LOCKFILE_NAMES

    db = KnownPackagesDB()
    for ecosystem in sorted(set(LOCKFILE_NAMES.values())):
        assert db.has_ecosystem_data(ecosystem), f"no known-package data for {ecosystem!r}"


def test_ecosystem_without_data_is_reported_honestly():
    """Unknown ecosystems must not read as 'no similar packages found' (#77)."""
    db = KnownPackagesDB()
    assert not db.has_ecosystem_data("dotnet")
    with pytest.raises(UnknownEcosystemError) as excinfo:
        db.get_similar("Newtonsoft.Json", ecosystem="dotnet")
    assert "dotnet" in str(excinfo.value)

    result = RiskScorer().score("Newtonsoft.Json", "dotnet", 0.7)
    assert result.level == RiskLevel.MEDIUM
    assert "no known-package data" in result.reason.lower()
    assert "dotnet" in result.reason


def test_unknown_ecosystem_error_is_importable_from_the_package_root():
    import taintrace

    assert issubclass(taintrace.UnknownEcosystemError, LookupError)


# ── The similarity engine stays exact on a large java data set ─────


def test_levenshtein_matches_a_reference_implementation():
    """Similarity is now backed by rapidfuzz; scores must not drift."""
    from taintrace.similarity import SimilarityEngine

    engine = SimilarityEngine()
    pairs = [
        ("proc-macro1", "proc-macro2"),
        ("rеаct", "react"),  # cyrillic homoglyph
        ("org.apache.commons:commons-lang3", "org.apache.commons:commons-lang"),
        ("", "serde"),
        ("k8s.io/client-go", "k8s.io/client-goo"),
        ("guava", "guava-annotations"),
    ]
    for left, right in pairs:
        expected = _reference_levenshtein(left, right)
        longest = max(len(left), len(right)) or 1
        assert engine.levenshtein(left, right) == expected
        assert engine._levenshtein_similarity(left, right) == pytest.approx(
            1 - expected / longest)


def _reference_levenshtein(left, right):
    previous = list(range(len(right) + 1))
    for i, l in enumerate(left, start=1):
        current = [i]
        for j, r in enumerate(right, start=1):
            current.append(min(previous[j] + 1, current[j - 1] + 1, previous[j - 1] + (l != r)))
        previous = current
    return previous[-1]


def test_scoring_a_large_java_data_set_stays_fast():
    """A 200-dependency build file must not take minutes to scan."""
    import time

    db = KnownPackagesDB()
    scorer = RiskScorer(db)
    start = time.monotonic()
    for index in range(50):
        scorer.score(f"com.example.group{index}:artifact-{index}", "java", 0.7)
    elapsed = time.monotonic() - start
    assert elapsed < 5, f"scoring 50 unknown java packages took {elapsed:.1f}s"


def test_get_similar_matches_an_exhaustive_scan():
    """Candidate prefiltering must not change which packages are reported."""
    db = KnownPackagesDB()
    engine = SimilarityEngine()
    for query in ["org.apache.commons:commons-lang", "com.google.guava:guav",
                  "org.springframework:spring-corr", "com.acme:totally-unknown"]:
        expected = sorted(
            ((name, engine.similarity(query, name))
             for name in db._packages["java"]
             if engine.similarity(query, name) >= 0.8),
            key=lambda item: -item[1])[:10]
        actual = sorted(db.get_similar(query, threshold=0.8, ecosystem="java"),
                        key=lambda item: -item[1])
        assert [name for name, _ in actual] == [name for name, _ in expected], query


# ── Soundex saturation must not manufacture false positives ───────


def test_soundex_collision_is_not_a_perfect_match_for_unrelated_names():
    """A 4-char soundex hash saturating on long names is a collision, not a match.

    Every ``org.*`` Maven coordinate hashes to ``o621``. Without corroboration the
    phonetic signal scores unrelated coordinates 1.0, which would flag every Java
    dependency as a CRITICAL typosquat.
    """
    engine = SimilarityEngine()
    assert engine._soundex("org.apache.commons:commons-lang3") == \
        engine._soundex("org.projectlombok:lombok.ast")  # the collision
    assert engine.similarity(
        "org.apache.commons:commons-lang3", "org.projectlombok:lombok.ast") < 0.7


def test_unrelated_java_coordinates_are_not_flagged_as_typosquats():
    db = KnownPackagesDB()
    scorer = RiskScorer(db)
    for name in ["com.acme:my-service", "com.acme:payments-api", "org.mycorp:internal-tools"]:
        result = scorer.score(name, "java", 0.7)
        assert result.level in (RiskLevel.LOW, RiskLevel.MEDIUM), \
            f"{name} scored {result.level} with {result.similar_packages[:3]}"


def test_real_typosquats_are_still_detected():
    """Guarding against false positives must not blunt true positives."""
    engine = SimilarityEngine()
    typos = [
        ("com.google.guava:guav", "com.google.guava:guava"),
        ("org.apache.commons:commons-lang", "org.apache.commons:commons-lang3"),
        ("org.slf4j:slf4j-ap", "org.slf4j:slf4j-api"),
    ]
    for typo, genuine in typos:
        assert engine.similarity(typo, genuine) >= 0.85, (typo, genuine)


def test_short_name_phonetic_typosquats_still_score_perfectly():
    """Soundex is meaningful for short names; do not blunt the signal there."""
    engine = SimilarityEngine()
    assert engine._soundex("react") == engine._soundex("reakt")
    assert engine.similarity("react", "reakt") == 1.0