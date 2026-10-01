"""Regression tests for Cargo.toml parsing: sub-tables, versions and negative cases.

Covers:
- #143 -- ``[dependencies.<name>]`` sub-tables are dropped by ``_parse_cargo_toml``.
- #144 -- parser tests asserted presence only, so both silent drops and phantom
  crates went unnoticed. Every negative case here is paired with a positive
  assertion on the *same* input, so a regression in either direction fails.
- #92 / #65 / #72 -- the same line-oriented loop also emitted phantom crates for
  multi-line inline tables and duplicated crates across sections.
"""

import pytest

from taintrace.lockfile import LockfileParser


def _parse(tmp_path, content, name="Cargo.toml"):
    path = tmp_path / name
    path.write_text(content)
    return LockfileParser().parse(path)


def _byname(deps):
    return {d.name: d.version for d in deps}


@pytest.fixture
def subtable_cargo_toml(tmp_path):
    """A Cargo.toml mixing plain deps, sub-table deps and unrelated tables."""
    return _parse(tmp_path, """[package]
name = "demo"
version = "0.1.0"

[dependencies]
serde = "1.0"
rand = { version = "0.8", features = ["small_rng"] }

[dependencies.tokio]
version = "1.0"
features = ["full"]

[dependencies.reqwest]
version = "0.11"

[dev-dependencies]
criterion = "0.5"

[dev-dependencies.proptest]
version = "1.0"

[build-dependencies]
cc = "1.0"

[features]
default = []

[badges]
maintenance = { status = "actively-developed" }

[profile.release]
lto = true
""")


class TestSubTableSyntax:
    """#143: ``[dependencies.<name>]`` sub-tables must yield a Dependency."""

    def test_dependency_subtable_name_and_version(self, subtable_cargo_toml):
        versions = _byname(subtable_cargo_toml)
        assert versions.get("tokio") == "1.0"
        assert versions.get("reqwest") == "0.11"

    def test_dev_dependency_subtable(self, subtable_cargo_toml):
        versions = _byname(subtable_cargo_toml)
        assert versions.get("proptest") == "1.0"
        assert versions.get("criterion") is not None

    def test_subtable_is_rust_ecosystem(self, subtable_cargo_toml):
        tokio = next(d for d in subtable_cargo_toml if d.name == "tokio")
        assert tokio.ecosystem == "rust"

    def test_build_dependency_subtable(self, tmp_path):
        deps = _parse(tmp_path, """[build-dependencies.cc]
version = "1.0"
""")
        assert _byname(deps) == {"cc": "1.0"}

    def test_subtable_without_blank_line(self, tmp_path):
        """A bare ``[`` previously terminated the section chunk."""
        deps = _parse(tmp_path, """[dependencies]
serde = "1.0"
[dependencies.tokio]
version = "1.0"
[dependencies.reqwest]
version = "0.11"
""")
        assert _byname(deps) == {"serde": "1.0", "tokio": "1.0", "reqwest": "0.11"}

    def test_target_specific_subtable(self, tmp_path):
        deps = _parse(tmp_path, """[target.'cfg(unix)'.dependencies]
libc = "0.2"

[target.'cfg(windows)'.dependencies.winapi]
version = "0.3"
""")
        assert _byname(deps) == {"libc": "0.2", "winapi": "0.3"}

    def test_crate_in_plain_and_subtable_form_is_not_double_counted(self, tmp_path):
        """#65/#72 acceptance: one Dependency per crate name."""
        deps = _parse(tmp_path, """[dependencies]
tokio = "1.0"

[dependencies.tokio]
version = "1.5"
""")
        names = [d.name for d in deps]
        assert names.count("tokio") == 1


class TestVersionContent:
    """#144: versions, not just presence.

    ``serde = "1.0"`` is the most common Cargo dependency form; it used to be
    reported as version ``0.0.0``, which silently disables version-aware
    checks downstream.
    """

    def test_bare_string_version_is_preserved(self, subtable_cargo_toml):
        versions = _byname(subtable_cargo_toml)
        assert versions.get("serde") == "1.0"
        assert versions.get("criterion") == "0.5"
        assert versions.get("cc") == "1.0"

    def test_inline_table_version_is_preserved(self, subtable_cargo_toml):
        assert _byname(subtable_cargo_toml).get("rand") == "0.8"

    def test_no_dependency_reports_placeholder_version(self, subtable_cargo_toml):
        assert [d.name for d in subtable_cargo_toml if d.version == "0.0.0"] == []


class TestNegativeCases:
    """#144: keys that are NOT crates must never be reported."""

    def test_unrelated_table_keys_are_absent(self, subtable_cargo_toml):
        names = set(_byname(subtable_cargo_toml))
        for phantom in ("default", "maintenance", "lto", "name", "version", "features"):
            assert phantom not in names

    def test_subtable_spec_keys_are_not_crates(self, tmp_path):
        deps = _parse(tmp_path, """[dependencies.tokio]
version = "1.0"
features = ["full"]
default-features = false
optional = true
git = "https://github.com/tokio-rs/tokio"
""")
        assert _byname(deps) == {"tokio": "1.0"}

    def test_multiline_inline_table_emits_no_phantom_crates(self, tmp_path):
        """#92: keys of a multi-line inline table were reported as crates."""
        deps = _parse(tmp_path, """[dependencies]
serde = "1.0"
rand = {
    version = "0.8",
    features = ["std"],
}
tokio = "1.0"
""")
        assert _byname(deps) == {"serde": "1.0", "rand": "0.8", "tokio": "1.0"}

    def test_package_metadata_is_not_a_dependency(self, tmp_path):
        deps = _parse(tmp_path, """[package]
name = "my-app"
version = "0.1.0"
edition = "2021"

[dependencies]
serde = "1.0"
""")
        assert _byname(deps) == {"serde": "1.0"}


class TestDeduplication:
    """#65/#72: a crate in several sections yields one entry."""

    def test_crate_in_dependencies_and_dev_dependencies(self, tmp_path):
        deps = _parse(tmp_path, """[dependencies]
serde = "1.0"

[dev-dependencies]
serde = "0.9"
""")
        assert [(d.name, d.version) for d in deps] == [("serde", "1.0")]

    def test_production_entry_wins_over_dev(self, tmp_path):
        deps = _parse(tmp_path, """[dev-dependencies]
criterion = "0.3"

[dependencies]
criterion = "0.5"
""")
        assert [(d.name, d.version) for d in deps] == [("criterion", "0.5")]

    def test_distinct_crates_are_preserved(self, subtable_cargo_toml):
        names = [d.name for d in subtable_cargo_toml]
        assert len(names) == len(set(names))
        assert set(names) == {"serde", "rand", "tokio", "reqwest", "criterion", "proptest", "cc"}


class TestWorkspaceInheritance:
    """Existing behaviour from #96 must survive the rewrite."""

    def test_workspace_inherited_version_resolved(self, tmp_path):
        workspace = tmp_path / "workspace"
        member = workspace / "member"
        member.mkdir(parents=True)
        (workspace / "Cargo.toml").write_text(
            '[workspace]\nmembers = ["member"]\n\n'
            '[workspace.dependencies]\nserde = "1.0"\n'
        )
        deps = _parse(tmp_path, '[package]\nname = "member"\n\n'
                     '[dependencies]\nserde = { workspace = true }\n',
                     name="workspace/member/Cargo.toml")
        assert [(d.name, d.version) for d in deps] == [("serde", "1.0")]

    def test_workspace_inherited_subtable(self, tmp_path):
        workspace = tmp_path / "workspace"
        member = workspace / "member"
        member.mkdir(parents=True)
        (workspace / "Cargo.toml").write_text(
            '[workspace]\nmembers = ["member"]\n\n'
            '[workspace.dependencies]\ntokio = "1.28"\n'
        )
        deps = _parse(tmp_path, '[package]\nname = "member"\n\n'
                     '[dependencies.tokio]\nversion.workspace = true\n',
                     name="workspace/member/Cargo.toml")
        assert [(d.name, d.version) for d in deps] == [("tokio", "1.28")]