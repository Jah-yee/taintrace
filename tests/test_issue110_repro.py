"""Regression tests for issue #110: _parse_cargo_toml guard on blank/comment/header lines.

These tests are deliberately discriminating: the parser must not silently drop
dependencies that follow a blank line or a comment inside a dependency table, and
it must NOT invent dependencies from unrelated TOML tables that follow
``[dependencies]`` (e.g. ``[features]``, ``[profile.release]``, ``[badges]``).
"""

from taintrace.lockfile import LockfileParser


def _names(tmp_path, content):
    cargo_toml = tmp_path / "Cargo.toml"
    cargo_toml.write_text(content)
    return [d.name for d in LockfileParser().parse(cargo_toml)]


class TestCargoTomlDoesNotDropDependencies:
    def test_dependency_after_blank_line_inside_table(self, tmp_path):
        """A blank line inside [dependencies] does not end the table."""
        names = _names(tmp_path, """[dependencies]
serde = "1.0"

tokio = "1.0"
""")
        assert "serde" in names
        assert "tokio" in names

    def test_dependency_after_comment_inside_table(self, tmp_path):
        """A comment line inside [dependencies] does not end the table."""
        names = _names(tmp_path, """[dependencies]
serde = "1.0"
# async runtime
tokio = "1.0"
""")
        assert "serde" in names
        assert "tokio" in names

    def test_multi_section_cargo_toml_all_deps_parsed(self, tmp_path):
        """[dependencies], [dev-dependencies] and [build-dependencies] are all parsed."""
        names = _names(tmp_path, """[dependencies]
serde = "1.0"

[dev-dependencies]
criterion = "0.5"

[build-dependencies]
cc = "1.0"
""")
        for expected in ("serde", "criterion", "cc"):
            assert expected in names


class TestCargoTomlDoesNotInventDependencies:
    def test_features_table_keys_are_not_dependencies(self, tmp_path):
        """Keys under [features] are not crates."""
        names = _names(tmp_path, """[dependencies]
serde = "1.0"

[features]
default = ["serde"]
full = []
""")
        assert "serde" in names
        assert "default" not in names
        assert "full" not in names

    def test_profile_release_keys_are_not_dependencies(self, tmp_path):
        """Keys under [profile.release] are not crates."""
        names = _names(tmp_path, """[dependencies]
serde = "1.0"

[profile.release]
lto = true
codegen-units = 1
opt-level = 3
""")
        assert "serde" in names
        for phantom in ("lto", "codegen-units", "opt-level"):
            assert phantom not in names

    def test_dev_dependencies_followed_by_features_table(self, tmp_path):
        """Unrelated tables after [dev-dependencies] are not crates either."""
        names = _names(tmp_path, """[dev-dependencies]
criterion = "0.5"

[features]
default = []
""")
        assert "criterion" in names
        assert "default" not in names

    def test_badges_table_keys_are_not_dependencies(self, tmp_path):
        """Keys under [badges] are not crates."""
        names = _names(tmp_path, """[dependencies]
serde = "1.0"

[badges]
maintenance = { repository = "example/repo" }
""")
        assert "serde" in names
        assert "maintenance" not in names
