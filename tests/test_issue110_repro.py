"""Reproduction test for issue #110: _parse_cargo_toml uses break instead of continue."""

import pytest

from taintrace.lockfile import LockfileParser


class TestCargoTomlParsingAllSections:
    def test_multi_section_cargo_toml_all_deps_parsed(self, tmp_path):
        """Deps after a section header in the same block are parsed (not skipped)."""
        cargo_toml = tmp_path / "Cargo.toml"
        cargo_toml.write_text("""[dependencies]
serde = "1.0"
tokio = "1.0"

[dev-dependencies]
criterion = "0.5"

[build-dependencies]
cc = "1.0"
""")
        parser = LockfileParser()
        deps = parser.parse(cargo_toml)
        names = [d.name for d in deps]
        assert "serde" in names
        assert "tokio" in names
        assert "criterion" in names
        assert "cc" in names

    def test_non_dependency_section_header_mid_block(self, tmp_path):
        """A non-dependency header like [features] mid-block must not stop parsing."""
        cargo_toml = tmp_path / "Cargo.toml"
        cargo_toml.write_text("""[dependencies]
serde = "1.0"

[features]
default = ["serde"]

[dependencies]
tokio = "1.0"
""")
        parser = LockfileParser()
        deps = parser.parse(cargo_toml)
        names = [d.name for d in deps]
        assert "serde" in names
        assert "tokio" in names