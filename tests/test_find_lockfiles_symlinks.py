"""Regression tests for #99 / #112: _find_lockfiles follows symlinks.

A symlink pointing at an ancestor directory makes the recursive walk revisit
the same tree repeatedly. Because ``Path.is_dir()`` follows symlinks, a loop
such as ``a/loop -> .`` was traversed until the path length limit ended it,
reporting the same real lockfile dozens of times (37 paths for one file in my
reproduction).

Policy under test:
  1. the walk never descends into a symlinked directory, so a loop cannot
     multiply or repeat the tree;
  2. results are de-duplicated by resolved real path, so a lockfile reachable
     both directly and through a symlink is reported once.
"""

import os

import pytest

from taintrace.cli import _find_lockfiles


def _symlink_or_skip(target, link):
    try:
        os.symlink(str(target), str(link))
    except (OSError, NotImplementedError, AttributeError):  # pragma: no cover
        pytest.skip("symlinks unavailable on this platform")


class TestSymlinkLoop:
    def test_symlink_loop_does_not_multiply_results(self, tmp_path):
        """One real lockfile must be reported exactly once."""
        (tmp_path / "a").mkdir()
        (tmp_path / "a" / "Cargo.toml").write_text('[dependencies]\nserde = "1.0"\n')
        _symlink_or_skip(tmp_path, tmp_path / "a" / "loop")

        found = _find_lockfiles(tmp_path)

        assert len(found) == 1
        assert found[0][0].name == "Cargo.toml"

    def test_symlink_loop_does_not_traverse_symlinked_dirs(self, tmp_path):
        """No returned path may pass through a symlinked directory."""
        (tmp_path / "a").mkdir()
        (tmp_path / "a" / "Cargo.toml").write_text('[dependencies]\nserde = "1.0"\n')
        _symlink_or_skip(tmp_path, tmp_path / "a" / "loop")

        found = _find_lockfiles(tmp_path)

        assert all("loop" not in path.parts for path, _ in found)

    def test_nested_loop_is_bounded(self, tmp_path):
        """A deeper loop must still terminate with a bounded result set."""
        (tmp_path / "a" / "b").mkdir(parents=True)
        (tmp_path / "a" / "b" / "Cargo.toml").write_text('[dependencies]\nserde = "1.0"\n')
        _symlink_or_skip(tmp_path, tmp_path / "a" / "b" / "loop")

        found = _find_lockfiles(tmp_path)

        assert len(found) == 1


class TestNormalTraversalIsUnaffected:
    def test_real_subdirectories_are_still_scanned(self, tmp_path):
        """Skipping symlinked dirs must not stop the walk descending into real ones."""
        (tmp_path / "Cargo.toml").write_text('[dependencies]\nserde = "1.0"\n')
        (tmp_path / "b").mkdir()
        (tmp_path / "b" / "package-lock.json").write_text('{"packages": {}}')

        found = _find_lockfiles(tmp_path)

        assert {p.name for p, _ in found} == {"Cargo.toml", "package-lock.json"}

    def test_deeply_nested_real_dirs_are_scanned(self, tmp_path):
        deep = tmp_path / "x" / "y" / "z"
        deep.mkdir(parents=True)
        (deep / "requirements.txt").write_text("requests==2.31.0\n")

        found = _find_lockfiles(tmp_path)

        assert len(found) == 1

    def test_symlinked_lockfile_is_not_duplicated(self, tmp_path):
        """A lockfile reached directly and via a symlink is reported once."""
        real = tmp_path / "real"
        real.mkdir()
        (real / "Cargo.toml").write_text('[dependencies]\nserde = "1.0"\n')
        _symlink_or_skip(real / "Cargo.toml", tmp_path / "Cargo.toml")

        found = _find_lockfiles(tmp_path)

        assert [p.name for p, _ in found] == ["Cargo.toml"]