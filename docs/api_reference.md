# taintrace API Reference

This reference covers the public Python API and command-line interface. The
same classes are re-exported from `taintrace`, so either the package-level or
module-level imports shown below can be used.

## Table of Contents

- [Quick start](#quick-start)
- [`taintrace`](#taintrace)
- [`taintrace.lockfile`](#taintracelockfile)
- [`taintrace.detector`](#taintracedetector)
- [`taintrace.scorer`](#taintracescorer)
- [`taintrace.similarity`](#taintracesimilarity)
- [`taintrace.db`](#taintracedb)
- [`taintrace.config`](#taintraceconfig)
- [`taintrace.cli`](#taintracecli)
- [Supported lockfiles](#supported-lockfiles)

## Quick start

Install the package, then scan a lockfile with the high-level detector:

```python
from pathlib import Path

from taintrace import TyposquatDetector

detector = TyposquatDetector(ecosystem="rust", similarity_threshold=0.7)
results = detector.scan(Path("Cargo.lock"))

for result in results:
    if result.is_suspect:
        print(result.dependency.name, result.risk_level, result.reason)
```

`scan()` returns one `DetectionResult` for every parsed, non-ignored
dependency. It does not raise an exception for an empty lockfile, but the
lockfile path must exist and be readable.

## `taintrace`

The package exports the following public objects from `taintrace.__init__`:

| Name | Purpose |
| --- | --- |
| `Dependency` | A dependency extracted from a lockfile. |
| `LockfileParser` | Parses supported lockfile formats. |
| `SimilarityEngine` | Compares package names. |
| `KnownPackagesDB` | Provides the built-in package database. |
| `UnknownEcosystemError` | Raised when an ecosystem has no known-package data. |
| `RiskScorer` | Converts package similarity into a risk result. |
| `RiskResult` | Dataclass returned by `RiskScorer.score`. |
| `RiskLevel` | `LOW`, `MEDIUM`, `HIGH`, or `CRITICAL`. |
| `TyposquatDetector` | Scans lockfiles and individual dependencies. |
| `DetectionResult` | Dataclass returned by detector scans. |

The package also defines `taintrace.__version__`, currently a string such as
`"0.2.1"`.

## `taintrace.lockfile`

### `Dependency`

```python
Dependency(name: str, version: str, ecosystem: str)
```

A parsed dependency. `ecosystem` identifies the registry used for comparison,
for example `"rust"`, `"node"`, or `"python"`.

```python
from taintrace import Dependency

dependency = Dependency("serde", "1.0.210", "rust")
print(dependency.name, dependency.version)
```

### `LockfileParser`

#### `LockfileParser() -> LockfileParser`

Creates a stateless parser. No network access is performed.

#### `parse(path: Path) -> list[Dependency]`

Detects the format from the file name and returns parsed dependencies. Unknown
file names are treated as Cargo lockfiles. Invalid JSON-based formats are
generally treated as empty input and return `[]`; text formats can raise the
underlying `OSError` when the file cannot be read.

```python
from pathlib import Path
from taintrace import LockfileParser

dependencies = LockfileParser().parse(Path("requirements.txt"))
for dependency in dependencies:
    print(f"{dependency.name}=={dependency.version}")
```

#### `LockfileParser.parse_go_sum(content: str) -> list[Dependency]`

Parses Go `go.sum` content directly, removes `/go.mod` suffixes, and
deduplicates `(module, version)` pairs. Blank lines and comments are ignored.

```python
from taintrace import LockfileParser

content = "example.com/tool v1.2.3 h1:checksum\n"
dependencies = LockfileParser.parse_go_sum(content)
assert dependencies[0].name == "example.com/tool"
```

The same function is available as the module-level alias
`taintrace.lockfile.parse_go_sum(content: str)`.

## `taintrace.detector`

### `DetectionResult`

```python
DetectionResult(
    dependency: Dependency,
    is_suspect: bool,
    risk_level: str,
    risk_score: float,
    similar_packages: list[str],
    similarity_scores: list[tuple[str, float]],
    reason: str,
)
```

The result of scoring one dependency. `is_suspect` is true for `HIGH` and
`CRITICAL` results. `risk_score` is between `0.0` and `1.0`.

### `TyposquatDetector`

#### `TyposquatDetector(ecosystem: str = "rust", similarity_threshold: float = 0.7) -> TyposquatDetector`

Creates a detector backed by the embedded, offline package database.
`similarity_threshold` controls which similar names are considered. It is
normally between `0.0` and `1.0`; values outside that range are passed to the
scoring layer without additional validation.

#### `scan(lockfile_path: Path) -> list[DetectionResult]`

Parses and scores a lockfile. Packages listed in discovered configuration as
ignored are omitted. Raises the file-reading errors produced by the parser
when the path cannot be read.

#### `scan_dependency(name: str, version: str = "0.0.0", ecosystem: str = "rust") -> DetectionResult`

Scores one dependency without creating a lockfile. The `version` is retained
in the returned `Dependency`, but does not affect the package-name score.

```python
from taintrace import TyposquatDetector

result = TyposquatDetector().scan_dependency("proc-macro1", "1.0.0")
print(result.risk_level, result.risk_score, result.similar_packages)
```

## `taintrace.scorer`

### `RiskLevel`

An enum with four ordered values: `LOW` (`0`), `MEDIUM` (`1`), `HIGH` (`2`),
and `CRITICAL` (`3`). `str(level)` returns the uppercase name.

### `RiskResult`

```python
RiskResult(
    package_name: str,
    level: RiskLevel,
    score: float,
    similar_packages: list[tuple[str, float]],
    reason: str,
)
```

The value returned by `RiskScorer.score`. `similar_packages` contains at most
the ten highest-scoring known packages.

### `RiskScorer`

#### `RiskScorer(db: KnownPackagesDB | None = None) -> RiskScorer`

Creates a scorer. If `db` is omitted, a new built-in `KnownPackagesDB` is
created.

#### `score(package_name: str, ecosystem: str = "rust", similarity_threshold: float = 0.7) -> RiskResult`

Scores a package name. Known packages receive `LOW` and score `0.0`; unknown
packages with no match receive `MEDIUM` and score `0.3`. Similarity thresholds
of at least `0.95`, `0.85`, or `0.75` produce `CRITICAL`, `HIGH`, or `MEDIUM`
respectively; lower matches are `LOW`.

```python
from taintrace import RiskScorer

result = RiskScorer().score("reqeusts", ecosystem="python")
assert 0.0 <= result.score <= 1.0
print(result.level, result.reason)
```

## `taintrace.similarity`

### `SimilarityEngine`

#### `similarity(name1: str, name2: str) -> float`

Returns a combined similarity score between `0.0` and `1.0`, using edit
distance, Soundex, substring matching, and a small set of Unicode confusables.
Identical strings return `1.0`.

The Soundex component is damped when the two names are long enough for the
four-character code to saturate: Soundex emits a fixed four-character code, so
long names sharing a prefix collide (`org.*` coordinates all hash to `o621`).
Without that guard a collision scored `1.0` and unrelated packages were
reported as perfect typosquats.

#### `could_match(name1: str, name2: str, threshold: float) -> bool`

A cheap necessary condition for `similarity(name1, name2) >= threshold`, used to
skip candidates that cannot possibly reach the threshold. It returns `True` for
a superset of the real matches: name-length compatibility covers the edit
distance, substring and homoglyph components, and a close Soundex code covers
the phonetic one.

#### `levenshtein(s1: str, s2: str) -> int`

Returns the minimum number of insertions, deletions, and substitutions needed
to change one string into the other.

#### `normalize_homoglyphs(s: str) -> str`

Lowercases a string and replaces the engine's supported high-confidence
confusable characters with ASCII equivalents.

```python
from taintrace import SimilarityEngine

engine = SimilarityEngine()
assert engine.levenshtein("kitten", "sitting") == 3
assert engine.similarity("proc-macro1", "proc-macro2") > 0.9
print(engine.normalize_homoglyphs("pаypal"))
```

## `taintrace.db`

### `KnownPackagesDB`

#### `KnownPackagesDB() -> KnownPackagesDB`

Loads the built-in package names into memory. The database is offline and
cannot be populated through the public API. The `java` ecosystem is loaded
from packaged data (`taintrace/data/java_packages.txt`), generated from the
Maven Central repository index by `scripts/generate_java_packages.py`.

#### `is_known(name: str, ecosystem: str = "rust") -> bool`

Returns whether `name` is present in the selected ecosystem's known-package
list, case-insensitively. Unknown ecosystems return `False`. For `java`, a
bare `artifactId` also resolves against every curated `groupId`.

#### `has_ecosystem_data(ecosystem: str) -> bool`

Returns whether the ecosystem has any known-package data at all. An ecosystem
registered but empty silently disables similarity matching (#77); this makes
that condition detectable.

#### `ecosystems() -> list[str]`

Returns the ecosystems that have known-package data, sorted.

#### `get_similar(name: str, threshold: float = 0.8, ecosystem: str = "rust") -> list[tuple[str, float]]`

Returns up to ten known package names whose similarity is at least
`threshold`, sorted from highest to lowest score.

Raises `taintrace.UnknownEcosystemError` when `ecosystem` has no data, so a
coverage gap is never reported as an empty match list.

```python
from taintrace import KnownPackagesDB

db = KnownPackagesDB()
assert db.is_known("Serde", "rust")
matches = db.get_similar("proc-macro1", ecosystem="rust")
print(matches[:1])
```

## `taintrace.config`

Configuration values use the keys `threshold`, `format` or `output_format`,
`ecosystem`, `no_informational`, and `ignore`. Invalid keys and invalid values
are discarded by `validate_config`.

### `interpolate_env_vars(data: Any) -> Any`

Recursively replaces `$VAR` and `${VAR}` in strings nested in dictionaries and
lists. Missing variables are left unchanged; non-container values are returned
as-is.

### `parse_config_file(path: Path) -> dict`

Parses TOML, YAML, or JSON based on the file name and returns an interpolated
dictionary. A missing or unsupported file returns `{}`. Invalid JSON and YAML
are treated as empty configuration; TOML parser errors may propagate.

### `validate_config(config: dict) -> dict`

Filters and normalizes supported configuration keys. Thresholds outside
`0.0..1.0`, unsupported formats/ecosystems, and invalid threshold values are
ignored.

### `find_default_config(cwd: Path | None = None) -> Path | None`

Searches the current directory, its parents, and user-level configuration
paths. Returns the first matching file or `None`.

### `load_config(config_path: Path | str | None = None, cwd: Path | None = None) -> dict`

Loads and validates an explicitly supplied file, or discovers a default file
when no path is supplied. A directory passed as `config_path` is treated as
`cwd`; no configuration found returns `{}`.

### `get_ignored_packages(cwd: Path | None = None, config_path: Path | None = None) -> list[str]`

Returns the configured `ignore` list, or `[]` when no configuration is found.

```python
from pathlib import Path
from taintrace.config import load_config

config = load_config(Path(".taintrace.toml"))
print(config.get("threshold", 0.7))
```

## `taintrace.cli`

The CLI is implemented with Click and is installed as the `taintrace`
executable. These commands are the stable user-facing interface:

```bash
taintrace check Cargo.lock --format json
taintrace score proc-macro1 --ecosystem rust
taintrace scan-directory . --format sarif
```

#### `cli() -> None`

Click group entry point. It provides `--version` and dispatches the commands
below. It is normally invoked through the installed `taintrace` executable.

#### `check(lockfiles: tuple[Path, ...], config_file: Path | None, output_format: str, threshold: float, ecosystem: str, no_informational: bool, ignore: tuple[str, ...]) -> None`

Click command that checks one or more existing lockfiles. `output_format` is
`cli`, `json`, or `sarif`; `threshold` is between `0.0` and `1.0`; `ecosystem`
can be `auto`, `rust`, `node`, `python`, `go`, `ruby`, `php`, `swift`,
`elixir`, or `java`. `config_file` is optional and `ignore` can contain
multiple package names. It exits `2` when no lockfile is supplied and `1`
when suspects are found.

#### `score(name: str, ecosystem: str = "rust") -> None`

Click command that prints the risk assessment for one package name. The
ecosystem must be one of `rust`, `node`, `python`, `go`, `ruby`, `php`,
`swift`, or `elixir`.

#### `scan_directory(path: Path = Path("."), config_file: Path | None = None, output_format: str = "cli", threshold: float = 0.7, no_informational: bool = False, ignore: tuple[str, ...] = ()) -> None`

Click command that recursively scans supported lockfiles below `path`,
skipping `.git`, `node_modules`, `vendor`, `dist`, `build`, and cache
directories. It prints a no-lockfiles message and returns when none are
found. Its output and exit behavior otherwise match `check`.

- `check LOCKFILE...` parses one or more lockfiles and reports suspects.
- `score NAME` scores one package name.
- `scan-directory PATH` recursively discovers and scans supported lockfiles.

Common options include `--config`, `--threshold`, `--format` (`cli`, `json`,
or `sarif`), and repeated `--ignore`. The process exits with `0` when no
suspects are found and `1` when at least one suspect is found. Invalid paths
or command-line arguments are reported by Click.

## Supported lockfiles

`LockfileParser.parse` recognizes these file names:

| Ecosystem | File names |
| --- | --- |
| Rust | `Cargo.lock`, `Cargo.toml` |
| Node.js | `package-lock.json`, `pnpm-lock.yaml`, `yarn.lock`, `bun.lock`, `bun.lockb` |
| Python | `requirements.txt`, `poetry.lock`, `uv.lock`, `pyproject.toml`, `Pipfile.lock` |
| Go | `go.sum` |
| Ruby | `Gemfile.lock` |
| PHP | `composer.json`, `composer.lock` |
| Swift | `Package.resolved`, `Package.swift` |
| Elixir | `mix.lock` |
| Java/Gradle | `build.gradle`, `build.gradle.kts`, `libs.versions.toml` |

`bun.lockb` is binary and returns no dependencies with a `UserWarning`; convert
it to `bun.lock` before scanning for useful results.