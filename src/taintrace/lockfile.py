"""Lockfile parsers for multiple ecosystems."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional, Tuple
import json
import re


@dataclass
class Dependency:
    """A parsed dependency from any lockfile."""
    name: str
    version: str
    ecosystem: str  # Registry used for known-package comparisons


# Map of lowercase filenames to (parser_func, ecosystem)
EXTENDED_FORMATS = {
    "poetry.lock": ("python", "_parse_poetry"),
    "pnpm-lock.yaml": ("node", "_parse_pnpm"),
    "yarn.lock": ("node", "_parse_yarn"),
    "cargo.toml": ("rust", "_parse_cargo_toml"),
    "uv.lock": ("python", "_parse_uv_lock"),
    "pyproject.toml": ("python", "_parse_pyproject_toml"),
    "gemfile.lock": ("ruby", "_parse_gemfile_lock"),
    "pipfile.lock": ("python", "_parse_pipfile_lock"),
    "bun.lock": ("node", "_parse_bun_lock"),
    "bun.lockb": ("node", "_parse_bun_lockb"),
    "composer.json": ("php", "_parse_composer_json"),
    "composer.lock": ("php", "_parse_composer_lock"),
    "package.resolved": ("swift", "_parse_package_resolved"),
    "package.swift": ("swift", "_parse_package_swift"),
    "mix.lock": ("elixir", "_parse_mix_lock"),
    "build.gradle": ("java", "_parse_gradle"),
    "build.gradle.kts": ("java", "_parse_gradle"),
    "libs.versions.toml": ("java", "_parse_gradle_version_catalog"),
}


class LockfileParser:
    """Parse lockfiles and extract dependency names."""

    def parse(self, path: Path) -> List[Dependency]:
        """Auto-detect lockfile type and parse accordingly."""
        name = path.name.lower()
        if name == "cargo.lock":
            return self._parse_cargo(path)
        elif name == "package-lock.json":
            return self._parse_package_lock(path)
        elif name == "requirements.txt":
            return self._parse_requirements(path)
        elif name == "go.sum":
            return self._parse_go_sum(path)
        elif name in EXTENDED_FORMATS:
            _, method_name = EXTENDED_FORMATS[name]
            return getattr(self, method_name)(path)
        else:
            # Try as Cargo.lock by default
            return self._parse_cargo(path)

    def _parse_gradle(self, path: Path) -> List[Dependency]:
        """Parse literal Maven coordinates from Gradle Groovy/Kotlin build files."""
        content = path.read_text(encoding="utf-8", errors="replace")
        deps = []
        pattern = re.compile(
            r"(?:implementation|api|compileOnly|runtimeOnly|testImplementation|"
            r"testCompileOnly|testRuntimeOnly|annotationProcessor|kapt)\s*"
            r"(?:\(\s*)?[\"']([^\"']+:[^\"']+:[^\"']+)[\"']"
        )
        for match in pattern.finditer(content):
            coordinate = match.group(1)
            group, name, version = coordinate.split(":", 2)
            deps.append(Dependency(name=f"{group}:{name}", version=version, ecosystem="java"))
        return deps

    def _parse_gradle_version_catalog(self, path: Path) -> List[Dependency]:
        """Parse Gradle version-catalog library entries from libs.versions.toml."""
        content = path.read_text(encoding="utf-8", errors="replace")
        versions = {}
        section = ""
        deps = []
        for raw_line in content.splitlines():
            line = raw_line.split("#", 1)[0].strip()
            if not line:
                continue
            section_match = re.match(r"^\[([^]]+)\]$", line)
            if section_match:
                section = section_match.group(1)
                continue
            if section == "versions":
                match = re.match(r'^[\w.-]+\s*=\s*["\']([^"\']+)["\']', line)
                if match:
                    key = line.split("=", 1)[0].strip()
                    versions[key] = match.group(1)
            elif section == "libraries":
                module = re.search(r'module\s*=\s*["\']([^"\']+)["\']', line)
                if not module:
                    continue
                direct = re.search(r'(?<!\.)version\s*=\s*["\']([^"\']+)["\']', line)
                ref = re.search(r'version\.ref\s*=\s*["\']([^"\']+)["\']', line)
                version = direct.group(1) if direct else versions.get(ref.group(1), "") if ref else ""
                deps.append(Dependency(name=module.group(1), version=version, ecosystem="java"))
        return deps

    def _parse_poetry(self, path: Path) -> List[Dependency]:
        """Parse Poetry lockfile (poetry.lock TOML format)."""
        deps = []
        content = path.read_text(encoding="utf-8", errors="replace")
        blocks = re.split(r"\[\[package\]\]", content)
        for block in blocks[1:]:
            name_match = re.search(r'name\s*=\s*"([^"]+)"', block)
            version_match = re.search(r'version\s*=\s*"([^"]+)"', block)
            if name_match and version_match:
                deps.append(Dependency(
                    name=name_match.group(1),
                    version=version_match.group(1),
                    ecosystem="python",
                ))
        return deps

    def _parse_pnpm(self, path: Path) -> List[Dependency]:
        """Parse pnpm lockfile (pnpm-lock.yaml) — handles v6/v9+ formats."""
        deps = []
        content = path.read_text(encoding="utf-8", errors="replace")

        # Modern pnpm (v9+) uses `packages:` with keys like "/package-name/1.0.0:"
        packages_match = re.search(
            r"^packages:\s*$(.+?)(?:\n^[a-z]|\Z)", content, re.MULTILINE | re.DOTALL
        )
        if packages_match:
            for line in packages_match.group(1).strip().splitlines():
                line = line.strip()
                if not line.startswith("/"):
                    continue
                pkg_key = line.rstrip(":")
                # "/name/version" or "/@scope/name/version"
                m = re.match(r"^/(?:@([^/]+)/)?(.+?)/([0-9][^/]+)$", pkg_key)
                if m:
                    scope, name, version = m.groups()
                    full_name = f"@{scope}/{name}" if scope else name
                    deps.append(Dependency(name=full_name, version=version, ecosystem="node"))
        else:
            # Older pnpm format: `dependencies:` section
            deps_match = re.search(
                r"^dependencies:\s*$(.+?)(?:\n^[a-z]|\Z)", content, re.MULTILINE | re.DOTALL
            )
            if deps_match:
                for line in deps_match.group(1).strip().splitlines():
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    # Format: "package-name: version" or "@scope/package: version"
                    dep_match = re.match(r"^(.+?):\s+(.+)$", line)
                    if dep_match:
                        name = dep_match.group(1).strip()
                        version = dep_match.group(2).strip()
                        deps.append(Dependency(name=name, version=version, ecosystem="node"))
        return deps

    def _parse_yarn(self, path: Path) -> List[Dependency]:
        """Parse Yarn Classic lockfile (yarn.lock)."""
        deps = []
        content = path.read_text(encoding="utf-8", errors="replace")

        for block in re.split(r"\n\n+", content):
            if not block.strip():
                continue
            first_line = block.splitlines()[0].strip()
            if first_line.startswith("#"):
                continue

            spec_match = re.match(r'^"?([^"]+)"?\s*$', first_line)
            if not spec_match:
                continue

            spec = spec_match.group(1)
            name_ver = re.match(r"^(@?[^@]+)@(.+)$", spec)
            if not name_ver:
                continue

            name, version_spec = name_ver.group(1), name_ver.group(2)
            if "workspace:" in version_spec:
                continue

            version_match = re.search(r'^\s+version\s+"([^"]+)"', block, re.MULTILINE)
            resolved = version_match.group(1) if version_match else version_spec

            deps.append(Dependency(name=name, version=resolved, ecosystem="node"))
        return deps

    @staticmethod
    def _find_cargo_workspace_root(path: Path) -> Optional[Path]:
        """Find the nearest ancestor Cargo.toml declaring a workspace."""
        start = path.parent if path.name.lower() == "cargo.toml" else path
        for directory in (start, *start.parents):
            candidate = directory / "Cargo.toml"
            if not candidate.is_file():
                continue
            content = candidate.read_text(encoding="utf-8", errors="replace")
            if re.search(r"^\[workspace\]\s*$", content, flags=re.MULTILINE):
                return candidate
        return None

    @staticmethod
    def _parse_cargo_workspace_dependencies(path: Optional[Path]) -> dict[str, str]:
        """Read versions from a Cargo workspace's [workspace.dependencies] section."""
        if path is None:
            return {}

        content = path.read_text(encoding="utf-8", errors="replace")
        section_match = re.search(
            r"^\[workspace\.dependencies\]\s*$([\s\S]*?)(?=^\[|\Z)",
            content,
            flags=re.MULTILINE,
        )
        if not section_match:
            return {}

        versions: dict[str, str] = {}
        for raw_line in section_match.group(1).splitlines():
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue

            dep_match = re.match(r'^([a-zA-Z0-9_-]+)\s*=\s*(.+?)\s*(?:#.*)?$', line)
            if not dep_match:
                continue

            name, spec = dep_match.groups()
            quoted_version = re.fullmatch(r'"([^"]+)"', spec)
            if quoted_version:
                versions[name] = quoted_version.group(1)
                continue

            version_match = re.search(r'version\s*=\s*"([^"]+)"', spec)
            if version_match:
                versions[name] = version_match.group(1)

        return versions

    # Sections whose keys name crates. Order matters: ``[dependencies]`` outranks
    # ``[build-dependencies]``, which outranks ``[dev-dependencies]``, so that a
    # crate declared in several sections keeps its production version (#65/#72).
    _CARGO_DEP_SECTIONS = {
        "dependencies": 0,
        "build-dependencies": 1,
        "dev-dependencies": 2,
    }

    @classmethod
    def _cargo_section_kind(cls, header: str) -> Optional[Tuple[int, Optional[str]]]:
        """Classify a TOML table header as a Cargo dependency table.

        Returns ``(precedence, crate_name)`` for a dependency table, where
        ``crate_name`` is the sub-table suffix for ``[dependencies.<name>]``
        syntax (#143), and ``None`` for the plain ``[dependencies]`` form.
        Returns ``None`` when the header is not a dependency table at all.
        """
        parts = header.split(".")
        # Drop an optional ``[target.'cfg(unix)'.dependencies...]`` prefix.
        if parts[0] == "target":
            parts = parts[2:]

        if not parts:
            return None

        section = parts[0]
        if section not in cls._CARGO_DEP_SECTIONS:
            return None

        precedence = cls._CARGO_DEP_SECTIONS[section]
        if len(parts) == 1:
            return precedence, None

        # ``[dependencies.tokio]`` / ``[dev-dependencies."my-crate"]``: the
        # remaining path segments spell the crate name.
        crate = ".".join(parts[1:]).strip().strip("\"'")
        if not crate:
            return None
        return precedence, crate

    @staticmethod
    def _cargo_version_from_spec(spec: str, workspace_versions: dict[str, str], name: str) -> str:
        """Extract a version from a Cargo dependency spec.

        Handles the bare string form (``serde = "1.0"``), the inline table form
        (``serde = { version = "1.0" }``) and workspace inheritance.
        """
        spec = spec.strip()
        spec = re.sub(r"#.*$", "", spec).strip()

        if re.search(r"\bworkspace\s*=\s*true\b", spec):
            return workspace_versions.get(name, "workspace")

        quoted = re.fullmatch(r'"([^"]+)"', spec)
        if quoted:
            return quoted.group(1)

        ver_match = re.search(r'version\s*=\s*"([^"]+)"', spec)
        if ver_match:
            return ver_match.group(1)

        # A sub-table may inherit via ``version.workspace = true``.
        return "0.0.0"

    def _parse_cargo_toml(self, path: Path) -> List[Dependency]:
        """Parse Cargo.toml dependency sections, including workspace-inherited versions."""
        content = path.read_text(encoding="utf-8", errors="replace")

        workspace_root = self._find_cargo_workspace_root(path)
        workspace_versions = self._parse_cargo_workspace_dependencies(workspace_root)

        # name -> (precedence, order, version); first declaration wins at equal
        # precedence so the production entry beats dev/build copies (#65/#72).
        found: dict[str, Tuple[int, int, str]] = {}
        order = 0

        section_kind: Optional[Tuple[int, Optional[str]]] = None
        sub_table: Optional[str] = None
        pending: Optional[Tuple[str, int]] = None
        pending_spec: List[str] = []

        def record(name: str, precedence: int, version: str) -> None:
            nonlocal order
            existing = found.get(name)
            if existing is not None and existing[0] <= precedence:
                return
            if existing is not None:
                order -= 1  # re-insert the upgraded entry at this position
            found[name] = (precedence, order, version)
            order += 1

        def flush_pending() -> None:
            """Commit a multi-line inline table, e.g. ``rand = {`` ... ``}``."""
            nonlocal pending, pending_spec
            if pending is not None:
                name, precedence = pending
                record(name, precedence, self._cargo_version_from_spec(
                    " ".join(pending_spec), workspace_versions, name))
            pending, pending_spec = None, []

        for raw_line in content.splitlines():
            line = raw_line.split("#", 1)[0].strip()
            if not line:
                continue

            if line.startswith("["):
                flush_pending()
                header = line.strip("[]").strip()
                section_kind = self._cargo_section_kind(header)
                sub_table = section_kind[1] if section_kind else None
                continue

            if section_kind is None:
                continue

            precedence, header_crate = section_kind

            if sub_table is not None:
                # Inside ``[dependencies.<name>]`` every key is part of the spec.
                key, sep, value = line.partition("=")
                if not sep:
                    continue
                key = key.strip()
                if key == "version":
                    record(header_crate, precedence,
                           self._cargo_version_from_spec(value, workspace_versions, header_crate))
                elif key == "version.workspace" and value.strip() == "true":
                    record(header_crate, precedence,
                           workspace_versions.get(header_crate, "workspace"))
                continue

            if pending is not None:
                pending_spec.append(line)
                joined = " ".join(pending_spec)
                if joined.count("{") <= joined.count("}"):
                    name, precedence = pending
                    record(name, precedence,
                           self._cargo_version_from_spec(joined, workspace_versions, name))
                    pending, pending_spec = None, []
                continue

            name_match = re.match(r'^([a-zA-Z0-9_.-]+)\s*=\s*(.*)$', line)
            if not name_match:
                continue

            name, spec = name_match.group(1), name_match.group(2)

            # A multi-line inline table: accumulate until braces balance so its
            # keys are not mistaken for crates (#92).
            if spec.count("{") > spec.count("}"):
                pending = (name, precedence)
                pending_spec = [spec]
                continue

            record(name, precedence,
                   self._cargo_version_from_spec(spec, workspace_versions, name))

        flush_pending()

        return [
            Dependency(name=name, version=entry[2], ecosystem="rust")
            for name, entry in sorted(found.items(), key=lambda kv: kv[1][1])
        ]
    def _parse_cargo(self, path: Path) -> List[Dependency]:
        """Parse Cargo.lock TOML format."""
        deps = []
        content = path.read_text()
        # Match [[package]] blocks with name and version
        blocks = re.split(r'\[\[package\]\]', content)
        for block in blocks[1:]:  # skip preamble
            name_match = re.search(r'name\s*=\s*"([^"]+)"', block)
            version_match = re.search(r'version\s*=\s*"([^"]+)"', block)
            if name_match and version_match:
                deps.append(Dependency(
                    name=name_match.group(1),
                    version=version_match.group(1),
                    ecosystem="rust"
                ))
        return deps

    def _parse_package_lock(self, path: Path) -> List[Dependency]:
        """Parse package-lock.json (npm)."""
        import json
        deps = []
        try:
            data = json.loads(path.read_text())
            packages = data.get("packages", {})
            for pkg_path, pkg_info in packages.items():
                if not pkg_path.startswith("node_modules/"):
                    continue
                pkg_name = pkg_path.replace("node_modules/", "")
                version = pkg_info.get("version", "0.0.0")
                deps.append(Dependency(
                    name=pkg_name,
                    version=version,
                    ecosystem="node"
                ))
        except (json.JSONDecodeError, KeyError):
            pass
        return deps

    def _parse_requirements(self, path: Path) -> List[Dependency]:
        """Parse requirements.txt (pip)."""
        deps = []
        content = path.read_text()
        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            # Handle "package==1.0.0", "package>=1.0", "package"
            match = re.match(r'^([a-zA-Z0-9_-]+)', line)
            if match:
                name = match.group(1)
                version_match = re.search(r'[=<>!]+\s*([0-9.]+)', line)
                version = version_match.group(1) if version_match else "0.0.0"
                deps.append(Dependency(
                    name=name,
                    version=version,
                    ecosystem="python"
                ))
        return deps

    @staticmethod
    def parse_go_sum(content: str) -> list[Dependency]:
        """Parse go.sum format."""
        deps = []
        seen = set()
        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split()
            if len(parts) >= 2:
                name = parts[0]
                version = parts[1]
                if version.endswith("/go.mod"):
                    version = version[:-7]
                if (name, version) not in seen:
                    seen.add((name, version))
                    deps.append(Dependency(
                        name=name,
                        version=version,
                        ecosystem="go",
                    ))
        return deps

    def _parse_go_sum(self, path: Path) -> List[Dependency]:
        """Parse go.sum (Go)."""
        content = path.read_text(encoding="utf-8", errors="replace")
        return self.parse_go_sum(content)

    def _parse_uv_lock(self, path: Path) -> List[Dependency]:
        """Parse uv.lock (Astral uv package manager for Python).
        
        Format is TOML with [[package]] sections containing name and version.
        """
        deps = []
        content = path.read_text(encoding="utf-8", errors="replace")
        blocks = re.split(r'\[\[package\]\]', content)
        for block in blocks[1:]:
            name_match = re.search(r'name\s*=\s*"([^"]+)"', block)
            version_match = re.search(r'version\s*=\s*"([^"]+)"', block)
            if name_match and version_match:
                deps.append(Dependency(
                    name=name_match.group(1),
                    version=version_match.group(1),
                    ecosystem="python"
                ))
        return deps

    def _parse_pyproject_toml(self, path: Path) -> List[Dependency]:
        """Parse pyproject.toml (PEP 621) for dependency names.
        
        Extracts packages from:
        - [project].dependencies (PEP 621 standard)
        - [tool.poetry.dependencies] (Poetry format)
        
        Version specifiers (>=, <=, ==, ~=, etc.) are stripped to return
        only the package name for typosquat comparison.
        """
        deps = []
        content = path.read_text(encoding="utf-8", errors="replace")
        
        # Extract [project].dependencies section
        # Look for [project] followed by dependencies = [ ... ]
        project_deps_match = re.search(
            r'^\s*\[project\][^\[]*?dependencies\s*=\s*\[(.*?)\]',
            content, re.MULTILINE | re.DOTALL
        )
        if project_deps_match:
            deps_text = project_deps_match.group(1)
            for line in deps_text.splitlines():
                line = line.strip().strip(',').strip('"').strip("'")
                if not line or line.startswith('#'):
                    continue
                # Extract package name (before version specifier)
                # Handles: "package>=1.0", "package == 1.0.*", "package"
                name_match = re.match(r'^([a-zA-Z0-9_.-]+)', line)
                if name_match:
                    name = name_match.group(1)
                    deps.append(Dependency(name=name, version="", ecosystem="python"))
        
        # Extract [tool.poetry.dependencies] section
        poetry_match = re.search(
            r'\[tool\.poetry\.dependencies\](.*?)(?:^\[|\Z)',
            content, re.MULTILINE | re.DOTALL
        )
        if poetry_match:
            for line in poetry_match.group(1).strip().splitlines():
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                # Format: name = "version" or name = {version = "..."}
                dep_match = re.match(r'^([a-zA-Z0-9_.-]+)\s*=\s*', line)
                if dep_match:
                    name = dep_match.group(1)
                    # Skip python version constraint
                    if name == 'python':
                        continue
                    deps.append(Dependency(name=name, version="", ecosystem="python"))
        
        return deps

    def _parse_gemfile_lock(self, path: Path) -> List[Dependency]:
        """Parse Bundler Gemfile.lock (Ruby).

        Format:
            GEM
              remote: https://rubygems.org/
              specs:
                rails (7.1.3)
                  actioncable (= 7.1.3)
                nokogiri (1.16.5)

            PLATFORMS
              ruby

            BUNDLED WITH
               2.5.11

        Only top-level specs (4-space indent) are included, not sub-dependencies.
        """
        deps = []
        content = path.read_text(encoding="utf-8", errors="replace")
        in_specs = False
        for line in content.splitlines():
            stripped = line.strip()
            if stripped == "specs:":
                in_specs = True
                continue
            if stripped in ("PLATFORMS", "DEPENDENCIES", "BUNDLED WITH", "GEM", "GIT"):
                in_specs = False
                continue
            if in_specs and stripped:
                # Top-level specs have 4-space indent, sub-deps have 6+
                indent = len(line) - len(line.lstrip())
                if indent == 4 and "(" in stripped:
                    match = re.match(r'^([a-zA-Z0-9_.-]+)\s+\(([^)]+)\)', stripped)
                    if match:
                        deps.append(Dependency(
                            name=match.group(1),
                            version=match.group(2),
                            ecosystem="ruby",
                        ))
        return deps

    def _parse_pipfile_lock(self, path: Path) -> List[Dependency]:
        """Parse Pipenv Pipfile.lock (JSON).

        Format:
            {
              "default": {
                "requests": {
                  "hashes": ["sha256:..."],
                  "version": "==2.31.0"
                }
              },
              "develop": { ... }
            }
        """
        deps = []
        try:
            data = json.loads(path.read_text(encoding="utf-8", errors="replace"))
        except (json.JSONDecodeError, FileNotFoundError):
            return deps
        for section in ("default", "develop"):
            if not isinstance(data.get(section), dict):
                continue
            for pkg_name, pkg_info in data[section].items():
                if not isinstance(pkg_info, dict):
                    continue
                version = pkg_info.get("version", "")
                # Strip leading == from version
                if version.startswith("=="):
                    version = version[2:]
                deps.append(Dependency(
                    name=pkg_name,
                    version=version,
                    ecosystem="python",
                ))
        return deps

    def _parse_bun_lock(self, path: Path) -> List[Dependency]:
        """Parse Bun text lockfile (bun.lock).

        Bun's text format (v1.0+) is JSON-like with a "packages" dict:
        {
          "packages": {
            "react": "18.2.0",
            "lodash": "4.17.21",
            "@types/react": "18.2.0"
          }
        }
        """
        deps = []
        try:
            data = json.loads(path.read_text(encoding="utf-8", errors="replace"))
        except (json.JSONDecodeError, FileNotFoundError):
            return deps
        packages = data.get("packages", {})
        if isinstance(packages, dict):
            for name, version in packages.items():
                if isinstance(version, str):
                    deps.append(Dependency(name=name, version=version, ecosystem="node"))
        return deps

    def _parse_bun_lockb(self, path: Path) -> List[Dependency]:
        """Parse Bun binary lockfile (bun.lockb).

        Binary format — cannot parse without Bun runtime.
        Return empty list with a warning.
        """
        import warnings
        warnings.warn(
            "bun.lockb is a binary format and cannot be parsed without Bun runtime. "
            "Use 'bun bun.lock' to convert to text format first.",
            UserWarning,
            stacklevel=2,
        )
        return []

    def _parse_composer_json(self, path: Path) -> List[Dependency]:
        """Parse composer.json require/require-dev sections.

        Format:
            {
              "require": {
                "guzzlehttp/guzzle": "^7.0",
                "symfony/console": "^6.0"
              },
              "require-dev": {
                "phpunit/phpunit": "^10.0"
              }
            }
        """
        deps = []
        try:
            data = json.loads(path.read_text(encoding="utf-8", errors="replace"))
        except (json.JSONDecodeError, FileNotFoundError):
            return deps
        for section in ("require", "require-dev"):
            if not isinstance(data.get(section), dict):
                continue
            for pkg_name, version_spec in data[section].items():
                # Skip the php version constraint
                if pkg_name == "php":
                    continue
                # Extract base version from constraint (e.g., "^7.0" -> "7.0")
                version = re.sub(r'^[~^>=<\s]+', '', str(version_spec)).strip()
                if not version:
                    version = "0.0.0"
                deps.append(Dependency(
                    name=pkg_name,
                    version=version,
                    ecosystem="php",
                ))
        return deps

    def _parse_composer_lock(self, path: Path) -> List[Dependency]:
        """Parse composer.lock packages array.

        Format:
            {
              "packages": [
                {
                  "name": "guzzlehttp/guzzle",
                  "version": "7.8.0",
                  ...
                },
                ...
              ],
              "packages-dev": [...]
            }
        """
        deps = []
        try:
            data = json.loads(path.read_text(encoding="utf-8", errors="replace"))
        except (json.JSONDecodeError, FileNotFoundError):
            return deps
        for section in ("packages", "packages-dev"):
            for pkg in data.get(section, []):
                if not isinstance(pkg, dict):
                    continue
                name = pkg.get("name", "")
                version = pkg.get("version", "0.0.0")
                if name:
                    deps.append(Dependency(name=name, version=version, ecosystem="php"))
        return deps

    def _parse_package_resolved(self, path: Path) -> List[Dependency]:
        """Parse Swift Package Manager's Package.resolved JSON format.

        SwiftPM v2 and v3 put ``pins`` at the document root, while v1 stores
        the same array under ``object``. GitHub dependencies use a stable
        ``github.com/owner/repository`` name so similarly named repositories
        remain distinguishable.
        """
        try:
            data = json.loads(path.read_text(encoding="utf-8", errors="replace"))
        except (json.JSONDecodeError, FileNotFoundError):
            return []

        pins = data.get("pins")
        if not isinstance(pins, list):
            legacy = data.get("object", {})
            pins = legacy.get("pins", []) if isinstance(legacy, dict) else []

        deps = []
        for pin in pins:
            if not isinstance(pin, dict):
                continue
            state = pin.get("state", {})
            if not isinstance(state, dict):
                state = {}
            location = pin.get("location") or pin.get("repositoryURL") or ""
            name = self._swift_package_name(
                str(location), str(pin.get("identity") or pin.get("package") or "")
            )
            if not name:
                continue
            version = state.get("version") or state.get("revision") or state.get("branch") or ""
            deps.append(Dependency(name=name, version=str(version), ecosystem="swift"))
        return deps

    def _parse_package_swift(self, path: Path) -> List[Dependency]:
        """Parse remote ``.package`` declarations from Package.swift."""
        content = path.read_text(encoding="utf-8", errors="replace")
        deps = []
        declarations = re.findall(r"\.package\s*\((.*?)\)", content, re.DOTALL)
        for declaration in declarations:
            location_match = re.search(
                r'(?:url|location)\s*:\s*"([^"]+)"', declaration
            )
            if not location_match:
                continue
            location = location_match.group(1)
            name = self._swift_package_name(location, "")
            if not name:
                continue
            version_match = re.search(
                r'(?:from|exact|branch|revision)\s*:\s*"([^"]+)"', declaration
            )
            version = version_match.group(1) if version_match else ""
            deps.append(Dependency(name=name, version=version, ecosystem="swift"))
        return deps

    @staticmethod
    def _swift_package_name(location: str, fallback: str) -> str:
        """Return a canonical name for a Swift package location."""
        github_match = re.search(
            r"github\.com[/:]([^/]+)/([^/#]+)", location, flags=re.IGNORECASE
        )
        if github_match:
            owner, repository = github_match.groups()
            return f"github.com/{owner}/{repository.removesuffix('.git')}"
        return fallback

    def _parse_mix_lock(self, path: Path) -> List[Dependency]:
        """Parse Hex package entries from an Elixir ``mix.lock`` file.

        ``mix.lock`` is an Elixir term rather than JSON. Each Hex entry starts
        with a package map key followed by ``{:hex, :package, "version", ...}``.
        Git and path entries are intentionally ignored because they are not
        packages published in the Hex registry.
        """
        content = path.read_text(encoding="utf-8", errors="replace")
        pattern = re.compile(
            r'["\']([a-zA-Z0-9_.-]+)["\']\s*:\s*'
            r'\{\s*:hex\s*,\s*:(?:"([^"\\]+)"|([a-zA-Z0-9_.-]+))\s*,\s*'
            r'"([^"\\]+)"',
            re.DOTALL,
        )
        deps = []
        for match in pattern.finditer(content):
            lock_name, quoted_package, atom_package, version = match.groups()
            package_name = quoted_package or atom_package or lock_name
            deps.append(Dependency(name=package_name, version=version, ecosystem="elixir"))
        return deps


parse_go_sum = LockfileParser.parse_go_sum
