"""Config loading and validation for taintrace."""

from __future__ import annotations

import json
import os
import re
from pathlib import Path
from typing import Any, Optional, Union

CONFIG_FILE_NAMES = [
    ".taintrace.toml",
    "taintrace.toml",
    ".taintrace.yaml",
    ".taintrace.yml",
    "taintrace.yaml",
    "taintrace.yml",
    ".taintracerc",
    "pyproject.toml",
]

USER_CONFIG_PATHS = [
    Path.home() / ".config" / "taintrace" / "config.toml",
    Path.home() / ".config" / "taintrace" / "config.yaml",
    Path.home() / ".config" / "taintrace" / "config.yml",
    Path.home() / ".taintrace.toml",
    Path.home() / ".taintrace.yaml",
    Path.home() / ".taintrace.yml",
]

VALID_CONFIG_KEYS = {
    "threshold",
    "format",
    "output_format",
    "ecosystem",
    "no_informational",
    "ignore",
}

VALID_ECOSYSTEMS = {
    "auto", "rust", "node", "python", "go", "ruby", "php", "swift", "elixir", "java"
}

VALID_FORMATS = {"cli", "json", "sarif"}


def interpolate_env_vars(data: Any) -> Any:
    """Recursively interpolate environment variables in strings ($VAR and ${VAR})."""
    if isinstance(data, str):
        def _replace(match: re.Match) -> str:
            var_name = match.group(1) or match.group(2)
            return os.environ.get(var_name, match.group(0))

        pattern = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}|\$([A-Za-z_][A-Za-z0-9_]*)")
        return pattern.sub(_replace, data)
    elif isinstance(data, dict):
        return {k: interpolate_env_vars(v) for k, v in data.items()}
    elif isinstance(data, list):
        return [interpolate_env_vars(v) for v in data]
    return data


def _parse_toml_file(path: Path) -> dict:
    try:
        import tomllib
    except ImportError:
        try:
            import tomli as tomllib  # type: ignore
        except ImportError:
            return {}

    with open(path, "rb") as f:
        data = tomllib.load(f)

    if path.name == "pyproject.toml":
        return data.get("tool", {}).get("taintrace", {})

    # If top-level has a [taintrace] table, use that; otherwise use root dict
    if "taintrace" in data and isinstance(data["taintrace"], dict):
        return data["taintrace"]
    return data


def _parse_yaml_file(path: Path) -> dict:
    try:
        import yaml
        with open(path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}
    except ImportError:
        # Fallback simple parser for basic YAML key-value pairs and lists
        data = _simple_yaml_fallback(path)
    except Exception:
        return {}

    if isinstance(data, dict):
        if "taintrace" in data and isinstance(data["taintrace"], dict):
            return data["taintrace"]
        return data
    return {}


def _simple_yaml_fallback(path: Path) -> dict:
    """Minimal YAML parser fallback if PyYAML is not installed."""
    data: dict[str, Any] = {}
    current_list_key = None
    try:
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                raw = line.strip()
                if not raw or raw.startswith("#"):
                    continue
                if raw.startswith("- ") and current_list_key:
                    item = raw[2:].strip().strip("'\"")
                    data.setdefault(current_list_key, []).append(item)
                    continue
                if ":" in raw:
                    parts = raw.split(":", 1)
                    k = parts[0].strip()
                    v = parts[1].strip()
                    if v == "":
                        current_list_key = k
                        data[k] = []
                    else:
                        current_list_key = None
                        if v.startswith("[") and v.endswith("]"):
                            items = [x.strip().strip("'\"") for x in v[1:-1].split(",") if x.strip()]
                            data[k] = items
                        elif v.lower() in ("true", "yes"):
                            data[k] = True
                        elif v.lower() in ("false", "no"):
                            data[k] = False
                        else:
                            try:
                                data[k] = float(v) if "." in v else int(v)
                            except ValueError:
                                data[k] = v.strip("'\"")
    except Exception:
        pass
    return data


def parse_config_file(path: Path) -> dict:
    """Parse a config file based on its extension."""
    if not path.is_file():
        return {}

    ext = path.suffix.lower()
    name = path.name.lower()

    if ext in (".toml", "") or name in (".taintrace.toml", "taintrace.toml", ".taintracerc", "pyproject.toml"):
        data = _parse_toml_file(path)
    elif ext in (".yaml", ".yml") or "yaml" in name or "yml" in name:
        data = _parse_yaml_file(path)
    elif ext == ".json":
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
            if "taintrace" in data and isinstance(data["taintrace"], dict):
                data = data["taintrace"]
        except Exception:
            data = {}
    else:
        # Try TOML first, then YAML
        data = _parse_toml_file(path) or _parse_yaml_file(path)

    if not isinstance(data, dict):
        return {}

    return interpolate_env_vars(data)


def validate_config(config: dict) -> dict:
    """Validate config keys and normalize types."""
    clean: dict[str, Any] = {}
    for k, v in config.items():
        key = str(k).lower().replace("-", "_")
        if key not in VALID_CONFIG_KEYS:
            continue

        if key == "threshold":
            try:
                val = float(v)
                if 0.0 <= val <= 1.0:
                    clean["threshold"] = val
            except (ValueError, TypeError):
                pass
        elif key in ("format", "output_format"):
            val_str = str(v).lower()
            if val_str in VALID_FORMATS:
                clean["output_format"] = val_str
        elif key == "ecosystem":
            eco_str = str(v).lower()
            if eco_str in VALID_ECOSYSTEMS:
                clean["ecosystem"] = eco_str
        elif key == "no_informational":
            clean["no_informational"] = bool(v)
        elif key == "ignore":
            if isinstance(v, (list, tuple)):
                clean["ignore"] = [str(x) for x in v]
            elif isinstance(v, str):
                clean["ignore"] = [x.strip() for x in v.split(",") if x.strip()]
        else:
            clean[key] = v

    return clean


def find_default_config(cwd: Optional[Path] = None) -> Optional[Path]:
    """Find the first matching default config file in current or parent dirs, then user home."""
    if cwd is None:
        cwd = Path.cwd()

    # Search in current directory and parent directories up to root
    current = cwd
    while True:
        for name in CONFIG_FILE_NAMES:
            candidate = current / name
            if candidate.is_file():
                return candidate
        if current.parent == current:
            break
        current = current.parent

    # Search in user home directory
    for candidate in USER_CONFIG_PATHS:
        try:
            if candidate.is_file():
                return candidate
        except Exception:
            pass

    return None


def load_config(
    config_path: Optional[Union[Path, str]] = None,
    cwd: Optional[Path] = None,
) -> dict:
    """Load and validate configuration from explicit path or default discovery.
    
    If the first argument is a directory, it is treated as `cwd` for backward compatibility.
    """
    if config_path is not None:
        p = Path(config_path)
        if p.is_dir():
            cwd = p
            config_path = None
        elif p.is_file():
            raw = parse_config_file(p)
            return validate_config(raw)
        else:
            return {}

    discovered = find_default_config(cwd)
    if discovered is not None:
        raw = parse_config_file(discovered)
        return validate_config(raw)

    return {}


def get_ignored_packages(cwd: Optional[Path] = None, config_path: Optional[Path] = None) -> list[str]:
    """Get list of ignored packages from config."""
    config = load_config(config_path=config_path, cwd=cwd)
    return config.get("ignore", [])
