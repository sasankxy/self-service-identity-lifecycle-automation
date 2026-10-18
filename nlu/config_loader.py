"""Loads the local JSON configuration (dictionaries, aliases, patterns)."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Optional, Tuple

PACKAGE_DIR = Path(__file__).resolve().parent
DEFAULT_CONFIG_DIR = PACKAGE_DIR / "config"
DEFAULT_MODELS_DIR = PACKAGE_DIR / "models"
DEFAULT_DATA_DIR = PACKAGE_DIR / "data"


def load_configs(config_dir: Optional[Path] = None) -> Tuple[dict, dict]:
    config_dir = Path(config_dir) if config_dir else DEFAULT_CONFIG_DIR
    with open(config_dir / "entities.json", encoding="utf-8") as f:
        entities = json.load(f)
    with open(config_dir / "patterns.json", encoding="utf-8") as f:
        patterns = json.load(f)
    return entities, patterns
