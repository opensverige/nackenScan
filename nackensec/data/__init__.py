# NäckenSec — Swedish AI Agent Security
# Copyright (c) 2026 OpenSverige
# License: AGPL-3.0 (see LICENSE-AGPL)
# Commercial licensing: licensing@opensverige.se
from pathlib import Path

DATA_DIR = Path(__file__).parent
RULES_DIR = DATA_DIR.parent / "rules"
SWEDISH_RULES_DIR = RULES_DIR / "swedish"
COMMUNITY_RULES_DIR = RULES_DIR / "community"
