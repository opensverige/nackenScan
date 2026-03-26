"""Shared fixtures for NäckenSec tests."""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

import pytest

if TYPE_CHECKING:
    from skill_scanner.core.models import Skill

FIXTURES_DIR = Path(__file__).parent / "fixtures"


def load_skill(fixture_name: str) -> Skill:
    """Load a skill from fixtures using Cisco's SkillLoader."""
    from skill_scanner.core.loader import SkillLoader

    skill_dir = FIXTURES_DIR / fixture_name
    loader = SkillLoader()
    return loader.load_skill(skill_dir)


@pytest.fixture
def clean_fortnox_skill():
    return load_skill("clean_fortnox_agent")


@pytest.fixture
def malicious_skill():
    return load_skill("malicious_agent")
