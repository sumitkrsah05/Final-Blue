"""Prompt templates, kept out of business logic."""

from prompts.blue_analysis_prompt import (
    PROMPT_VERSION,
    SYSTEM_PROMPT,
    build_executive_summary_prompt,
    build_finding_analysis_prompt,
    build_system_prompt,
    build_technical_summary_prompt,
)

__all__ = [
    "PROMPT_VERSION",
    "SYSTEM_PROMPT",
    "build_executive_summary_prompt",
    "build_finding_analysis_prompt",
    "build_system_prompt",
    "build_technical_summary_prompt",
]
