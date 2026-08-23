"""Markdown renderer for privacy-safe commercial benchmark evidence."""

from __future__ import annotations

import os
import tempfile
from pathlib import Path
from typing import Mapping

from jinja2 import Environment, StrictUndefined


def render_benchmark_markdown(evidence: Mapping[str, object]) -> str:
    """Render versioned benchmark evidence with the packaged template."""

    template_path = Path(__file__).with_name("benchmark_template.md")
    environment = Environment(
        undefined=StrictUndefined,
        autoescape=False,
        trim_blocks=True,
        lstrip_blocks=True,
    )
    template = environment.from_string(template_path.read_text(encoding="utf-8"))
    return template.render(**evidence).rstrip() + "\n"


def write_benchmark_markdown(
    evidence: Mapping[str, object], output: str | Path
) -> Path:
    """Atomically render and write a UTF-8 Markdown report."""

    path = Path(output)
    path.parent.mkdir(parents=True, exist_ok=True)
    rendered = render_benchmark_markdown(evidence)
    temporary_name: str | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            dir=path.parent,
            prefix=f".{path.name}.",
            suffix=".tmp",
            delete=False,
        ) as temporary:
            temporary.write(rendered)
            temporary.flush()
            os.fsync(temporary.fileno())
            temporary_name = temporary.name
        os.replace(temporary_name, path)
    finally:
        if temporary_name and os.path.exists(temporary_name):
            os.unlink(temporary_name)
    return path


__all__ = ["render_benchmark_markdown", "write_benchmark_markdown"]
