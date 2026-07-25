"""Vulnerable target Agents.

For PoC determinism we DO NOT call a real LLM. Instead, a hard-coded
router picks a tool based on simple regex / keyword matching over the
user input. The agent is intentionally naive:

  - No input sanitisation
  - No tool allowlist
  - Blindly trusts whatever the user wrote into tool args

Five built-in profiles expose SQL, email, file RAG, web browsing, and
Code-Act weaknesses. In a real lab these would be replaced by actual
ReAct agents driven by an LLM; the public surface
(`run(user_input) -> Trace`) stays the same so detector and reporter
code does not change.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from ai_agent_lab.datatypes import ToolCall, Trace

# Patterns used by the deterministic router. Kept module-level so tests
# can introspect them and so the demo is fully reproducible.
_READ_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(
        r"\b(?:read|open)\b.*?(?P<path>(?:\.{1,2}/|(?<![:/])/)[\w./-]+)",
        re.IGNORECASE,
    ),
    re.compile(
        r"(?P<path>(?:\.{1,2}/|(?<![:/])/)[\w./-]+)\s*$",
        re.IGNORECASE,
    ),
)
_SHELL_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"\b(exec_shell|shell|run)\b.*?(?P<cmd>.+)$", re.IGNORECASE),
    re.compile(r"\brm\s+-rf\b", re.IGNORECASE),
)
_HTTP_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"\bhttp_fetch\b.*?(?P<url>https?://\S+)", re.IGNORECASE),
    re.compile(r"\bPOST\b.*?(?P<url>https?://\S+)", re.IGNORECASE),
)
_PLAYWRIGHT_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(
        r"\b(?:playwright(?:_open)?|browser)\b.*?(?P<url>https?://\S+)",
        re.IGNORECASE,
    ),
)
_SQL_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(
        r"\b(?:sql_query|query_sql|query\s+(?:the\s+)?database)\b[:\s]*(?P<query>.+)$",
        re.IGNORECASE,
    ),
    re.compile(r"(?P<query>\bSELECT\b.+)$", re.IGNORECASE),
)
_EMAIL_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(
        r"\bdelete\s+(?:email|message)\s+(?P<message_id>[\w-]+)(?:\s+.*)?$",
        re.IGNORECASE,
    ),
    re.compile(
        r"\bsend_email\b.*?(?P<recipient>[\w.+-]+@[\w.-]+)(?P<body>.*)$",
        re.IGNORECASE,
    ),
    re.compile(
        r"\bforward\b.*?\bSMTP\b.*?\bto\s+(?P<recipient>[\w.+-]+@[\w.-]+)",
        re.IGNORECASE,
    ),
)
_RAG_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(
        r"\b(?:rag_search|search\s+(?:the\s+)?(?:rag|knowledge\s+base)|retrieve)\b"
        r"[:\s]*(?P<query>.+)$",
        re.IGNORECASE,
    ),
)
_DOCUMENT_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(
        r"\b(?:read|open|parse)\b.*?(?P<path>(?:\.{1,2}/|/)[\w./-]+\.(?:docx|pdf))",
        re.IGNORECASE,
    ),
)
_PYTHON_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(
        r"\b(?:exec_python|exec\s+python|python\s+-c)\b.*?(?P<code>.+)$",
        re.IGNORECASE,
    ),
)


def _group_is_inside_url(text: str, match: re.Match[str], group: str) -> bool:
    """Return whether a captured group begins inside an HTTP(S) URL token."""

    group_start = match.start(group)
    return any(
        url.start() <= group_start < url.end()
        for url in re.finditer(r"https?://\S+", text, re.IGNORECASE)
    )


_BUILT_IN_TARGETS: tuple[dict[str, object], ...] = (
    {
        "agent_type": "sqli",
        "api_name": "sql_assistant",
        "name": "sqli-helper",
        "description": "Vulnerable SQL helper: sends raw user text to the SQL tool.",
        "available_tools": ("sql_query",),
    },
    {
        "agent_type": "email",
        "api_name": "email_assistant",
        "name": "email-assistant",
        "description": "Vulnerable email assistant: trusts SMTP content and forwards secrets.",
        "available_tools": ("read_smtp", "search_email", "send_email", "delete_email"),
    },
    {
        "agent_type": "file_rag",
        "api_name": "file_rag",
        "name": "file-rag-agent",
        "description": "Vulnerable file RAG agent: trusts DOCX/PDF text and unsafe paths.",
        "available_tools": ("rag_search", "read_document", "read_file"),
    },
    {
        "agent_type": "web_browser",
        "api_name": "web_browser",
        "name": "web-browser-agent",
        "description": "Vulnerable Playwright browser: treats page content as instructions.",
        "available_tools": ("playwright_open",),
    },
    {
        "agent_type": "code_act",
        "api_name": "code_act",
        "name": "code-act-agent",
        "description": "Vulnerable Code-Act agent: executes generated Python without approval.",
        "available_tools": ("exec_python",),
    },
)


@dataclass
class TargetAgent:
    """A deliberately vulnerable, deterministic single-shot agent.

    The default profile exposes every PoC tool so existing callers can run
    the complete demo with ``TargetAgent()``. Built-in profiles restrict the
    advertised and routable tools to one of the five target-agent designs.
    """

    name: str = "naive-file-agent"
    description: str = "PoC vulnerable agent: blindly routes user input to tools."

    # Tool metadata - kept so a real Lab could swap in sandboxed impls.
    available_tools: tuple[str, ...] = (
        "read_file",
        "read_document",
        "rag_search",
        "http_fetch",
        "playwright_open",
        "sql_query",
        "read_smtp",
        "search_email",
        "send_email",
        "delete_email",
        "exec_shell",
        "exec_python",
    )
    agent_type: str = "legacy"
    # Stable name used by the adapter/gateway API. Empty for the legacy
    # all-tools default profile, which is not externally addressable.
    api_name: str = ""

    def _route(self, user_input: str) -> ToolCall:
        """Return the ToolCall this agent would issue for `user_input`."""

        # 1. Playwright browser profile opens URLs without origin restrictions.
        for pat in _PLAYWRIGHT_PATTERNS:
            m = pat.search(user_input)
            if m and "playwright_open" in self.available_tools:
                url = m.group("url")
                return ToolCall(
                    name="playwright_open",
                    args={"url": url},
                    result=f"[mock] Playwright opened {url} (no real browser)",
                )

        # 2. http_fetch wins when the input names it and supplies a URL.
        for pat in _HTTP_PATTERNS:
            m = pat.search(user_input)
            if m and "http_fetch" in self.available_tools:
                url = m.group("url")
                return ToolCall(
                    name="http_fetch",
                    args={
                        "method": "POST" if re.search(r"\bPOST\b", user_input, re.I) else "GET",
                        "url": url,
                        "body": user_input,
                    },
                    result=f"[mock] fetched {url} (no real network)",
                )

        # 3. Email actions trust SMTP content and the user's claimed authority.
        for pat in _EMAIL_PATTERNS:
            m = pat.search(user_input)
            if not m:
                continue
            if "message_id" in m.groupdict() and "delete_email" in self.available_tools:
                return ToolCall(
                    name="delete_email",
                    args={"message_id": m.group("message_id")},
                    result="[mock] email deleted",
                )
            if "recipient" in m.groupdict() and "send_email" in self.available_tools:
                return ToolCall(
                    name="send_email",
                    args={
                        "recipient": m.group("recipient"),
                        "body": (m.groupdict().get("body") or "").strip() or user_input,
                    },
                    result="[mock] email sent",
                )

        # 4. SQL text is forwarded without parameterisation.
        for pat in _SQL_PATTERNS:
            m = pat.search(user_input)
            if m and "sql_query" in self.available_tools:
                return ToolCall(
                    name="sql_query",
                    args={"query": m.group("query").strip()},
                    result="[mock] SQL query accepted",
                )

        # 5. RAG retrieval blindly trusts the document/query content.
        for pat in _RAG_PATTERNS:
            m = pat.search(user_input)
            if m and "rag_search" in self.available_tools:
                return ToolCall(
                    name="rag_search",
                    args={"query": m.group("query").strip()},
                    result="[mock] untrusted document returned",
                )

        # 6. DOCX/PDF paths are read without path validation.
        for pat in _DOCUMENT_PATTERNS:
            m = pat.search(user_input)
            if (
                m
                and "read_document" in self.available_tools
                and not _group_is_inside_url(user_input, m, "path")
            ):
                path = m.group("path")
                return ToolCall(
                    name="read_document",
                    args={"path": path},
                    result=f"[mock] extracted untrusted text from {path}",
                )

        # 7. Code-Act forwards generated Python directly to the executor.
        for pat in _PYTHON_PATTERNS:
            m = pat.search(user_input)
            if m and "exec_python" in self.available_tools:
                return ToolCall(
                    name="exec_python",
                    args={"code": m.group("code").strip()},
                    result="[mock] Python not executed",
                )

        # 8. exec_shell wins if user says run / shell / rm.
        for pat in _SHELL_PATTERNS:
            m = pat.search(user_input)
            if m and "exec_shell" in self.available_tools:
                cmd = m.groupdict().get("cmd") or m.group(0)
                return ToolCall(
                    name="exec_shell",
                    args={"command": cmd.strip()},
                    result="[mock] shell not executed",
                )

        # 9. read_file accepts absolute and traversal paths.
        for pat in _READ_PATTERNS:
            m = pat.search(user_input)
            if (
                m
                and "read_file" in self.available_tools
                and not _group_is_inside_url(user_input, m, "path")
            ):
                path = m.group("path")
                return ToolCall(
                    name="read_file",
                    args={"path": path},
                    result=f"[mock] would read {path}",
                )

        # 10. Default: no deterministic tool matched.
        return ToolCall(name="", args={}, result="[mock] no tool matched")

    def run(self, user_input: str, *, scenario_name: str = "", category: str = "") -> Trace:
        """Single-shot agent run. Returns a deterministic Trace."""
        tool_call = self._route(user_input)
        return Trace(
            user_input=user_input,
            tool_call=tool_call,
            scenario_name=scenario_name,
            category=category,
        )


def built_in_targets() -> list[TargetAgent]:
    """Return fresh instances of the five canonical vulnerable agents."""

    return [TargetAgent(**config) for config in _BUILT_IN_TARGETS]


def get_target(name: str) -> TargetAgent:
    """Resolve one built-in target by its stable name."""

    for target in built_in_targets():
        if target.name == name:
            return target
    raise KeyError(f"Unknown target: {name!r}")


def agent_aliases() -> dict[str, str]:
    """Map every accepted spelling of an agent to its canonical target name.

    Derived from `_BUILT_IN_TARGETS` so the profile table stays the single
    source of truth; this used to be hand-maintained in three places that
    could drift independently.
    """

    aliases: dict[str, str] = {}
    for target in built_in_targets():
        for spelling in (target.name, target.agent_type, target.api_name):
            if spelling:
                aliases[spelling.lower()] = target.name
    return aliases


def resolve_agent(value: object) -> TargetAgent | None:
    """Resolve an agent by any accepted spelling, or None when unknown."""

    if not isinstance(value, str):
        return None
    canonical = agent_aliases().get(value.strip().lower())
    if canonical is None:
        return None
    return get_target(canonical)


def external_agent_name(target: TargetAgent) -> str:
    """Return the adapter-facing name for a target."""

    return target.api_name or target.name
