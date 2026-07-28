"""Shared policy primitives for the defender components.

Kept separate from `detector.py` on purpose. The detector classifies -- it
answers "was this an attack?" from heuristics tuned against a labelled corpus.
These are *policy* predicates: deployment-configurable rules about what an
agent is permitted to do, which hold regardless of whether anyone considers a
given request hostile.
"""

from __future__ import annotations

import ipaddress
import re
from pathlib import PurePosixPath
from urllib.parse import parse_qs, urlparse

# Paths worth refusing to touch no matter how the request was phrased.
SENSITIVE_PATH = re.compile(
    r"/etc/(?:passwd|shadow|sudoers|hosts)|\.ssh(?:/|\b)|id_rsa|id_ed25519|"
    r"/run/secrets|\.env\b|\.aws/|\.kube/|windows[\\/]system32",
    re.IGNORECASE,
)

# Calls that hand generated code the host's authority.
PRIVILEGED_CALL = re.compile(
    r"\bos\.(?:system|popen|setuid|setgid|seteuid|chmod|chown)\b|"
    r"\bsubprocess\.(?:run|Popen|call|check_output|check_call)\b|"
    r"\b(?:ba)?sh\s+-c\b|\brm\s+-rf\b|\beval\s*\(|\b__import__\s*\(",
    re.IGNORECASE,
)

# SQL that changes the shape of the statement rather than its parameters.
UNSAFE_SQL = re.compile(
    r"\bor\s+1\s*=\s*1\b|\bdrop\s+table\b|\bunion\s+(?:all\s+)?select\b"
    r"[^\n]{0,80}?(?:--|#|;)|;\s*\w+|--\s*$",
    re.IGNORECASE,
)

# Attempts to override the operator's instructions, wherever they arrive from.
INJECTION_IMPERATIVE = re.compile(
    r"\bignore\s+(?:all\s+)?(?:previous|prior|above)\s+instructions?\b|"
    r"\bdisregard\s+(?:the\s+)?(?:above|prior|previous)\s+instructions?\b|"
    r"\byou\s+are\s+now\s+(?:a|an)\b|"
    r"\boverride\s+(?:the\s+)?(?:system\s+)?(?:policy|prompt|instructions?)\b",
    re.IGNORECASE,
)

# Tools that change state irreversibly and therefore need explicit approval.
DESTRUCTIVE_TOOLS = frozenset({"delete_email", "exec_shell", "exec_python"})

# Phrases that stand in for a human having approved the action.
CONFIRMATION = re.compile(
    r"\b(?:confirmed|approved|user\s+confirmed|with\s+confirmation)\b",
    re.IGNORECASE,
)
# ... and the explicit refusal of one.
CONFIRMATION_WAIVED = re.compile(
    r"\bwithout\s+(?:user\s+)?confirmation\b|\bno\s+confirmation\b|"
    r"\bskip\s+(?:the\s+)?confirmation\b",
    re.IGNORECASE,
)

# Requests for unbounded generation -- a resource-exhaustion attempt that
# never touches a tool, so nothing downstream of the input layer would ever
# see it. Deliberately narrow: bare "infinite" is too common in ordinary
# feature talk ("infinite scroll") to use alone, so this needs a huge
# explicit repeat count, or a verb + infinite/endless/unbounded + content
# noun + an explicit resource-exhaustion stop condition. Kept textually
# identical to detector.py's `model_dos` rule on purpose -- same signal,
# different layer (classification vs. policy), see module docstring.
UNBOUNDED_GENERATION = re.compile(
    r"\brepeat\b[^\n]{0,60}?\b\d{5,}\b[^\n]{0,20}?\btimes\b|"
    r"\b(?:generate|produce|output|create|stream|emit)\b[^\n]{0,40}?"
    r"\b(?:infinite|endless|unbounded|never[- ]ending)\b[^\n]{0,40}?"
    r"\b(?:loop|stream|output|response|tokens?|text|generation)\b"
    r"[^\n]{0,60}?\b(?:until|without)\b[^\n]{0,40}?"
    r"\b(?:memory|limit|stop(?:ping)?|resources?|crash(?:es)?|exhaust\w*)\b",
    re.IGNORECASE,
)


def escapes_workspace(path: str) -> bool:
    """True when `path` leaves the agent's working directory.

    Counts `..` against accumulated depth rather than pattern-matching, so
    `a/../b` stays inside while `../../x` does not. Absolute paths and known
    sensitive targets are always out.
    """

    if not path:
        return False
    if SENSITIVE_PATH.search(path):
        return True
    normalised = path.replace("\\", "/")
    if normalised.startswith("/") or re.match(r"^[A-Za-z]:", normalised):
        return True
    depth = 0
    for part in PurePosixPath(normalised).parts:
        if part == "..":
            depth -= 1
        elif part not in (".", "/"):
            depth += 1
        if depth < 0:
            return True
    return False


def blocked_host(url: str) -> str | None:
    """Return the hostname when a URL targets somewhere an agent must not go.

    Link-local and private ranges cover cloud metadata endpoints and internal
    services -- the SSRF cases -- without needing a hostname denylist.
    """

    host = urlparse(url).hostname or ""
    if not host:
        return None
    if host.endswith("metadata.google.internal"):
        return host
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        return None
    if address.is_link_local or address.is_private or address.is_loopback:
        return host
    return None


def credentials_in_url(url: str) -> str | None:
    """Return the parameter name when a URL carries a credential in its query.

    Shipping a token in a query string leaks it to logs, referrers and the
    remote host, so it is refused regardless of destination.
    """

    query = parse_qs(urlparse(url).query)
    for key in query:
        if re.search(
            r"(?:api|access|bearer|auth|session|canary|secret)[_-]?(?:key|token)"
            r"|password|passwd",
            key,
            re.IGNORECASE,
        ):
            return key
    return None
