"""semgate - harness-agnostic semantic auto mode (enforce mode: the host acts on semgate's decision).

We judge. The host acts.
"""

__version__ = "0.4.2"   # the one version: pyproject.toml reads it (dynamic = ["version"])

from .gate import Gate  # noqa: E402,F401  - the embed-in-your-own-agent entry point
from .judge import Decision  # noqa: E402,F401
from .harness import approve, check  # noqa: E402,F401  - the hook pipeline for any harness (dict in, dict out)
