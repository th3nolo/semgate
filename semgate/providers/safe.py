"""Opt-in privacy boundary for every semantic call, including auxiliary calls."""
from __future__ import annotations

from typing import Any, Dict, Mapping

from ..privacydata import safe_inputs
from .base import JudgeProvider, PredicateAnswer, ProviderError


class SafeProvider(JudgeProvider):
    def __init__(self, inner: JudgeProvider, *, allow_calls: bool = True):
        self.inner = inner
        self.allow_calls = allow_calls
        self.name = inner.name
        self.model = getattr(inner, "model", "")

    def evaluate(self, state: Mapping[str, Any], questions: Dict[str, Dict[str, Any]]) -> Dict[str, PredicateAnswer]:
        if not self.allow_calls:
            raise ProviderError("privacy: remote calls disabled")
        try:
            clean_state, clean_questions = safe_inputs(state, questions)
            return self.inner.evaluate(clean_state, clean_questions)
        except Exception as exc:
            # SDKs and custom transports can echo their entire input/key. Only
            # the exception class crosses back into reasons, stderr or stores.
            raise ProviderError(f"privacy: provider failed ({type(exc).__name__})") from None


def configured(provider: Any, config: Mapping[str, Any]) -> Any:
    setting = config.get("privacy_gate")
    if provider is None or setting is None or setting is False or (isinstance(setting, Mapping) and setting.get("enabled") is False):
        return provider
    from ..privacy import from_config
    gate = from_config(config)
    allow_remote = gate is not None and not gate.problem and gate.allow_remote
    return SafeProvider(provider, allow_calls=allow_remote or provider.name in ("fake", "recorded"))
