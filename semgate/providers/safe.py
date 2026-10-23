"""Opt-in privacy boundary for every semantic call, including auxiliary calls."""
from __future__ import annotations

from typing import Any, Dict, Mapping

from ..privacydata import Minimizer, safe_inputs
from .base import JudgeProvider, PredicateAnswer, ProviderError


class SafeProvider(JudgeProvider):
    def __init__(self, inner: JudgeProvider, *, allow_calls: bool = True, seed: Minimizer | None = None,
                 fixed_questions: bool = False):
        self.inner = inner
        self.allow_calls = allow_calls
        self.seed = seed
        self.fixed_questions = fixed_questions
        self.name = inner.name
        self.model = getattr(inner, "model", "")

    def evaluate(self, state: Mapping[str, Any], questions: Dict[str, Dict[str, Any]]) -> Dict[str, PredicateAnswer]:
        if not self.allow_calls:
            raise ProviderError("privacy: remote calls disabled")
        try:
            clean_state, clean_questions = safe_inputs(state, questions, seed=self.seed,
                                                       fixed_questions=self.fixed_questions)
            return self.inner.evaluate(clean_state, clean_questions)
        except Exception as exc:
            # SDKs and custom transports can echo their entire input/key. Only
            # the exception class crosses back into reasons, stderr or stores.
            raise ProviderError(f"privacy: provider failed ({type(exc).__name__})") from None


def for_envelope(provider: Any, envelope: Any, *, prepared: Any = None, offline_shell: bool = False) -> Any:
    """Seed auxiliary calls before they can classify task text remotely.

    Incomplete disclosure inspection disables these calls. The private offline
    execution contract cannot disclose its opaque shell payload. The inner
    configured wrapper still enforces the operator's remote-call opt-in.
    """
    if provider is None:
        return None
    try:
        from ..privacyinspect import inspect
        inspection = prepared.inspect(envelope) if prepared is not None else inspect(envelope)
        return SafeProvider(provider, allow_calls=inspection.minimization_complete and (inspection.complete or offline_shell),
                            seed=inspection.cleaner, fixed_questions=True)
    except Exception:
        return SafeProvider(provider, allow_calls=False)


def configured(provider: Any, config: Mapping[str, Any]) -> Any:
    setting = config.get("privacy_gate")
    if provider is None or setting is None or setting is False or (isinstance(setting, Mapping) and setting.get("enabled") is False):
        return provider
    from ..privacy import from_config
    gate = from_config(config)
    allow_remote = gate is not None and not gate.problem and gate.allow_remote
    return SafeProvider(provider, allow_calls=allow_remote or provider.name in ("fake", "recorded"), fixed_questions=True)
