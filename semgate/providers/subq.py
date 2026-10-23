"""Fixed-origin, no-redirect System One transport for the privacy judges.

No retries or response-body diagnostics. The shared transport also supplies
the pinned Jev privacy call without changing the existing permission router.
"""
from __future__ import annotations

import json
import math
from typing import Any, Dict, Mapping
import urllib.error
import urllib.request

from ..privacydata import safe_inputs
from .base import Answers, JudgeProvider, PredicateAnswer, ProviderError
from .common import question_fields
from .keys import find_key

MAX_RESPONSE_BYTES = 1048576


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args: Any, **kwargs: Any) -> None:
        return None


def _probability(value: Any) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value) or not 0 <= value <= 1:
        raise ProviderError("invalid provider probability")
    return float(value)


class SystemOneProvider(JudgeProvider):
    endpoint = ""
    key_name = ""
    default_model = ""

    def __init__(self, model: str = "", *, timeout_s: float = 5.0):
        self.model = model or self.default_model
        self.timeout_s = float(timeout_s)
        if not math.isfinite(self.timeout_s) or not 0 < self.timeout_s <= 30:
            raise ValueError("provider timeout must be between 0 and 30 seconds")

    def _request(self, payload: Mapping[str, Any]) -> Mapping[str, Any]:
        key, _ = find_key(self.key_name)
        if not key:
            raise ProviderError(f"{self.name}: API key unavailable")
        request = urllib.request.Request(self.endpoint, data=json.dumps(payload, allow_nan=False).encode("utf-8"),
                                         headers={"Authorization": "Bearer " + key, "Content-Type": "application/json"})
        try:
            with urllib.request.build_opener(_NoRedirect()).open(request, timeout=self.timeout_s) as response:
                data = response.read(MAX_RESPONSE_BYTES + 1)
            if len(data) > MAX_RESPONSE_BYTES:
                raise ProviderError("provider response limit exceeded")
            return json.loads(data)
        except urllib.error.HTTPError as exc:
            raise ProviderError(f"{self.name}: HTTP {exc.code}") from None
        except Exception as exc:
            raise ProviderError(f"{self.name}: request failed ({type(exc).__name__})") from None

    def evaluate(self, state: Mapping[str, Any], questions: Dict[str, Dict[str, Any]]) -> Dict[str, PredicateAnswer]:
        if not 1 <= len(questions) <= 16:
            raise ProviderError("privacy transport requires 1 to 16 questions")
        try:
            state, questions = safe_inputs(state, questions)
            wire = {qid: {"type": qtype, **fields} for qid, question in questions.items()
                    for qtype, fields in (question_fields(question),)}
            response = self._request({"model": self.model, "state": state, "questions": wire})
            if response.get("model") != self.model or set(response["answers"]) != set(questions):
                raise ProviderError("provider model or question mismatch")
            answers = Answers(served={"model": response["model"]})
            for qid, question in wire.items():
                answer = response["answers"][qid]
                kind = question["type"]
                if answer["type"] != kind:
                    raise ProviderError("provider answer type mismatch")
                if kind == "noul":
                    probability = _probability(answer["noul"])
                    answers[qid] = PredicateAnswer(qid, probability=probability, confidence=abs(probability - 0.5) * 2)
                    continue
                probabilities = {str(k): _probability(v) for k, v in answer["probabilities"].items()}
                if abs(sum(probabilities.values()) - 1) > 0.01:
                    raise ProviderError("invalid provider distribution")
                confidence = _probability(answer["confidence"])
                value = answer[kind]
                if kind == "choice":
                    if set(probabilities) != set(question["criteria"]) or value not in probabilities:
                        raise ProviderError("invalid provider choice")
                    if probabilities[value] + 1e-6 < max(probabilities.values()):
                        raise ProviderError("inconsistent provider choice")
                else:
                    if (set(probabilities) != {str(i) for i in range(len(question["criteria"]))}
                            or isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value)
                            or not 0 <= value <= len(question["criteria"]) - 1):
                        raise ProviderError("invalid provider score")
                answers[qid] = PredicateAnswer(qid, value=value, confidence=confidence,
                                               raw={"probabilities": probabilities, "source": self.name})
            return answers
        except Exception as exc:
            # Never let malformed output echo arbitrary model text into logs.
            if isinstance(exc, ProviderError):
                raise
            raise ProviderError(f"{self.name}: invalid response ({type(exc).__name__})") from None


class SubQProvider(SystemOneProvider):
    name = "subq"
    endpoint = "https://api.subq.ai/v1/systemone"
    key_name = "SUBQ_API_KEY"
    default_model = "subq-snap-preview"


class JevPrivacyProvider(SystemOneProvider):
    name = "typesafe-privacy"
    endpoint = "https://api.typesafe.ai/v1/systemone"
    key_name = "TYPESAFE_API_KEY"
    default_model = "jev-1.13.0"
