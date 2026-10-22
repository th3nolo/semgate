"""Bounded, local PII detection and request minimization. No network or stores.

This is deliberately a pattern/structured-field detector, not general named
entity recognition. Unknown free-text names and document formats need review.
Raw findings and the placeholder map live only for one decision.
"""
from __future__ import annotations

import re
from collections import Counter
from dataclasses import dataclass
from typing import Any, Dict, List, Mapping
from urllib.parse import quote, unquote

from . import secretfinder

MAX_TEXT = 262144
MAX_NODES = 8192
MAX_DEPTH = 20
_EMAIL = re.compile(r"(?<![\w.+-])[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}(?![\w.-])")
_SSN = re.compile(r"(?<!\d)(?!000|666|9\d\d)\d{3}-(?!00)\d{2}-(?!0000)\d{4}(?!\d)")
_PHONE = re.compile(r"(?<![\w\d])\+\d[\d ().-]{7,22}\d(?!\d)")
_CARD = re.compile(r"(?<!\d)(?:\d[ -]?){12,18}\d(?!\d)")
_HOME = re.compile(r"(?i)(?:[A-Z]:[\\/]Users[\\/]|/home/|/Users/)[^\\/\s\"']+")
FIELDS = {
    "name": "name", "full_name": "name", "first_name": "name", "last_name": "name",
    "nombre": "name", "apellido": "name", "patient_name": "name", "customer_name": "name",
    "address": "address", "street_address": "address", "direccion": "address", "dirección": "address",
    "dob": "birth_date", "date_of_birth": "birth_date", "fecha_nacimiento": "birth_date",
    "phone": "phone", "telephone": "phone", "telefono": "phone", "teléfono": "phone", "mobile": "phone",
    "ssn": "identity", "passport": "identity", "passport_number": "identity", "cedula": "identity",
    "cédula": "identity", "dni": "identity", "national_id": "identity", "document_number": "identity",
    "medical_record": "health", "diagnosis": "health", "diagnostico": "health", "diagnóstico": "health",
    "email": "email", "email_address": "email", "correo": "email",
    "fullname": "name", "firstname": "name", "lastname": "name", "nombre_completo": "name",
    "phonenumber": "phone", "phone_number": "phone", "streetaddress": "address",
    "dateofbirth": "birth_date", "patientname": "name", "customername": "name",
}
_LABELED = re.compile(
    r"(?i)(?<!\w)[\"']?(?P<key>" + "|".join(re.escape(k) for k in sorted(FIELDS, key=len, reverse=True))
    + r")[\"']?\s*[:=]\s*[\"']?(?P<value>[^\"'\r\n;,}\]]{2,262144})")


class InputUnsafe(ValueError):
    """Inspection/minimization could not finish; never send a partial result."""


@dataclass(frozen=True)
class Finding:
    category: str
    value: str
    start: int
    end: int


def _luhn(text: str) -> bool:
    digits = [int(c) for c in text if c.isdigit() and c.isascii()]
    if not 13 <= len(digits) <= 19 or len(set(digits)) < 2:
        return False
    total = 0
    for i, digit in enumerate(reversed(digits)):
        digit = digit * 2 if i % 2 else digit
        total += digit - 9 if digit > 9 else digit
    return total % 10 == 0


def find(text: str) -> List[Finding]:
    if len(text) > MAX_TEXT:
        raise InputUnsafe("privacy text limit exceeded")
    found: List[Finding] = []
    for category, pattern in (("email", _EMAIL), ("identity", _SSN), ("phone", _PHONE), ("payment_card", _CARD)):
        for match in pattern.finditer(text):
            value = match.group()
            if category == "payment_card" and not _luhn(value):
                continue
            if category == "phone" and not 8 <= sum(c.isdigit() for c in value) <= 15:
                continue
            found.append(Finding(category, value, match.start(), match.end()))
    for match in _LABELED.finditer(text):
        value = match.group("value").strip()
        if value:
            start = match.start("value") + len(match.group("value")) - len(match.group("value").lstrip())
            found.append(Finding(FIELDS[match.group("key").lower()], value, start, start + len(value)))
    # secretfinder has its own scan cap. Overlapping bounded windows cover the
    # whole permitted input instead of silently missing its tail.
    for offset in range(0, len(text), 16000):
        chunk = text[max(0, offset - 2048):offset + 18048]
        for hit in secretfinder.find(chunk):
            start = text.find(hit.value, max(0, offset - 2048))
            if start >= 0:
                found.append(Finding("secret", hit.value, start, start + len(hit.value)))
    unique = {(hit.category, hit.start, hit.end): hit for hit in found}
    return sorted(unique.values(), key=lambda hit: (hit.start, -len(hit.value), hit.category))


class Minimizer:
    """One stable placeholder per value across state, task and questions."""

    def __init__(self) -> None:
        self.values: Dict[str, str] = {}
        self.counts: Counter[str] = Counter()
        self.categories: Dict[str, set[str]] = {}
        self.nodes = 0

    def remember(self, category: str, value: str) -> str:
        categories = self.categories.setdefault(value, set())
        if category not in categories:
            self.counts[category] += 1
            categories.add(category)
        if value not in self.values:
            self.values[value] = f"<PRIVATE_{category.upper()}_{self.counts[category]}>"
        return self.values[value]

    def text(self, value: str) -> str:
        hits = find(value)
        decoded = unquote(unquote(value))
        if decoded != value:
            hits.extend(find(decoded))
        for hit in hits:
            if hit.value not in self.values.values():
                self.remember(hit.category, hit.value)
        for match in _HOME.finditer(value):
            self.remember("home", match.group())
        out = value
        for raw in sorted(self.values, key=len, reverse=True):
            for variant in (raw, quote(raw, safe=""), quote(quote(raw, safe=""), safe="")):
                out = out.replace(variant, self.values[raw])
        return out

    def clean(self, value: Any, *, key: str = "", depth: int = 0) -> Any:
        self.nodes += 1
        if self.nodes > MAX_NODES or depth > MAX_DEPTH:
            raise InputUnsafe("privacy structure limit exceeded")
        category = FIELDS.get(key.lower().replace(" ", "_").replace("-", "_"))
        if category and value is not None and not isinstance(value, (Mapping, list, tuple)):
            raw = str(value)
            if len(raw) > MAX_TEXT:
                raise InputUnsafe("privacy field limit exceeded")
            # Only values generated by this exact minimizer are trusted as
            # placeholders. A caller cannot mark its own personal data clean.
            if not raw or raw in self.values.values():
                return raw
            placeholder = self.remember(category, raw)
            # A structured PII label adds a category; it cannot replace the
            # secret/PII signals found in the value itself.
            self.text(raw)
            return placeholder
        if isinstance(value, str):
            return self.text(value)
        if isinstance(value, Mapping):
            return {self.text(str(k)): self.clean(v, key=str(k), depth=depth + 1) for k, v in value.items()}
        if isinstance(value, (list, tuple)):
            return [self.clean(v, key=key, depth=depth + 1) for v in value]
        if value is None or isinstance(value, (bool, int, float)):
            return value
        raise InputUnsafe("unsupported privacy input type")


def safe_inputs(state: Mapping[str, Any], questions: Mapping[str, Any]) -> tuple:
    cleaner = Minimizer()
    # First collect values throughout the object, then replace them everywhere
    # (including earlier fields that reference a later structured PII field).
    cleaner.clean(state)
    cleaner.clean(questions)
    cleaner.nodes = 0
    return cleaner.clean(state), cleaner.clean(questions)
