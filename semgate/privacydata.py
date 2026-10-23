"""Bounded, local PII detection and request minimization. No network or stores.

This is deliberately a pattern/structured-field detector, not general named
entity recognition. Unknown free-text names and document formats need review.
Raw findings and the placeholder map live only for one decision.
"""
from __future__ import annotations

import codecs
import csv
from copy import deepcopy
import io
import json
import re
from collections import Counter
from dataclasses import dataclass
from typing import Any, Dict, List, Mapping
from urllib.parse import parse_qsl, quote, unquote_plus, urlencode

from . import secretfinder

MAX_TEXT = 262144
MAX_NODES = 8192
MAX_DEPTH = 20
_PERCENT_BYTES = re.compile(r"(?:%[0-9a-fA-F]{2})+")
_JSON_ESCAPE = re.compile(r'\\u[dD][89aAbB][0-9a-fA-F]{2}\\u[dD][c-fC-F][0-9a-fA-F]{2}|\\(?:["\\/bfnrt]|u[0-9a-fA-F]{4})')
_JSON_START = re.compile(r"[\[{]")
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


def _unique_json_pairs(pairs):
    out = {}
    for key, value in pairs:
        if key in out:
            raise InputUnsafe("duplicate JSON member")
        out[key] = value
    return out


def json_value(text: str) -> Any:
    """Decode data without silently discarding an earlier object member."""
    return json.loads(text, object_pairs_hook=_unique_json_pairs)


def _field_key(key: str) -> str:
    return key.strip().lower().replace(" ", "_").replace("-", "_")


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
    # This layer's text bound is below the detector's scan bound. Preserve
    # source spans: a normalized PEM body is not contiguous in wrapped input.
    # The public detector deduplicates values; keep every PEM occurrence so
    # different wrapping of the same body is also removed.
    if len(text) > secretfinder.MAX_SCAN:
        raise InputUnsafe("privacy secret scan limit exceeded")
    if sum(1 for _ in secretfinder._PEM_BEGIN.finditer(text)) > secretfinder.PEM_MAX_BLOCKS:
        raise InputUnsafe("privacy PEM block limit exceeded")
    for hit in secretfinder._pem(text):
        begin = secretfinder._PEM_BEGIN.match(text, hit.start)
        marker = "-----END " + begin.group(1) + "-----"
        if (hit.end == begin.end() + secretfinder.PEM_MAX_BODY and hit.end < len(text)
                and not text[hit.start:hit.end].endswith(marker)):
            raise InputUnsafe("privacy PEM body limit exceeded")
        found.append(Finding("secret", hit.value, hit.start, hit.end))
    for hit in secretfinder.find(text):
        if hit.type != "PEM private key":
            found.append(Finding("secret", hit.value, hit.start, hit.end))
    unique = {(hit.category, hit.start, hit.end): hit for hit in found}
    return sorted(unique.values(), key=lambda hit: (hit.start, -len(hit.value), hit.category))


def _decoded_view(text: str, spans: list[tuple[int, int]]) -> tuple[str, list[tuple[int, int]]]:
    """URL-decode once while retaining each character's original input span.

    UTF-8 replacement characters can cover several bytes. Assign all emitted
    characters that span so removing a finding also removes its encoded bytes.
    """
    pieces, positions = [], []
    cursor = 0
    for match in _PERCENT_BYTES.finditer(text):
        pieces.append(text[cursor:match.start()])
        positions.extend(spans[cursor:match.start()])
        data = bytes.fromhex(match.group().replace("%", ""))
        decoder = codecs.getincrementaldecoder("utf-8")("replace")
        pending = 0
        for index, byte in enumerate(data):
            emitted = decoder.decode(bytes((byte,)))
            end = index + 1 - len(decoder.getstate()[0])
            if emitted:
                source = (spans[match.start() + pending * 3][0], spans[match.start() + end * 3 - 1][1])
                pieces.append(emitted)
                positions.extend([source] * len(emitted))
                pending = end
        emitted = decoder.decode(b"", final=True)
        if emitted:
            source = (spans[match.start() + pending * 3][0], spans[match.end() - 1][1])
            pieces.append(emitted)
            positions.extend([source] * len(emitted))
        cursor = match.end()
    pieces.append(text[cursor:])
    positions.extend(spans[cursor:])
    return "".join(pieces), positions


def _json_decoded_view(text: str, spans: list[tuple[int, int]]) -> tuple[str, list[tuple[int, int]]]:
    """Decode JSON escapes, retaining the full source span (including pairs)."""
    pieces, positions, cursor = [], [], 0
    for match in _JSON_ESCAPE.finditer(text):
        pieces.append(text[cursor:match.start()])
        positions.extend(spans[cursor:match.start()])
        decoded = json.loads('"' + match.group() + '"')
        source = (spans[match.start()][0], spans[match.end() - 1][1])
        pieces.append(decoded)
        positions.extend([source] * len(decoded))
        cursor = match.end()
    pieces.append(text[cursor:])
    positions.extend(spans[cursor:])
    return "".join(pieces), positions


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

    def _remember_secret_field(self, value: str, key: str) -> bool:
        normalized = _field_key(key)
        if (secretfinder.quoted_name(normalized) and (secretfinder.quoted_value(value)
                or secretfinder.secret_name(normalized) and secretfinder.secret_value(value, normalized, True))):
            self.remember("secret", value)
            return True
        return False

    def _learn_secret_tree(self, value: Any, key: str, depth: int) -> None:
        """Apply the existing labeled-secret predicate to structured leaves."""
        self.nodes += 1
        if self.nodes > MAX_NODES or depth > MAX_DEPTH:
            raise InputUnsafe("privacy structure limit exceeded")
        if isinstance(value, Mapping):
            for cell in value.values():
                self._learn_secret_tree(cell, key, depth + 1)
        elif isinstance(value, (list, tuple)):
            for cell in value:
                self._learn_secret_tree(cell, key, depth + 1)
        elif isinstance(value, str):
            if len(value) > MAX_TEXT:
                raise InputUnsafe("privacy text limit exceeded")
            self._remember_secret_field(value, key)
            if value.lstrip().startswith(("{", "[")):
                try:
                    parsed = json_value(value)
                except json.JSONDecodeError:
                    pass  # a regex/example string need not be a JSON container
                else:
                    self._learn_secret_tree(parsed, key, depth + 1)
            if "=" in value and all(re.fullmatch(r"[A-Za-z0-9_.%+\[\]-]{1,256}=[\s\S]*", part)
                                    for part in value.split("&")):
                for _, cell in parse_qsl(value, keep_blank_values=True, max_num_fields=MAX_NODES):
                    self._learn_secret_tree(cell, key, depth + 1)
            first = value.splitlines()[0] if value.splitlines() else ""
            if ("\n" in value or "\r" in value) and ("," in first or "\t" in first):
                try:
                    for row in csv.reader(io.StringIO(value), delimiter="\t" if "\t" in first else ",", strict=True):
                        for cell in row:
                            self._learn_secret_tree(cell, key, depth + 1)
                except csv.Error as exc:
                    raise InputUnsafe("uninspectable secret-field table") from exc
            if _PERCENT_BYTES.search(value):
                decoded = unquote_plus(value)
                if decoded != value:
                    self._learn_secret_tree(decoded, key, depth + 1)

    def _structured_text(self, value: str, depth: int) -> str:
        """Sanitize parsed containers, preserving surrounding unstructured text."""
        if depth > MAX_DEPTH:
            raise InputUnsafe("privacy structure limit exceeded")
        if len(value) > MAX_TEXT:
            raise InputUnsafe("privacy text limit exceeded")
        table = self._table_text(value, depth)
        if table is not None:
            return table
        decoder = json.JSONDecoder(object_pairs_hook=_unique_json_pairs)
        pieces, cursor, index = [], 0, 0
        while index < len(value):
            match = _JSON_START.search(value, index)
            if match is None:
                break
            start = match.start()
            self.nodes += 1
            if self.nodes > MAX_NODES:
                raise InputUnsafe("privacy structure limit exceeded")
            try:
                parsed, end = decoder.raw_decode(value, start)
            except json.JSONDecodeError:
                index = start + 1
                continue
            except RecursionError as exc:
                raise InputUnsafe("privacy structure limit exceeded") from exc
            cleaned = self.clean(parsed, depth=depth + 1)
            pieces.extend((value[cursor:start], json.dumps(cleaned, ensure_ascii=True) if cleaned != parsed else value[start:end]))
            cursor = index = end
        if pieces:
            return "".join([*pieces, value[cursor:]])
        # A form value may itself be a supported JSON/CSV/TSV container. Parse
        # the encoded field boundaries before decoding, so escaped ampersands
        # and quoted cells remain data. Never normalize an unchanged input.
        if "=" in value and all(re.fullmatch(r"[A-Za-z0-9_.%+\[\]-]{1,256}=[\s\S]*", part)
                                for part in value.split("&")):
            try:
                fields = parse_qsl(value, keep_blank_values=True, max_num_fields=MAX_NODES)
            except (ValueError, UnicodeError) as exc:
                raise InputUnsafe("uninspectable encoded form") from exc
            cleaned = [(key, self.clean(cell, key=key, depth=depth + 1)) for key, cell in fields]
            if cleaned != fields:
                return urlencode(cleaned)
        if _PERCENT_BYTES.search(value):
            try:
                decoded = unquote_plus(value)
            except UnicodeError as exc:
                raise InputUnsafe("uninspectable encoded structure") from exc
            cleaned = self._structured_text(decoded, depth + 1)
            if cleaned != decoded:
                # This is a sanitized model projection, not executable input.
                # Re-encode the complete structured projection so CSV quoting
                # and JSON escaping cannot leave a recoverable private cell.
                return quote(cleaned, safe="")
        return value

    def _table_text(self, value: str, depth: int) -> str | None:
        text = value.lstrip("\ufeff \t\r\n")
        if "\n" not in text and "\r" not in text:
            return None
        first = text.splitlines()[0]
        delimiter = "\t" if "\t" in first else ","
        try:
            headers = next(csv.reader([first], delimiter=delimiter), [])
        except csv.Error:
            return None
        if not any(_field_key(header) in FIELDS or (
                re.fullmatch(r"[A-Za-z_][\w.-]{0,79}", header.strip())
                and secretfinder.quoted_name(_field_key(header))) for header in headers):
            return None
        try:
            reader = csv.reader(io.StringIO(text), delimiter=delimiter, strict=True)
            next(reader)
            rows, changed = [], False
            for row in reader:
                if not row:
                    continue
                if len(row) != len(headers):
                    raise InputUnsafe("uninspectable structured row")
                # Serialize the sanitized cells, including CSV quote doubling
                # and embedded newlines; decoded values may not occur verbatim.
                cleaned = [self.clean(cell, key=header, depth=depth + 1) for header, cell in zip(headers, row)]
                rows.append(cleaned)
                changed |= cleaned != row
            clean_headers = [self.text(header) for header in headers]
            if changed or clean_headers != headers:
                output = io.StringIO(newline="")
                writer = csv.writer(output, delimiter=delimiter, lineterminator="\n")
                writer.writerow(clean_headers)
                writer.writerows(rows)
                return output.getvalue()
        except csv.Error as exc:
            raise InputUnsafe("uninspectable structured text") from exc
        return value

    def text(self, value: str, *, discover: bool = True) -> str:
        if len(value) > MAX_TEXT:
            raise InputUnsafe("privacy text limit exceeded")
        views = [(value, None)]
        decoded, spans = value, None
        for _ in range(MAX_DEPTH):
            changed = False
            for pattern, decode in ((_PERCENT_BYTES, _decoded_view), (_JSON_ESCAPE, _json_decoded_view)):
                if not pattern.search(decoded):
                    continue
                if spans is None:
                    spans = [(i, i + 1) for i in range(len(value))]
                decoded, spans = decode(decoded, spans)
                views.append((decoded, spans))
                changed = True
            if not changed:
                break
        else:
            if _PERCENT_BYTES.search(decoded) or _JSON_ESCAPE.search(decoded):
                raise InputUnsafe("privacy decoding depth exceeded")
        if discover:
            for text, _ in views:
                for hit in find(text):
                    if hit.value not in self.values.values():
                        placeholder = self.remember(hit.category, hit.value)
                        raw = text[hit.start:hit.end]
                        if raw != hit.value:
                            # Retain formatting aliases as well as normalized
                            # referents; interval replacement needs source text.
                            self.values.setdefault(raw, placeholder)
                            self.categories.setdefault(raw, set()).add(hit.category)
                for match in _HOME.finditer(text):
                    self.remember("home", match.group())
        intervals = []
        for text, positions in views:
            for raw in sorted(self.values, key=len, reverse=True):
                start = text.find(raw)
                while start >= 0:
                    end = start + len(raw)
                    left, right = (positions[start][0], positions[end - 1][1]) if positions is not None else (start, end)
                    intervals.append((left, right, self.values[raw]))
                    start = text.find(raw, end)
        merged = []
        for start, end, placeholder in sorted(intervals, key=lambda item: (item[0], -item[1])):
            if merged and start < merged[-1][1]:
                left, right, replacement = merged[-1]
                merged[-1] = (left, max(right, end), replacement)
            else:
                merged.append((start, end, placeholder))
        pieces, cursor = [], 0
        for start, end, placeholder in merged:
            pieces.extend((value[cursor:start], placeholder))
            cursor = end
        pieces.append(value[cursor:])
        return "".join(pieces)

    def clean(self, value: Any, *, key: str = "", depth: int = 0) -> Any:
        self.nodes += 1
        if self.nodes > MAX_NODES or depth > MAX_DEPTH:
            raise InputUnsafe("privacy structure limit exceeded")
        if secretfinder.quoted_name(_field_key(key)):
            self._learn_secret_tree(value, key, depth)
        structured = self._structured_text(value, depth) if isinstance(value, str) else None
        category = FIELDS.get(_field_key(key))
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
            if len(value) > MAX_TEXT:
                raise InputUnsafe("privacy text limit exceeded")
            # Preserve the assignment context used by the existing detector;
            # a generic credential need not have a vendor-specific prefix.
            if self._remember_secret_field(value, key):
                return self.text(value)
            return self.text(structured)
        if isinstance(value, Mapping):
            cleaned = {}
            for k, v in value.items():
                name = str(k)
                # Unknown component keys (given/family, street/city, etc.)
                # retain the enclosing sensitive label. A recognized child
                # label still supplies its own category, including secrets.
                if category and isinstance(v, str) and secretfinder.quoted_name(_field_key(name)):
                    self.clean(v, key=name, depth=depth + 1)
                context = name if not category or _field_key(name) in FIELDS else key
                cleaned[self.text(name)] = self.clean(v, key=context, depth=depth + 1)
            return cleaned
        if isinstance(value, (list, tuple)):
            return [self.clean(v, key=key, depth=depth + 1) for v in value]
        if value is None or isinstance(value, bool):
            return value
        if isinstance(value, (int, float)):
            raw = str(value)
            minimized = self.text(raw)
            return value if minimized == raw else minimized
        raise InputUnsafe("unsupported privacy input type")


def safe_inputs(state: Mapping[str, Any], questions: Mapping[str, Any], *, seed: Minimizer | None = None,
                fixed_questions: bool = False) -> tuple:
    """Minimize data; reserve fixed_questions for trusted application rubrics."""
    # Application-owned rubrics are control definitions. Untrusted payload
    # values must not teach their cleaner to rewrite a score, label or type.
    # Inspect fixed definitions independently and abstain if they themselves
    # contain detectable sensitive data. Generic dynamic questions keep the
    # shared state/question minimization contract below.
    if fixed_questions:
        _, checked = safe_inputs({}, questions)
        if checked != questions:
            raise InputUnsafe("privacy question definition requires review")
    cleaner = deepcopy(seed) if seed is not None else Minimizer()
    cleaner.nodes = 0
    # First collect values throughout the object, then replace them everywhere
    # (including earlier fields that reference a later structured PII field).
    cleaner.clean(state)
    if not fixed_questions:
        cleaner.clean(questions)
    cleaner.nodes = 0
    return cleaner.clean(state), checked if fixed_questions else cleaner.clean(questions)
