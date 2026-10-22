"""Closed CSV/JSON views for agent-writable diagnostic sources.

Only operator-enumerated strings and bounded integers are transmitted. Parse
then serialize the allowed view, so ignored syntax/extra fields cannot hide
unclassified text. This is not general free-text PII classification.
"""
from __future__ import annotations

import csv
import io
import json
import re


def validate(contract: dict) -> None:
    if (not isinstance(contract, dict) or set(contract) != {"format", "fields", "max_rows"}
            or contract["format"] not in {"csv", "json"} or type(contract["max_rows"]) is not int
            or not 1 <= contract["max_rows"] <= 128 or not isinstance(contract["fields"], dict)
            or not 1 <= len(contract["fields"]) <= 64):
        raise ValueError("invalid prepared data contract")
    for name, rule in contract["fields"].items():
        if not isinstance(name, str) or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,63}", name) or not isinstance(rule, dict):
            raise ValueError("invalid prepared field")
        if set(rule) == {"enum"}:
            if (not isinstance(rule["enum"], list) or not 1 <= len(rule["enum"]) <= 128
                    or any(not isinstance(v, str) or len(v) > 4000 for v in rule["enum"])):
                raise ValueError("invalid prepared enumeration")
        elif set(rule) == {"integer"}:
            bound = rule["integer"]
            if not isinstance(bound, list) or len(bound) != 2 or any(type(v) is not int for v in bound) or not -10**9 <= bound[0] <= bound[1] <= 10**9:
                raise ValueError("invalid prepared integer bounds")
        else:
            raise ValueError("unclassified free-text fields are not permitted")


def _object(pairs):
    if len({k for k, _ in pairs}) != len(pairs):
        raise ValueError("duplicate JSON field")
    return dict(pairs)


def canonicalize(body: bytes, contract: dict) -> bytes:
    validate(contract)
    text = body.decode("utf-8-sig")
    fields = contract["fields"]
    is_list = False
    if contract["format"] == "json":
        value = json.loads(text, object_pairs_hook=_object)
        is_list = isinstance(value, list)
        rows = value if isinstance(value, list) else [value]
    else:
        try:
            values = list(csv.reader(io.StringIO(text, newline=""), strict=True))
        except csv.Error:
            raise ValueError("invalid CSV syntax") from None
        if not values or len(set(values[0])) != len(values[0]) or set(values[0]) != set(fields):
            raise ValueError("unexpected CSV header")
        rows = []
        for row in values[1:]:
            if not row:
                continue
            if len(row) != len(values[0]):
                raise ValueError("unexpected CSV field count")
            rows.append(dict(zip(values[0], row)))
    if not 1 <= len(rows) <= contract["max_rows"]:
        raise ValueError("prepared row count outside contract")
    output = []
    for row in rows:
        if not isinstance(row, dict) or set(row) != set(fields):
            raise ValueError("unclassified prepared fields")
        normalized = {}
        for name, rule in fields.items():
            value = row[name]
            if "enum" in rule:
                if not isinstance(value, str) or value not in rule["enum"]:
                    raise ValueError("unclassified prepared value")
            else:
                if contract["format"] == "csv":
                    if not re.fullmatch(r"-?[0-9]{1,10}", value):
                        raise ValueError("invalid prepared integer")
                    value = int(value)
                if type(value) is not int or not rule["integer"][0] <= value <= rule["integer"][1]:
                    raise ValueError("prepared integer outside bounds")
            normalized[name] = value
        output.append(normalized)
    if contract["format"] == "json":
        view = output if is_list else output[0]
        return (json.dumps(view, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n").encode()
    stream = io.StringIO(newline="")
    writer = csv.DictWriter(stream, fieldnames=list(fields), lineterminator="\n")
    writer.writeheader()
    writer.writerows(output)
    return stream.getvalue().encode()
