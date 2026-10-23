"""The harness sends a closed data view, never unclassified source text."""
import pytest

from semgate.sendcontracts import canonicalize, validate


def contract(fmt="json"):
    return {"format": fmt, "fields": {"status": {"enum": ["ready", "failed"]},
            "count": {"integer": [0, 10]}}, "max_rows": 2}


def test_json_and_csv_canonical_views_have_only_permitted_values():
    assert canonicalize(b' {"count":2,"status":"ready"} ', contract()) == b'{"count":2,"status":"ready"}\n'
    assert canonicalize(b'count,status\r\n02,"ready"\r\n', contract("csv")) == b'status,count\nready,2\n'


@pytest.mark.parametrize("body", [
    b'{"status":"ready","count":1,"email":"person@example.test"}',
    b'{"status":"person@example.test","count":1}',
    b'{"status":"ready","count":true}', b'{"status":"ready","count":1.0}',
    b'{"status":"ready","count":NaN}', b'{"status":"ready","count":11}',
    b'{"status":"ready","count":1,"count":2}', b'[]',
    b'[{"status":"ready","count":1},{"status":"ready","count":1},{"status":"ready","count":1}]',
])
def test_json_cannot_smuggle_unknown_fields_or_values(body):
    with pytest.raises(ValueError):
        canonicalize(body, contract())


@pytest.mark.parametrize("body", [b'status,count,email\nready,1,person@example.test\n',
    b'status,count\nready,1,extra\n', b'status,status\nready,ready\n',
    b'status,count\n"ready,1\n', b'status,count\nready,1e1\n'])
def test_csv_cannot_smuggle_extra_columns_or_noncanonical_numbers(body):
    with pytest.raises(ValueError):
        canonicalize(body, contract("csv"))


def test_open_text_contract_is_not_an_authoritative_classification():
    value = contract()
    value["fields"]["message"] = {"string": True}
    with pytest.raises(ValueError):
        validate(value)
