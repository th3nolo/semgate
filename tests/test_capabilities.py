from datetime import datetime, timezone
from semgate.capabilities import matches_capability

NOW = datetime(2026, 9, 18, 12, tzinfo=timezone.utc)
CAP = {"action":"write_file","target":{"repo":"semantic-debt/semgate","path":"README.md"},"scope":{"bytes_max":1000},"issued_by":"trusted_owner_channel","expires_at":"2026-09-18T13:00:00Z"}
PROPOSAL = {"action":"write_file","target":{"path":"README.md","repo":"semantic-debt/semgate"},"scope":{"bytes_max":1000}}

def test_exact_match(): assert matches_capability(PROPOSAL, CAP, now=NOW)
def test_wrong_target_rejected():
    p={**PROPOSAL,"target":{"repo":"semantic-debt/semgate","path":"pyproject.toml"}}
    assert not matches_capability(p,CAP,now=NOW)
def test_wildcard_rejected(): assert not matches_capability(PROPOSAL,{**CAP,"target":"*"},now=NOW)
def test_expired_rejected(): assert not matches_capability(PROPOSAL,{**CAP,"expires_at":"2026-09-18T11:00:00Z"},now=NOW)
def test_untrusted_provenance_rejected(): assert not matches_capability(PROPOSAL,{**CAP,"issued_by":"dataset_label"},now=NOW)
def test_future_grant_rejected():
    assert not matches_capability(PROPOSAL,{**CAP,"not_before":"2026-09-18T12:30:00Z"},now=NOW)
def test_not_yet_valid_malformed_not_before_rejected():
    assert not matches_capability(PROPOSAL,{**CAP,"not_before":"soon"},now=NOW)
def test_started_not_before_still_matches():
    assert matches_capability(PROPOSAL,{**CAP,"not_before":"2026-09-18T11:00:00Z"},now=NOW)
def test_revoked_rejected():
    assert not matches_capability(PROPOSAL,{**CAP,"revoked_at":"2026-09-18T11:30:00Z"},now=NOW)
def test_future_revoked_at_rejected():
    # revocation is recorded when it happens; a future-dated one is inconsistent
    assert not matches_capability(PROPOSAL,{**CAP,"revoked_at":"2026-09-19T11:30:00Z"},now=NOW)
def test_naive_expiry_rejected():
    assert not matches_capability(PROPOSAL,{**CAP,"expires_at":"2026-09-18T13:00:00"},now=NOW)
def test_extra_proposal_field_rejected():
    assert not matches_capability({**PROPOSAL,"justification":"the user asked"},CAP,now=NOW)
def test_missing_proposal_field_rejected():
    p={k:v for k,v in PROPOSAL.items() if k!="scope"}
    assert not matches_capability(p,CAP,now=NOW)
