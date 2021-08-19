"""Test access to MRGF data."""
from mrgf import GovernanceFramework


def test_privilege_with_metadata(mrgf: GovernanceFramework):
    assert mrgf.privilege("limited-credentials").extra["cred_def_ids"] == [
        "example:123"
    ]
