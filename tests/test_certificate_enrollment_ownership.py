from types import SimpleNamespace

from opentakserver.blueprints.marti_api.certificate_enrollment_api import (
    enrollment_eud_is_owned_by_user,
)


def test_certificate_enrollment_cannot_claim_another_users_eud():
    requesting_user = SimpleNamespace(id=7)

    assert enrollment_eud_is_owned_by_user(None, requesting_user)
    assert enrollment_eud_is_owned_by_user(SimpleNamespace(user_id=None), requesting_user)
    assert enrollment_eud_is_owned_by_user(SimpleNamespace(user_id=7), requesting_user)
    assert not enrollment_eud_is_owned_by_user(SimpleNamespace(user_id=8), requesting_user)
