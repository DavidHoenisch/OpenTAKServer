from datetime import datetime, timezone
from types import SimpleNamespace
from unittest.mock import patch

from sqlalchemy import insert

from opentakserver.models.CasEvac import CasEvac
from opentakserver.models.Point import Point


def test_casevac_accepts_and_serializes_hlz_zone_attributes(app):
    statement = insert(CasEvac.__table__).values(
        zone_protected_coord="34.12345,-117.12345",
        zone_prot_marker="Green smoke",
    )

    assert "zone_protected_coord" in str(statement.compile())
    assert "zone_prot_marker" in str(statement.compile())

    casevac = CasEvac(
        zone_protected_coord="34.12345,-117.12345",
        zone_prot_marker="Green smoke",
    )

    assert casevac.serialize()["zone_protected_coord"] == "34.12345,-117.12345"
    assert casevac.serialize()["zone_prot_marker"] == "Green smoke"


def test_casevac_emits_hlz_zone_attributes_in_cot(app):
    timestamp = datetime(2026, 8, 29, tzinfo=timezone.utc)
    casevac = CasEvac(
        uid="ed6cb39d-b25f-45f1-a063-b41008a316a8",
        title="MED.29.123456",
        zone_protected_coord="34.12345,-117.12345",
        zone_prot_marker="Green smoke",
        point=Point(
            timestamp=timestamp,
            ce=5,
            hae=100,
            le=5,
            latitude=34.12345,
            longitude=-117.12345,
        ),
    )

    with patch(
        "opentakserver.models.CasEvac.current_user",
        SimpleNamespace(username="CP"),
    ):
        medevac = casevac.to_cot().find("./detail/_medevac_")

    assert medevac is not None
    assert medevac.get("zone_protected_coord") == "34.12345,-117.12345"
    assert medevac.get("zone_prot_marker") == "Green smoke"


def test_casevac_cot_attributes_ignore_unknown_fields_without_rejecting_event():
    attributes, ignored = CasEvac.cot_attributes(
        {
            "title": "MED.29.123456",
            "casevac": "true",
            "zone_prot_marker": "Green smoke",
            "future_atak_field": "future value",
        }
    )

    assert attributes == {
        "title": "MED.29.123456",
        "casevac": True,
        "zone_prot_marker": "Green smoke",
    }
    assert ignored == ["future_atak_field"]
