import inspect
from types import SimpleNamespace
from unittest.mock import Mock

from opentakserver.models.CasEvac import CasEvac
from opentakserver.models.GroupUser import GroupUser


class QueryResult:
    def __init__(self, rows):
        self.rows = rows

    def first(self):
        return self.rows[0] if self.rows else None

    def all(self):
        return self.rows


class Query:
    def __init__(self, model):
        self.model = model
        self.filters = {}

    def filter_by(self, **filters):
        self.filters.update(filters)
        return self

    def where(self, *_conditions):
        return self


class Session:
    def __init__(self, casevac, memberships_by_user_id):
        self.casevac = casevac
        self.memberships_by_user_id = memberships_by_user_id
        self.deleted = []
        self.commits = 0

    def query(self, model):
        return Query(model)

    def execute(self, query):
        if query.model is CasEvac:
            return QueryResult([(self.casevac,)])
        if query.model is GroupUser:
            memberships = self.memberships_by_user_id.get(query.filters["user_id"], [])
            return QueryResult([(membership,) for membership in memberships])
        raise AssertionError(f"Unexpected query model: {query.model}")

    def delete(self, value):
        self.deleted.append(value)

    def commit(self):
        self.commits += 1


def test_cp_delete_routes_to_the_casevac_creators_audience(app, monkeypatch):
    from opentakserver.blueprints.ots_api import api as api_module
    from opentakserver.blueprints.ots_api import casevac_api as casevac_module

    admin = SimpleNamespace(id=10)
    creator = SimpleNamespace(id=20)
    casevac_uid = "50c3dfa0-b555-4e0f-a9c0-eaf86798627a"
    casevac = SimpleNamespace(
        uid=casevac_uid,
        cot=SimpleNamespace(type="b-r-f-h-c"),
        eud=SimpleNamespace(user=creator),
    )
    admin_membership = SimpleNamespace(group=SimpleNamespace(name="CP-ONLY"))
    creator_membership = SimpleNamespace(group=SimpleNamespace(name="FIELD-USERS"))
    session = Session(
        casevac,
        {
            admin.id: [admin_membership],
            creator.id: [creator_membership],
        },
    )
    database = SimpleNamespace(session=session)
    channel = Mock()
    connection = Mock()
    connection.channel.return_value = channel

    monkeypatch.setattr(casevac_module, "db", database)
    monkeypatch.setattr(api_module, "db", database)
    monkeypatch.setattr(casevac_module, "current_user", admin)
    monkeypatch.setattr(casevac_module, "socketio", Mock())
    monkeypatch.setattr(api_module.pika, "BlockingConnection", Mock(return_value=connection))

    with app.test_request_context(f"/api/casevac?uid={casevac_uid}", method="DELETE"):
        response = inspect.unwrap(casevac_module.delete_casevac)()

    assert response.get_json() == {"success": True}
    assert [call.kwargs["routing_key"] for call in channel.basic_publish.call_args_list] == [
        "FIELD-USERS.OUT"
    ]
    assert session.deleted == [casevac]
