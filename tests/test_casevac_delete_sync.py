import json
from types import SimpleNamespace
from unittest.mock import Mock
from xml.etree.ElementTree import tostring

from opentakserver.cot_parser.cot_parser import CoTController
from opentakserver.functions import generate_delete_cot


def test_casevac_forced_delete_removes_row_and_notifies_webui(app):
    casevac_uid = "casevac-delete-regression"
    casevac = SimpleNamespace(uid=casevac_uid)
    result = Mock()
    result.first.return_value = (casevac,)
    database = Mock()
    database.session.execute.return_value = result
    socket_io = Mock()
    controller = CoTController(app.app_context(), Mock(), database, socket_io)

    for method_name in (
        "insert_cot",
        "parse_point",
        "parse_geochat",
        "parse_video",
        "parse_alert",
        "parse_casevac",
        "parse_marker",
        "parse_rbline",
        "parse_stats",
        "generate_mission_change",
        "route_cot",
    ):
        setattr(controller, method_name, Mock())

    controller.rabbit_channel = Mock()
    delete_cot = tostring(generate_delete_cot(casevac_uid, "b-r-f-h-c")).decode("utf-8")
    body = json.dumps({"uid": "atak-phone", "cot": delete_cot}).encode("utf-8")

    controller.on_message(
        channel=None,
        basic_deliver=SimpleNamespace(delivery_tag=7),
        properties=None,
        body=body,
    )

    database.session.delete.assert_called_once_with(casevac)
    database.session.commit.assert_called()
    socket_io.emit.assert_any_call("casevac_delete", {"uid": casevac_uid}, namespace="/socket.io")
