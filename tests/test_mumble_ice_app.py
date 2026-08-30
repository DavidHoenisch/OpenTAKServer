from unittest.mock import MagicMock, patch

import pytest

Ice = pytest.importorskip("Ice")

from opentakserver.mumble.mumble_ice_app import (  # noqa: E402
    MumbleConfigurationError,
    MumbleIceApp,
    MumbleIceDaemon,
)


def make_app():
    app = MagicMock()
    app.config = {
        "OTS_MUMBLE_ICE_HOST": "mumble-server",
        "OTS_MUMBLE_ICE_PORT": 6502,
        "OTS_MUMBLE_ICE_CALLBACK_HOST": "ots",
        "OTS_MUMBLE_ICE_SECRET": "test-ice-secret",
        "OTS_MUMBLE_ICE_RETRY_SECONDS": 7,
        "OTS_MUMBLE_ICE_MAX_RETRY_SECONDS": 20,
    }
    return app


def test_mumble_ice_app_uses_configured_docker_endpoints():
    app = make_app()
    logger = MagicMock()
    ice = MagicMock()
    adapter = ice.createObjectAdapterWithEndpoints.return_value

    with (
        patch("opentakserver.mumble.mumble_ice_app.Murmur.MetaPrx.uncheckedCast"),
        patch("opentakserver.mumble.mumble_ice_app.Murmur.MetaCallbackPrx.uncheckedCast"),
        patch(
            "opentakserver.mumble.mumble_ice_app.Murmur.ServerUpdatingAuthenticatorPrx.uncheckedCast"
        ),
        patch.object(MumbleIceApp, "attach_callbacks", return_value=True),
    ):
        mumble = MumbleIceApp(app, logger, ice)
        assert mumble.initialize_ice_connection() is True

    ice.stringToProxy.assert_called_once_with("Meta:tcp -h mumble-server -p 6502")
    ice.createObjectAdapterWithEndpoints.assert_called_once_with("Callback.Client", "tcp -h ots")
    adapter.activate.assert_called_once_with()


def test_mumble_ice_daemon_configures_shared_secret():
    app = make_app()
    daemon = MumbleIceDaemon(app, MagicMock())
    communicator = MagicMock()

    with (
        patch("opentakserver.mumble.mumble_ice_app.Ice.createProperties") as create_properties,
        patch("opentakserver.mumble.mumble_ice_app.Ice.initialize", return_value=communicator),
    ):
        daemon._create_communicator()

    properties = create_properties.return_value
    properties.setProperty.assert_any_call("Ice.ImplicitContext", "Shared")
    communicator.getImplicitContext.return_value.put.assert_called_once_with(
        "secret", "test-ice-secret"
    )


def test_mumble_ice_daemon_waits_before_retrying_failed_connection():
    app = make_app()
    daemon = MumbleIceDaemon(app, MagicMock())
    daemon._run_once = MagicMock(side_effect=Ice.ConnectionRefusedException())
    daemon.shutdown_event = MagicMock()
    daemon.shutdown_event.is_set.return_value = False
    daemon.shutdown_event.wait.return_value = True

    daemon.run()

    daemon._run_once.assert_called_once_with()
    daemon.shutdown_event.wait.assert_called_once_with(7)


def test_mumble_ice_daemon_stops_on_configuration_error():
    app = make_app()
    logger = MagicMock()
    daemon = MumbleIceDaemon(app, logger)
    daemon._run_once = MagicMock(side_effect=MumbleConfigurationError("invalid Ice secret"))
    daemon.shutdown_event = MagicMock()
    daemon.shutdown_event.is_set.return_value = False

    daemon.run()

    daemon._run_once.assert_called_once_with()
    daemon.shutdown_event.wait.assert_not_called()
    logger.error.assert_called_once_with(
        "Mumble authentication handler stopped: %s", daemon._run_once.side_effect
    )


def test_mumble_ice_daemon_caps_transient_retry_backoff():
    app = make_app()
    daemon = MumbleIceDaemon(app, MagicMock())
    daemon._run_once = MagicMock(return_value=False)
    daemon.shutdown_event = MagicMock()
    daemon.shutdown_event.is_set.return_value = False
    daemon.shutdown_event.wait.side_effect = [False, False, True]

    daemon.run()

    assert [call.args[0] for call in daemon.shutdown_event.wait.call_args_list] == [7, 14, 20]
