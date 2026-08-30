import os
import threading

import Ice

from opentakserver.mumble.mumble_authenticator import MumbleAuthenticator

# Load up Murmur slice file into Ice
Ice.loadSlice(
    "",
    [
        "-I" + Ice.getSliceDir(),
        os.path.join(os.path.dirname(os.path.realpath(__file__)), "Murmur.ice"),
    ],
)
import Murmur  # noqa: E402


class MumbleIceDaemon(threading.Thread):
    def __init__(self, app, logger):
        super().__init__()
        self.app = app
        self.logger = logger
        self.logger.info("mumble daemon init")
        self.daemon = True
        self.shutdown_event = threading.Event()

    def _create_communicator(self):
        props = Ice.createProperties()
        props.setProperty("Ice.ImplicitContext", "Shared")
        props.setProperty("Ice.Default.EncodingVersion", "1.0")
        props.setProperty("Ice.Default.InvocationTimeout", str(30 * 1000))
        props.setProperty("Ice.MessageSizeMax", str(1024))
        idata = Ice.InitializationData()
        idata.properties = props

        ice = Ice.initialize(idata)
        secret = self.app.config.get("OTS_MUMBLE_ICE_SECRET", "")
        if secret:
            ice.getImplicitContext().put("secret", secret)
        return ice

    def _run_once(self):
        ice = self._create_communicator()
        retry_seconds = self.app.config.get("OTS_MUMBLE_ICE_RETRY_SECONDS", 5)

        try:
            mumble_ice_app = MumbleIceApp(self.app, self.logger, ice)
            if not mumble_ice_app.initialize_ice_connection():
                return

            self.logger.info("Mumble authentication handler connected")
            while not self.shutdown_event.wait(retry_seconds):
                if not mumble_ice_app.attach_callbacks():
                    return
        finally:
            ice.destroy()

    def run(self):
        retry_seconds = self.app.config.get("OTS_MUMBLE_ICE_RETRY_SECONDS", 5)

        while not self.shutdown_event.is_set():
            try:
                self._run_once()
            except Ice.Exception as e:
                self.logger.warning("Mumble Ice connection failed: %s", e)
            except BaseException as e:
                self.logger.error("Mumble authentication handler failed: %s", e)

            if self.shutdown_event.wait(retry_seconds):
                break


class MumbleIceApp(Ice.Application):
    def __init__(self, app, logger, ice):
        super().__init__()
        self.app = app
        self.logger = logger
        self.ice = ice
        self.meta = None
        self.metacb = None
        self.connected = False
        self.failed_watch = False
        self.watchdog = None
        self.auth = None
        self.adapter = None

    def run(self, *args):
        return 0 if self.initialize_ice_connection() else 1

    def initialize_ice_connection(self):
        """
        Establishes the two-way Ice connection and adds the authenticator to the
        configured servers
        """

        host = self.app.config.get("OTS_MUMBLE_ICE_HOST", "127.0.0.1")
        port = self.app.config.get("OTS_MUMBLE_ICE_PORT", 6502)
        callback_host = self.app.config.get("OTS_MUMBLE_ICE_CALLBACK_HOST", "127.0.0.1")

        self.logger.debug("Connecting to Ice server (%s:%s)", host, port)
        base = self.ice.stringToProxy(f"Meta:tcp -h {host} -p {port}")
        self.meta = Murmur.MetaPrx.uncheckedCast(base)

        self.adapter = self.ice.createObjectAdapterWithEndpoints(
            "Callback.Client", f"tcp -h {callback_host}"
        )
        self.adapter.activate()

        metacbprx = self.adapter.addWithUUID(MetaCallback(self))
        self.metacb = Murmur.MetaCallbackPrx.uncheckedCast(metacbprx)

        authprx = self.adapter.addWithUUID(MumbleAuthenticator(self.app, self.logger, self.ice))
        self.auth = Murmur.ServerUpdatingAuthenticatorPrx.uncheckedCast(authprx)

        return self.attach_callbacks()

    def attach_callbacks(self):
        """
        Attaches all callbacks for meta and authenticators
        """

        try:
            self.logger.debug("Attaching meta callback")

            self.meta.addCallback(self.metacb)

            for server in self.meta.getBootedServers():
                self.logger.debug(
                    "Setting mumble authenticator for virtual server {}".format(server.id())
                )
                server.setAuthenticator(self.auth)

        except (
            Murmur.InvalidSecretException,
            Ice.UnknownUserException,
            Ice.ConnectionRefusedException,
        ) as e:
            if isinstance(e, Ice.ConnectionRefusedException):
                self.logger.warning("Server refused connection")
            elif (
                isinstance(e, Murmur.InvalidSecretException)
                or isinstance(e, Ice.UnknownUserException)
                and (e.unknown == "Murmur::InvalidSecretException")
            ):
                self.logger.error("Invalid ice secret")
            else:
                # We do not actually want to handle this one, re-raise it
                raise e

            self.connected = False
            return False

        self.connected = True
        return True


class MetaCallback(Murmur.MetaCallback):
    def __init__(self, authenticator):
        Murmur.MetaCallback.__init__(self)
        self.authenticator = authenticator

    def started(self, server, current=None):
        """
        This function is called when a virtual server is started
        and makes sure an authenticator gets attached if needed.
        """
        self.authenticator.logger.info(
            "Setting authenticator for virtual server {}".format(server.id())
        )
        try:
            server.setAuthenticator(self.authenticator.auth)
        # Apparently this server was restarted without us noticing
        except (Murmur.InvalidSecretException, Ice.UnknownUserException) as e:
            if hasattr(e, "unknown") and e.unknown != "Murmur::InvalidSecretException":
                # Special handling for Murmur 1.2.2 servers with invalid slice files
                raise e

            return

    def stopped(self, server, current=None):
        """
        This function is called when a virtual server is stopped
        """
        if self.authenticator.connected:
            # Only try to output the server id if we think we are still connected to prevent
            # flooding of our thread pool
            try:
                self.authenticator.logger.info(
                    "Authenticated virtual server {} got stopped".format(server.id())
                )
                return
            except Ice.ConnectionRefusedException:
                self.authenticator.connected = False

        self.authenticator.logger.info("Server shutdown stopped a virtual server")
