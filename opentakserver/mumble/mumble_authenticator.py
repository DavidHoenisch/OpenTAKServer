import hashlib
import os
from datetime import datetime, timezone

import Ice
from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
from flask import Flask
from flask_ldap3_login import AuthenticationResponseStatus
from flask_security import verify_password

from ..extensions import ldap_manager

# Load up Murmur slice file into Ice
Ice.loadSlice(
    "",
    [
        "-I" + Ice.getSliceDir(),
        os.path.join(os.path.dirname(os.path.realpath(__file__)), "Murmur.ice"),
    ],
)
import Murmur  # noqa: E402

# Reserve a deterministic range so ATAK Vx's parallel `callsign---uid`
# connections do not collide with the desktop identity for the same OTS user.
MUMBLE_ID_RANGE = 1000
MUMBLE_ID_CALLSIGN_OFFSET_RANGE = MUMBLE_ID_RANGE - 1


class MumbleAuthenticator(Murmur.ServerUpdatingAuthenticator):
    def __init__(self, app, logger, ice):
        Murmur.ServerUpdatingAuthenticator.__init__(self)
        self.app: Flask = app
        self.logger = logger
        self.ice = ice
        self.identity_names = {}

    @staticmethod
    def _verified_client_common_name(app, certlist):
        """Return the CN only for a current client certificate issued by this OTS CA."""
        if not certlist:
            return None

        ca_path = os.path.join(app.config.get("OTS_CA_FOLDER"), "ca.pem")
        try:
            with open(ca_path, "rb") as ca_file:
                ca_certificate = x509.load_pem_x509_certificate(ca_file.read())
        except (OSError, ValueError, TypeError):
            return None

        now = datetime.now(timezone.utc)
        for cert_bytes in certlist:
            try:
                certificate = x509.load_der_x509_certificate(cert_bytes)
                certificate.verify_directly_issued_by(ca_certificate)
                if not (certificate.not_valid_before_utc <= now <= certificate.not_valid_after_utc):
                    continue
                usage = certificate.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
                if ExtendedKeyUsageOID.CLIENT_AUTH not in usage:
                    continue
                common_names = certificate.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
                if not common_names:
                    continue
                return common_names[0].value
            except (InvalidSignature, ValueError, TypeError, x509.ExtensionNotFound):
                continue
        return None

    @staticmethod
    def _verified_eud_from_cert(app, certlist):
        """Resolve an EUD only from a client certificate issued by this OTS CA."""
        from opentakserver.models.EUD import EUD

        common_name = MumbleAuthenticator._verified_client_common_name(app, certlist)
        return EUD.query.filter_by(uid=common_name).first() if common_name else None

    @staticmethod
    def resolve_identity(app, username, certlist=None):
        """Return an OTS user plus Vx/certificate identity flags."""
        from opentakserver.models.EUD import EUD

        verified_eud = MumbleAuthenticator._verified_eud_from_cert(app, certlist)
        if verified_eud and verified_eud.user_id:
            user = app.security.datastore.find_user(id=verified_eud.user_id)
            if user:
                return user, True, True

        user = app.security.datastore.find_user(username=username)
        if user:
            return user, False, False

        eud = EUD.query.filter_by(callsign=username).first()
        base_callsign = username
        if not eud and "---" in username:
            base_callsign = username.split("---", 1)[0]
            eud = EUD.query.filter_by(callsign=base_callsign).first()

        if not eud:
            spaced_callsign = base_callsign.replace("_", " ")
            if spaced_callsign != base_callsign:
                eud = EUD.query.filter_by(callsign=spaced_callsign).first()

        if eud and eud.user_id:
            user = app.security.datastore.find_user(id=eud.user_id)
            if user:
                return user, True, False
        return None, False, False

    @staticmethod
    def mumble_identity(user, is_callsign_identity, presented_username):
        if is_callsign_identity:
            digest = int(hashlib.sha256(presented_username.encode()).hexdigest(), 16)
            offset = digest % MUMBLE_ID_CALLSIGN_OFFSET_RANGE + 1
            return user.id * MUMBLE_ID_RANGE + offset, presented_username
        return user.id * MUMBLE_ID_RANGE, user.username

    def authenticate(self, username, password, certlist, certhash, strong, current=None):
        if username == "SuperUser":
            return -2, None, None

        self.logger.info("Mumble auth request for %s", username)

        with self.app.app_context():
            user, is_callsign_identity, certificate_authenticated = self.resolve_identity(
                self.app, username, certlist
            )
            if not user:
                self.logger.warning("Mumble auth: user %s not found", username)
                return -1, None, None
            if not user.active:
                self.logger.warning("Mumble auth: user %s is deactivated", username)
                return -1, None, None

            authenticated = certificate_authenticated
            if not authenticated and self.app.config.get("OTS_ENABLE_LDAP"):
                auth_result = ldap_manager.authenticate(user.username, password)
                if auth_result.status == AuthenticationResponseStatus.success:
                    from opentakserver.blueprints.ots_api.ldap_api import save_user

                    save_user(
                        auth_result.user_dn,
                        auth_result.user_id,
                        auth_result.user_info,
                        auth_result.user_groups,
                    )
                    authenticated = True
            elif not authenticated and verify_password(password, user.password):
                authenticated = True

            if not authenticated:
                self.logger.warning("Mumble auth: bad credentials for %s", username)
                return -1, None, None

            groups = [group.name for group in user.groups]
            if any(role.name == "administrator" for role in user.roles):
                groups.append("admin")

            mumble_id, display_name = self.mumble_identity(user, is_callsign_identity, username)
            self.identity_names[mumble_id] = display_name
            self.logger.info("Mumble auth: %s has been authenticated", display_name)
            return mumble_id, display_name, groups

    def getInfo(self, id, current=None):
        if id is None or id <= 0:
            return False, None
        try:
            with self.app.app_context():
                from opentakserver.extensions import db
                from opentakserver.models.user import User

                user = db.session.get(User, id // MUMBLE_ID_RANGE)
                if not user:
                    return False, None
                info = {Murmur.UserInfo.UserName: self.identity_names.get(id, user.username)}
                if user.email:
                    info[Murmur.UserInfo.UserEmail] = user.email
                return True, info
        except Exception as e:
            self.logger.error("Mumble getInfo(%s) failed: %s", id, e)
            return False, None

    def nameToId(self, name, current=None):
        if not name or name == "SuperUser":
            return -2
        try:
            with self.app.app_context():
                user, is_callsign_identity, _ = self.resolve_identity(self.app, name)
                if not user:
                    return -2
                mumble_id, display_name = self.mumble_identity(user, is_callsign_identity, name)
                self.identity_names[mumble_id] = display_name
                return mumble_id
        except Exception as e:
            self.logger.error("Mumble nameToId(%s) failed: %s", name, e)
            return -2

    def idToName(self, id, current=None):
        if id is None or id <= 0:
            return ""
        try:
            with self.app.app_context():
                from opentakserver.extensions import db
                from opentakserver.models.user import User

                user = db.session.get(User, id // MUMBLE_ID_RANGE)
                return self.identity_names.get(id, user.username if user else "")
        except Exception as e:
            self.logger.error("Mumble idToName(%s) failed: %s", id, e)
            return ""

    def idToTexture(self, id, current=None):
        return b""

    def registerUser(self, info, current=None):
        return -2

    def unregisterUser(self, id, current=None):
        return -1

    def getRegisteredUsers(self, filter, current=None):
        return {}

    def setInfo(self, id, info, current=None):
        return 0

    def setTexture(self, id, texture, current=None):
        return -1
