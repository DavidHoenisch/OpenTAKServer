import hashlib
import os
import uuid
from datetime import datetime, timezone

import Ice
from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
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

# ATAK Vx identities live well above ordinary OTS database user IDs. The
# in-memory collision check keeps simultaneous identities unique even if their
# deterministic hash candidates collide.
MUMBLE_VX_ID_BASE = 1_000_000_000
MUMBLE_VX_ID_RANGE = 1_000_000_000


class MumbleAuthenticator(Murmur.ServerUpdatingAuthenticator):
    def __init__(self, app, logger, ice):
        Murmur.ServerUpdatingAuthenticator.__init__(self)
        self.app: Flask = app
        self.logger = logger
        self.ice = ice
        self.identity_names = {}
        self.identity_ids = {}
        self.identity_user_ids = {}

    @staticmethod
    def _verified_client_certificate(app, certlist):
        """Return only a current leaf client certificate issued by this OTS CA."""
        if not certlist:
            return None

        ca_path = os.path.join(app.config.get("OTS_CA_FOLDER"), "ca.pem")
        try:
            with open(ca_path, "rb") as ca_file:
                ca_certificate = x509.load_pem_x509_certificate(ca_file.read())
        except (OSError, ValueError, TypeError):
            return None

        now = datetime.now(timezone.utc)
        try:
            certificate = x509.load_der_x509_certificate(bytes(certlist[0]))
            certificate.verify_directly_issued_by(ca_certificate)
            if not (certificate.not_valid_before_utc <= now <= certificate.not_valid_after_utc):
                return None
            usage = certificate.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
            if ExtendedKeyUsageOID.CLIENT_AUTH not in usage:
                return None
            return certificate
        except (InvalidSignature, ValueError, TypeError, x509.ExtensionNotFound):
            return None

    @staticmethod
    def _stored_certificate_matches(certificate, certificate_path):
        try:
            with open(certificate_path, "rb") as certificate_file:
                stored_certificate = x509.load_pem_x509_certificate(certificate_file.read())
            return stored_certificate.fingerprint(hashes.SHA256()) == certificate.fingerprint(
                hashes.SHA256()
            )
        except (OSError, ValueError, TypeError):
            return False

    @staticmethod
    def _verified_certificate_record(app, certlist):
        """Bind the presented leaf to the exact certificate recorded at enrollment."""
        from opentakserver.models.Certificate import Certificate

        certificate = MumbleAuthenticator._verified_client_certificate(app, certlist)
        if not certificate:
            return None

        common_names = certificate.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        if not common_names:
            return None

        records = Certificate.query.filter_by(common_name=common_names[0].value).all()
        for record in records:
            if MumbleAuthenticator._stored_certificate_matches(
                certificate, record.user_cert_filename
            ):
                return record
        return None

    @staticmethod
    def _canonical_vx_username(eud, presented_username):
        if not eud.callsign or "---" not in presented_username:
            return None
        presented_callsign, connection_uid = presented_username.split("---", 1)
        expected_callsign = eud.callsign.replace(" ", "_")
        if presented_callsign.casefold() != expected_callsign.casefold():
            return None
        try:
            connection_uid = str(uuid.UUID(connection_uid))
        except (ValueError, AttributeError):
            return None
        return f"{expected_callsign}---{connection_uid}"

    @staticmethod
    def resolve_identity(app, username, certlist=None):
        """Return an OTS user plus Vx/certificate identity flags."""
        from opentakserver.models.EUD import EUD

        certificate_record = MumbleAuthenticator._verified_certificate_record(app, certlist)
        if certificate_record and certificate_record.eud and certificate_record.eud.user_id:
            canonical_name = MumbleAuthenticator._canonical_vx_username(
                certificate_record.eud, username
            )
            user = app.security.datastore.find_user(id=certificate_record.eud.user_id)
            if user and canonical_name:
                return user, True, True, canonical_name

        user = app.security.datastore.find_user(username=username)
        if user:
            return user, False, False, user.username

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
                if "---" in username:
                    canonical_name = MumbleAuthenticator._canonical_vx_username(eud, username)
                    if canonical_name:
                        return user, True, False, canonical_name
                    return None, False, False, username
                return user, False, False, user.username
        return None, False, False, username

    def mumble_identity(self, user, is_callsign_identity, presented_username):
        existing_id = self.identity_ids.get(presented_username)
        if existing_id is not None:
            return existing_id, presented_username

        if is_callsign_identity:
            digest = int(hashlib.sha256(f"{user.id}:{presented_username}".encode()).hexdigest(), 16)
            mumble_id = MUMBLE_VX_ID_BASE + digest % MUMBLE_VX_ID_RANGE
            while (
                mumble_id in self.identity_names
                and self.identity_names[mumble_id] != presented_username
            ):
                mumble_id = MUMBLE_VX_ID_BASE + (
                    (mumble_id - MUMBLE_VX_ID_BASE + 1) % MUMBLE_VX_ID_RANGE
                )
        else:
            mumble_id = user.id

        self.identity_ids[presented_username] = mumble_id
        self.identity_names[mumble_id] = presented_username
        self.identity_user_ids[mumble_id] = user.id
        return mumble_id, presented_username

    def authenticate(self, username, password, certlist, certhash, strong, current=None):
        if username == "SuperUser":
            return -2, None, None

        self.logger.info("Mumble auth request for %s", username)

        with self.app.app_context():
            (
                user,
                is_callsign_identity,
                certificate_authenticated,
                canonical_name,
            ) = self.resolve_identity(self.app, username, certlist)
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

            mumble_id, display_name = self.mumble_identity(
                user, is_callsign_identity, canonical_name
            )
            self.logger.info("Mumble auth: %s has been authenticated", display_name)
            return mumble_id, display_name, groups

    def getInfo(self, id, current=None):
        if id is None or id <= 0:
            return False, None
        try:
            with self.app.app_context():
                from opentakserver.extensions import db
                from opentakserver.models.user import User

                user = db.session.get(User, self.identity_user_ids.get(id, id))
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
                user, is_callsign_identity, _, canonical_name = self.resolve_identity(
                    self.app, name
                )
                if not user:
                    return -2
                mumble_id, _ = self.mumble_identity(user, is_callsign_identity, canonical_name)
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

                user = db.session.get(User, self.identity_user_ids.get(id, id))
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
