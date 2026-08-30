from datetime import datetime, timedelta, timezone
from types import ModuleType
from unittest.mock import MagicMock, patch

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

pytest.importorskip("Ice")

from opentakserver.mumble.mumble_authenticator import MumbleAuthenticator  # noqa: E402


def make_authenticator():
    auth = MumbleAuthenticator.__new__(MumbleAuthenticator)  # skip Ice setup
    auth.app = MagicMock()
    auth.logger = MagicMock()
    auth.identity_names = {}
    auth.identity_ids = {}
    auth.identity_user_ids = {}
    return auth


def issue_certificate(issuer_key, issuer_name, common_name, client_auth):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    now = datetime.now(timezone.utc)
    builder = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(issuer_name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=1))
    )
    if client_auth:
        builder = builder.add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]), critical=True
        )
    return builder.sign(issuer_key, hashes.SHA256())


def test_only_ots_issued_leaf_certificate_is_accepted(tmp_path):
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "OTS Test CA")])
    now = datetime.now(timezone.utc)
    ca_certificate = (
        x509.CertificateBuilder()
        .subject_name(ca_name)
        .issuer_name(ca_name)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(ca_key, hashes.SHA256())
    )
    ots_client = issue_certificate(ca_key, ca_name, "ANDROID-verified", True)

    other_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    other_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Other CA")])
    untrusted_client = issue_certificate(other_key, other_name, "ANDROID-forged", True)

    (tmp_path / "ca.pem").write_bytes(ca_certificate.public_bytes(serialization.Encoding.PEM))
    app = MagicMock()
    app.config.get.return_value = str(tmp_path)

    assert (
        MumbleAuthenticator._verified_client_certificate(
            app, [ots_client.public_bytes(serialization.Encoding.DER)]
        ).subject
        == ots_client.subject
    )
    assert (
        MumbleAuthenticator._verified_client_certificate(
            app, [untrusted_client.public_bytes(serialization.Encoding.DER)]
        )
        is None
    )


def test_verified_leaf_resolves_through_exact_enrollment_record(tmp_path):
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "OTS Test CA")])
    now = datetime.now(timezone.utc)
    ca_certificate = (
        x509.CertificateBuilder()
        .subject_name(ca_name)
        .issuer_name(ca_name)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(ca_key, hashes.SHA256())
    )
    client = issue_certificate(ca_key, ca_name, "enrollment-csr-cn", True)
    spoof = issue_certificate(ca_key, ca_name, "ANDROID-target", True)
    (tmp_path / "ca.pem").write_bytes(ca_certificate.public_bytes(serialization.Encoding.PEM))
    client_path = tmp_path / "client.pem"
    client_path.write_bytes(client.public_bytes(serialization.Encoding.PEM))

    app = MagicMock()
    app.config.get.return_value = str(tmp_path)
    enrollment = MagicMock(
        common_name="enrollment-csr-cn",
        eud_uid="ANDROID-real",
        user_cert_filename=str(client_path),
        eud=MagicMock(uid="ANDROID-real", user_id=42, callsign="ANVIL"),
    )
    ambiguous_victim = MagicMock(
        common_name="enrollment-csr-cn",
        eud_uid="ANDROID-victim",
        user_cert_filename=str(client_path),
    )
    certificate_model = MagicMock()
    certificate_model.query.filter_by.return_value.all.side_effect = [
        [enrollment],
        [],
        [enrollment, ambiguous_victim],
    ]
    certificate_module = ModuleType("opentakserver.models.Certificate")
    certificate_module.Certificate = certificate_model

    with patch.dict("sys.modules", {"opentakserver.models.Certificate": certificate_module}):
        resolved = MumbleAuthenticator._verified_certificate_record(
            app, [client.public_bytes(serialization.Encoding.DER)]
        )
        rejected_spoof = MumbleAuthenticator._verified_certificate_record(
            app, [spoof.public_bytes(serialization.Encoding.DER)]
        )
        rejected_ambiguity = MumbleAuthenticator._verified_certificate_record(
            app, [client.public_bytes(serialization.Encoding.DER)]
        )

    assert resolved.eud.uid == "ANDROID-real"
    assert resolved.common_name != resolved.eud.uid
    assert rejected_spoof is None
    assert rejected_ambiguity is None


def test_vx_username_must_match_enrolled_eud_callsign():
    eud = MagicMock(callsign="COMMAND ONE")

    assert (
        MumbleAuthenticator._canonical_vx_username(
            eud, "COMMAND_ONE---47c4c853-4e52-4b97-9a0b-08a0f961b0fa"
        )
        == "COMMAND_ONE---47c4c853-4e52-4b97-9a0b-08a0f961b0fa"
    )
    assert (
        MumbleAuthenticator._canonical_vx_username(
            eud, "IMPOSTOR---47c4c853-4e52-4b97-9a0b-08a0f961b0fa"
        )
        is None
    )


def test_vx_parallel_connections_receive_distinct_ids():
    auth = make_authenticator()
    user = MagicMock(id=42, username="test_alpha")
    first_username = "ANVIL---47c4c853-4e52-4b97-9a0b-08a0f961b0fa"
    second_username = "ANVIL---9501be80-73bd-4df2-afc5-d3980e692d3f"

    first_id, first_name = auth.mumble_identity(user, True, first_username)
    second_id, second_name = auth.mumble_identity(user, True, second_username)

    assert first_id != second_id
    assert first_name == first_username
    assert second_name == second_username


def test_desktop_identity_uses_stable_ots_user_range():
    auth = make_authenticator()
    user = MagicMock(id=42, username="test_alpha")

    mumble_id, display_name = auth.mumble_identity(user, False, "test_alpha")

    assert mumble_id == 42
    assert display_name == "test_alpha"


def test_vx_certificate_identity_authenticates_without_password():
    auth = make_authenticator()
    user = MagicMock(id=42, username="test_alpha", active=True, groups=[], roles=[])
    vx_username = "ANVIL---47c4c853-4e52-4b97-9a0b-08a0f961b0fa"

    with (
        patch.object(
            MumbleAuthenticator,
            "resolve_identity",
            return_value=(user, True, True, vx_username),
        ),
        patch("opentakserver.mumble.mumble_authenticator.verify_password") as verify_password,
    ):
        mumble_id, display_name, groups = auth.authenticate(
            vx_username, "", [b"certificate"], "hash", False
        )

    assert mumble_id >= 1_000_000_000
    assert display_name == vx_username
    assert groups == []
    verify_password.assert_not_called()


def test_unverified_callsign_requires_ots_password():
    auth = make_authenticator()
    user = MagicMock(id=42, username="test_alpha", active=True, groups=[], roles=[])

    with (
        patch.object(
            MumbleAuthenticator,
            "resolve_identity",
            return_value=(user, True, False, "ANVIL---untrusted"),
        ),
        patch(
            "opentakserver.mumble.mumble_authenticator.verify_password",
            return_value=False,
        ),
    ):
        result = auth.authenticate("ANVIL---untrusted", "", [], "", False)

    assert result == (-1, None, None)
