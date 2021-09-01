"""Test CredOfferAccept message and handler."""
from acapy_plugin_toolbox.holder.v0_1.messages.cred_request_sent import CredRequestSent
from contextlib import contextmanager
from typing import Optional, Set, Union

from aries_cloudagent.connections.models.conn_record import ConnRecord
from aries_cloudagent.messaging.base_handler import RequestContext
from aries_cloudagent.protocols.issue_credential.v1_0.models.credential_exchange import (
    V10CredentialExchange as CredExRecord,
)
from asynctest import mock
from mrgf.governance_framework import GovernanceFramework
import pytest

from acapy_plugin_toolbox.holder.v0_1.messages import cred_offer_accept as test_module
from acapy_plugin_toolbox.holder.v0_1 import CredOfferAccept


@pytest.fixture
def cred_record():
    """Factory for test credential records."""

    def _cred_record():
        return test_module.CredExRecord()

    yield _cred_record


@pytest.fixture
def message():
    """Message fixture."""
    yield CredOfferAccept(credential_exchange_id="mock_cred_ex_id")


@pytest.fixture
def context(context, message):
    """Context fixture."""
    context.message = message
    yield context


@pytest.fixture
def mock_record_query():
    """Mock CredExRecord.query on a module."""

    @contextmanager
    def _mock_record_query(obj, result=None, spec=None):
        with mock.patch.object(
            obj,
            "query",
            mock.CoroutineMock(return_value=result or mock.MagicMock(spec=spec)),
        ) as record_query:
            yield record_query

    yield _mock_record_query


@pytest.fixture
def create_mock_connection_record(context: RequestContext, message: CredOfferAccept):
    def _create_mock_connection_record(roles: Optional[Union[str, Set[str]]] = None):
        mocked_connection_record = mock.MagicMock(spec=ConnRecord)
        mocked_connection_record.connection_id = "mocked connection id"
        mocked_connection_record.metadata_get_all = mock.CoroutineMock(
            return_value={} if not roles else {"roles": roles}
        )
        mocked_connection_record.my_did = "mock_my_did"
        return mocked_connection_record

    yield _create_mock_connection_record


@pytest.fixture
def create_mock_credential(
    context: RequestContext, message: CredOfferAccept, mrgf: GovernanceFramework
):
    def _create_mock_credential(cred_def_id: Optional[str] = None):
        mock_credential = mock.MagicMock(spec=CredExRecord)
        mock_credential.credential_definition_id = cred_def_id or "mock_cred_def_id"
        return mock_credential

    yield _create_mock_credential


@pytest.mark.asyncio
async def test_handler(
    context,
    cred_record,
    message,
    mock_responder,
    mock_retrieve_by_id,
    mock_get_connection,
    create_mock_connection_record,
):
    """Test CredOfferAccept handler."""
    rec1 = cred_record()
    recipient_conn = create_mock_connection_record()
    with mock_retrieve_by_id(
        test_module.CredExRecord, rec1, spec=test_module.CredExRecord
    ) as retrieve_by_id, mock_get_connection(
        test_module, recipient_conn
    ) as mock_get_connection, mock.patch.object(
        test_module,
        "CredentialManager",
        mock.MagicMock(spec=test_module.CredentialManager),
    ) as mock_credential_manager:
        mock_credential_manager.return_value.create_request = mock.CoroutineMock(
            return_value=(rec1, mock.MagicMock())
        )
        await message.handle(context, mock_responder)
    retrieve_by_id.assert_called_once()
    mock_get_connection.assert_called_once()
    assert len(mock_responder.messages) == 2
    _, [cred_offer_accept, _] = mock_responder.messages
    assert isinstance(cred_offer_accept, CredRequestSent)


@pytest.mark.asyncio
async def test_handler_unauthorized(
    context,
    cred_record,
    message,
    mock_responder,
    mock_retrieve_by_id,
    mock_get_connection,
    create_mock_connection_record,
):
    """Test CredOfferAccept handler."""
    rec1 = cred_record()
    recipient_conn = create_mock_connection_record("partner")
    context.connection_record = recipient_conn
    with mock_retrieve_by_id(
        test_module.CredExRecord, rec1, spec=test_module.CredExRecord
    ), mock_get_connection(test_module, recipient_conn), pytest.raises(
        test_module.AuthorizationError
    ):
        await message.handle(context, mock_responder)


@pytest.mark.asyncio
async def test_authorization_default(
    context: RequestContext, message: CredOfferAccept, create_mock_connection_record
):
    """Test that no privileges on principal derived from context results in no
    returned credentials.
    """
    conn = create_mock_connection_record()
    context.connection_record = conn

    credential = mock.MagicMock(spec=CredExRecord)
    result = await message.authorized_to_accept(context, credential)
    assert result is False


@pytest.mark.asyncio
async def test_authorization_limited_true(
    context: RequestContext,
    message: CredOfferAccept,
    mrgf: GovernanceFramework,
    create_mock_connection_record,
    create_mock_credential,
):
    """Test that the correct credential is returned when its mock_cred_def_id
    matches that which the connection is privileged to access
    """
    conn = create_mock_connection_record(roles="partner")
    context.connection_record = conn

    mrgf.privilege("limited-credentials").extra["cred_def_ids"] = ["mock_cred_def_id"]
    mock_credential = create_mock_credential()
    result = await message.authorized_to_accept(context, mock_credential)
    assert result is True


@pytest.mark.asyncio
async def test_authorization_limited_false(
    context: RequestContext,
    message: CredOfferAccept,
    mrgf: GovernanceFramework,
    create_mock_connection_record,
    create_mock_credential,
):
    """Test that a credential that the connection is not
    privileged to access is not returned
    """
    conn = create_mock_connection_record(roles="partner")
    context.connection_record = conn

    mrgf.privilege("limited-credentials").extra["cred_def_ids"] = ["mock_cred_def_id"]
    mock_credential = create_mock_credential("other_mock_cred_def_id")
    result = await message.authorized_to_accept(context, mock_credential)
    assert result is False


@pytest.mark.asyncio
async def test_authorization_all(
    context: RequestContext, message: CredOfferAccept, create_mock_credential
):
    """Test that all credentials are returned when
    connection is in default admin role
    """
    mock_credential = create_mock_credential()

    result = await message.authorized_to_accept(context, mock_credential)
    assert result is True
