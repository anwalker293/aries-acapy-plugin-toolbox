"""Test CredGetList message and handler."""
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

from acapy_plugin_toolbox.decorators.pagination import Paginate
from acapy_plugin_toolbox.holder import v0_1 as test_module
from acapy_plugin_toolbox.holder.v0_1 import CredGetList, CredList


@pytest.fixture
def cred_record():
    """Factory for test credential records."""

    def _cred_record():
        return test_module.CredExRecord()

    yield _cred_record


@pytest.fixture
def message():
    """Message fixture."""
    paginate = Paginate()
    yield CredGetList(paginate=paginate)


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
def create_mock_connection_record(context: RequestContext, message: CredGetList):
    def _create_mock_connection_record(roles: Optional[Union[str, Set[str]]] = None):
        mocked_connection_record = mock.MagicMock(spec=ConnRecord)
        mocked_connection_record.connection_id = "mocked connection id"
        mocked_connection_record.metadata_get_all = mock.CoroutineMock(
            return_value={} if not roles else {"roles": roles}
        )
        context.connection_record = mocked_connection_record
        return mocked_connection_record

    yield _create_mock_connection_record


@pytest.fixture
def create_mock_credential(
    context: RequestContext, message: CredGetList, mrgf: GovernanceFramework
):
    def _create_mock_credential(cred_def_id: Optional[str] = None):
        mock_credential = mock.MagicMock(spec=CredExRecord)
        mock_credential.credential_definition_id = cred_def_id or "mock_cred_def_id"
        return mock_credential

    yield _create_mock_credential


@pytest.mark.asyncio
async def test_handler(
    context, mock_responder, message, mock_record_query, cred_record
):
    """Test CredGetList handler."""
    rec1 = cred_record()
    with mock_record_query(
        test_module.CredExRecord, [rec1], spec=test_module.CredExRecord
    ) as record_query:
        await message.handle(context, mock_responder)
    record_query.assert_called_once()
    assert len(mock_responder.messages) == 1
    cred_list, _ = mock_responder.messages[0]
    assert isinstance(cred_list, CredList)
    assert cred_list.serialize()
    assert cred_list.results == [rec1.serialize()]
    assert cred_list.page is not None
    assert cred_list.page.count == 1


@pytest.mark.asyncio
async def test_filtered_credentials_default(
    context: RequestContext, message: CredGetList, create_mock_connection_record
):
    """Test that no privileges on principal derived from context results in no
    returned credentials.
    """
    create_mock_connection_record()

    credentials = [mock.MagicMock(spec=CredExRecord)]
    result = await message.filtered_credentials(context, credentials)
    assert result == []


@pytest.mark.asyncio
async def test_filtered_credentials_default_empty(
    context: RequestContext, message: CredGetList, create_mock_connection_record
):
    """Test that no privileges on principal derived from context results in no
    returned credentials.
    """
    create_mock_connection_record()

    result = await message.filtered_credentials(context, [])
    assert result == []


@pytest.mark.asyncio
async def test_filtered_credentials_limited_privileged_cred_present(
    context: RequestContext,
    message: CredGetList,
    mrgf: GovernanceFramework,
    create_mock_connection_record,
    create_mock_credential,
):
    """Test that the correct credential is returned when its mock_cred_def_id
    matches that which the connection is privileged to access
    """
    create_mock_connection_record(roles="partner")

    mrgf.privilege("limited-credentials").extra["cred_def_ids"] = ["mock_cred_def_id"]
    mock_credential = create_mock_credential()
    result = await message.filtered_credentials(context, [mock_credential])
    assert result == [mock_credential]


@pytest.mark.asyncio
async def test_filtered_credentials_limited_privileged_cred_absent(
    context: RequestContext,
    message: CredGetList,
    mrgf: GovernanceFramework,
    create_mock_connection_record,
    create_mock_credential,
):
    """Test that a credential that the connection is not
    privileged to access is not returned
    """
    create_mock_connection_record(roles="partner")

    mrgf.privilege("limited-credentials").extra["cred_def_ids"] = ["mock_cred_def_id"]
    mock_credential = create_mock_credential("other_mock_cred_def_id")
    result = await message.filtered_credentials(context, [mock_credential])
    assert result == []


@pytest.mark.asyncio
async def test_filtered_credentials_limited_privileged_cred_among_unprivileged_creds(
    context: RequestContext,
    message: CredGetList,
    mrgf: GovernanceFramework,
    create_mock_connection_record,
    create_mock_credential,
):
    """Test that the only correct credential is returned from a list including
    credentials that the connection is not privileged to access
    """
    create_mock_connection_record(roles="partner")

    mrgf.privilege("limited-credentials").extra["cred_def_ids"] = ["mock_cred_def_id"]
    mock_credential1 = create_mock_credential()
    mock_credential2 = create_mock_credential("other_mock_cred_def_id")

    mock_credentials_list = [mock_credential1, mock_credential2]
    result = await message.filtered_credentials(context, mock_credentials_list)
    assert result == [mock_credential1]


@pytest.mark.asyncio
async def test_all_credentials(
    context: RequestContext, message: CredGetList, create_mock_credential
):
    """Test that all credentials are returned when
    connection is in default admin role
    """
    mock_credential1 = create_mock_credential()
    mock_credential2 = create_mock_credential()

    result = await message.filtered_credentials(
        context, [mock_credential1, mock_credential2]
    )
    assert result == [mock_credential1, mock_credential2]
