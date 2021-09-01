from typing import cast

from aries_cloudagent.messaging.base_handler import BaseResponder, RequestContext
from aries_cloudagent.messaging.models.base import BaseModelError
from aries_cloudagent.messaging.valid import UUIDFour
from aries_cloudagent.protocols.issue_credential.v1_0.manager import (
    CredentialManager,
    CredentialManagerError,
)
from aries_cloudagent.protocols.issue_credential.v1_0.models.credential_exchange import (
    V10CredentialExchange as CredExRecord,
)
from aries_cloudagent.storage.error import StorageError
from marshmallow import fields
from mrgf import GovernanceFramework, context_to_principal

from ....util import (
    ExceptionReporter,
    expand_message_class,
    get_connection,
    log_handling,
    require,
)
from .base import AdminHolderMessage
from .cred_request_sent import CredRequestSent


class AuthorizationError(Exception):
    """Raised when connection is not authorized to accept a credential offer."""


@expand_message_class
class CredOfferAccept(AdminHolderMessage):
    """Credential offer accept message."""

    message_type = "credential-offer-accept"

    class Fields:
        """Fields of cred offer accept message."""

        credential_exchange_id = fields.Str(
            required=True,
            description="ID of the credential exchange to accept",
            example=UUIDFour.EXAMPLE,
        )

    def __init__(self, credential_exchange_id: str, **kwargs):
        super().__init__(**kwargs)
        self.credential_exchange_id = credential_exchange_id

    @log_handling
    @require(lambda p: "admin-holder" in p.privileges)
    async def handle(self, context: RequestContext, responder: BaseResponder):
        """Handle credential offer accept message."""

        cred_ex_record = None
        connection_record = None
        async with context.session() as session:
            async with ExceptionReporter(
                responder, (StorageError, CredentialManagerError, BaseModelError), self
            ):
                cred_ex_record = await CredExRecord.retrieve_by_id(
                    session, self.credential_exchange_id
                )
                cred_ex_record = cast(CredExRecord, cred_ex_record)
                connection_id = cred_ex_record.connection_id
                connection_record = await get_connection(session, connection_id)

        if not await self.authorized_to_accept(context, cred_ex_record):
            raise AuthorizationError(
                "Connection is not authorized to accept this credential offer."
            )

        credential_manager = CredentialManager(context.profile)
        (
            cred_ex_record,
            credential_request_message,
        ) = await credential_manager.create_request(
            cred_ex_record, connection_record.my_did
        )

        sent = CredRequestSent(record=cred_ex_record)
        sent.assign_thread_from(self)

        await responder.send(credential_request_message, connection_id=connection_id)
        await responder.send_reply(sent)

    async def authorized_to_accept(
        self, context: RequestContext, cred_ex_record: CredExRecord
    ) -> bool:
        principal = await context_to_principal(context)
        if "all-credentials" in principal.privileges:
            return True
        elif "limited-credentials" in principal.privileges:
            return await self.authorized_to_accept_limited(context, cred_ex_record)
        return False

    async def authorized_to_accept_limited(
        self, context: RequestContext, cred_ex_record: CredExRecord
    ):
        framework = context.inject(GovernanceFramework)
        assert framework
        approved = framework.privilege("limited-credentials").extra["cred_def_ids"]
        return cred_ex_record.credential_definition_id in approved
