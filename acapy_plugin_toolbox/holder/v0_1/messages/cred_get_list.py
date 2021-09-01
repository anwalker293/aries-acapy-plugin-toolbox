from typing import List, Optional, cast

from aries_cloudagent.messaging.base_handler import BaseResponder, RequestContext
from aries_cloudagent.protocols.issue_credential.v1_0.models.credential_exchange import (
    V10CredentialExchange as CredExRecord,
)
from marshmallow import fields, validate
from mrgf import context_to_principal, GovernanceFramework

from ....decorators.pagination import Paginate
from ....util import expand_message_class, log_handling, require
from .base import AdminHolderMessage
from .cred_list import CredList


@expand_message_class
class CredGetList(AdminHolderMessage):
    """Credential list retrieval message."""

    message_type = "credentials-get-list"

    class Fields:
        """Credential get list fields."""

        paginate = fields.Nested(
            Paginate.Schema,
            required=False,
            data_key="~paginate",
            missing=Paginate(limit=10, offset=0),
            description="Pagination decorator.",
        )
        states = fields.List(
            fields.Str(required=True),
            required=False,
            example=["offer_received"],
            description="Filter listed credentials by state.",
            validate=validate.OneOf(
                [
                    CredExRecord.STATE_ACKED,
                    CredExRecord.STATE_CREDENTIAL_RECEIVED,
                    CredExRecord.STATE_ISSUED,
                    CredExRecord.STATE_OFFER_RECEIVED,
                    CredExRecord.STATE_OFFER_SENT,
                    CredExRecord.STATE_PROPOSAL_RECEIVED,
                    CredExRecord.STATE_PROPOSAL_SENT,
                    CredExRecord.STATE_REQUEST_RECEIVED,
                    CredExRecord.STATE_REQUEST_SENT,
                ]
            ),
        )

    def __init__(
        self, paginate: Paginate, states: Optional[List[str]] = None, **kwargs
    ):
        super().__init__(**kwargs)
        self.paginate = paginate
        self.states = states

    @log_handling
    @require(lambda p: "admin-holder" in p.privileges)
    async def handle(self, context: RequestContext, responder: BaseResponder):
        """Handle received get cred list request."""
        async with context.session() as session:
            credentials = cast(List[CredExRecord], await CredExRecord.query(session))

            credentials = await self.filtered_credentials(context, credentials)

            if self.states:
                credentials = [c for c in credentials if c.state in self.states]

            credentials, page = self.paginate.apply(credentials)

            cred_list = CredList(
                results=[credential.serialize() for credential in credentials],
                page=page,
            )
            cred_list.assign_thread_from(context.message)  # self
            await responder.send_reply(cred_list)

    async def filtered_credentials(
        self, context: RequestContext, credentials: List[CredExRecord]
    ):
        principal = await context_to_principal(context)
        if "limited-credentials" in principal.privileges:
            return await self.filtered_credentials_for_limited(context, credentials)
        elif "all-credentials" in principal.privileges:
            return credentials

        return []

    async def filtered_credentials_for_limited(
        self,
        context: RequestContext,
        credentials: List[CredExRecord],
    ):
        """Return filtered credentials for limited-credentials privileged connections."""
        framework = cast(GovernanceFramework, context.inject(GovernanceFramework))
        approved = framework.privilege("limited-credentials").extra["cred_def_ids"]

        credentials = [
            cred for cred in credentials if cred.credential_definition_id in approved
        ]
        return credentials
