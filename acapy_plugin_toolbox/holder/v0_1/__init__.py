"""Define messages for credential holder admin protocols."""

# pylint: disable=invalid-name
# pylint: disable=too-few-public-methods

import logging
import re
from typing import Optional

from aries_cloudagent.config.injection_context import InjectionContext
from aries_cloudagent.core.event_bus import Event, EventBus
from aries_cloudagent.core.profile import Profile
from aries_cloudagent.core.protocol_registry import ProtocolRegistry
from aries_cloudagent.messaging.base_handler import BaseResponder
from aries_cloudagent.protocols.issue_credential.v1_0.models.credential_exchange import (
    V10CredentialExchange as CredExRecord,
)
from aries_cloudagent.protocols.present_proof.v1_0.models.presentation_exchange import (
    V10PresentationExchange as PresExRecord,
)
from mrgf.governance_framework import GovernanceFramework, Principal

from ...util import send_to_admins
from .messages import (
    AdminHolderMessage,
    CredDelete,
    CredDeleted,
    CredExchange,
    CredGetList,
    CredList,
    CredOfferAccept,
    CredOfferRecv,
    CredOfferReject,
    CredOfferRejectSent,
    CredReceived,
    CredRequestSent,
    PresDelete,
    PresDeleted,
    PresExchange,
    PresGetList,
    PresGetMatchingCredentials,
    PresList,
    PresMatchingCredentials,
    PresRejectSent,
    PresRequestApprove,
    PresRequestReceived,
    PresRequestReject,
    PresSent,
    SendCredProposal,
    SendPresProposal,
)

LOGGER = logging.getLogger(__name__)


PROTOCOL = AdminHolderMessage.protocol
TITLE = "Holder Admin Protocol"
NAME = "admin-holder"
VERSION = "0.1"
MESSAGE_TYPES = {
    msg_class.Meta.message_type: "{}.{}".format(
        msg_class.__module__, msg_class.__name__
    )
    for msg_class in [
        CredDelete,
        CredDeleted,
        CredExchange,
        CredGetList,
        CredList,
        CredOfferAccept,
        CredOfferRecv,
        CredOfferReject,
        CredOfferRejectSent,
        CredReceived,
        CredRequestSent,
        PresDelete,
        PresDeleted,
        PresExchange,
        PresGetList,
        PresGetMatchingCredentials,
        PresList,
        PresMatchingCredentials,
        PresRejectSent,
        PresRequestApprove,
        PresRequestReceived,
        PresRequestReject,
        PresSent,
        SendCredProposal,
        SendPresProposal,
    ]
}


async def setup(
    context: InjectionContext, protocol_registry: Optional[ProtocolRegistry] = None
):
    """Setup the holder plugin."""
    if not protocol_registry:
        protocol_registry = context.inject(ProtocolRegistry)
    protocol_registry.register_message_types(MESSAGE_TYPES)
    bus: EventBus = context.inject(EventBus)
    bus.subscribe(
        re.compile(f"acapy::record::{CredExRecord.RECORD_TOPIC}::.*"),
        issue_credential_event_handler,
    )
    bus.subscribe(
        re.compile(f"acapy::record::{PresExRecord.RECORD_TOPIC}::.*"),
        present_proof_event_handler,
    )


async def issue_credential_event_handler(profile: Profile, event: Event):
    """Handle issue credential events."""
    record: CredExRecord = CredExRecord.deserialize(event.payload)
    LOGGER.debug("IssueCredential Event; %s: %s", event.topic, event.payload)

    if record.state not in (
        CredExRecord.STATE_OFFER_RECEIVED,
        CredExRecord.STATE_CREDENTIAL_RECEIVED,
    ):
        return

    responder = profile.inject(BaseResponder)
    assert responder
    message = None
    if record.state == CredExRecord.STATE_OFFER_RECEIVED:
        message = CredOfferRecv(record=record)
        LOGGER.debug("Prepared Message: %s", message.serialize())

    if record.state == CredExRecord.STATE_CREDENTIAL_RECEIVED:
        message = CredReceived(record=record)
        LOGGER.debug("Prepared Message: %s", message.serialize())

    framework = profile.inject(GovernanceFramework)
    assert framework
    approved = framework.privilege("limited-credentials").extra["cred_def_ids"]

    def send_condition(principal: Principal):
        # TODO generalize privilege?
        if "limited-credentials" in principal.privileges:
            return record.credential_definition_id in approved
        if "all-credentials" in principal.privileges:
            return True
        return False

    if message:
        async with profile.session() as session:
            await send_to_admins(session, message, responder, condition=send_condition)


async def present_proof_event_handler(profile: Profile, event: Event):
    """Handle present proof events."""
    record: PresExRecord = PresExRecord.deserialize(event.payload)
    LOGGER.debug("PresentProof Event; %s: %s", event.topic, event.payload)

    if record.state == PresExRecord.STATE_REQUEST_RECEIVED:
        responder = profile.inject(BaseResponder)
        message: PresRequestReceived = PresRequestReceived(record)
        LOGGER.debug("Prepared Message: %s", message.serialize())
        await message.retrieve_matching_credentials(profile)
        async with profile.session() as session:
            await send_to_admins(session, message, responder)
