"""Pickup protocol support."""

from aries_cloudagent.messaging.request_context import RequestContext
from aries_cloudagent.messaging.responder import BaseResponder
from marshmallow import fields
from acapy_plugin_toolbox.util import expand_message_class, with_generic_init
from aries_cloudagent.messaging.agent_message import AgentMessage


class PickupMessage(AgentMessage):
    """Pickup Protocol base message."""
    protocol = "https://didcomm.org/messagepickup/2.0"


@with_generic_init
@expand_message_class
class StatusRequest(PickupMessage):
    """Status request message."""

    class Fields:
        """StatusRequest fields."""
        recipient_key = fields.Str(
            required=False,
            description="did:key representation of the recipient key denoting the "
            "message queue for which report the status"
        )

    async def handle(self, context: RequestContext, responder: BaseResponder):
        """Handle status request message."""


@with_generic_init
@expand_message_class
class Status(PickupMessage):
    """Status message."""

    class Fields:
        """Status fields."""
        recipient_key = fields.Str(
            required=False,
            description="did:key representation of the recipient key denoting the "
            "message queue for which report the status"
        )
        message_count = fields.Int(required=True)
        duration_waited = fields.Int(required=False)
        newest_time = fields.DateTime(required=False)
        oldest_time = fields.DateTime(required=False)
        total_size = fields.Int(required=False)
