"""Define messages for connections admin protocol."""

# pylint: disable=invalid-name
# pylint: disable=too-few-public-methods

import re
from typing import Any, Dict, Sequence
import json


from aries_cloudagent.connections.models.conn_record import ConnRecord
from aries_cloudagent.core.profile import InjectionContext, Profile, ProfileSession
from aries_cloudagent.core.protocol_registry import ProtocolRegistry
from aries_cloudagent.core.event_bus import Event, EventBus
from aries_cloudagent.messaging.base_handler import (
    BaseHandler,
    BaseResponder,
    RequestContext,
)
from aries_cloudagent.protocols.connections.v1_0.manager import ConnectionManager
from aries_cloudagent.protocols.connections.v1_0.messages.connection_invitation import (
    ConnectionInvitation,
)
from aries_cloudagent.protocols.problem_report.v1_0.message import ProblemReport
from aries_cloudagent.storage.error import StorageNotFoundError
from aries_cloudagent.storage.base import BaseStorage
from aries_cloudagent.storage.record import StorageRecord
from marshmallow import Schema, fields, validate
from mrgf import Selector, request_handler_principal_finder

from .util import generate_model_schema, require, send_to_admins

PROTOCOL = (
    "https://github.com/hyperledger/aries-toolbox/"
    "tree/master/docs/admin-connections/0.1"
)

# Message Types
GET_LIST = "{}/get-list".format(PROTOCOL)
LIST = "{}/list".format(PROTOCOL)
UPDATE = "{}/update".format(PROTOCOL)
CONNECTION = "{}/connection".format(PROTOCOL)
DELETE = "{}/delete".format(PROTOCOL)
DELETED = "{}/deleted".format(PROTOCOL)
RECEIVE_INVITATION = "{}/receive-invitation".format(PROTOCOL)
CONNECTED = "{}/connected".format(PROTOCOL)

# Message Type string to Message Class map
MESSAGE_TYPES = {
    GET_LIST: "acapy_plugin_toolbox.connections.GetList",
    LIST: "acapy_plugin_toolbox.connections.List",
    UPDATE: "acapy_plugin_toolbox.connections.Update",
    CONNECTION: "acapy_plugin_toolbox.connections.Connnection",
    DELETE: "acapy_plugin_toolbox.connections.Delete",
    DELETED: "acapy_plugin_toolbox.connections.Deleted",
    RECEIVE_INVITATION: "acapy_plugin_toolbox.connections." "ReceiveInvitation",
    CONNECTED: "acapy_plugin_toolbox.connections.Connected",
}

EVENT_PATTERN = re.compile(f"acapy::record::{ConnRecord.RECORD_TOPIC}::.*")


async def setup(context: InjectionContext, protocol_registry: ProtocolRegistry = None):
    """Setup the connections plugin."""
    if not protocol_registry:
        protocol_registry = context.inject(ProtocolRegistry)

    protocol_registry.register_message_types(MESSAGE_TYPES)
    event_bus = context.inject(EventBus)
    event_bus.subscribe(EVENT_PATTERN, connections_event_handler)


async def connections_event_handler(profile: Profile, event: Event):
    """Handle connection events.

    Send connected message to admins when connections reach active state.
    """
    record: ConnRecord = ConnRecord.deserialize(event.payload)
    if record.state == ConnRecord.State.RESPONSE:
        responder = profile.inject(BaseResponder)
        async with profile.session() as session:
            await send_to_admins(
                session,
                Connected(**conn_record_to_message_repr(record)),
                responder,
            )


BaseConnectionSchema = Schema.from_dict(
    {
        "label": fields.Str(required=True),
        "my_did": fields.Str(required=True),
        "connection_id": fields.Str(required=True),
        "state": fields.Str(
            validate=validate.OneOf(["pending", "active", "error"]), required=True
        ),
        "their_did": fields.Str(required=False),  # May be missing if pending
        "raw_repr": fields.Dict(required=False),
    }
)


Connection, ConnectionSchema = generate_model_schema(
    name="Connection",
    handler="acapy_plugin_toolbox.util.PassHandler",
    msg_type=CONNECTION,
    schema=BaseConnectionSchema,
)


Connected, ConnectedSchema = generate_model_schema(
    name="Connected",
    handler="acapy_plugin_toolbox.util.PassHandler",
    msg_type=CONNECTED,
    schema=BaseConnectionSchema,
)


def conn_record_to_message_repr(conn: ConnRecord) -> Dict[str, Any]:
    """Map ConnRecord onto Connection."""

    def _state_map(state: str) -> str:
        if state in ("active", "response"):
            return "active"
        if state == "error":
            return "error"
        return "pending"

    return {
        "label": conn.their_label,
        "my_did": conn.my_did,
        "their_did": conn.their_did,
        "state": _state_map(conn.state),
        "connection_id": conn.connection_id,
        "raw_repr": conn.serialize(),
    }


GetList, GetListSchema = generate_model_schema(
    name="GetList",
    handler="acapy_plugin_toolbox.connections.GetListHandler",
    msg_type=GET_LIST,
    schema={
        "my_did": fields.Str(required=False),
        "state": fields.Str(
            validate=validate.OneOf(
                [
                    "pending",
                    "active",
                    "error",
                ]
            ),
            required=False,
        ),
        "their_did": fields.Str(required=False),
    },
)


List, ListSchema = generate_model_schema(
    name="List",
    handler="acapy_plugin_toolbox.util.PassHandler",
    msg_type=LIST,
    schema={
        "connections": fields.List(fields.Nested(BaseConnectionSchema), required=True)
    },
)


class GetListHandler(BaseHandler):
    """Handler for get connection list request."""
    selector = Selector(request_handler_principal_finder)

    @require(lambda p: "admin-connections" in p.privileges)
    async def handle(self, context: RequestContext, responder: BaseResponder):
        """Handle get connection list request."""

        tag_filter = dict(
            filter(
                lambda item: item[1] is not None,
                {
                    "my_did": context.message.my_did,
                    "their_did": context.message.their_did,
                }.items(),
            )
        )
        # Filter out invitations, admin-invitations will handle those
        post_filter_negative = {"state": ConnRecord.State.INVITATION.rfc160}
        # TODO: Filter on state (needs mapping back to ACA-Py connection states)

        records = await self.retrieve_connections_filtered(context)

        results = [
            Connection(**conn_record_to_message_repr(record)) for record in records
        ]
        connection_list = List(connections=results)
        connection_list.assign_thread_from(context.message)
        await responder.send_reply(connection_list)

    @selector.select
    async def retrieve_connections_filtered(self, context: RequestContext):
        """Retrieve connections filtered on principal."""
        return []

    @retrieve_connections_filtered.register(
        lambda p: "created-connections" in p.privileges
    )
    async def created(self, context: RequestContext):
        """Return connections created by this admin connection."""
        async with context.session() as session:
            return await retrieve_connection_by_creator(
                session, context.connection_record.connection_id
            )

    @retrieve_connections_filtered.register(
        lambda p: "all-connections" in p.privileges
    )
    async def all_connections(self, context: RequestContext):
        """Return connections created by this admin connection."""
        async with context.session() as session:
            return await ConnRecord.query(session)


Update, UpdateSchema = generate_model_schema(
    name="Update",
    handler="acapy_plugin_toolbox.connections.UpdateHandler",
    msg_type=UPDATE,
    schema={
        "connection_id": fields.Str(required=True),
        "label": fields.Str(required=False),
    },
)


class UpdateHandler(BaseHandler):
    """Handler for update connection request."""

    @require(lambda p: "admin-connections" in p.privileges)
    async def handle(self, context: RequestContext, responder: BaseResponder):
        """Handle update connection request."""
        session = await context.session()
        try:
            connection = await ConnRecord.retrieve_by_id(
                session, context.message.connection_id
            )
        except StorageNotFoundError:
            report = ProblemReport(
                description={"en": "Connection not found."}, who_retries="none"
            )
            report.assign_thread_from(context.message)
            await responder.send_reply(report)

        new_label = context.message.label or connection.their_label
        connection.their_label = new_label
        await connection.save(session, reason="Update request received.")
        conn_response = Connection(**conn_record_to_message_repr(connection))
        conn_response.assign_thread_from(context.message)
        await responder.send_reply(conn_response)


Delete, DeleteSchema = generate_model_schema(
    name="Delete",
    handler="acapy_plugin_toolbox.connections.DeleteHandler",
    msg_type=DELETE,
    schema={
        "connection_id": fields.Str(required=True),
    },
)

Deleted, DeletedSchema = generate_model_schema(
    name="Deleted",
    handler="acapy_plugin_toolbox.util.PassHandler",
    msg_type=DELETED,
    schema={
        "connection_id": fields.Str(required=True),
    },
)


class DeleteHandler(BaseHandler):
    """Handler for delete connection request."""

    @require(lambda p: "admin-connections" in p.privileges)
    async def handle(self, context: RequestContext, responder: BaseResponder):
        """Handle delete connection request."""
        if context.message.connection_id == context.connection_record.connection_id:

            report = ProblemReport(
                description={"en": "Current connection cannot be deleted."},
                who_retries="none",
            )
            report.assign_thread_from(context.message)
            await responder.send_reply(report)
            return

        session = await context.session()
        try:
            connection = await ConnRecord.retrieve_by_id(
                session, context.message.connection_id
            )
        except StorageNotFoundError:
            report = ProblemReport(
                description={"en": "Connection not found."}, who_retries="none"
            )
            report.assign_thread_from(context.message)
            await responder.send_reply(report)
            return

        await connection.delete_record(session)
        deleted = Deleted(connection_id=connection.connection_id)
        deleted.assign_thread_from(context.message)
        await responder.send_reply(deleted)


ReceiveInvitation, ReceiveInvitationSchema = generate_model_schema(
    name="ReceiveInvitation",
    handler="acapy_plugin_toolbox.connections.ReceiveInvitationHandler",
    msg_type=RECEIVE_INVITATION,
    schema={
        "invitation": fields.Str(required=True),
        "auto_accept": fields.Bool(missing=False),
        "mediation_id": fields.Str(required=False),
    },
)


class ReceiveInvitationHandler(BaseHandler):
    """Handler for receive invitation request."""

    @require(lambda p: "admin-connections" in p.privileges)
    async def handle(self, context: RequestContext, responder: BaseResponder):
        """Handle receive invitation request."""
        session = await context.session()
        connection_mgr = ConnectionManager(session)
        invitation = ConnectionInvitation.from_url(context.message.invitation)
        connection = await connection_mgr.receive_invitation(
            invitation,
            auto_accept=context.message.auto_accept,
            mediation_id=context.message.mediation_id,
        )
        connection_resp = Connection(**conn_record_to_message_repr(connection))
        await responder.send_reply(connection_resp)
        async with context.session() as session:
            conn_record = await ConnRecord.retrieve_by_id(
                session, context.connection_record.connection_id
            )
            await conn_record.metadata_set(
                session, "creator", context.connection_record.connection_id
            )
            print(await conn_record.metadata_get_all(session))
            print(
                await retrieve_connection_by_creator(
                    session, context.connection_record.connection_id
                )
            )


async def retrieve_connection_by_creator(
    session: ProfileSession,
    creator: str,
) -> Sequence[ConnRecord]:
    """Helper method that filters connection records
    based on the creator connection metadata"""
    storage: BaseStorage = session.inject(BaseStorage)
    records: Sequence[StorageRecord] = await storage.find_all_records(
        ConnRecord.RECORD_TYPE_METADATA, {"key": "creator"}
    )
    records = [record for record in records if json.loads(record.value) == creator]
    results = []
    for record in records:
        results.append(
            await ConnRecord.retrieve_by_id(session, record.tags["connection_id"])
        )
    return results
