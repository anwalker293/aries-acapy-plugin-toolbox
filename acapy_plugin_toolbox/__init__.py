"""Shortcut to group all and rexports."""

import os
import logging
from pathlib import Path

from aries_cloudagent.config.injection_context import InjectionContext
from aries_cloudagent.core.plugin_registry import PluginRegistry

from mrgf import (
    setup as mrgf_setup,
    Config,
)

from . import (
    basicmessage,
    connections,
    credential_definitions,
    dids,
    invitations,
    issuer,
    mediator,
    routing,
    schemas,
    static_connections,
    taa,
    trustping,
)
from .holder import v0_1 as holder

MODULES = [
    basicmessage,
    connections,
    credential_definitions,
    dids,
    invitations,
    issuer,
    mediator,
    routing,
    schemas,
    static_connections,
    taa,
    trustping,
    holder,
]

DEFAULT_MRGF_PATH = str(Path(__file__).parent / "default.mrgf.json")
GOVERNANCE_PLUGIN = "mrgf"
LOGGER = logging.getLogger(__name__)


async def setup(context: InjectionContext):
    """Load Toolbox Plugin."""
    log_level = os.environ.get("ACAPY_TOOLBOX_LOG_LEVEL", logging.WARNING)
    logging.getLogger("acapy_plugin_toolbox").setLevel(log_level)
    print("Setting logging level of acapy_plugin_toolbox to", log_level)
    for mod in MODULES:
        await mod.setup(context)

    # Load MRGF
    plugin_registry = context.inject(PluginRegistry)
    assert plugin_registry
    if GOVERNANCE_PLUGIN not in plugin_registry.plugin_names:
        LOGGER.warning(
            "acapy_plugin_toolbox requires a loaded governance framework to operate. "
            "A default governance framework will be loaded."
        )
        await mrgf_setup(context, Config(path=DEFAULT_MRGF_PATH))
        plugin_registry.register_plugin(GOVERNANCE_PLUGIN)
