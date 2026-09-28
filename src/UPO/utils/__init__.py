"""Cross-cutting helpers shared by every UPO subsystem.

NOTE: we deliberately do *not* re-export ``console`` here. ``from .console
import console`` would rebind the package attribute ``UPO.utils.console``
from the submodule to the ``Console`` *instance*, breaking
``import UPO.utils.console as console_mod`` style access. Every consumer
imports ``UPO.utils.console`` directly anyway.
"""

from __future__ import annotations