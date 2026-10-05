# Copyright 2026 Cisco Systems, Inc.
# All rights reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

from neutron.api import extensions as old_extensions
from neutron.db import segments_db
from neutron.plugins.ml2 import driver_context

from networking_cisco.ml2_drivers.ndfc import extension_overrides


# Existing dynamic VLANs must not bypass NDFC's initial ND binding level.
if not getattr(driver_context.NetworkContext,
               '_networking_cisco_compat', False):
    _original_network_context_init = driver_context.NetworkContext.__init__

    def _network_context_init(self, plugin, plugin_context, network,
                              original_network=None, segments=None):
        if segments is None:
            segments = segments_db.get_network_segments(
                plugin_context, network['id'])
        _original_network_context_init(
            self, plugin, plugin_context, network,
            original_network=original_network, segments=segments)

    driver_context.NetworkContext.__init__ = _network_context_init
    driver_context.NetworkContext._networking_cisco_compat = True


# Monkeypatch Neutron to allow overriding its own extension
# descriptors. Note that extension descriptor classes cannot be
# monkeypatched directly because they are loaded explicitly by file
# name and then used immediately.
_real_get_extensions_path = old_extensions.get_extensions_path


def get_extensions_path(service_plugins=None):
    path = _real_get_extensions_path(service_plugins)
    return extension_overrides.__path__[0] + ':' + path


old_extensions.get_extensions_path = get_extensions_path
