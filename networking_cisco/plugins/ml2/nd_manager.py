# Copyright 2026 Cisco Systems, Inc.
# All Rights Reserved.
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

from oslo_log import log as logging

from networking_cisco.ml2_drivers.ndfc import extension_driver as nd_ext
from networking_cisco.ml2_drivers.ndfc.ndfc import get_ndfc_conf


LOG = logging.getLogger(__name__)


class NdManager(object):
    """Coordinator for ND-specific ML2 behavior."""

    def __init__(self):
        self._ext_driver = nd_ext.NdExtensionDriver()
        try:
            self._ext_driver.initialize()
        except Exception:
            LOG.exception("Failed to initialize NdExtensionDriver")

    def handle_address_scope_create(self, context, body, result):
        if not hasattr(self, "_ext_driver"):
            return
        if not hasattr(self._ext_driver, "process_create_address_scope"):
            return
        self._ext_driver.process_create_address_scope(context, body, result)

    def delete_vrf_for_address_scope(self, nd_name):
        if not nd_name:
            return
        try:
            ndfc = get_ndfc_conf()
            deleted = ndfc.delete_vrf(nd_name)
            if not deleted:
                LOG.error(
                    "Failed to delete VRF %s in ND for "
                    "address-scope cleanup", nd_name,
                )
            else:
                LOG.debug(
                    "Deleted VRF %s in ND for address-scope cleanup",
                    nd_name,
                )
        except Exception:
            LOG.exception(
                "Exception while deleting VRF %s in ND for "
                "address-scope cleanup", nd_name,
            )

    def extend_address_scope(self, session, base_model, result):
        if not hasattr(self, "_ext_driver"):
            return
        self._ext_driver.extend_address_scope_dict(session, base_model, result)

    def extend_network(self, session, base_model, result):
        if not hasattr(self, "_ext_driver"):
            return
        if not hasattr(self._ext_driver, "extend_network_dict"):
            return
        self._ext_driver.extend_network_dict(session, base_model, result)
