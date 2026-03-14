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

from neutron_lib.db import api as db_api
from oslo_log import log as logging

from networking_cisco.plugins.ml2.nd_manager import NdManager


LOG = logging.getLogger(__name__)


class NdExtensionManager(object):

    def __init__(self, nd_manager=None):
        self._nd_manager = nd_manager or NdManager()

    @staticmethod
    def _is_session_active(session):
        try:
            return db_api.is_session_active(session)
        except Exception:  # pragma: no cover - defensive
            LOG.exception("NdExtensionManager._is_session_active failed")
            return False

    def extend_address_scope_dict(self, session, base_model, result):
        if not result:
            return
        self._nd_manager.extend_address_scope(session, base_model, result)

    def extend_network_dict(self, session, base_model, result):
        if not result:
            return
        self._nd_manager.extend_network(session, base_model, result)

    def handle_address_scope_create(self, context, body, result):
        self._nd_manager.handle_address_scope_create(context, body, result)

    def delete_vrf_for_address_scope(self, nd_vrf_name):
        self._nd_manager.delete_vrf_for_address_scope(nd_vrf_name)
