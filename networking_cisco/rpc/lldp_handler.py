# Copyright (c) 2024 Cisco Systems Inc.
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

import oslo_messaging

from networking_cisco.backwards_compatibility import db_api
from networking_cisco.rpc import lldp_topology


class LldpTopologyRpcEndpoint(object):
    """Server side handlers for topology notifications

    This implements the neutron RPC handlers for topology
    updates from agents.

    The implementation is currently just a place holder
    for future work.
    """

    target = oslo_messaging.Target(version=lldp_topology.VERSION)

    def __init__(self, callback_context):
        self.cb_ctx = callback_context

    @db_api.retry_if_session_inactive()
    def update_link(self, context, *args, **kwargs):
        context._session = db_api.get_writer_session()
        return self.cb_ctx.update_link(context, *args, **kwargs)

    @db_api.retry_if_session_inactive()
    def delete_link(self, context, *args, **kwargs):
        # Don't take any action on link deletion in order to tolerate
        # situations like fabric upgrade or flapping links. Old links
        # are removed once a specific host is attached somewhere else.
        return
