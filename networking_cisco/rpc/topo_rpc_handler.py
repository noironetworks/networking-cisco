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

from networking_cisco.rpc import lldp_handler
from networking_cisco.rpc import lldp_topology
from neutron_lib import rpc as n_rpc


class TopologyRpcHandlerMixin(object):

    def _start_rpc_listeners(self):
        conn = n_rpc.Connection()

        # Topology RPC hander.
        self._topology_endpoint = lldp_handler.LldpTopologyRpcEndpoint(self)
        conn.create_consumer(
            lldp_topology.TOPIC_LLDP_TOPOLOGY_SERVICE,
            [self._topology_endpoint],
            fanout=False)

        # Start listeners and return list of servers.
        return conn.consume_in_threads()
