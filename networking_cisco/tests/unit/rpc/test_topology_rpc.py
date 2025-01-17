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

from unittest import mock

from neutron.tests import base

from networking_cisco.rpc import topo_rpc_handler


class CallbackHandler(topo_rpc_handler.TopologyRpcHandlerMixin):

    def update_link(self, context, *args, **kwargs):
        pass

    def delete_link(self, context, *args, **kwargs):
        pass


class TestTopologyRpcCallback(base.BaseTestCase):

    def setUp(self):
        super(TestTopologyRpcCallback, self).setUp()
        self.callbacks = CallbackHandler()

        self.callbacks._start_rpc_listeners()

    def test_udpate_link(self):
        context = mock.Mock()
        peer = ('host1', 'enp7s0', '80:6a:00:73:41:54', '172.28.9.26',
             'padkrish-9-26', 0, 'Ethernet1/5', 0, 'FLM2616092G')
        self.callbacks._topology_endpoint.update_link(
                context, peer)
