# Copyright 2025 Cisco Systems, Inc.
# All Rights Reserved
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
#

import abc
from unittest import mock

from networking_cisco.ml2_drivers.ndfc import ndfc
from networking_cisco.ml2_drivers.ndfc import ndfc_helper
from networking_cisco.tests.unit.ml2_drivers.ndfc import test_ndfc_mech
from neutron.common import config
from neutron.tests.unit.plugins.ml2 import test_plugin


class TestNDFCBase(abc.ABC):
    def setUp(self):
        config.register_common_config_options()
        super().setUp()


class TestNDFC(TestNDFCBase, test_plugin.Ml2PluginV2TestCase):
    def setUp(self):
        self.ndfc_instance = ndfc.Ndfc(ndfc_ip='192.168.1.1', user='admin',
                pwd='password', fabric='fabric_name')
        self.mock_exist_attach = mock.patch.object(
            ndfc_helper.NdfcHelper, 'get_network_switch_interface_map',
            return_value=None).start()
        super(TestNDFC, self).setUp()

    @mock.patch.object(ndfc_helper.NdfcHelper, 'create_vrf')
    @mock.patch.object(ndfc_helper.NdfcHelper, 'delete_vrf')
    def test_vrf(self, *args):
        vrf_name = 'test_vrf'
        ret = self.ndfc_instance.create_vrf(vrf_name)
        self.assertTrue(ret)

        ret = self.ndfc_instance.delete_vrf(vrf_name)
        self.assertTrue(ret)

    @mock.patch.object(ndfc_helper.NdfcHelper, 'create_network')
    @mock.patch.object(ndfc_helper.NdfcHelper, 'update_network')
    @mock.patch.object(ndfc_helper.NdfcHelper, 'delete_network')
    def test_network(self, *args):
        vrf_name = 'test_vrf'
        network_name = 'test_network'
        vlan = '100'
        physnet = 'physnet1'
        ret = self.ndfc_instance.create_network(vrf_name, network_name,
                vlan, physnet)
        self.assertTrue(ret)

        gw = '10.10.10.0/24'
        ret = self.ndfc_instance.update_network(vrf_name, network_name,
                vlan, gw, physnet)
        self.assertTrue(ret)

    @mock.patch.object(ndfc_helper.NdfcHelper, 'attach_deploy_network')
    @mock.patch.object(ndfc_helper.NdfcHelper,
            'get_network_switch_interface_map')
    def test_network_attach_detach(self, *args):
        vrf_name = 'test_vrf'
        network_name = 'test_network'
        vlan = '100'
        leaf_attachments = test_ndfc_mech.TEST_LEAF_ATTACHMENTS

        ret = self.ndfc_instance.attach_network(vrf_name, network_name,
                vlan, leaf_attachments)
        self.assertTrue(ret)

        ret = self.ndfc_instance.detach_network(vrf_name, network_name,
                vlan, leaf_attachments)
        self.assertTrue(ret)
