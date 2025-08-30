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

        ret = self.ndfc_instance.delete_network(network_name,
                vlan, physnet)
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

    def test_create_detach_payload(self):
        vrf_name = 'test_vrf'
        network_name = 'test_network'
        vlan = '100'

        leaf_attachments = {
            'leaf1': {
                'interfaces': ['eth1', 'eth2'],
                'tor_sw_intf_map': {
                    'tor1': {
                        'tor_name': 'tor_switch_1',
                        'tor_interfaces': ['tor_intf1']
                    }
                }
            }
        }
        collated_attach = {
            'leaf1': {
                'interfaces': ['eth1', 'eth2'],
                'tor_sw_intf_map': {
                    'tor1': {
                        'tor_name': 'tor_switch_1',
                        'tor_interfaces': ['tor_intf1']
                    }
                }
            }
        }
        detach_payload = self.ndfc_instance._create_detach_payload(
            leaf_attachments, collated_attach, vrf_name, network_name, vlan)

        expected_payload = [{
            'networkName': network_name,
            'lanAttachList': [
                {
                    'fabric': self.ndfc_instance.fabric,
                    'networkName': network_name,
                    'serialNumber': 'leaf1',
                    'detachSwitchPorts': 'eth1,eth2',
                    'vlan': vlan,
                    'dot1QVlan': ndfc.constants.DOT1Q_VLAN,
                    'switchPorts': 'eth1,eth2',
                    'untagged': 'false',
                    'freeformConfig': '',
                    'deployment': 'true',
                    'extensionValues': '',
                    'instanceValues': '',
                    'torPorts': 'tor_switch_1(tor_intf1)'
                }
            ]
        }]
        self.assertEqual(detach_payload, expected_payload)

    def test_merge_attachments(self):
        existing_attachments = {
            'leaf1': {
                'interfaces': ['eth1'],
                'tor_sw_intf_map': {
                    'SN_tor_switch_1': {
                        'tor_name': 'tor_switch_1',
                        'tor_interfaces': ['tor_intf1']
                    }
                }
            },
            'leaf2': {
                'interfaces': ['eth3']
            }
        }
        new_attachments = {
            'leaf1': {
                'interfaces': ['eth2'],
                'tor_sw_intf_map': {
                    'SN_tor_switch_1': {
                        'tor_name': 'tor_switch_1',
                        'tor_interfaces': ['tor_intf2']
                    }
                }
            },
            'leaf3': {
                'interfaces': ['eth4'],
                'tor_sw_intf_map': {
                    'SN_tor_switch_2': {
                        'tor_name': 'tor_switch_2',
                        'tor_interfaces': ['tor_intf3']
                    }
                }
            }
        }
        merged_attachments = self.ndfc_instance._merge_attachments(
            existing_attachments, new_attachments)

        expected_attachments = {
            'leaf1': {
                'interfaces': ['eth1', 'eth2'],
                'tor_sw_intf_map': {
                    'SN_tor_switch_1': {
                        'tor_name': 'tor_switch_1',
                        'tor_interfaces': ['tor_intf1', 'tor_intf2']
                    }
                }
            },
            'leaf3': {
                'interfaces': ['eth4'],
                'tor_sw_intf_map': {
                    'SN_tor_switch_2': {
                        'tor_name': 'tor_switch_2',
                        'tor_interfaces': ['tor_intf3']
                    }
                }
            }
        }
        self.assertEqual(merged_attachments, expected_attachments)

    def test_remove_attachments(self):
        existing_attachments = {
            'leaf1': {
                'interfaces': ['eth1', 'eth2'],
                'tor_sw_intf_map': {
                    'SN_tor_switch_1': {
                        'tor_name': 'tor_switch_1',
                        'tor_interfaces': ['tor_intf1', 'tor_intf2']
                    }
                }
            },
            'leaf2': {
                'interfaces': ['eth3']
            }
        }
        remove_attachments = {
            'leaf1': {
                'interfaces': ['eth2'],
                'tor_sw_intf_map': {
                    'SN_tor_switch_1': {
                        'tor_name': 'tor_switch_1',
                        'tor_interfaces': ['tor_intf2']
                    }
                }
            }
        }
        remaining_attachments = self.ndfc_instance._remove_attachments(
            existing_attachments, remove_attachments)

        expected_attachments = {
            'leaf1': {
                'interfaces': ['eth1'],
                'tor_sw_intf_map': {
                    'SN_tor_switch_1': {
                        'tor_name': 'tor_switch_1',
                        'tor_interfaces': ['tor_intf1']
                    }
                }
            }
        }
        self.assertEqual(remaining_attachments, expected_attachments)

    @mock.patch.object(ndfc_helper.NdfcHelper, 'get_vrf_attachments')
    def test_get_vrf_vlan(self, mock_get_vrf_attachments):
        vrf_name = 'test_vrf'
        mock_get_vrf_attachments.return_value = [
            {
                "lanAttachList": [
                    {"vlanId": "100", "someOtherKey": "value1"},
                    {"vlanId": "101", "someOtherKey": "value2"}
                ]
            }
        ]
        vlan_id = self.ndfc_instance.get_vrf_vlan(vrf_name)
        self.assertEqual(vlan_id, "100")
        mock_get_vrf_attachments.assert_called_with(
            self.ndfc_instance.fabric, vrf_name)
