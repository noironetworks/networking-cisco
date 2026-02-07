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
from oslo_serialization import jsonutils


class TestNDFCBase(abc.ABC):
    def setUp(self):
        config.register_common_config_options()
        super().setUp()


class TestNDFC(TestNDFCBase, test_plugin.Ml2PluginV2TestCase):
    def setUp(self):
        self.mock_ndfc_helper_login = mock.patch.object(
            ndfc_helper.NdfcHelper, 'login').start()
        self.mock_ndfc_helper_logout = mock.patch.object(
            ndfc_helper.NdfcHelper, 'logout').start()

        self.mock_requests_get = mock.patch('requests.get').start()
        self.mock_requests_post = mock.patch('requests.post').start()
        self.mock_requests_delete = mock.patch('requests.delete').start()
        self.mock_requests_put = mock.patch('requests.put').start()

        self.mock_ndfc_helper_login.return_value = (True, "fake_jwt_token")
        self.mock_ndfc_helper_logout.return_value = None
        self.mock_requests_get.return_value = mock.MagicMock(status_code=404)
        self.mock_requests_post.return_value = mock.MagicMock(
            status_code=200, jsonutils=lambda: {'jwttoken': 'fake_jwt_token'})
        self.mock_requests_delete.return_value = mock.MagicMock(
                status_code=200)
        self.mock_requests_put.return_value = mock.MagicMock(status_code=200)

        self.ndfc_instance = ndfc.Ndfc(ndfc_ip='192.168.1.1', user='admin',
                pwd='password', fabric='fabric_name',
                force_old_api=False)
        self.mock_exist_attach = mock.patch.object(
            ndfc_helper.NdfcHelper, 'get_network_switch_interface_map',
            return_value=None).start()
        super(TestNDFC, self).setUp()

    def tearDown(self):
        mock.patch.stopall()
        super(TestNDFC, self).tearDown()

    @mock.patch.object(ndfc_helper.NdfcHelper, 'create_vrf')
    @mock.patch.object(ndfc_helper.NdfcHelper, 'delete_vrf')
    def test_vrf(self, *args):
        vrf_name = 'test_vrf'
        ret = self.ndfc_instance.create_vrf(vrf_name)
        self.assertTrue(ret)

        ret = self.ndfc_instance.delete_vrf(vrf_name)
        self.assertTrue(ret)

    @mock.patch.object(ndfc_helper.NdfcHelper, 'create_vrf')
    @mock.patch.object(ndfc_helper.NdfcHelper, 'delete_vrf')
    def test_vrf_v2(self, *args):
        vrf_name = 'test_vrf'
        self.ndfc_instance.ndfc_obj.nd_new_version = True
        ret = self.ndfc_instance.create_vrf(vrf_name)
        self.assertTrue(ret)

        ret = self.ndfc_instance.delete_vrf(vrf_name)
        self.assertTrue(ret)

    @mock.patch.object(ndfc_helper.NdfcHelper, 'create_network')
    @mock.patch.object(ndfc_helper.NdfcHelper, 'update_network')
    @mock.patch.object(ndfc_helper.NdfcHelper, 'delete_network')
    @mock.patch.object(ndfc_helper.NdfcHelper, '_get_network_info')
    def test_network(self, mock_get_network_info, mock_delete_network,
            mock_update_network, mock_create_network):
        vrf_name = 'test_vrf'
        network_name = 'test_network'
        vlan = '100'
        physnet = 'physnet1'
        payload = {'netName': 'test_network',
                'networkTemplateConfig': jsonutils.dumps(
                    {'gatewayIpAddress': ''})}
        mock_get_network_info.return_value = payload
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

    @mock.patch.object(ndfc_helper.NdfcHelper, 'create_network')
    @mock.patch.object(ndfc_helper.NdfcHelper, 'update_network')
    @mock.patch.object(ndfc_helper.NdfcHelper, 'delete_network')
    @mock.patch.object(ndfc_helper.NdfcHelper, '_get_network_info')
    def test_network_v2(self, mock_get_network_info, mock_delete_network,
            mock_update_network, mock_create_network):
        vrf_name = 'test_vrf'
        network_name = 'test_network'
        vlan = '100'
        physnet = 'physnet1'
        self.ndfc_instance.ndfc_obj.nd_new_version = True
        ret = self.ndfc_instance.create_network(vrf_name, network_name,
                vlan, physnet)
        self.assertTrue(ret)

        payload = {'networkName': 'test_net',
                'l3Data': {}}
        mock_get_network_info.return_value = payload
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

    @mock.patch.object(ndfc_helper.NdfcHelper, 'attach_deploy_network')
    @mock.patch.object(ndfc_helper.NdfcHelper,
            'get_network_switch_interface_map')
    def test_network_attach_detach_v2(self, *args):
        vrf_name = 'test_vrf'
        network_name = 'test_network'
        vlan = '100'
        leaf_attachments = test_ndfc_mech.TEST_LEAF_ATTACHMENTS
        self.ndfc_instance.ndfc_obj.nd_new_version = True

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

    def test_create_attach_payload_with_vpc_peer(self):
        vrf_name = 'test_vrf'
        network_name = 'test_network'
        vlan = '100'

        collated_attach = {
            'leaf1': {
                'interfaces': ['eth1'],
                'peer_serial': 'leaf2'
            }
        }

        legacy_payload = self.ndfc_instance._create_attach_payload(
            collated_attach, vrf_name, network_name, vlan)

        self.assertEqual(len(legacy_payload), 1)
        self.assertEqual(legacy_payload[0]['networkName'], network_name)
        lan_list = legacy_payload[0]['lanAttachList']
        self.assertEqual(len(lan_list), 2)
        snums = {entry['serialNumber'] for entry in lan_list}
        self.assertEqual(snums, {'leaf1', 'leaf2'})
        peer_entries = [e for e in lan_list if e['serialNumber'] == 'leaf2']
        self.assertEqual(len(peer_entries), 1)
        peer_entry = peer_entries[0]
        self.assertIsNone(peer_entry.get('switchPorts'))
        self.assertIsNone(peer_entry.get('torPorts'))

        self.ndfc_instance.ndfc_obj.nd_new_version = True
        v2_payload = self.ndfc_instance._create_attach_payload_v2(
            collated_attach, vrf_name, network_name, vlan)

        attachments = v2_payload['attachments']
        self.assertEqual(len(attachments), 2)
        switch_ids = {a['switchId'] for a in attachments}
        self.assertEqual(switch_ids, {'leaf1', 'leaf2'})
        peer_attachments = [a for a in attachments if a['switchId'] == 'leaf2']
        self.assertEqual(len(peer_attachments), 1)
        self.assertEqual(peer_attachments[0]['interfaces'], [])

    def test_create_detach_payload_with_vpc_peer(self):
        vrf_name = 'test_vrf'
        network_name = 'test_network'
        vlan = '100'

        collated_attach = {
            'leaf1': {
                'interfaces': ['eth1'],
                'peer_serial': 'leaf2'
            }
        }

        leaf_attachments = {
            'leaf1': {
                'interfaces': ['eth1']
            }
        }

        detach_payload = self.ndfc_instance._create_detach_payload(
            leaf_attachments, collated_attach, vrf_name, network_name, vlan)

        self.assertEqual(len(detach_payload), 1)
        self.assertEqual(detach_payload[0]['networkName'], network_name)
        lan_list = detach_payload[0]['lanAttachList']

        self.assertEqual(len(lan_list), 2)
        snums = {entry['serialNumber'] for entry in lan_list}
        self.assertEqual(snums, {'leaf1', 'leaf2'})

        leaf1_entries = [e for e in lan_list if e['serialNumber'] == 'leaf1']
        self.assertEqual(len(leaf1_entries), 1)
        self.assertEqual(leaf1_entries[0]['detachSwitchPorts'], 'eth1')

        peer_entries = [e for e in lan_list if e['serialNumber'] == 'leaf2']
        self.assertEqual(len(peer_entries), 1)
        peer_entry = peer_entries[0]
        self.assertEqual(peer_entry.get('detachSwitchPorts'), '')
        self.assertIsNone(peer_entry.get('switchPorts'))
        self.assertIsNone(peer_entry.get('torPorts'))
        self.assertFalse(peer_entry['deployment'])

    def test_create_detach_payload_with_vpc_peer_v2(self):
        vrf_name = 'test_vrf'
        network_name = 'test_network'
        vlan = '100'

        collated_attach = {
            'leaf1': {
                'interfaces': ['eth1'],
                'peer_serial': 'leaf2'
            }
        }

        leaf_attachments = {
            'leaf1': {
                'interfaces': ['eth1']
            }
        }

        self.ndfc_instance.ndfc_obj.nd_new_version = True
        detach_payload_v2 = self.ndfc_instance._create_detach_payload_v2(
            leaf_attachments, collated_attach, vrf_name, network_name, vlan)

        attachments = detach_payload_v2['attachments']
        self.assertEqual(len(attachments), 2)
        switch_ids = {a['switchId'] for a in attachments}
        self.assertEqual(switch_ids, {'leaf1', 'leaf2'})

        for att in attachments:
            self.assertFalse(att['attach'])
            self.assertEqual(att['interfaces'], [])

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

    @mock.patch.object(ndfc_helper.NdfcHelper, 'get_vrf_attachments')
    def test_get_vrf_vlan_v2(self, mock_get_vrf_attachments):
        vrf_name = 'test_vrf'
        mock_get_vrf_attachments.return_value = {
                "attachments": [
                    {"vlanId": "100", "someOtherKey": "value1"},
                    {"vlanId": "101", "someOtherKey": "value2"}
                ]
        }
        self.ndfc_instance.ndfc_obj.nd_new_version = True
        vlan_id = self.ndfc_instance.get_vrf_vlan(vrf_name)
        self.assertEqual(vlan_id, "100")
        mock_get_vrf_attachments.assert_called_with(
            self.ndfc_instance.fabric, vrf_name)
