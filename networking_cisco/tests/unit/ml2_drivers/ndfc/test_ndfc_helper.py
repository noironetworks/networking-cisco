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

from networking_cisco.ml2_drivers.ndfc import ndfc_helper
from neutron.common import config
from neutron.tests.unit.plugins.ml2 import test_plugin


class TestNDFCHelperBase(abc.ABC):
    def setUp(self):
        config.register_common_config_options()
        super().setUp()


class TestNDFCHelper(TestNDFCHelperBase, test_plugin.Ml2PluginV2TestCase):
    def setUp(self):
        self.mock_login = mock.patch.object(ndfc_helper.NdfcHelper,
                'login').start()
        self.mock_logout = mock.patch.object(ndfc_helper.NdfcHelper,
                'logout').start()
        self.mock_requests_get = mock.patch('requests.get').start()
        self.mock_requests_post = mock.patch('requests.post').start()
        self.mock_requests_delete = mock.patch('requests.delete').start()
        self.mock_requests_put = mock.patch('requests.put').start()

        self.mock_login.return_value = (False, "")
        self.mock_logout.return_value = None
        self.mock_requests_get.return_value = mock.MagicMock(
                status_code=404)
        self.mock_requests_post.return_value = mock.MagicMock(
                status_code=404)
        self.mock_requests_delete.return_value = mock.MagicMock(
                status_code=404)
        self.mock_requests_put.return_value = mock.MagicMock(
                status_code=404)

        self.helper = ndfc_helper.NdfcHelper(ip='192.168.1.1',
                user='admin', pwd='password')
        super(TestNDFCHelper, self).setUp()

    def tearDown(self):
        mock.patch.stopall()
        super(TestNDFCHelper, self).tearDown()

    @mock.patch('requests.post')
    def test_create_vrf(self, mock_post):
        mock_response = mock.MagicMock()
        mock_response.status_code = 200
        mock_post.return_value = mock_response

        fabric = 'test_fabric'
        payload = {'name': 'test_vrf'}

        result = self.helper.create_vrf(fabric, payload)
        self.assertTrue(result)

        mock_response.status_code = 400
        mock_post.return_value = mock_response

        result = self.helper.create_vrf(fabric, payload)
        self.assertFalse(result)

    @mock.patch('requests.post')
    def test_create_vrf_v2(self, mock_post):
        mock_response = mock.MagicMock()
        mock_response.status_code = 200
        mock_post.return_value = mock_response

        fabric = 'test_fabric'
        payload = {'name': 'test_vrf'}
        self.helper.nd_new_version = True

        result = self.helper.create_vrf(fabric, payload)
        self.assertTrue(result)

        mock_response.status_code = 400
        mock_post.return_value = mock_response

        result = self.helper.create_vrf(fabric, payload)
        self.assertFalse(result)

    @mock.patch('requests.post')
    @mock.patch('requests.delete')
    def test_delete_vrf(self, mock_post, mock_delete):
        mock_response = mock.MagicMock()
        mock_response.status_code = 200
        mock_post.return_value = mock_response

        fabric = 'test_fabric'
        vrf = 'test_vrf'

        result = self.helper.delete_vrf(fabric, vrf)
        self.assertTrue(result)

        mock_response.status_code = 400
        mock_post.return_value = mock_response

        result = self.helper.delete_vrf(fabric, vrf)
        self.assertFalse(result)

    @mock.patch('requests.post')
    @mock.patch('requests.delete')
    def test_delete_vrf_v2(self, mock_post, mock_delete):
        mock_response = mock.MagicMock()
        mock_response.status_code = 200
        mock_post.return_value = mock_response

        fabric = 'test_fabric'
        vrf = 'test_vrf'
        self.helper.nd_new_version = True

        result = self.helper.delete_vrf(fabric, vrf)
        self.assertTrue(result)

        mock_response.status_code = 400
        mock_post.return_value = mock_response

        result = self.helper.delete_vrf(fabric, vrf)
        self.assertFalse(result)

    @mock.patch('requests.post')
    def test_create_network(self, mock_post):
        mock_create_response = mock.MagicMock()
        mock_create_response.status_code = 200
        mock_post.return_value = mock_create_response

        fabric = 'test_fabric'
        payload = {'name': 'test_network'}

        result = self.helper.create_network(fabric, payload)
        self.assertTrue(result)

        mock_create_response.status_code = 400
        mock_post.return_value = mock_create_response

        result = self.helper.create_network(fabric, payload)
        self.assertFalse(result)

    @mock.patch('requests.post')
    def test_create_network_v2(self, mock_post):
        mock_create_response = mock.MagicMock()
        mock_create_response.status_code = 200
        mock_post.return_value = mock_create_response

        fabric = 'test_fabric'
        payload = {'name': 'test_network'}
        self.helper.nd_new_version = True

        result = self.helper.create_network(fabric, payload)
        self.assertTrue(result)

        mock_create_response.status_code = 400
        mock_post.return_value = mock_create_response

        result = self.helper.create_network(fabric, payload)
        self.assertFalse(result)

    @mock.patch('requests.post')
    @mock.patch('requests.put')
    def test_update_network(self, mock_post, mock_put):
        mock_response = mock.MagicMock()
        mock_response.status_code = 200
        mock_post.return_value = mock_response

        fabric = 'test_fabric'
        network_name = 'test_network'
        payload = {'name': 'test_network'}

        result = self.helper.update_network(fabric, network_name, payload)
        self.assertTrue(result)

        mock_response.status_code = 400
        mock_post.return_value = mock_response

        result = self.helper.update_network(fabric, network_name, payload)
        self.assertFalse(result)

    @mock.patch('requests.post')
    @mock.patch('requests.put')
    def test_update_network_v2(self, mock_post, mock_put):
        mock_response = mock.MagicMock()
        mock_response.status_code = 200
        mock_post.return_value = mock_response

        fabric = 'test_fabric'
        network_name = 'test_network'
        payload = {'name': 'test_network'}
        self.helper.nd_new_version = True

        result = self.helper.update_network(fabric, network_name, payload)
        self.assertTrue(result)

        mock_response.status_code = 400
        mock_post.return_value = mock_response

        result = self.helper.update_network(fabric, network_name, payload)
        self.assertFalse(result)

    @mock.patch('requests.post')
    @mock.patch('requests.put')
    def test_update_deploy_network(self, mock_post, mock_put):
        mock_login_response = mock.MagicMock()
        mock_login_response.status_code = 200
        mock_login_response.json.return_value = {'jwttoken': 'fake_token'}

        mock_deploy_response = mock.MagicMock()
        mock_deploy_response.status_code = 200

        mock_post.side_effect = [mock_login_response, mock_deploy_response]

        mock_response = mock.MagicMock()
        mock_response.status_code = 200
        mock_put.return_value = mock_response

        fabric = 'test_fabric'
        network_name = 'test_network'
        update_payload = {'name': 'updated_network'}
        deploy_payload = {'config': 'deploy_config'}

        result = self.helper.update_deploy_network(fabric, network_name,
                update_payload, deploy_payload)
        self.assertTrue(result)

        mock_response.status_code = 400
        mock_put.return_value = mock_response

        result = self.helper.update_deploy_network(fabric, network_name,
                update_payload, deploy_payload)
        self.assertFalse(result)

    @mock.patch('requests.post')
    @mock.patch('requests.put')
    def test_update_deploy_network_v2(self, mock_post, mock_put):
        mock_login_response = mock.MagicMock()
        mock_login_response.status_code = 200
        mock_login_response.json.return_value = {'jwttoken': 'fake_token'}

        mock_deploy_response = mock.MagicMock()
        mock_deploy_response.status_code = 200

        mock_post.side_effect = [mock_login_response, mock_deploy_response]

        mock_response = mock.MagicMock()
        mock_response.status_code = 200
        mock_put.return_value = mock_response

        fabric = 'test_fabric'
        network_name = 'test_network'
        update_payload = {'name': 'updated_network'}
        deploy_payload = {'config': 'deploy_config'}
        self.helper.nd_new_version = True

        result = self.helper.update_deploy_network(fabric, network_name,
                update_payload, deploy_payload)
        self.assertTrue(result)

        mock_response.status_code = 400
        mock_put.return_value = mock_response

        result = self.helper.update_deploy_network(fabric, network_name,
                update_payload, deploy_payload)
        self.assertFalse(result)

    @mock.patch('requests.post')
    @mock.patch('requests.put')
    def test_attach_deploy_network(self, mock_post, mock_put):
        mock_login_response = mock.MagicMock()
        mock_login_response.status_code = 200
        mock_login_response.json.return_value = {'jwttoken': 'fake_token'}

        mock_deploy_response = mock.MagicMock()
        mock_deploy_response.status_code = 200

        mock_post.side_effect = [mock_login_response, mock_deploy_response]

        mock_response = mock.MagicMock()
        mock_response.status_code = 200
        mock_put.return_value = mock_response

        fabric = 'test_fabric'
        attach_payload = {'network': 'test_network'}
        deploy_payload = {'config': 'deploy_config'}

        result = self.helper.attach_deploy_network(fabric,
                attach_payload, deploy_payload)
        self.assertTrue(result)

        mock_response.status_code = 400
        mock_put.return_value = mock_response

        result = self.helper.attach_deploy_network(fabric,
                attach_payload, deploy_payload)
        self.assertFalse(result)

    @mock.patch('requests.post')
    @mock.patch('requests.put')
    def test_attach_deploy_network_v2(self, mock_post, mock_put):
        mock_login_response = mock.MagicMock()
        mock_login_response.status_code = 200
        mock_login_response.json.return_value = {'jwttoken': 'fake_token'}

        mock_deploy_response = mock.MagicMock()
        mock_deploy_response.status_code = 200

        mock_post.side_effect = [mock_login_response, mock_deploy_response]

        mock_response = mock.MagicMock()
        mock_response.status_code = 200
        mock_put.return_value = mock_response

        fabric = 'test_fabric'
        attach_payload = {'network': 'test_network'}
        deploy_payload = {'config': 'deploy_config'}
        self.helper.nd_new_version = True

        result = self.helper.attach_deploy_network(fabric,
                attach_payload, deploy_payload)
        self.assertTrue(result)

        mock_response.status_code = 400
        mock_put.return_value = mock_response

        result = self.helper.attach_deploy_network(fabric,
                attach_payload, deploy_payload)
        self.assertFalse(result)

    @mock.patch('requests.post')
    @mock.patch('requests.delete')
    def test_delete_network(self, mock_post, mock_delete):
        mock_response = mock.MagicMock()
        mock_response.status_code = 200
        mock_post.return_value = mock_response

        fabric = 'test_fabric'
        network = 'test_network'

        result = self.helper.delete_network(fabric, network)
        self.assertTrue(result)

        mock_response.status_code = 400
        mock_post.return_value = mock_response

        result = self.helper.delete_network(fabric, network)
        self.assertFalse(result)

    @mock.patch('requests.post')
    @mock.patch('requests.delete')
    def test_delete_network_v2(self, mock_post, mock_delete):
        mock_response = mock.MagicMock()
        mock_response.status_code = 200
        mock_post.return_value = mock_response

        fabric = 'test_fabric'
        network = 'test_network'
        self.helper.nd_new_version = True

        result = self.helper.delete_network(fabric, network)
        self.assertTrue(result)

        mock_response.status_code = 400
        mock_post.return_value = mock_response

        result = self.helper.delete_network(fabric, network)
        self.assertFalse(result)

    @mock.patch('requests.post')
    def test_config_deploy_save(self, mock_post):
        mock_response = mock.MagicMock()
        mock_response.status_code = 200
        mock_post.return_value = mock_response

        fabric = 'test_fabric'
        deploy_payload = {'config': 'deploy_config'}

        result = self.helper._config_deploy_save(fabric, deploy_payload)
        self.assertTrue(result)

        mock_response.status_code = 400
        mock_post.return_value = mock_response

        result = self.helper._config_deploy_save(fabric, deploy_payload)
        self.assertFalse(result)

    @mock.patch('requests.post')
    def test_config_deploy_save_v2(self, mock_post):
        mock_response = mock.MagicMock()
        mock_response.status_code = 200
        mock_post.return_value = mock_response

        fabric = 'test_fabric'
        deploy_payload = {'config': 'deploy_config'}
        self.helper.nd_new_version = True

        result = self.helper._config_deploy_save(fabric, deploy_payload)
        self.assertTrue(result)

        mock_response.status_code = 400
        mock_post.return_value = mock_response

        result = self.helper._config_deploy_save(fabric, deploy_payload)
        self.assertFalse(result)

    @mock.patch('requests.get')
    @mock.patch('requests.post')
    def test_get_network_switch_interface_map(self, mock_post, mock_get):
        mock_get_response = mock.MagicMock()
        mock_get_response.status_code = 200
        mock_get_response.json.return_value = [
            {
                'lanAttachList': [
                    {
                        'switchSerialNo': 'SN123',
                        'portNames': 'Ethernet1/1,Ethernet1/2',
                        'switchRole': 'leaf',
                        'switchName': 'Switch1'
                    }
                ]
            }
        ]
        mock_get.return_value = mock_get_response

        fabric = 'test_fabric'
        network = 'test_network'

        result = self.helper.get_network_switch_interface_map(fabric, network)

        expected_result = {
            'SN123': {
                'interfaces': ['Ethernet1/1', 'Ethernet1/2'],
                'switch_name': 'Switch1'
            }
        }
        self.assertEqual(result, expected_result)

    @mock.patch.object(ndfc_helper.NdfcHelper, '_get_attachments')
    @mock.patch('requests.post')
    def test_get_network_switch_interface_map_v2(
            self, mock_post, mock_get_attachments):
        mock_get_attachments.return_value = {
            "attachments": [
                {
                    "attach": True,
                    "switchRole": "leaf",
                    "switchId": "SN123",
                    "switchName": "Leaf1",
                    "networkName": "NetworkA",
                    "interfaces": [
                        {
                            "interfaceRange": "Ethernet1/1",
                            "dot1qVlan": "true",
                            "encapVlan": "100",
                            "innerVlan": 100,
                            "nativeVlan": False
                        }
                    ]
                }
            ]
        }

        fabric = 'test_fabric'
        network = 'test_network'
        self.helper.nd_new_version = True

        result = self.helper.get_network_switch_interface_map(fabric, network)

        expected_result = {
            'SN123': {
                'switch_name': 'Leaf1',
                'interfaces': ['Ethernet1/1']
            }
        }
        self.assertEqual(result, expected_result)

    def test_parse_tor_interface_map_valid(self):
        portnames = "SN1(Ethernet1/1) SN2(Ethernet1/2) SN3(Port-channel1)"
        expected_result = {
            "SN_SN1": {
                "tor_interfaces": ["Ethernet1/1"],
                "tor_name": "SN1"
            },
            "SN_SN2": {
                "tor_interfaces": ["Ethernet1/2"],
                "tor_name": "SN2"
            },
            "SN_SN3": {
                "tor_interfaces": ["Port-channel1"],
                "tor_name": "SN3"
            }
        }
        result = self.helper._parse_tor_interface_map(portnames)
        self.assertEqual(result, expected_result)

    def test_parse_tor_interface_map_invalid_format(self):
        portnames = "InvalidFormat"
        result = self.helper._parse_tor_interface_map(portnames)
        self.assertEqual(result, {})

    def test_parse_tor_interface_map_empty(self):
        portnames = ""
        result = self.helper._parse_tor_interface_map(portnames)
        self.assertEqual(result, {})

    @mock.patch('requests.get')
    @mock.patch('requests.post')
    def test_get_network_switch_map(self, mock_post, mock_get):
        mock_get_response = mock.MagicMock()
        mock_get_response.status_code = 200
        mock_get_response.json.return_value = [
            {
                'lanAttachList': [
                    {
                        'switchSerialNo': 'SN123',
                        'portNames': 'Ethernet1/1',
                        'switchRole': 'leaf',
                        'networkName': 'Network1',
                        'peerSerialNo': ''
                    },
                    {
                        'switchSerialNo': 'SN124',
                        'portNames': 'Ethernet1/2',
                        'switchRole': 'leaf',
                        'networkName': 'Network1',
                        'peerSerialNo': 'SN125'
                    }
                ]
            }
        ]
        mock_get.return_value = mock_get_response

        fabric = 'test_fabric'
        network = 'test_network'

        result = self.helper.get_network_switch_map(fabric, network)

        expected_result = {
            'SN123': 'Network1',
            'SN124': 'Network1',
            'SN125': 'Network1'
        }
        self.assertEqual(result, expected_result)

    @mock.patch.object(ndfc_helper.NdfcHelper, '_get_attachments')
    @mock.patch('requests.post')
    def test_get_network_switch_map_v2(self, mock_post,
            mock_get_attachments):
        mock_get_attachments.return_value = {
            "attachments": [
                {
                    "attached": True,
                    "switchRole": "leaf",
                    "switchId": "SN123",
                    "networkName": "Network1",
                    "peerSwitchId": ""
                },
                {
                    "attached": True,
                    "switchRole": "leaf",
                    "switchId": "SN124",
                    "networkName": "Network1",
                    "peerSwitchId": "SN125"
                }
            ]
        }

        fabric = 'test_fabric'
        network = 'test_network'
        self.helper.nd_new_version = True

        result = self.helper.get_network_switch_map(fabric, network)

        expected_result = {
            'SN123': 'Network1',
            'SN124': 'Network1',
            'SN125': 'Network1'
        }
        self.assertEqual(result, expected_result)

    @mock.patch.object(ndfc_helper.NdfcHelper, 'login', return_value=True)
    @mock.patch.object(ndfc_helper.NdfcHelper, '_get_vrf_attachments')
    @mock.patch.object(ndfc_helper.NdfcHelper, 'logout')
    def test_get_vrf_attachments_success(self, mock_logout,
            mock_get_vrf_attachments, mock_login):
        mock_get_vrf_attachments.return_value = {'vrf': 'vrf_attachments'}
        fabric = 'test_fabric'
        vrf = 'test_vrf'

        result = self.helper.get_vrf_attachments(fabric, vrf)

        expected_result = {'vrf': 'vrf_attachments'}
        self.assertEqual(result, expected_result)
        mock_login.assert_called_once()
        mock_get_vrf_attachments.assert_called_once_with(fabric, vrf)
        mock_logout.assert_called_once()

    @mock.patch.object(ndfc_helper.NdfcHelper, 'login', return_value=True)
    @mock.patch.object(ndfc_helper.NdfcHelper, '_get_vrf_attachments')
    @mock.patch.object(ndfc_helper.NdfcHelper, 'logout')
    def test_get_vrf_attachments_v2(self, mock_logout,
            mock_get_vrf_attachments, mock_login):
        mock_get_vrf_attachments.return_value = {'vrf': 'vrf_attachments'}
        fabric = 'test_fabric'
        vrf = 'test_vrf'
        self.helper.nd_new_version = True

        result = self.helper.get_vrf_attachments(fabric, vrf)

        expected_result = {'vrf': 'vrf_attachments'}
        self.assertEqual(result, expected_result)
        mock_login.assert_called_once()
        mock_get_vrf_attachments.assert_called_once_with(fabric, vrf)
        mock_logout.assert_called_once()

    @mock.patch.object(ndfc_helper.NdfcHelper, 'login', return_value=True)
    @mock.patch.object(ndfc_helper.NdfcHelper, '_get_vrf_attachments')
    @mock.patch.object(ndfc_helper.NdfcHelper, 'logout')
    def test_get_vrf_attachments_failure(self, mock_logout,
            mock_get_vrf_attachments, mock_login):
        mock_get_vrf_attachments.return_value = None

        fabric = 'test_fabric'
        vrf = 'test_vrf'

        result = self.helper.get_vrf_attachments(fabric, vrf)

        self.assertIsNone(result)
        mock_login.assert_called_once()
        mock_get_vrf_attachments.assert_called_once_with(fabric, vrf)
        mock_logout.assert_called_once()

    @mock.patch.object(ndfc_helper.NdfcHelper, 'login', return_value=True)
    @mock.patch.object(ndfc_helper.NdfcHelper, '_get_network_info')
    @mock.patch.object(ndfc_helper.NdfcHelper, 'logout')
    def test_get_network_info_success(self, mock_logout,
            mock_get_network_info, mock_login):
        mock_get_network_info.return_value = {'network': 'info'}
        fabric = 'test_fabric'
        network = 'test_network'

        result = self.helper.get_network_info(fabric, network)

        expected_result = {'network': 'info'}
        self.assertEqual(result, expected_result)
        mock_login.assert_called_once()
        mock_get_network_info.assert_called_once_with(fabric, network)
        mock_logout.assert_called_once()

    @mock.patch.object(ndfc_helper.NdfcHelper, 'login', return_value=True)
    @mock.patch.object(ndfc_helper.NdfcHelper, '_get_network_info')
    @mock.patch.object(ndfc_helper.NdfcHelper, 'logout')
    def test_get_network_info_failure(self, mock_logout,
            mock_get_network_info, mock_login):
        mock_get_network_info.return_value = None

        fabric = 'test_fabric'
        network = 'test_network'

        result = self.helper.get_network_info(fabric, network)

        self.assertIsNone(result)
        mock_login.assert_called_once()
        mock_get_network_info.assert_called_once_with(fabric, network)
        mock_logout.assert_called_once()

    @mock.patch.object(ndfc_helper.NdfcHelper, 'login', return_value=True)
    @mock.patch.object(ndfc_helper.NdfcHelper, '_get_network_info')
    @mock.patch.object(ndfc_helper.NdfcHelper, 'logout')
    def test_get_network_info_v2(self, mock_logout,
            mock_get_network_info, mock_login):
        mock_get_network_info.return_value = {'network': 'info'}
        fabric = 'test_fabric'
        network = 'test_network'
        self.helper.nd_new_version = True

        result = self.helper.get_network_info(fabric, network)

        expected_result = {'network': 'info'}
        self.assertEqual(result, expected_result)
        mock_login.assert_called_once()
        mock_get_network_info.assert_called_once_with(fabric, network)
        mock_logout.assert_called_once()

    @mock.patch('requests.get')
    @mock.patch('requests.post')
    def test_get_switches(self, mock_post, mock_get):
        mock_get_response = mock.MagicMock()
        mock_get_response.status_code = 200
        mock_get_response.json.return_value = [
            {
                'serialNumber': 'SN123',
                'ipAddress': '192.168.1.10',
                'switchRole': 'leaf',
                'logicalName': 'Switch1'
            },
            {
                'serialNumber': 'SN124',
                'ipAddress': '192.168.1.11',
                'switchRole': 'leaf',
                'logicalName': 'Switch2'
            }
        ]
        mock_get.return_value = mock_get_response

        fabric = 'test_fabric'

        result = self.helper.get_switches(fabric)

        expected_result = {
            '192.168.1.10': {
                'serial': 'SN123',
                'ip': '192.168.1.10',
                'role': 'leaf',
                'name': 'Switch1'
            },
            '192.168.1.11': {
                'serial': 'SN124',
                'ip': '192.168.1.11',
                'role': 'leaf',
                'name': 'Switch2'
            }
        }
        self.assertEqual(result, expected_result)

    @mock.patch('requests.get')
    @mock.patch('requests.post')
    def test_get_switches_v2(self, mock_post, mock_get):
        mock_get_response = mock.MagicMock()
        mock_get_response.status_code = 200
        mock_get_response.json.return_value = {
            'switches': [
                {
                    'serialNumber': 'SN123',
                    'fabricManagementIp': '192.168.1.10',
                    'switchRole': 'leaf',
                    'hostname': 'Switch1'
                },
                {
                    'serialNumber': 'SN124',
                    'fabricManagementIp': '192.168.1.11',
                    'switchRole': 'leaf',
                    'hostname': 'Switch2'
                }
            ]
        }
        mock_get.return_value = mock_get_response

        fabric = 'test_fabric'
        self.helper.nd_new_version = True

        result = self.helper.get_switches(fabric)

        expected_result = {
            '192.168.1.10': {
                'serial': 'SN123',
                'ip': '192.168.1.10',
                'role': 'leaf',
                'name': 'Switch1'
            },
            '192.168.1.11': {
                'serial': 'SN124',
                'ip': '192.168.1.11',
                'role': 'leaf',
                'name': 'Switch2'
            }
        }
        self.assertEqual(result, expected_result)

    @mock.patch('requests.get')
    @mock.patch('requests.post')
    def test_get_switches_previous_swlist(self, mock_post, mock_get):
        mock_get_response = mock.MagicMock()
        mock_get_response.status_code = 200
        mock_get_response.json.return_value = []
        mock_get.return_value = mock_get_response

        fabric = 'test_fabric'
        previous_switch_list = [
            {
                'serialNumber': 'SN999',
                'ipAddress': '10.0.0.1',
                'switchRole': 'spine',
                'logicalName': 'OldSwitch'
            }
        ]

        # Call get_switches with previous_switch_list
        result = self.helper.get_switches(fabric, previous_switch_list)

        # Result should be the previous_switch_list since _get_switches failed
        self.assertEqual(result, previous_switch_list)

    @mock.patch('requests.get')
    @mock.patch('requests.post')
    def test_get_switches_previous_swlist_v2(self, mock_post, mock_get):
        mock_get_response = mock.MagicMock()
        mock_get_response.status_code = 200
        mock_get_response.json.return_value = []
        mock_get.return_value = mock_get_response

        fabric = 'test_fabric'
        self.helper.nd_new_version = True
        previous_switch_list = {
            '10.0.0.1': {
                'serial': 'SN999',
                'ip': '10.0.0.1',
                'role': 'spine',
                'name': 'OldSwitch'
            }
        }

        # Call get_switches with previous_switch_list
        result = self.helper.get_switches(fabric, previous_switch_list)

        # Result should be the previous_switch_list since _get_switches failed
        self.assertEqual(result, previous_switch_list)

    @mock.patch.object(ndfc_helper.NdfcHelper, 'login', return_value=True)
    @mock.patch.object(ndfc_helper.NdfcHelper, 'logout')
    @mock.patch('requests.get')
    def test_get_switches_role_tor(self, mock_get, mock_logout, mock_login):
        mock_inventory_response = mock.MagicMock()
        mock_inventory_response.status_code = 200
        mock_inventory_response.json.return_value = [
            {
                'serialNumber': 'SN123',
                'ipAddress': '192.168.1.10',
                'switchRole': 'tor',
                'logicalName': 'Switch1'
            }
        ]
        mock_topology_response = mock.MagicMock()
        mock_topology_response.status_code = 200
        mock_topology_response.json.return_value = {
            'nodeList': [
                {'data': {'logicalName': 'Leaf1',
                    'switchRole': 'leaf',
                    'serialNumber': 'SN124'}},
                {'data': {'logicalName': 'Switch1',
                    'switchRole': 'tor',
                    'serialNumber': 'SN123'}}
            ],
            'edgeList': [
                {'data': {'fromSwitch': 'Switch1',
                    'toSwitch': 'Leaf1',
                    'fromInterface': 'Eth1',
                    'toInterface': 'Eth2'}}
            ]
        }
        mock_get.side_effect = [mock_inventory_response,
                mock_topology_response]

        fabric = 'test_fabric'

        result = self.helper.get_switches(fabric)

        expected_result = {
            '192.168.1.10': {
                'serial': 'SN123',
                'ip': '192.168.1.10',
                'role': 'tor',
                'name': 'Switch1',
                'tor_leaf_nodes': {'Leaf1': 'SN124'},
                'tor_leaf_intf': {'Leaf1': 'Eth2'}
            }
        }
        self.assertEqual(result, expected_result)
        mock_login.assert_called_once()
        mock_logout.assert_called_once()

    @mock.patch.object(ndfc_helper.NdfcHelper, 'login', return_value=True)
    @mock.patch.object(ndfc_helper.NdfcHelper, 'logout')
    @mock.patch('requests.get')
    def test_get_switches_role_tor_v2(self, mock_get,
            mock_logout, mock_login):
        mock_inventory_response = mock.MagicMock()
        mock_inventory_response.status_code = 200
        mock_inventory_response.json.return_value = {
            'switches': [
                {
                    'serialNumber': 'SN123',
                    'fabricManagementIp': '192.168.1.10',
                    'switchRole': 'tor',
                    'hostname': 'Switch1'
                }
            ]
        }
        mock_topology_response = mock.MagicMock()
        mock_topology_response.status_code = 200
        mock_topology_response.json.return_value = {
            'nodeList': [
                {'data': {'logicalName': 'Leaf1',
                    'switchRole': 'leaf',
                    'serialNumber': 'SN124'}},
                {'data': {'logicalName': 'Switch1',
                    'switchRole': 'tor',
                    'serialNumber': 'SN123'}}
            ],
            'edgeList': [
                {'data': {'fromSwitch': 'Switch1',
                    'toSwitch': 'Leaf1',
                    'fromInterface': 'Eth1',
                    'toInterface': 'Eth2'}}
            ]
        }
        mock_get.side_effect = [mock_inventory_response,
                mock_topology_response]

        fabric = 'test_fabric'
        self.helper.nd_new_version = True

        result = self.helper.get_switches(fabric)

        expected_result = {
            '192.168.1.10': {
                'serial': 'SN123',
                'ip': '192.168.1.10',
                'role': 'tor',
                'name': 'Switch1',
                'tor_leaf_nodes': {'Leaf1': 'SN124'},
                'tor_leaf_intf': {'Leaf1': 'Eth2'}
            }
        }
        self.assertEqual(result, expected_result)
        mock_login.assert_called_once()
        mock_logout.assert_called_once()

    @mock.patch('requests.get')
    @mock.patch('requests.post')
    def test_get_po(self, mock_post, mock_get):
        mock_get_response = mock.MagicMock()
        mock_get_response.status_code = 200
        mock_get_response.json.return_value = [
            {
                'ifName': 'Ethernet1/1',
                'ifType': 'INTERFACE_ETHERNET',
                'channelIdStr': '10'
            }
        ]
        mock_get.return_value = mock_get_response

        fabric = 'test_fabric'
        snum = 'SN123'
        ifname = 'Ethernet1/1'

        result = self.helper.get_po(fabric, snum, ifname)

        expected_result = '10'
        self.assertEqual(result, expected_result)

    @mock.patch('requests.get')
    @mock.patch('requests.post')
    def test_get_po_v2(self, mock_post, mock_get):
        mock_get_response = mock.MagicMock()
        mock_get_response.status_code = 200
        mock_get_response.json.return_value = {
            'interfaces': [
                {
                    'interfaceName': 'Ethernet1/1',
                    'interfaceType': 'ethernet',
                    'channelId': 10
                }
            ]
        }
        mock_get.return_value = mock_get_response

        fabric = 'test_fabric'
        snum = 'SN123'
        ifname = 'Ethernet1/1'
        self.helper.nd_new_version = True

        result = self.helper.get_po(fabric, snum, ifname)

        expected_result = '10'
        self.assertEqual(result, expected_result)

    @mock.patch('requests.get')
    @mock.patch('requests.post')
    def test_get_po_channelidstr_null(self, mock_post, mock_get):
        mock_get_response = mock.MagicMock()
        mock_get_response.status_code = 200
        mock_get_response.json.return_value = [
            {
                'ifName': 'Ethernet1/10',
                'ifType': 'INTERFACE_ETHERNET',
                'channelIdStr': None,
            }
        ]
        mock_get.return_value = mock_get_response

        fabric = 'kkf5'
        snum = 'FDO23390CUU'
        ifname = 'Ethernet1/10'

        result = self.helper.get_po(fabric, snum, ifname)

        expected_result = ''
        self.assertEqual(result, expected_result)

    @mock.patch('requests.get')
    @mock.patch('requests.post')
    def test_get_po_v2_channelid_absent(self, mock_post, mock_get):
        mock_get_response = mock.MagicMock()
        mock_get_response.status_code = 200
        mock_get_response.json.return_value = {
            'interfaces': [
                {
                    'interfaceName': 'Ethernet1/10',
                    'interfaceType': 'ethernet',
                    # intentionally no 'channelId' field
                }
            ]
        }
        mock_get.return_value = mock_get_response

        fabric = 'kkf5'
        snum = 'FDO23390CUU'
        ifname = 'Ethernet1/10'
        self.helper.nd_new_version = True

        result = self.helper.get_po(fabric, snum, ifname)

        expected_result = ''
        self.assertEqual(result, expected_result)

    @mock.patch('requests.post')
    def test_attach_network_fail_on_200_with_fail_message_in_body(self,
                                                                  mock_post):
        """
        Test that _attach_network returns False if status is 200 OK but
        the response body contains a 'fail' keyword.
        """
        mock_response = mock.MagicMock()
        mock_response.status_code = 200
        mock_response.reason = 'OK'
        mock_response.json.return_value = {
            'status': 'Operation Failed: Invalid parameters provided.'
        }

        mock_post.return_value = mock_response

        result = self.helper._attach_network('fabric-test',
                                             {'some': 'payload'})

        self.assertFalse(result)

    @mock.patch.object(ndfc_helper.NdfcHelper, '_get_vpc_pair')
    @mock.patch.object(ndfc_helper.NdfcHelper, 'login', return_value=True)
    @mock.patch.object(ndfc_helper.NdfcHelper, 'logout')
    def test_get_vpc_peer_success(self, mock_logout, mock_login,
            mock_get_vpc_pair):
        fabric = 'test_fabric'
        switch_id = 'SN123'
        mock_get_vpc_pair.return_value = {'peerSwitchId': 'SN456'}

        peer_serial = self.helper.get_vpc_peer(fabric, switch_id)

        self.assertEqual('SN456', peer_serial)
        mock_login.assert_called_once()
        mock_get_vpc_pair.assert_called_once_with(fabric, switch_id)
        mock_logout.assert_called_once()

    @mock.patch.object(ndfc_helper.NdfcHelper, '_get_vpc_pair')
    @mock.patch.object(ndfc_helper.NdfcHelper, 'login', return_value=True)
    @mock.patch.object(ndfc_helper.NdfcHelper, 'logout')
    def test_get_vpc_peer_no_peer(self, mock_logout, mock_login,
            mock_get_vpc_pair):
        fabric = 'test_fabric'
        switch_id = 'SN123'
        mock_get_vpc_pair.return_value = None

        peer_serial = self.helper.get_vpc_peer(fabric, switch_id)

        self.assertIsNone(peer_serial)
        mock_login.assert_called_once()
        mock_get_vpc_pair.assert_called_once_with(fabric, switch_id)
        mock_logout.assert_called_once()

    @mock.patch('requests.get')
    def test_get_vpc_pair_v2_collection(self, mock_get):
        fabric = 'test_fabric'
        switch_id = 'FDO23390CUN'
        self.helper.nd_new_version = True

        mock_response = mock.MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            'vpcPairs': [
                {
                    'peer1SwitchId': 'FDO23390CUN',
                    'peer2SwitchId': 'FDO23390CUU'
                },
                {
                    'peer1SwitchId': 'OTHER1',
                    'peer2SwitchId': 'OTHER2'
                }
            ]
        }
        mock_get.return_value = mock_response

        result = self.helper._get_vpc_pair(fabric, switch_id)
        self.assertEqual({'peerSwitchId': 'FDO23390CUU'}, result)

    @mock.patch('requests.get')
    def test_get_vpc_pair_collection(self, mock_get):
        fabric = 'test_fabric'
        switch_id = 'FDO23390CUN'
        self.helper.nd_new_version = False

        mock_response = mock.MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = [
            {
                'peerOneId': 'FDO28290NZ2',
                'peerTwoId': 'FDO28290NZE'
            },
            {
                'peerOneId': 'FDO23390CUN',
                'peerTwoId': 'FDO23390CUU'
            }
        ]
        mock_get.return_value = mock_response

        result = self.helper._get_vpc_pair(fabric, switch_id)
        self.assertEqual({'peerSwitchId': 'FDO23390CUU'}, result)

    @mock.patch.object(ndfc_helper.NdfcHelper, 'login', return_value=True)
    @mock.patch.object(ndfc_helper.NdfcHelper, 'logout')
    @mock.patch('requests.get')
    def test_determine_nd_api_version_v2(self, mock_get, mock_logout,
                                         mock_login):
        mock_get_response = mock.MagicMock()
        mock_get_response.status_code = 200
        mock_get.return_value = mock_get_response

        self.helper.determine_nd_api_version()

        self.assertTrue(self.helper.nd_new_version)

    @mock.patch.object(ndfc_helper.NdfcHelper, 'login', return_value=True)
    @mock.patch.object(ndfc_helper.NdfcHelper, 'logout')
    @mock.patch('requests.get')
    def test_determine_nd_api_version_old(self, mock_get, mock_logout,
                                          mock_login):
        mock_get_response = mock.MagicMock()
        mock_get_response.status_code = 501
        mock_get.return_value = mock_get_response

        self.helper.determine_nd_api_version()

        self.assertFalse(self.helper.nd_new_version)

    def test_determine_nd_api_version_old_forced(self):
        self.helper.force_old_api = True
        self.helper.determine_nd_api_version()

        self.assertFalse(self.helper.nd_new_version)

    @mock.patch.object(ndfc_helper.NdfcHelper, 'login', return_value=False)
    @mock.patch('requests.get')
    def test_determine_nd_api_version_failure(self, mock_get, mock_login):
        mock_get.return_value = None

        self.helper.determine_nd_api_version()

        self.assertFalse(self.helper.nd_new_version)
