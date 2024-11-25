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
        self.helper = ndfc_helper.NdfcHelper(ip='192.168.1.1',
                user='admin', pwd='password')
        super(TestNDFCHelper, self).setUp()

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
                        'portNames': ['Ethernet1/1', 'Ethernet1/2'],
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
    def test_get_po(self, mock_post, mock_get):
        mock_get_response = mock.MagicMock()
        mock_get_response.status_code = 200
        mock_get_response.json.return_value = [
            {
                'ifName': 'Ethernet1/1',
                'ifType': 'INTERFACE_ETHERNET',
                'channelIdStr': 'Port-channel10'
            }
        ]
        mock_get.return_value = mock_get_response

        snum = 'SN123'
        ifname = 'Ethernet1/1'

        result = self.helper.get_po(snum, ifname)

        expected_result = 'Port-channel10'
        self.assertEqual(result, expected_result)
