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
                force_old_api=False, enable_l3_on_border=False,
                attach_max_retries=3)
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

    @mock.patch.object(ndfc_helper.NdfcHelper, 'update_network')
    @mock.patch.object(ndfc.Ndfc, '_get_deploy_payload', return_value=[])
    @mock.patch.object(ndfc_helper.NdfcHelper, 'get_network_info')
    def test_update_network_sets_ipv6_gateway_v2(
            self, mock_get_network_info, mock_get_deploy_payload,
            mock_update_network):
        vrf_name = 'new_vrf'
        network_name = 'test_network'
        vlan = '100'
        physnet = 'physnet1'
        gw_v6 = '2001:db8:20:1::1/64'

        self.ndfc_instance.ndfc_obj.nd_new_version = True

        payload = {
            'networkName': network_name,
            'l3Data': {
                'gatewayIpv4Address': '10.10.10.0/24',
                'gatewayIpv6Address': ''
            }
        }
        mock_get_network_info.return_value = payload

        ret = self.ndfc_instance.update_network(vrf_name, network_name,
                                                vlan, gw_v6, physnet)
        self.assertTrue(ret)

        mock_get_network_info.assert_called_once_with(
            self.ndfc_instance.fabric, network_name)
        mock_update_network.assert_called_once()
        _fabric, _net_name, updated_payload = (
            mock_update_network.call_args[0])

        self.assertEqual(network_name, _net_name)
        self.assertEqual(vrf_name, updated_payload['vrfName'])
        l3_data = updated_payload['l3Data']
        self.assertEqual('10.10.10.0/24', l3_data['gatewayIpv4Address'])
        self.assertEqual(gw_v6, l3_data['gatewayIpv6Address'])

    @mock.patch.object(ndfc_helper.NdfcHelper, 'update_network')
    @mock.patch.object(ndfc.Ndfc, '_get_deploy_payload', return_value=[])
    @mock.patch.object(ndfc_helper.NdfcHelper, 'get_network_info')
    def test_update_network_clears_gateways_on_empty_gw_v2(
            self, mock_get_network_info, mock_get_deploy_payload,
            mock_update_network):
        vrf_name = 'new_vrf'
        network_name = 'test_network'
        vlan = '100'
        physnet = 'physnet1'

        self.ndfc_instance.ndfc_obj.nd_new_version = True

        payload = {
            'networkName': network_name,
            'l3Data': {
                'gatewayIpv4Address': '10.10.10.0/24',
                'gatewayIpv6Address': '2001:db8:20:1::1/64'
            }
        }
        mock_get_network_info.return_value = payload

        ret = self.ndfc_instance.update_network(vrf_name, network_name,
                                                vlan, '', physnet)
        self.assertTrue(ret)

        mock_update_network.assert_called_once()
        _fabric, _net_name, updated_payload = (
            mock_update_network.call_args[0])

        l3_data = updated_payload['l3Data']
        self.assertNotIn('gatewayIpv4Address', l3_data)
        self.assertNotIn('gatewayIpv6Address', l3_data)

    @mock.patch.object(ndfc_helper.NdfcHelper, 'update_network')
    @mock.patch.object(ndfc.Ndfc, '_get_deploy_payload', return_value=[])
    @mock.patch.object(ndfc_helper.NdfcHelper, 'get_network_info')
    def test_update_network_sets_ipv6_gateway(self, mock_get_network_info,
            mock_get_deploy_payload, mock_update_network):
        vrf_name = 'new_vrf'
        network_name = 'test_network'
        vlan = '100'
        physnet = 'physnet1'
        gw_v6 = '2001:db8:20:1::1/64'

        payload = {
            'networkTemplateConfig': jsonutils.dumps({
                'gatewayIpAddress': '10.10.10.0/24',
                'gatewayIpV6Address': ''
            })
        }
        mock_get_network_info.return_value = payload

        ret = self.ndfc_instance.update_network(vrf_name, network_name,
                                                vlan, gw_v6, physnet)
        self.assertTrue(ret)

        mock_update_network.assert_called_once()
        _fabric, _net_name, updated_payload = (
            mock_update_network.call_args[0])

        tmpl_cfg = updated_payload['networkTemplateConfig']
        self.assertEqual('10.10.10.0/24', tmpl_cfg['gatewayIpAddress'])
        self.assertEqual(gw_v6, tmpl_cfg['gatewayIpV6Address'])

    @mock.patch.object(ndfc_helper.NdfcHelper, 'update_network')
    @mock.patch.object(ndfc.Ndfc, '_get_deploy_payload', return_value=[])
    @mock.patch.object(ndfc_helper.NdfcHelper, 'get_network_info')
    def test_update_network_clears_gateways_on_empty_gw(self,
            mock_get_network_info, mock_get_deploy_payload,
            mock_update_network):
        vrf_name = 'new_vrf'
        network_name = 'test_network'
        vlan = '100'
        physnet = 'physnet1'

        payload = {
            'networkTemplateConfig': jsonutils.dumps({
                'gatewayIpAddress': '10.10.10.0/24',
                'gatewayIpV6Address': '2001:db8:20:1::1/64'
            })
        }
        mock_get_network_info.return_value = payload

        ret = self.ndfc_instance.update_network(vrf_name, network_name,
                                                vlan, '', physnet)
        self.assertTrue(ret)

        mock_update_network.assert_called_once()
        _fabric, _net_name, updated_payload = (
            mock_update_network.call_args[0])

        tmpl_cfg = updated_payload['networkTemplateConfig']
        self.assertEqual('', tmpl_cfg['gatewayIpAddress'])
        self.assertEqual('', tmpl_cfg['gatewayIpV6Address'])

    @mock.patch.object(ndfc_helper.NdfcHelper, 'update_network')
    @mock.patch.object(ndfc.Ndfc, '_get_deploy_payload', return_value=[])
    @mock.patch.object(ndfc_helper.NdfcHelper, 'get_network_info')
    def test_update_network_sets_vrf_in_payload_v2(
            self, mock_get_network_info, mock_get_deploy_payload,
            mock_update_network):
        vrf_name = 'new_vrf'
        network_name = 'test_network'
        vlan = '100'
        physnet = 'physnet1'
        gw = '10.10.10.0/24'

        self.ndfc_instance.ndfc_obj.nd_new_version = True

        payload = {
            'networkName': network_name,
            'l3Data': {}
        }
        mock_get_network_info.return_value = payload

        ret = self.ndfc_instance.update_network(vrf_name, network_name,
                                                vlan, gw, physnet)
        self.assertTrue(ret)

        mock_get_network_info.assert_called_once_with(
            self.ndfc_instance.fabric, network_name)
        mock_update_network.assert_called_once()
        fabric, net_name, updated_payload = (
            mock_update_network.call_args[0])

        self.assertEqual(self.ndfc_instance.fabric, fabric)
        self.assertEqual(network_name, net_name)
        self.assertEqual(vrf_name, updated_payload['vrfName'])
        l3_data = updated_payload['l3Data']
        self.assertIsInstance(l3_data, dict)
        self.assertEqual(gw, l3_data['gatewayIpv4Address'])

    @mock.patch.object(ndfc_helper.NdfcHelper, 'update_network')
    @mock.patch.object(ndfc.Ndfc, '_get_deploy_payload', return_value=[])
    @mock.patch.object(ndfc_helper.NdfcHelper, 'get_network_info')
    def test_update_network_sets_vrf_in_payload(
            self, mock_get_network_info, mock_get_deploy_payload,
            mock_update_network):
        vrf_name = 'new_vrf'
        network_name = 'test_network'
        vlan = '100'
        physnet = 'physnet1'
        gw = '10.10.10.0/24'

        payload = {
            'networkTemplateConfig': jsonutils.dumps({
                'gatewayIpAddress': ''
            })
        }
        mock_get_network_info.return_value = payload

        ret = self.ndfc_instance.update_network(vrf_name, network_name,
                                                vlan, gw, physnet)
        self.assertTrue(ret)

        mock_get_network_info.assert_called_once_with(
            self.ndfc_instance.fabric, network_name)
        mock_update_network.assert_called_once()
        _fabric, _net_name, updated_payload = (
            mock_update_network.call_args[0])

        self.assertEqual(network_name, _net_name)
        self.assertEqual(vrf_name, updated_payload['vrf'])
        tmpl_cfg = updated_payload['networkTemplateConfig']
        self.assertIsInstance(tmpl_cfg, dict)
        self.assertEqual(gw, tmpl_cfg['gatewayIpAddress'])
        self.assertEqual(vrf_name, tmpl_cfg['vrfName'])

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

    @mock.patch.object(ndfc.time, 'sleep')
    @mock.patch.object(ndfc_helper.NdfcHelper, 'create_network')
    def test_create_network_v2_retries_auto_alloc_with_original_payload(
            self, mock_create_network, mock_sleep):
        vrf_name = 'test_vrf'
        network_name = 'test_network'
        physnet = 'physnet1'
        payloads = []

        def create_network_side_effect(fabric, payload):
            payloads.append(jsonutils.loads(jsonutils.dumps(payload)))
            if len(payloads) == 1:
                payload['networks'][0]['networkId'] = 30000
                payload['networks'][0]['l2Data']['rtAuto'] = True
                raise ndfc_helper.NdfcNetworkIdAlreadyAllocated(30000)
            return True

        mock_create_network.side_effect = create_network_side_effect
        self.ndfc_instance.ndfc_obj.nd_new_version = True

        ret = self.ndfc_instance.create_network(vrf_name, network_name,
                None, physnet)

        self.assertTrue(ret)
        self.assertEqual(2, mock_create_network.call_count)
        self.assertNotIn('networkId', payloads[0]['networks'][0])
        self.assertEqual(payloads[0], payloads[1])
        mock_sleep.assert_called_once_with(
            ndfc.NETWORK_CREATE_ID_RETRY_INTERVAL)

    @mock.patch.object(ndfc.time, 'sleep')
    @mock.patch.object(ndfc_helper.NdfcHelper, 'create_network')
    def test_create_network_v2_does_not_retry_explicit_network_id_collision(
            self, mock_create_network, mock_sleep):
        vrf_name = 'test_vrf'
        network_name = 'test_network'
        vlan = 100
        physnet = 'physnet1'
        mock_create_network.side_effect = (
            ndfc_helper.NdfcNetworkIdAlreadyAllocated(1000))
        self.ndfc_instance.ndfc_obj.nd_new_version = True

        ret = self.ndfc_instance.create_network(vrf_name, network_name,
                vlan, physnet)

        self.assertFalse(ret)
        self.assertEqual(1, mock_create_network.call_count)
        mock_sleep.assert_not_called()

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

    @mock.patch.object(ndfc_helper.NdfcHelper,
            'get_network_switch_interface_map', return_value=None)
    def test_network_attach_detach_none_guard(self, mock_get_map):
        vrf_name = 'test_vrf'
        network_name = 'test_network'
        vlan = '100'
        leaf_attachments = test_ndfc_mech.TEST_LEAF_ATTACHMENTS

        ret = self.ndfc_instance.attach_network(vrf_name, network_name,
                vlan, leaf_attachments)
        self.assertFalse(ret)

        ret = self.ndfc_instance.detach_network(vrf_name, network_name,
                vlan, leaf_attachments)
        self.assertFalse(ret)

    @mock.patch.object(ndfc_helper.NdfcHelper, 'attach_deploy_network')
    def test_attach_network_uses_supplied_attachment_map(
            self, mock_attach_deploy_network):
        vrf_name = 'test_vrf'
        network_name = 'test_network'
        vlan = '100'
        existing_attachments = {}
        leaf_attachments = test_ndfc_mech.TEST_LEAF_ATTACHMENTS
        self.mock_exist_attach.reset_mock()
        mock_attach_deploy_network.return_value = True

        ret = self.ndfc_instance.attach_network(
                vrf_name, network_name, vlan, leaf_attachments,
                existing_attachments=existing_attachments)

        self.assertTrue(ret)
        self.mock_exist_attach.assert_not_called()

    @mock.patch.object(ndfc_helper.NdfcHelper, 'attach_deploy_network')
    def test_detach_network_uses_supplied_attachment_map(
            self, mock_attach_deploy_network):
        vrf_name = 'test_vrf'
        network_name = 'test_network'
        vlan = '100'
        existing_attachments = {'leaf1': {'interfaces': ['Ethernet1/1']}}
        leaf_attachments = {'leaf1': {'interfaces': ['Ethernet1/1']}}
        self.mock_exist_attach.reset_mock()
        mock_attach_deploy_network.return_value = True

        ret = self.ndfc_instance.detach_network(
                vrf_name, network_name, vlan, leaf_attachments,
                existing_attachments=existing_attachments)

        self.assertTrue(ret)
        self.mock_exist_attach.assert_not_called()

    @mock.patch.object(ndfc_helper.NdfcHelper,
            'get_network_switch_interface_map')
    @mock.patch.object(ndfc_helper.NdfcHelper, 'attach_deploy_network')
    def test_attach_network_preserves_nd_direct_attachments(
            self, mock_attach_deploy_network, mock_get_nd_attachments):
        vrf_name = 'test_vrf'
        network_name = 'test_network'
        vlan = '100'
        leaf_attachments = {'leaf1': {'interfaces': ['eth-new']}}
        existing_attachments = {
            'leaf1': {'interfaces': ['eth-os-current']}
        }
        openstack_attachments = {
            'leaf1': {'interfaces': ['eth-os-current', 'eth-os-other']}
        }
        mock_get_nd_attachments.return_value = {
            'leaf1': {
                'interfaces': ['eth-os-current', 'eth-os-other', 'eth-nd']
            }
        }
        mock_attach_deploy_network.return_value = True

        ret = self.ndfc_instance.attach_network(
            vrf_name, network_name, vlan, leaf_attachments,
            existing_attachments=existing_attachments,
            openstack_attachments=openstack_attachments)

        self.assertTrue(ret)
        mock_get_nd_attachments.assert_called_once_with(
            self.ndfc_instance.fabric, network_name)
        attach_payload = mock_attach_deploy_network.call_args[0][1]
        lan_attach = attach_payload[0]['lanAttachList'][0]
        self.assertEqual(
            'eth-nd,eth-os-current,eth-new',
            lan_attach['switchPorts'])

    @mock.patch.object(ndfc_helper.NdfcHelper,
            'get_network_switch_interface_map')
    @mock.patch.object(ndfc_helper.NdfcHelper, 'attach_deploy_network')
    def test_detach_network_preserves_nd_direct_attachments(
            self, mock_attach_deploy_network, mock_get_nd_attachments):
        vrf_name = 'test_vrf'
        network_name = 'test_network'
        vlan = '100'
        leaf_attachments = {'leaf1': {'interfaces': ['eth-os-current']}}
        existing_attachments = {
            'leaf1': {'interfaces': ['eth-os-current']}
        }
        openstack_attachments = {
            'leaf1': {'interfaces': ['eth-os-current']}
        }
        mock_get_nd_attachments.return_value = {
            'leaf1': {'interfaces': ['eth-os-current', 'eth-nd']}
        }
        mock_attach_deploy_network.return_value = True

        ret = self.ndfc_instance.detach_network(
            vrf_name, network_name, vlan, leaf_attachments,
            existing_attachments=existing_attachments,
            openstack_attachments=openstack_attachments,
            network_has_other_ports=False)

        self.assertTrue(ret)
        detach_payload = mock_attach_deploy_network.call_args[0][1]
        lan_attach = detach_payload[0]['lanAttachList'][0]
        self.assertEqual('eth-os-current', lan_attach['detachSwitchPorts'])
        self.assertEqual('eth-nd', lan_attach['switchPorts'])
        self.assertEqual('true', lan_attach['deployment'])

    @mock.patch.object(ndfc_helper.NdfcHelper,
            'get_network_switch_interface_map')
    @mock.patch.object(ndfc_helper.NdfcHelper, 'attach_deploy_network')
    def test_detach_network_v2_preserves_nd_direct_with_partial_detach(
            self, mock_attach_deploy_network, mock_get_nd_attachments):
        vrf_name = 'test_vrf'
        network_name = 'test_network'
        vlan = '100'
        leaf_attachments = {'leaf1': {'interfaces': ['eth-os-current']}}
        existing_attachments = {
            'leaf1': {'interfaces': ['eth-os-current']}
        }
        openstack_attachments = {
            'leaf1': {'interfaces': ['eth-os-current']}
        }
        mock_get_nd_attachments.return_value = {
            'leaf1': {'interfaces': ['eth-os-current', 'eth-nd']}
        }
        mock_attach_deploy_network.return_value = True
        self.ndfc_instance.ndfc_obj.nd_new_version = True

        ret = self.ndfc_instance.detach_network(
            vrf_name, network_name, vlan, leaf_attachments,
            existing_attachments=existing_attachments,
            openstack_attachments=openstack_attachments,
            network_has_other_ports=False)

        self.assertTrue(ret)
        detach_payload = mock_attach_deploy_network.call_args[0][1]
        attachment = detach_payload['attachments'][0]
        self.assertFalse(attachment['attach'])
        interfaces = attachment['interfaces']
        self.assertEqual(1, len(interfaces))
        self.assertEqual('eth-os-current', interfaces[0]['interfaceRange'])

    @mock.patch.object(ndfc_helper.NdfcHelper,
            'get_network_switch_interface_map', return_value=None)
    def test_network_attach_detach_none_guard_v2(self, mock_get_map):
        vrf_name = 'test_vrf'
        network_name = 'test_network'
        vlan = '100'
        leaf_attachments = test_ndfc_mech.TEST_LEAF_ATTACHMENTS

        self.ndfc_instance.ndfc_obj.nd_new_version = True

        ret = self.ndfc_instance.attach_network(vrf_name, network_name,
                vlan, leaf_attachments)
        self.assertFalse(ret)

        ret = self.ndfc_instance.detach_network(vrf_name, network_name,
                vlan, leaf_attachments)
        self.assertFalse(ret)

    def test_create_network_payload_enable_l3_on_border(self):
        vrf_name = 'test_vrf'
        network_name = 'test_network'
        vlan = 100

        self.ndfc_instance.enable_l3_on_border = False
        payload = self.ndfc_instance._get_create_network_payload(
            vrf_name, network_name, vlan)
        template_cfg = payload['networkTemplateConfig']
        self.assertFalse(template_cfg['enableL3OnBorder'])

        self.ndfc_instance.enable_l3_on_border = True
        payload = self.ndfc_instance._get_create_network_payload(
            vrf_name, network_name, vlan)
        template_cfg = payload['networkTemplateConfig']
        self.assertTrue(template_cfg['enableL3OnBorder'])

    def test_create_network_payload_enable_l3_on_border_v2(self):
        vrf_name = 'test_vrf'
        network_name = 'test_network'
        vlan = 100

        self.ndfc_instance.ndfc_obj.nd_new_version = True

        self.ndfc_instance.enable_l3_on_border = False
        payload = self.ndfc_instance._get_create_network_payload_v2(
            vrf_name, network_name, vlan)
        l3_data = payload['networks'][0]['l3Data']
        self.assertIn('fabricData', l3_data)
        self.assertFalse(l3_data['fabricData']['gatewayOnBorder'])

        self.ndfc_instance.enable_l3_on_border = True
        payload = self.ndfc_instance._get_create_network_payload_v2(
            vrf_name, network_name, vlan)
        l3_data = payload['networks'][0]['l3Data']
        self.assertIn('fabricData', l3_data)
        self.assertTrue(l3_data['fabricData']['gatewayOnBorder'])

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

        leaf_attachments = {
            'leaf1': {
                'interfaces': ['eth1'],
                'peer_serial': 'leaf2'
            }
        }

        self.ndfc_instance.ndfc_obj.nd_new_version = True
        detach_payload_v2 = self.ndfc_instance._create_detach_payload_v2(
            leaf_attachments, vrf_name, network_name, vlan,
            network_has_other_ports=False)

        attachments = detach_payload_v2['attachments']
        self.assertEqual(len(attachments), 2)
        switch_ids = {a['switchId'] for a in attachments}
        self.assertEqual(switch_ids, {'leaf1', 'leaf2'})

        for att in attachments:
            self.assertFalse(att['attach'])
            self.assertEqual(att['interfaces'], [])

    @mock.patch('time.sleep')
    def test_attach_retries_on_transient_error(self, mock_sleep):
        helper = self.ndfc_instance.ndfc_obj
        helper.nd_new_version = True
        fail_response = mock.MagicMock(
            status_code=207,
            text='fail')
        fail_response.json.return_value = {
            'results': [{'status': 'failed',
                         'message': 'Failed : VRF Undeployment in Progress '
                                    'for switch TOR1.'}]}
        ok_response = mock.MagicMock(status_code=200, text='ok')
        ok_response.json.return_value = {}
        deploy_response = mock.MagicMock(status_code=200, text='ok')
        deploy_response.json.return_value = {}
        self.mock_requests_post.side_effect = [
                fail_response, ok_response, deploy_response]
        ret = helper.attach_deploy_network(
            'fabric', {'attachments': []}, {'networkNames': []})
        self.assertTrue(ret)
        self.assertEqual(mock_sleep.call_count, 1)

    @mock.patch('time.sleep')
    def test_attach_exhausts_retries(self, mock_sleep):
        helper = self.ndfc_instance.ndfc_obj
        helper.nd_new_version = True
        fail_response = mock.MagicMock(
            status_code=207,
            text='fail')
        fail_response.json.return_value = {
            'results': [{'status': 'failed',
                         'message': 'Failed : VRF Undeployment in Progress '
                                    'for switch TOR1.'}]}
        self.mock_requests_post.side_effect = [
            fail_response, fail_response, fail_response, fail_response]
        ret = helper.attach_deploy_network(
            'fabric', {'attachments': []}, {'networkNames': []})
        self.assertFalse(ret)
        self.assertEqual(mock_sleep.call_count, 3)

    @mock.patch('time.sleep')
    def test_attach_no_retry_on_non_transient_error(self, mock_sleep):
        helper = self.ndfc_instance.ndfc_obj
        helper.nd_new_version = True
        fail_response = mock.MagicMock(
            status_code=207,
            text='fail')
        fail_response.json.return_value = {
            'results': [{'status': 'failed',
                         'message': 'Invalid payload format.'}]}
        self.mock_requests_post.side_effect = [fail_response]
        ret = helper.attach_deploy_network(
            'fabric', {'attachments': []}, {'networkNames': []})
        self.assertFalse(ret)
        mock_sleep.assert_not_called()

    def test_attach_succeeds_first_attempt(self):
        helper = self.ndfc_instance.ndfc_obj
        helper.nd_new_version = True
        ok_response = mock.MagicMock(status_code=200, text='ok')
        ok_response.json.return_value = {}
        deploy_response = mock.MagicMock(status_code=200, text='ok')
        deploy_response.json.return_value = {}
        self.mock_requests_post.side_effect = [
                ok_response, deploy_response]
        ret = helper.attach_deploy_network(
            'fabric', {'attachments': []}, {'networkNames': []})
        self.assertTrue(ret)

    def test_attach_payload_v2_hardcodes_trunk_mode(self):
        network_name = 'test_network'
        vlan = '100'
        leaf_info = {
            'interfaces': ['Port-channel2']
        }

        self.ndfc_instance.ndfc_obj.nd_new_version = True
        interfaces = self.ndfc_instance._get_common_attach_payload_v2(
            'fabric_name', network_name, vlan, 'leaf1', leaf_info)

        self.assertEqual(len(interfaces), 1)
        self.assertEqual(interfaces[0]['interfaceRange'], 'Port-channel2')
        self.assertEqual(interfaces[0]['mode'], 'trunk')

    def test_create_detach_payload_skips_vpc_peer_with_active_interfaces(self):
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
        exist_attach = {
            'leaf2': {
                'interfaces': ['eth5']
            }
        }

        detach_payload = self.ndfc_instance._create_detach_payload(
            leaf_attachments, collated_attach, vrf_name, network_name, vlan,
            exist_attach=exist_attach)

        lan_list = detach_payload[0]['lanAttachList']
        self.assertEqual(len(lan_list), 1)
        self.assertEqual(lan_list[0]['serialNumber'], 'leaf1')

    def test_create_detach_payload_detaches_vpc_peer_with_no_active_intf(self):
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
        exist_attach = {
            'leaf2': {
                'interfaces': []
            }
        }

        detach_payload = self.ndfc_instance._create_detach_payload(
            leaf_attachments, collated_attach, vrf_name, network_name, vlan,
            exist_attach=exist_attach)

        lan_list = detach_payload[0]['lanAttachList']
        self.assertEqual(len(lan_list), 2)
        snums = {entry['serialNumber'] for entry in lan_list}
        self.assertEqual(snums, {'leaf1', 'leaf2'})

    def test_create_detach_payload_v2_partial_shared_switch(self):
        vrf_name = 'test_vrf'
        network_name = 'test_network'
        vlan = '100'

        exist_attach = {
            'leaf1': {
                'interfaces': ['eth1', 'eth2']
            }
        }
        leaf_attachments = {
            'leaf1': {
                'interfaces': ['eth1'],
                'peer_serial': 'leaf2'
            }
        }

        self.ndfc_instance.ndfc_obj.nd_new_version = True
        detach_payload_v2 = self.ndfc_instance._create_detach_payload_v2(
            leaf_attachments, vrf_name, network_name, vlan,
            exist_attach=exist_attach,
            network_has_other_ports=True)

        attachments = detach_payload_v2['attachments']
        self.assertEqual(len(attachments), 1)
        self.assertEqual(attachments[0]['switchId'], 'leaf1')
        self.assertFalse(attachments[0]['attach'])
        self.assertEqual(len(attachments[0]['interfaces']), 1)
        self.assertEqual(
            attachments[0]['interfaces'][0]['interfaceRange'], 'eth1')

    def test_create_detach_payload_v2_full_detach_with_vpc_peer(self):
        vrf_name = 'test_vrf'
        network_name = 'test_network'
        vlan = '100'

        leaf_attachments = {
            'leaf1': {
                'interfaces': ['eth1'],
                'peer_serial': 'leaf2'
            }
        }

        self.ndfc_instance.ndfc_obj.nd_new_version = True
        detach_payload_v2 = self.ndfc_instance._create_detach_payload_v2(
            leaf_attachments, vrf_name, network_name, vlan,
            network_has_other_ports=False)

        attachments = detach_payload_v2['attachments']
        self.assertEqual(len(attachments), 2)
        switch_ids = {a['switchId'] for a in attachments}
        self.assertEqual(switch_ids, {'leaf1', 'leaf2'})
        for att in attachments:
            self.assertFalse(att['attach'])
            self.assertEqual(att['interfaces'], [])

    def test_create_detach_payload_v2_partial_detach_sends_interfaces(self):
        vrf_name = 'test_vrf'
        network_name = 'test_network'
        vlan = '100'

        exist_attach = {
            'leaf1': {
                'interfaces': ['eth1', 'eth2']
            }
        }
        leaf_attachments = {
            'leaf1': {
                'interfaces': ['eth1']
            }
        }

        self.ndfc_instance.ndfc_obj.nd_new_version = True
        detach_payload_v2 = self.ndfc_instance._create_detach_payload_v2(
            leaf_attachments, vrf_name, network_name, vlan,
            exist_attach=exist_attach,
            network_has_other_ports=True)

        attachments = detach_payload_v2['attachments']
        self.assertEqual(len(attachments), 1)
        self.assertEqual(attachments[0]['switchId'], 'leaf1')
        self.assertFalse(attachments[0]['attach'])
        self.assertEqual(len(attachments[0]['interfaces']), 1)
        self.assertEqual(
            attachments[0]['interfaces'][0]['interfaceRange'], 'eth1')

    def test_create_detach_payload_v2_partial_detach_tor_sends_interfaces(
            self):
        vrf_name = 'test_vrf'
        network_name = 'test_network'
        vlan = '100'

        exist_attach = {
            'leaf1': {
                'tor_sw_intf_map': {
                    'SN_tor1': {
                        'tor_name': 'tor1',
                        'tor_interfaces': ['Ethernet1/1', 'Ethernet1/2']
                    }
                }
            }
        }
        leaf_attachments = {
            'leaf1': {
                'tor_sw_intf_map': {
                    'tor1': {
                        'tor_name': 'tor1',
                        'tor_interfaces': ['Ethernet1/1']
                    }
                }
            }
        }

        self.ndfc_instance.ndfc_obj.nd_new_version = True
        detach_payload_v2 = self.ndfc_instance._create_detach_payload_v2(
            leaf_attachments, vrf_name, network_name, vlan,
            exist_attach=exist_attach,
            network_has_other_ports=True)

        attachments = detach_payload_v2['attachments']
        self.assertEqual(len(attachments), 1)
        self.assertEqual(attachments[0]['switchId'], 'leaf1')
        self.assertFalse(attachments[0]['attach'])
        self.assertEqual(len(attachments[0]['interfaces']), 1)
        self.assertEqual(
            attachments[0]['interfaces'][0]['interfaceRange'], 'Ethernet1/1')

    def test_detach_v2_full_detach_no_vpc_peer_in_leaf_attachments(self):
        vrf_name = 'test_vrf'
        network_name = 'test_network'
        vlan = '100'

        leaf_attachments = {
            'leaf1': {
                'interfaces': ['eth1']
            }
        }

        self.ndfc_instance.ndfc_obj.nd_new_version = True
        detach_payload_v2 = self.ndfc_instance._create_detach_payload_v2(
            leaf_attachments, vrf_name, network_name, vlan,
            network_has_other_ports=False)

        attachments = detach_payload_v2['attachments']
        self.assertEqual(len(attachments), 1)
        self.assertFalse(attachments[0]['attach'])
        self.assertEqual(attachments[0]['interfaces'], [])

    def test_detach_v2_partial_detach_when_ports_remain(self):
        vrf_name = 'test_vrf'
        network_name = 'test_network'
        vlan = '100'

        exist_attach = {
            'leaf1': {
                'interfaces': ['eth1', 'eth2']
            }
        }
        leaf_attachments = {
            'leaf1': {
                'interfaces': ['eth1']
            }
        }

        self.ndfc_instance.ndfc_obj.nd_new_version = True
        detach_payload_v2 = self.ndfc_instance._create_detach_payload_v2(
            leaf_attachments, vrf_name, network_name, vlan,
            exist_attach=exist_attach,
            network_has_other_ports=True)

        attachments = detach_payload_v2['attachments']
        self.assertEqual(len(attachments), 1)
        self.assertFalse(attachments[0]['attach'])
        self.assertEqual(len(attachments[0]['interfaces']), 1)
        self.assertEqual(
            attachments[0]['interfaces'][0]['interfaceRange'], 'eth1')

    def test_detach_v2_full_detach_dedicated_switch(self):
        vrf_name = 'test_vrf'
        network_name = 'test_network'
        vlan = '100'

        leaf_attachments = {
            'leaf1': {
                'interfaces': ['eth1'],
                'peer_serial': 'leaf2'
            }
        }
        exist_attach = {
            'leaf1': {
                'interfaces': ['eth1']
            }
        }

        self.ndfc_instance.ndfc_obj.nd_new_version = True
        detach_payload_v2 = self.ndfc_instance._create_detach_payload_v2(
            leaf_attachments, vrf_name, network_name, vlan,
            exist_attach=exist_attach,
            network_has_other_ports=True)

        attachments = detach_payload_v2['attachments']
        self.assertEqual(len(attachments), 2)
        switch_ids = {a['switchId'] for a in attachments}
        self.assertEqual(switch_ids, {'leaf1', 'leaf2'})
        for att in attachments:
            self.assertFalse(att['attach'])
            self.assertEqual(att['interfaces'], [])

    def test_detach_v2_skips_vpc_peer_with_active_interfaces(self):
        """vPC peer still has interfaces from another compute — skip it."""
        vrf_name = 'test_vrf'
        network_name = 'test_network'
        vlan = '100'

        leaf_attachments = {
            'leaf1': {
                'interfaces': ['eth1'],
                'peer_serial': 'leaf2'
            }
        }
        exist_attach = {
            'leaf1': {
                'interfaces': ['eth1']
            },
            'leaf2': {
                'interfaces': ['eth5']
            }
        }

        self.ndfc_instance.ndfc_obj.nd_new_version = True
        detach_payload_v2 = self.ndfc_instance._create_detach_payload_v2(
            leaf_attachments, vrf_name, network_name, vlan,
            exist_attach=exist_attach,
            network_has_other_ports=True)

        attachments = detach_payload_v2['attachments']
        self.assertEqual(len(attachments), 1)
        self.assertEqual(attachments[0]['switchId'], 'leaf1')
        self.assertFalse(attachments[0]['attach'])
        self.assertEqual(attachments[0]['interfaces'], [])

    def test_detach_v1_forces_full_detach_when_no_ports_remain(self):
        vrf_name = 'test_vrf'
        network_name = 'test_network'
        vlan = '100'

        collated_attach = {
            'leaf1': {
                'interfaces': ['eth2'],
                'peer_serial': 'leaf2'
            }
        }
        leaf_attachments = {
            'leaf1': {
                'interfaces': ['eth1']
            }
        }

        detach_payload = self.ndfc_instance._create_detach_payload(
            leaf_attachments, collated_attach, vrf_name, network_name, vlan,
            network_has_other_ports=False)

        lan_list = detach_payload[0]['lanAttachList']
        self.assertEqual(len(lan_list), 2)
        snums = {entry['serialNumber'] for entry in lan_list}
        self.assertEqual(snums, {'leaf1', 'leaf2'})
        for entry in lan_list:
            self.assertFalse(entry['deployment'])

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

    @mock.patch.object(ndfc_helper.NdfcHelper, 'update_network')
    @mock.patch.object(ndfc.Ndfc, '_get_deploy_payload', return_value=[])
    @mock.patch.object(ndfc_helper.NdfcHelper, 'get_network_info')
    def test_update_network_removes_stale_empty_ipv6_on_ipv4_set_v2(
            self, mock_get_network_info, mock_get_deploy_payload,
            mock_update_network):
        vrf_name = 'new_vrf'
        network_name = 'test_network'
        vlan = '100'
        physnet = 'physnet1'
        gw = '192.168.1.1/24'

        self.ndfc_instance.ndfc_obj.nd_new_version = True

        payload = {
            'networkName': network_name,
            'l3Data': {
                'gatewayIpv4Address': '',
                'gatewayIpv6Address': ''
            }
        }
        mock_get_network_info.return_value = payload

        ret = self.ndfc_instance.update_network(vrf_name, network_name,
                                                vlan, gw, physnet)
        self.assertTrue(ret)

        mock_update_network.assert_called_once()
        _fabric, _net_name, updated_payload = (
            mock_update_network.call_args[0])

        l3_data = updated_payload['l3Data']
        self.assertEqual(gw, l3_data['gatewayIpv4Address'])
        self.assertNotIn('gatewayIpv6Address', l3_data)

    @mock.patch.object(ndfc_helper.NdfcHelper, 'update_network')
    @mock.patch.object(ndfc.Ndfc, '_get_deploy_payload', return_value=[])
    @mock.patch.object(ndfc_helper.NdfcHelper, 'get_network_info')
    def test_update_network_removes_stale_empty_ipv4_on_ipv6_set_v2(
            self, mock_get_network_info, mock_get_deploy_payload,
            mock_update_network):
        vrf_name = 'new_vrf'
        network_name = 'test_network'
        vlan = '100'
        physnet = 'physnet1'
        gw_v6 = '2001:db8:20:1::1/64'

        self.ndfc_instance.ndfc_obj.nd_new_version = True

        payload = {
            'networkName': network_name,
            'l3Data': {
                'gatewayIpv4Address': '',
                'gatewayIpv6Address': ''
            }
        }
        mock_get_network_info.return_value = payload

        ret = self.ndfc_instance.update_network(vrf_name, network_name,
                                                vlan, gw_v6, physnet)
        self.assertTrue(ret)

        mock_update_network.assert_called_once()
        _fabric, _net_name, updated_payload = (
            mock_update_network.call_args[0])

        l3_data = updated_payload['l3Data']
        self.assertNotIn('gatewayIpv4Address', l3_data)
        self.assertEqual(gw_v6, l3_data['gatewayIpv6Address'])

    @mock.patch.object(ndfc_helper.NdfcHelper, 'redeploy_network')
    @mock.patch.object(ndfc.Ndfc, '_get_deploy_payload')
    def test_redeploy_network_uses_helper_with_payload(self,
            mock_get_deploy_payload, mock_helper_redeploy):
        network_name = 'nd-net-1'
        deploy_payload = {'some': 'payload'}
        mock_get_deploy_payload.return_value = deploy_payload
        mock_helper_redeploy.return_value = True

        result = self.ndfc_instance.redeploy_network(network_name)

        mock_get_deploy_payload.assert_called_once_with(network_name)
        mock_helper_redeploy.assert_called_once_with(
            self.ndfc_instance.fabric, deploy_payload)
        self.assertTrue(result)

    @mock.patch.object(ndfc_helper.NdfcHelper, 'get_network_info')
    def test_get_network_deploy_status_success_values(self,
            mock_get_network_info):
        for status in ('deployed', 'inSync'):
            mock_get_network_info.reset_mock()
            mock_get_network_info.return_value = {
                'networkStatus': status,
            }

            result = self.ndfc_instance.get_network_deploy_status('nd-net-1')

            mock_get_network_info.assert_called_once_with(
                self.ndfc_instance.fabric, 'nd-net-1')
            self.assertIs(result, True)

    @mock.patch.object(ndfc_helper.NdfcHelper, 'get_network_info')
    def test_get_network_deploy_status_failure_values(self,
            mock_get_network_info):
        for status in ('failed', 'error', 'deployFailed'):
            mock_get_network_info.reset_mock()
            mock_get_network_info.return_value = {
                'networkStatus': status,
            }

            result = self.ndfc_instance.get_network_deploy_status('nd-net-1')

            mock_get_network_info.assert_called_once_with(
                self.ndfc_instance.fabric, 'nd-net-1')
            self.assertIs(result, False)

    @mock.patch.object(ndfc_helper.NdfcHelper, 'get_network_info')
    def test_get_network_deploy_status_neutral_not_applicable(self,
            mock_get_network_info):
        mock_get_network_info.return_value = {
            'networkStatus': 'notApplicable',
        }

        result = self.ndfc_instance.get_network_deploy_status('nd-net-1')

        mock_get_network_info.assert_called_once_with(
            self.ndfc_instance.fabric, 'nd-net-1')
        self.assertIsNone(result)

    @mock.patch.object(ndfc_helper.NdfcHelper, 'get_network_info')
    def test_get_network_deploy_status_missing_status_payload_present(self,
            mock_get_network_info):
        mock_get_network_info.return_value = {
            'networkName': 'nd-net-1',
        }

        result = self.ndfc_instance.get_network_deploy_status('nd-net-1')

        mock_get_network_info.assert_called_once_with(
            self.ndfc_instance.fabric, 'nd-net-1')
        self.assertIs(result, True)

    @mock.patch.object(ndfc_helper.NdfcHelper, 'get_network_info')
    def test_get_network_deploy_status_empty_payload_or_error(self,
            mock_get_network_info):
        mock_get_network_info.return_value = None
        result = self.ndfc_instance.get_network_deploy_status('nd-net-1')
        mock_get_network_info.assert_called_once_with(
            self.ndfc_instance.fabric, 'nd-net-1')
        self.assertIs(result, False)

        mock_get_network_info.reset_mock()
        mock_get_network_info.side_effect = Exception('boom')
        result = self.ndfc_instance.get_network_deploy_status('nd-net-1')
        mock_get_network_info.assert_called_once_with(
            self.ndfc_instance.fabric, 'nd-net-1')
        self.assertIs(result, False)
