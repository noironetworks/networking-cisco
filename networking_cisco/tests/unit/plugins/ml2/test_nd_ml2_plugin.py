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

from unittest import mock

from neutron.plugins.ml2 import plugin as ml2_plugin
from neutron.tests.unit import testlib_api

from networking_cisco.ml2_drivers.ndfc import constants as ndfc_const
from networking_cisco.ml2_drivers.ndfc import extension_db
from networking_cisco.ml2_drivers.ndfc.extensions import (
    ndfc_network_deploy as nd_net_ext
)
from networking_cisco.plugins.ml2.nd_extension_manager import (
        NdExtensionManager
)
from networking_cisco.plugins.ml2 import nd_ml2


class TestNdExtensionManager(testlib_api.SqlTestCase):

    def test_extend_address_scope_dict_delegates_to_nd_manager(self):
        nd_manager = mock.Mock()
        mgr = NdExtensionManager(nd_manager=nd_manager)

        session = mock.Mock()
        base_model = mock.Mock()
        result = {'id': 'as-id'}

        mgr.extend_address_scope_dict(session, base_model, result)

        nd_manager.extend_address_scope.assert_called_once_with(
            session, base_model, result)

    def test_extend_network_dict_delegates_to_nd_manager(self):
        nd_manager = mock.Mock()
        mgr = NdExtensionManager(nd_manager=nd_manager)

        session = mock.Mock()
        base_model = mock.Mock()
        result = {'id': 'net-id'}

        mgr.extend_network_dict(session, base_model, result)

        nd_manager.extend_network.assert_called_once_with(
            session, base_model, result)

    def test_handle_address_scope_create_delegates_to_nd_manager(self):
        nd_manager = mock.Mock()
        mgr = NdExtensionManager(nd_manager=nd_manager)

        context = mock.Mock()
        body = {'name': 'as1'}
        result = {'id': 'as-id'}

        mgr.handle_address_scope_create(context, body, result)

        nd_manager.handle_address_scope_create.assert_called_once_with(
            context, body, result)

    def test_delete_vrf_for_address_scope_delegates_to_nd_manager(self):
        nd_manager = mock.Mock()
        mgr = NdExtensionManager(nd_manager=nd_manager)

        mgr.delete_vrf_for_address_scope('vrf-ascope')

        nd_manager.delete_vrf_for_address_scope.assert_called_once_with(
            'vrf-ascope')


class TestNdMl2PluginExtensions(testlib_api.SqlTestCase):

    def test_supported_extension_aliases_includes_nd_network_deploy(self):
        plugin = nd_ml2.NdMl2Plugin()

        aliases = plugin.supported_extension_aliases

        self.assertIn(nd_net_ext.ALIAS, aliases)

    def test_update_network_triggers_mech_postcommit_for_nd_status(self):
        plugin = nd_ml2.NdMl2Plugin()
        ctx = mock.Mock()

        original = {'id': 'net-id',
                    'provider:network_type': ndfc_const.TYPE_ND}
        updated = {
            'id': 'net-id',
            'provider:network_type': ndfc_const.TYPE_ND,
            'nd-status': 'SYNC',
        }

        super_get = mock.Mock(return_value=original)
        super_update = mock.Mock(return_value=updated)
        mech_mgr = mock.Mock()
        plugin.mechanism_manager = mech_mgr

        with mock.patch.object(ml2_plugin.Ml2Plugin, 'get_network',
                               super_get), \
                mock.patch.object(ml2_plugin.Ml2Plugin, 'update_network',
                                  super_update), \
                mock.patch.object(nd_ml2.driver_context,
                                  'NetworkContext') as nc_cls:
            mech_ctx = mock.Mock()
            mech_ctx.current = updated
            nc_cls.return_value = mech_ctx

            body = {'network': {'nd-status': 'SYNC'}}
            res = plugin.update_network(ctx, 'net-id', body)

        self.assertEqual(updated, res)
        mech_mgr.update_network_postcommit.assert_called_once_with(mech_ctx)


class TestNdMl2PluginAddressScopeVrfCleanup(testlib_api.SqlTestCase):

    def setUp(self):
        super(TestNdMl2PluginAddressScopeVrfCleanup, self).setUp()
        self.plugin = nd_ml2.NdMl2Plugin()

    def _make_context_with_session(self):
        ctx = mock.Mock()
        ctx.session = mock.Mock()
        return ctx, ctx.session

    def test_delete_address_scope_deletes_vrf_when_last_reference(self):
        ctx, session = self._make_context_with_session()

        ext_row = extension_db.NdAddressScopeExtension(
            address_scope_id='as-id', nd_vrf_name='vrf-ascope')
        first_query = mock.Mock()
        first_query.filter_by.return_value = first_query
        first_query.first.return_value = ext_row

        second_query = mock.Mock()
        second_query.filter.return_value = second_query
        second_query.count.return_value = 0

        session.query.side_effect = [first_query, second_query]

        with mock.patch.object(ml2_plugin.Ml2Plugin, 'delete_address_scope'):
            self.plugin.nd_extension_manager = mock.Mock()

            self.plugin.delete_address_scope(ctx, 'as-id')

        nd_ext_mgr = self.plugin.nd_extension_manager
        nd_ext_mgr.delete_vrf_for_address_scope.assert_called_once_with(
            'vrf-ascope')

    def test_delete_address_scope_does_not_delete_vrf_when_others_exist(self):
        ctx, session = self._make_context_with_session()

        ext_row = extension_db.NdAddressScopeExtension(
            address_scope_id='as-id', nd_vrf_name='vrf-ascope')
        first_query = mock.Mock()
        first_query.filter_by.return_value = first_query
        first_query.first.return_value = ext_row

        second_query = mock.Mock()
        second_query.filter.return_value = second_query
        second_query.count.return_value = 2

        session.query.side_effect = [first_query, second_query]

        with mock.patch.object(ml2_plugin.Ml2Plugin, 'delete_address_scope'):
            self.plugin.nd_extension_manager = mock.Mock()

            self.plugin.delete_address_scope(ctx, 'as-id')

        nd_ext_mgr = self.plugin.nd_extension_manager
        nd_ext_mgr.delete_vrf_for_address_scope.assert_not_called()


class TestNdMl2PluginRouterInterfaceValidation(testlib_api.SqlTestCase):

    def setUp(self):
        super(TestNdMl2PluginRouterInterfaceValidation, self).setUp()
        self.plugin = nd_ml2.NdMl2Plugin()

    def _make_payload(self, network_id):
        payload = mock.Mock()
        payload.context = mock.Mock()
        payload.metadata = {'network_id': network_id}
        return payload

    def test_blocks_router_interface_on_nd_network(self):
        nd_network = {
            'id': 'net-nd',
            'provider:network_type': ndfc_const.TYPE_ND,
        }
        payload = self._make_payload('net-nd')

        with mock.patch.object(ml2_plugin.Ml2Plugin, 'get_network',
                               return_value=nd_network):
            self.assertRaises(
                nd_ml2.RouterNotCompatibleWithNetworkType,
                self.plugin._check_router_interface_network_type,
                'router_interface', 'before_create', self.plugin,
                payload=payload)

    def test_allows_router_interface_on_vlan_network(self):
        vlan_network = {
            'id': 'net-vlan',
            'provider:network_type': 'vlan',
        }
        payload = self._make_payload('net-vlan')

        with mock.patch.object(ml2_plugin.Ml2Plugin, 'get_network',
                               return_value=vlan_network):
            self.plugin._check_router_interface_network_type(
                'router_interface', 'before_create', self.plugin,
                payload=payload)

    def test_allows_router_interface_on_vxlan_network(self):
        vxlan_network = {
            'id': 'net-vxlan',
            'provider:network_type': 'vxlan',
        }
        payload = self._make_payload('net-vxlan')

        with mock.patch.object(ml2_plugin.Ml2Plugin, 'get_network',
                               return_value=vxlan_network):
            self.plugin._check_router_interface_network_type(
                'router_interface', 'before_create', self.plugin,
                payload=payload)

    def test_skips_check_when_payload_is_none(self):
        self.plugin._check_router_interface_network_type(
            'router_interface', 'before_create', self.plugin,
            payload=None)

    def test_skips_check_when_network_id_missing(self):
        payload = mock.Mock()
        payload.context = mock.Mock()
        payload.metadata = {}

        self.plugin._check_router_interface_network_type(
            'router_interface', 'before_create', self.plugin,
            payload=payload)

    def test_skips_check_when_network_fetch_fails(self):
        payload = self._make_payload('net-missing')

        with mock.patch.object(ml2_plugin.Ml2Plugin, 'get_network',
                               side_effect=Exception('not found')):
            self.plugin._check_router_interface_network_type(
                'router_interface', 'before_create', self.plugin,
                payload=payload)
