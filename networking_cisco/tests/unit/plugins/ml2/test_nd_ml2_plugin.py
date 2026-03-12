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

from neutron.tests.unit import testlib_api

from neutron.plugins.ml2 import plugin as ml2_plugin

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


class TestNdMl2PluginUpdateNetwork(testlib_api.SqlTestCase):

    @mock.patch('networking_cisco.plugins.ml2.nd_ml2.db_api.CONTEXT_WRITER')
    @mock.patch.object(ml2_plugin.Ml2Plugin, 'update_network')
    def test_update_network_persists_nd_status_for_nd_network(
            self, mock_update_network, mock_context_writer):
        plugin = nd_ml2.NdMl2Plugin()

        updated = {
            'id': 'net-id',
            'provider:network_type': ndfc_const.TYPE_ND,
        }
        mock_update_network.return_value = updated

        mock_cm = mock_context_writer.using.return_value
        mock_cm.__enter__.return_value = mock_cm
        mock_cm.__exit__.return_value = False

        context = mock.Mock()
        session = mock.Mock()
        context.session = session

        (session.query.return_value
         .filter_by.return_value
         .first.return_value) = None

        body = {'network': {'nd-status': 'FAILED'}}

        plugin.update_network(context, 'net-id', body)

        added = session.add.call_args[0][0]
        self.assertIsInstance(added, extension_db.NdNetworkExtension)
        self.assertEqual('net-id', added.network_id)
        self.assertEqual('FAILED', added.nd_status)


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
