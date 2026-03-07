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

from networking_cisco.ml2_drivers.ndfc import extension_db
from networking_cisco.ml2_drivers.ndfc import extension_driver as nd_ext_drv
from networking_cisco.plugins.ml2 import nd_manager
from networking_cisco.plugins.ml2 import nd_ml2


class TestNdExtensionDriver(testlib_api.SqlTestCase):

    def setUp(self):
        super(TestNdExtensionDriver, self).setUp()
        self.driver = nd_ext_drv.NdExtensionDriver()

    @mock.patch('networking_cisco.ml2_drivers.ndfc.extension_driver.'
                'get_ndfc_conf')
    @mock.patch('neutron_lib.db.api.CONTEXT_WRITER.using')
    def test_process_create_address_scope_persists_nd_vrf_name(
            self, mock_writer, mock_get_ndfc):
        ctx = mock.Mock()
        ctx.session = mock.Mock()
        (ctx.session.query.return_value
         .join.return_value
         .filter.return_value
         .all.return_value) = []

        data = {'nd-vrf-name': 'ndfc-scope', 'ip_version': 4}
        result = {'id': 'scope-id'}

        mock_ndfc = mock.Mock()
        mock_ndfc.create_vrf.return_value = True
        mock_get_ndfc.return_value = mock_ndfc

        self.driver.process_create_address_scope(ctx, data, result)

        added = ctx.session.add.call_args[0][0]
        self.assertIsInstance(added, extension_db.NdAddressScopeExtension)
        self.assertEqual('scope-id', added.address_scope_id)
        self.assertEqual('ndfc-scope', added.nd_vrf_name)

    @mock.patch('neutron_lib.db.api.CONTEXT_WRITER.using')
    def test_process_create_address_scope_skips_without_nd_vrf_name(
            self, mock_writer):
        ctx = mock.Mock()
        ctx.session = mock.Mock()

        data = {}
        result = {'id': 'scope-id'}

        self.driver.process_create_address_scope(ctx, data, result)

        ctx.session.add.assert_not_called()

    def test_extend_address_scope_dict_populates_nd_vrf_name(self):
        session = mock.Mock()
        base_model = mock.Mock()
        base_model.id = 'scope-id'
        ext_row = mock.Mock()
        ext_row.nd_vrf_name = 'nd-scope'

        (session.query.return_value
         .filter_by.return_value
         .first.return_value) = ext_row

        result = {}
        self.driver.extend_address_scope_dict(session, base_model, result)

        self.assertEqual('nd-scope', result.get('nd-vrf-name'))

    @mock.patch('networking_cisco.ml2_drivers.ndfc.extension_driver.'
                'get_ndfc_conf')
    @mock.patch('networking_cisco.ml2_drivers.ndfc.extension_driver.LOG')
    @mock.patch('neutron_lib.db.api.CONTEXT_WRITER.using')
    def test_process_create_address_scope_creates_vrf_success(
            self, mock_writer, mock_log, mock_get_ndfc_conf):
        ctx = mock.Mock()
        ctx.session = mock.Mock()

        data = {'nd-vrf-name': 'ndfc-scope'}
        result = {'id': 'scope-id'}

        mock_ndfc = mock.Mock()
        mock_ndfc.create_vrf.return_value = True
        mock_get_ndfc_conf.return_value = mock_ndfc

        self.driver.process_create_address_scope(ctx, data, result)

        mock_ndfc.create_vrf.assert_called_once_with('ndfc-scope')
        added = ctx.session.add.call_args[0][0]
        self.assertIsInstance(added, extension_db.NdAddressScopeExtension)
        self.assertEqual('scope-id', added.address_scope_id)
        self.assertEqual('ndfc-scope', added.nd_vrf_name)
        mock_log.debug.assert_any_call(
            'ND create_vrf succeeded for address scope nd-vrf-name '
            '%s (address_scope_id=%s)', 'ndfc-scope', 'scope-id')

    @mock.patch('networking_cisco.ml2_drivers.ndfc.extension_driver.'
                'get_ndfc_conf')
    @mock.patch('networking_cisco.ml2_drivers.ndfc.extension_driver.LOG')
    @mock.patch('neutron_lib.db.api.CONTEXT_WRITER.using')
    def test_process_create_address_scope_creates_vrf_failure(
            self, mock_writer, mock_log, mock_get_ndfc_conf):
        ctx = mock.Mock()
        ctx.session = mock.Mock()

        data = {'nd-vrf-name': 'ndfc-scope'}
        result = {'id': 'scope-id'}

        mock_ndfc = mock.Mock()
        mock_ndfc.create_vrf.return_value = False
        mock_get_ndfc_conf.return_value = mock_ndfc

        self.driver.process_create_address_scope(ctx, data, result)

        mock_ndfc.create_vrf.assert_called_once_with('ndfc-scope')
        added = ctx.session.add.call_args[0][0]
        self.assertIsInstance(added, extension_db.NdAddressScopeExtension)
        self.assertEqual('scope-id', added.address_scope_id)
        self.assertEqual('ndfc-scope', added.nd_vrf_name)
        mock_log.error.assert_any_call(
            'ND create_vrf failed for address scope nd-vrf-name '
            '%s (address_scope_id=%s)', 'ndfc-scope', 'scope-id')

    @mock.patch('networking_cisco.ml2_drivers.ndfc.extension_driver.'
                'get_ndfc_conf')
    @mock.patch('neutron_lib.db.api.CONTEXT_WRITER.using')
    def test_process_create_address_scope_rejects_duplicate_vrf_same_family(
            self, mock_writer, mock_get_ndfc_conf):
        ctx = mock.Mock()
        ctx.session = mock.Mock()

        data = {'nd-vrf-name': 'ndfc-scope', 'ip_version': 4}
        result = {'id': 'new-scope-id'}

        existing_scope = mock.Mock()
        existing_scope.id = 'existing-scope-id'
        existing_scope.ip_version = 4
        (ctx.session.query.return_value
         .join.return_value
         .filter.return_value
         .all.return_value) = [existing_scope]

        from neutron_lib import exceptions as n_exc
        self.assertRaises(n_exc.InvalidInput,
                          self.driver.process_create_address_scope,
                          ctx, data, result)

        mock_get_ndfc_conf.assert_not_called()
        ctx.session.add.assert_not_called()

    @mock.patch('networking_cisco.ml2_drivers.ndfc.extension_driver.'
                'get_ndfc_conf')
    @mock.patch('neutron_lib.db.api.CONTEXT_WRITER.using')
    def test_process_create_address_scope_allows_vrf_other_family(
            self, mock_writer, mock_get_ndfc_conf):
        ctx = mock.Mock()
        ctx.session = mock.Mock()

        data = {'nd-vrf-name': 'ndfc-scope', 'ip_version': 4}
        result = {'id': 'new-scope-id'}

        existing_scope = mock.Mock()
        existing_scope.id = 'existing-scope-id'
        existing_scope.ip_version = 6
        (ctx.session.query.return_value
         .join.return_value
         .filter.return_value
         .all.return_value) = [existing_scope]

        mock_ndfc = mock.Mock()
        mock_ndfc.create_vrf.return_value = True
        mock_get_ndfc_conf.return_value = mock_ndfc

        self.driver.process_create_address_scope(ctx, data, result)

        mock_ndfc.create_vrf.assert_called_once_with('ndfc-scope')
        added = ctx.session.add.call_args[0][0]
        self.assertIsInstance(added, extension_db.NdAddressScopeExtension)
        self.assertEqual('new-scope-id', added.address_scope_id)
        self.assertEqual('ndfc-scope', added.nd_vrf_name)


class TestNdMl2PluginAddressScope(testlib_api.SqlTestCase):

    def setUp(self):
        super(TestNdMl2PluginAddressScope, self).setUp()
        patcher = mock.patch.object(
            nd_ext_drv, 'NdExtensionDriver', autospec=True)
        self.addCleanup(patcher.stop)
        self.mock_driver_cls = patcher.start()
        self.mock_driver = self.mock_driver_cls.return_value

        self.plugin = nd_ml2.NdMl2Plugin()

    @mock.patch('neutron.plugins.ml2.plugin.Ml2Plugin.get_address_scope')
    def test_get_address_scope_calls_extend_hook(self, mock_get_scope):
        context = mock.Mock()
        context.session = mock.Mock()
        cm = mock.MagicMock()
        cm.__enter__.return_value = context.session
        context.session.begin = mock.MagicMock(return_value=cm)
        mock_get_scope.return_value = {'id': 'scope-id', 'name': 'foo'}

        base_model = mock.Mock(id='scope-id')
        with mock.patch.object(self.plugin, '_get_address_scope',
                               return_value=base_model):
            res = self.plugin.get_address_scope(context, 'scope-id')

        self.assertEqual('scope-id', res['id'])
        self.mock_driver.extend_address_scope_dict.assert_called_once_with(
            context.session, base_model, res)

    @mock.patch('neutron.plugins.ml2.plugin.Ml2Plugin.get_address_scopes')
    def test_get_address_scopes_calls_extend_hook_per_result(
            self, mock_get_scopes):
        context = mock.Mock()
        context.session = mock.Mock()
        cm = mock.MagicMock()
        cm.__enter__.return_value = context.session
        context.session.begin = mock.MagicMock(return_value=cm)
        scopes = [
            {'id': 'id1', 'name': 'a'},
            {'id': 'id2', 'name': 'b'},
        ]
        mock_get_scopes.return_value = scopes

        def fake_get_scope(ctx, sid):
            return mock.Mock(id=sid)

        with mock.patch.object(self.plugin, '_get_address_scope',
                               side_effect=fake_get_scope):
            res_list = self.plugin.get_address_scopes(context)

        self.assertEqual(2, len(res_list))
        calls = [
            mock.call(context.session, mock.ANY, scopes[0]),
            mock.call(context.session, mock.ANY, scopes[1]),
        ]
        self.mock_driver.extend_address_scope_dict.assert_has_calls(
            calls, any_order=True)

    @mock.patch.object(nd_manager.NdManager, 'delete_vrf_for_address_scope')
    @mock.patch('neutron.plugins.ml2.plugin.Ml2Plugin.delete_address_scope')
    def test_delete_address_scope_cleans_up_vrf(
            self, mock_base_delete, mock_delete_vrf):
        context = mock.Mock()
        session = mock.Mock()
        context.session = session
        ext_row = mock.Mock()
        ext_row.nd_vrf_name = 'vrf-1'
        query = session.query.return_value
        (query.filter_by.return_value
              .first.return_value) = ext_row
        (query.filter.return_value
              .count.return_value) = 0

        self.plugin.delete_address_scope(context, 'scope-id')

        mock_base_delete.assert_called_once_with(context, 'scope-id')
        mock_delete_vrf.assert_called_once_with('vrf-1')

    @mock.patch.object(nd_manager.NdManager, 'delete_vrf_for_address_scope')
    @mock.patch('neutron.plugins.ml2.plugin.Ml2Plugin.delete_address_scope')
    def test_delete_address_scope_keeps_vrf_when_other_scopes_exist(
            self, mock_base_delete, mock_delete_vrf):
        context = mock.Mock()
        session = mock.Mock()
        context.session = session
        ext_row = mock.Mock()
        ext_row.nd_vrf_name = 'shared-vrf'

        query = session.query.return_value
        (query.filter_by.return_value
              .first.return_value) = ext_row
        (query.filter.return_value
              .count.return_value) = 1

        self.plugin.delete_address_scope(context, 'scope-id')

        mock_base_delete.assert_called_once_with(context, 'scope-id')
        mock_delete_vrf.assert_not_called()

    @mock.patch.object(nd_manager.NdManager, 'delete_vrf_for_address_scope')
    @mock.patch('neutron.plugins.ml2.plugin.Ml2Plugin.delete_address_scope')
    def test_delete_address_scope_skips_vrf_when_no_nd_vrf_name(
            self, mock_base_delete, mock_delete_vrf):
        context = mock.Mock()
        session = mock.Mock()
        context.session = session
        (session.query.return_value
                .filter_by.return_value
                .first.return_value) = None

        self.plugin.delete_address_scope(context, 'scope-id')

        mock_base_delete.assert_called_once_with(context, 'scope-id')
        mock_delete_vrf.assert_not_called()

    @mock.patch.object(nd_manager.NdManager, 'delete_vrf_for_address_scope')
    @mock.patch('neutron_lib.context.get_admin_context')
    @mock.patch('neutron.plugins.ml2.plugin.Ml2Plugin.delete_address_scope')
    def test_delete_address_scope_uses_admin_session_when_missing(
            self, mock_base_delete, mock_get_admin_ctx, mock_delete_vrf):
        context = mock.Mock()
        context.session = None

        admin_ctx = mock.Mock()
        admin_session = mock.Mock()
        admin_ctx.session = admin_session
        mock_get_admin_ctx.return_value = admin_ctx

        ext_row = mock.Mock()
        ext_row.nd_vrf_name = 'vrf-2'
        admin_query = admin_session.query.return_value
        (admin_query.filter_by.return_value
                    .first.return_value) = ext_row
        (admin_query.filter.return_value
                    .count.return_value) = 0

        self.plugin.delete_address_scope(context, 'scope-id')

        mock_get_admin_ctx.assert_called_once_with()
        mock_base_delete.assert_called_once_with(context, 'scope-id')
        mock_delete_vrf.assert_called_once_with('vrf-2')

    @mock.patch.object(nd_manager.NdManager, 'delete_vrf_for_address_scope')
    @mock.patch('networking_cisco.plugins.ml2.nd_ml2.LOG')
    @mock.patch('neutron.plugins.ml2.plugin.Ml2Plugin.delete_address_scope')
    def test_delete_address_scope_logs_on_extension_lookup_error(
            self, mock_base_delete, mock_log, mock_delete_vrf):
        context = mock.Mock()
        session = mock.Mock()
        context.session = session

        (session.query.return_value
                .filter_by.return_value
                .first.side_effect) = Exception('db-error')

        self.plugin.delete_address_scope(context, 'scope-id')

        mock_log.exception.assert_any_call(
            'Failed to load NdAddressScopeExtension for %s', 'scope-id')
        mock_base_delete.assert_called_once_with(context, 'scope-id')
        mock_delete_vrf.assert_not_called()


class TestNdManager(testlib_api.SqlTestCase):

    @mock.patch('networking_cisco.plugins.ml2.nd_manager.get_ndfc_conf')
    def test_delete_vrf_for_address_scope_no_name(self, mock_get_ndfc_conf):
        mgr = nd_manager.NdManager()
        mgr.delete_vrf_for_address_scope(None)
        mock_get_ndfc_conf.assert_not_called()

    @mock.patch('networking_cisco.plugins.ml2.nd_manager.get_ndfc_conf')
    def test_delete_vrf_for_address_scope_success(self, mock_get_ndfc_conf):
        mgr = nd_manager.NdManager()
        mock_ndfc = mock.Mock()
        mock_ndfc.delete_vrf.return_value = True
        mock_get_ndfc_conf.return_value = mock_ndfc

        mgr.delete_vrf_for_address_scope('vrf-1')

        mock_get_ndfc_conf.assert_called_once_with()
        mock_ndfc.delete_vrf.assert_called_once_with('vrf-1')

    @mock.patch('networking_cisco.plugins.ml2.nd_manager.LOG')
    @mock.patch('networking_cisco.plugins.ml2.nd_manager.get_ndfc_conf')
    def test_delete_vrf_for_address_scope_logs_failure(
            self, mock_get_ndfc_conf, mock_log):
        mgr = nd_manager.NdManager()
        mock_ndfc = mock.Mock()
        mock_ndfc.delete_vrf.return_value = False
        mock_get_ndfc_conf.return_value = mock_ndfc

        mgr.delete_vrf_for_address_scope('vrf-1')

        mock_log.error.assert_any_call(
            'Failed to delete VRF %s in ND for address-scope cleanup',
            'vrf-1')
