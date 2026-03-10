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

from networking_cisco.plugins.ml2 import nd_manager


class TestNdManagerNetworkExtension(testlib_api.SqlTestCase):

    def setUp(self):
        super(TestNdManagerNetworkExtension, self).setUp()
        self.manager = nd_manager.NdManager()

    def test_extend_network_no_ext_driver(self):
        del self.manager._ext_driver

        session = mock.Mock()
        base_model = mock.Mock()
        result = {}

        self.manager.extend_network(session, base_model, result)

    def test_extend_network_no_extend_network_dict(self):
        self.manager._ext_driver = object()

        session = mock.Mock()
        base_model = mock.Mock()
        result = {}

        self.manager.extend_network(session, base_model, result)

    def test_extend_network_delegates_to_driver(self):
        driver = mock.Mock()
        self.manager._ext_driver = driver

        session = mock.Mock()
        base_model = mock.Mock()
        result = {'id': 'net-id'}

        self.manager.extend_network(session, base_model, result)

        driver.extend_network_dict.assert_called_once_with(
            session, base_model, result
        )


class TestNdManagerAddressScopeHelpers(testlib_api.SqlTestCase):

    def setUp(self):
        super(TestNdManagerAddressScopeHelpers, self).setUp()
        self.manager = nd_manager.NdManager()

    def test_handle_address_scope_create_no_ext_driver(self):
        del self.manager._ext_driver
        ctx = mock.Mock()
        body = {'address_scope': 'body'}
        result = {'id': 'as-id'}
        self.manager.handle_address_scope_create(ctx, body, result)

    def test_handle_address_scope_create_no_handler(self):
        self.manager._ext_driver = object()
        ctx = mock.Mock()
        body = {'address_scope': 'body'}
        result = {'id': 'as-id'}
        self.manager.handle_address_scope_create(ctx, body, result)

    def test_handle_address_scope_create_delegates(self):
        driver = mock.Mock()
        self.manager._ext_driver = driver
        ctx = mock.Mock()
        body = {'address_scope': 'body'}
        result = {'id': 'as-id'}

        self.manager.handle_address_scope_create(ctx, body, result)

        driver.process_create_address_scope.assert_called_once_with(
            ctx, body, result
        )

    def test_extend_address_scope_delegates(self):
        driver = mock.Mock()
        self.manager._ext_driver = driver
        session = mock.Mock()
        base_model = mock.Mock()
        result = {'id': 'as-id'}

        self.manager.extend_address_scope(session, base_model, result)

        driver.extend_address_scope_dict.assert_called_once_with(
            session, base_model, result
        )

    @mock.patch('networking_cisco.plugins.ml2.nd_manager.get_ndfc_conf')
    def test_delete_vrf_for_address_scope_happy_path(self, mock_get_conf):
        ndfc = mock.Mock()
        ndfc.delete_vrf.return_value = True
        mock_get_conf.return_value = ndfc

        self.manager.delete_vrf_for_address_scope('vrf-name')

        ndfc.delete_vrf.assert_called_once_with('vrf-name')
