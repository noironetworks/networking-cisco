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

from networking_cisco.ml2_drivers.ndfc import constants as ndfc_const
from networking_cisco.ml2_drivers.ndfc import extension_db
from networking_cisco.ml2_drivers.ndfc import extension_driver as nd_ext_drv
from networking_cisco.ml2_drivers.ndfc.extensions import (
    ndfc_network_deploy as nd_net_ext
)


class TestNdfcNetworkDeployExtensionDriver(testlib_api.SqlTestCase):

    def setUp(self):
        super(TestNdfcNetworkDeployExtensionDriver, self).setUp()
        self.driver = nd_ext_drv.NdExtensionDriver()

    @mock.patch('neutron_lib.db.api.CONTEXT_WRITER.using')
    def test_process_create_network_persists_nd_status_for_nd_network(
            self, mock_writer):
        ctx = mock.Mock()
        ctx.session = mock.Mock()
        (ctx.session.query.return_value
         .filter_by.return_value
         .first.return_value) = None

        data = {'nd-status': 'SUCCESS'}
        result = {
            'id': 'net-id',
            'provider:network_type': ndfc_const.TYPE_ND,
        }

        self.driver.process_create_network(ctx, data, result)

        added = ctx.session.add.call_args[0][0]
        self.assertIsInstance(added, extension_db.NdNetworkExtension)
        self.assertEqual('net-id', added.network_id)
        self.assertEqual('SUCCESS', added.nd_status)

    @mock.patch('neutron_lib.db.api.CONTEXT_WRITER.using')
    def test_process_create_network_skips_when_no_nd_status(self, mock_writer):
        ctx = mock.Mock()
        ctx.session = mock.Mock()

        data = {}
        result = {
            'id': 'net-id',
            'provider:network_type': ndfc_const.TYPE_ND,
        }

        self.driver.process_create_network(ctx, data, result)

        ctx.session.add.assert_not_called()

    @mock.patch('neutron_lib.db.api.CONTEXT_WRITER.using')
    def test_process_create_network_skips_for_non_nd_network(
            self, mock_writer):
        ctx = mock.Mock()
        ctx.session = mock.Mock()

        data = {'nd-status': 'SUCCESS'}
        result = {
            'id': 'net-id',
            'provider:network_type': 'vxlan',
        }

        self.driver.process_create_network(ctx, data, result)

        ctx.session.add.assert_not_called()

    @mock.patch('neutron_lib.db.api.CONTEXT_WRITER.using')
    def test_process_update_network_updates_existing_row(self, mock_writer):
        ctx = mock.Mock()
        ctx.session = mock.Mock()

        ext_row = mock.Mock()
        ext_row.nd_status = 'FAILED'
        (ctx.session.query.return_value
         .filter_by.return_value
         .first.return_value) = ext_row

        data = {'nd-status': 'SUCCESS'}
        result = {
            'id': 'net-id',
            'provider:network_type': ndfc_const.TYPE_ND,
        }

        self.driver.process_update_network(ctx, data, result)

        ctx.session.add.assert_not_called()
        self.assertEqual('SUCCESS', ext_row.nd_status)

    def test_extend_network_dict_populates_nd_status(self):
        session = mock.Mock()
        base_model = mock.Mock()
        base_model.id = 'net-id'
        ext_row = mock.Mock()
        ext_row.nd_status = 'SYNC'

        (session.query.return_value
         .filter_by.return_value
         .first.return_value) = ext_row

        result = {
            'id': 'net-id',
            'provider:network_type': ndfc_const.TYPE_ND,
        }

        self.driver.extend_network_dict(session, base_model, result)

        self.assertEqual('SYNC', result.get('nd-status'))

    def test_extend_network_dict_skips_for_non_nd_network(self):
        session = mock.Mock()
        base_model = mock.Mock()
        base_model.id = 'net-id'

        result = {
            'id': 'net-id',
            'provider:network_type': 'vxlan',
        }

        self.driver.extend_network_dict(session, base_model, result)

        session.query.assert_not_called()
        self.assertNotIn('nd-status', result)


class TestNdfcNetworkDeployExtensionDescriptor(testlib_api.SqlTestCase):

    def test_descriptor_alias_and_extended_resources(self):
        self.assertEqual('nd-network-deploy', nd_net_ext.ALIAS)
        self.assertEqual('nd-network-deploy',
                         nd_net_ext.Ndfc_network_deploy.get_alias())

        resources = nd_net_ext.Ndfc_network_deploy.get_extended_resources(
                '2.0')
        self.assertIn('networks', resources)
        self.assertIn(nd_net_ext.ND_STATUS, resources['networks'])

        self.assertEqual({},
                         nd_net_ext.Ndfc_network_deploy.get_extended_resources(
                             '1.0'))
