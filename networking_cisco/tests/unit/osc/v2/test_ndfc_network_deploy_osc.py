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

from argparse import ArgumentParser
from argparse import Namespace
from unittest import mock

from osc_lib import exceptions as osc_exc
from osc_lib.tests import utils as osc_utils

from networking_cisco.osc.v2 import network as ndfc_osc_network


class TestNdfcOscNetworkDeploy(osc_utils.TestCommand):

    def setUp(self):
        super(TestNdfcOscNetworkDeploy, self).setUp()

    def test_get_attrs_nd_adds_sync_status(self):
        parsed_args = Namespace(nd_status='SYNC')

        client_mgr = mock.Mock()

        with mock.patch.object(ndfc_osc_network, '_get_attrs_orig',
                               return_value={}):
            attrs = ndfc_osc_network._get_attrs_nd(client_mgr, parsed_args)

        self.assertEqual('SYNC', attrs.get('nd-status'))

    def test_get_attrs_nd_rejects_non_sync_status(self):
        parsed_args = Namespace(nd_status='SUCCESS')
        client_mgr = mock.Mock()

        with mock.patch.object(ndfc_osc_network, '_get_attrs_orig',
                               return_value={}):
            self.assertRaises(
                osc_exc.CommandError,
                ndfc_osc_network._get_attrs_nd,
                client_mgr,
                parsed_args)

    def test_get_attrs_nd_ignores_missing_nd_status(self):
        parsed_args = Namespace()
        client_mgr = mock.Mock()

        with mock.patch.object(ndfc_osc_network, '_get_attrs_orig',
                               return_value={}):
            attrs = ndfc_osc_network._get_attrs_nd(client_mgr, parsed_args)

        self.assertNotIn('nd-status', attrs)


class TestSetNetworkNdStatusHook(osc_utils.TestCommand):

    def setUp(self):
        super(TestSetNetworkNdStatusHook, self).setUp()
        cmd = mock.Mock()
        self.hook = ndfc_osc_network.SetNetworkNdStatus(cmd)

    def test_before_returns_parsed_args_when_nd_status_missing(self):
        parsed_args = Namespace(foo='bar')
        result = self.hook.before(parsed_args)
        self.assertIs(result, parsed_args)

    def test_before_rejects_non_nd_network(self):
        parsed_args = Namespace(network='net1', nd_status='SYNC')

        net = Namespace(id='net1', provider_network_type='vxlan')
        network_proxy = mock.Mock()
        network_proxy.find_network.return_value = net

        client_mgr = mock.Mock()
        client_mgr.network = network_proxy

        app = mock.Mock()
        app.client_manager = client_mgr
        self.hook.cmd.app = app

        self.assertRaises(osc_exc.CommandError, self.hook.before, parsed_args)

    def test_before_allows_sync_for_nd_network(self):
        parsed_args = Namespace(network='net1', nd_status='SYNC')

        net = Namespace(id='net1', provider_network_type='nd')
        network_proxy = mock.Mock()
        network_proxy.find_network.return_value = net

        client_mgr = mock.Mock()
        client_mgr.network = network_proxy

        app = mock.Mock()
        app.client_manager = client_mgr
        self.hook.cmd.app = app

        result = self.hook.before(parsed_args)
        self.assertIs(result, parsed_args)

    def test_after_noop_when_base_command_failed(self):
        parsed_args = Namespace(nd_status='FAILED')
        rc = self.hook.after(parsed_args, return_code=1)
        self.assertEqual(1, rc)

    def test_after_returns_zero_when_base_command_succeeds(self):
        parsed_args = Namespace(nd_status='SUCCESS')
        rc = self.hook.after(parsed_args, return_code=0)
        self.assertEqual(0, rc)


class TestShowNetworkNdStatusHook(osc_utils.TestCommand):

    def setUp(self):
        super(TestShowNetworkNdStatusHook, self).setUp()
        cmd = mock.Mock()
        self.hook = ndfc_osc_network.SetNetworkNdStatus(cmd)

    def test_get_parser_passthrough(self):
        parser = ArgumentParser(prog='test-network-show')
        result = self.hook.get_parser(parser)
        self.assertIs(result, parser)

    def test_before_after_passthrough(self):
        parsed_args = Namespace()
        rc_in = 0

        parsed_out = self.hook.before(parsed_args)
        rc_out = self.hook.after(parsed_args, rc_in)

        self.assertIs(parsed_out, parsed_args)
        self.assertEqual(rc_in, rc_out)
