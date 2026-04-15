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

from argparse import Namespace
from unittest import mock

from osc_lib import exceptions
from osc_lib.tests import utils as osc_utils

from networking_cisco.osc.v2 import address_scope as nd_osc_addr_scope


class TestNdOscAddressScope(osc_utils.TestCommand):

    def setUp(self):
        super(TestNdOscAddressScope, self).setUp()

    def test_get_attrs_nd_adds_nd_vrf_name(self):
        parsed_args = Namespace(nd_vrf_name='nd-scope')

        client_mgr = mock.Mock()

        with mock.patch.object(nd_osc_addr_scope, '_get_attrs_orig',
                               return_value={}):
            attrs = nd_osc_addr_scope._get_attrs_nd(client_mgr,
                                                    parsed_args)

        self.assertEqual('nd-scope', attrs.get('nd-vrf-name'))

    def test_create_before_rejects_nd_vrf_name_with_share(self):
        hook = nd_osc_addr_scope.CreateAddressScopeNd(None)

        parsed_args = Namespace(nd_vrf_name='nd-scope', share=True)

        self.assertRaises(exceptions.CommandError, hook.before, parsed_args)

    def test_create_before_allows_nd_vrf_name_without_share(self):
        hook = nd_osc_addr_scope.CreateAddressScopeNd(None)

        parsed_args = Namespace(nd_vrf_name='nd-scope', share=False)

        result = hook.before(parsed_args)
        self.assertIs(result, parsed_args)
