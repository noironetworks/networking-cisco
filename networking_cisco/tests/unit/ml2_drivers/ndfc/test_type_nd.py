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

from networking_cisco.backwards_compatibility import ml2_api as api

from networking_cisco.ml2_drivers.ndfc import constants as const
from networking_cisco.ml2_drivers.ndfc import type_nd

from neutron.tests.unit import testlib_api


class NdfcNdTypeTest(testlib_api.SqlTestCase):

    def setUp(self):
        super(NdfcNdTypeTest, self).setUp()
        # Ensure a deterministic default ND physnet for tests.
        type_nd.cfg.CONF.set_override(
            'default_nd_network', 'physnet-nd', group='ml2_type_nd')

        self.driver = type_nd.NdfcNdTypeDriver()

    def test_get_type(self):
        self.assertEqual(const.TYPE_ND, self.driver.get_type())

    def test_allocate_tenant_segment_uses_default_physnet(self):
        segment = self.driver.allocate_tenant_segment(session=None)
        self.assertEqual(const.TYPE_ND, segment[api.NETWORK_TYPE])
        self.assertEqual('physnet-nd', segment[api.PHYSICAL_NETWORK])
        # MTU should be an int (0 if nothing is configured).
        self.assertIsInstance(segment[api.MTU], int)

    def test_validate_provider_segment_requires_physnet(self):
        segment = {api.NETWORK_TYPE: const.TYPE_ND}
        self.assertRaises(
            type_nd.exc.InvalidInput,
            self.driver.validate_provider_segment,
            segment,
        )

    def test_validate_provider_segment_rejects_segmentation_id(self):
        segment = {
            api.NETWORK_TYPE: const.TYPE_ND,
            api.PHYSICAL_NETWORK: 'physnet-nd',
            api.SEGMENTATION_ID: 1234,
        }
        self.assertRaises(
            type_nd.exc.InvalidInput,
            self.driver.validate_provider_segment,
            segment,
        )

    def test_reserve_provider_segment_sets_mtu(self):
        segment = {
            api.NETWORK_TYPE: const.TYPE_ND,
            api.PHYSICAL_NETWORK: 'physnet-nd',
        }
        result = self.driver.reserve_provider_segment(session=None,
                                                      segment=segment)
        self.assertEqual(const.TYPE_ND, result[api.NETWORK_TYPE])
        self.assertEqual('physnet-nd', result[api.PHYSICAL_NETWORK])
        self.assertIsInstance(result[api.MTU], int)
