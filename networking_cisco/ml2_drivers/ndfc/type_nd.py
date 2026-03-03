# Copyright 2026 Cisco Systems, Inc.
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

from neutron.plugins.ml2.drivers import helpers
from neutron_lib import exceptions as exc
from neutron_lib.plugins.ml2 import api
from oslo_config import cfg
from oslo_log import log as logging

from networking_cisco._i18n import _
from networking_cisco.ml2_drivers.ndfc import constants as const

LOG = logging.getLogger(__name__)


nd_opts = [
    cfg.StrOpt('default_nd_network',
               default='physnet1',
               help=_('Default ND network (physical network) for tenants.')),
]

cfg.CONF.register_opts(nd_opts, 'ml2_type_nd')


class NdfcNdTypeDriver(helpers.BaseTypeDriver):

    def __init__(self):
        LOG.info('ML2 NdfcNdTypeDriver initialization complete')
        self.default_nd_network = cfg.CONF.ml2_type_nd.default_nd_network
        super(NdfcNdTypeDriver, self).__init__()

    def get_type(self):
        return const.TYPE_ND

    def initialize(self):
        pass

    def initialize_network_segment_range_support(self):
        pass

    def update_network_segment_range_allocations(self):
        pass

    def get_network_segment_ranges(self):
        pass

    def is_partial_segment(self, segment):
        return False

    def validate_provider_segment(self, segment):
        physical_network = segment.get(api.PHYSICAL_NETWORK)
        if not physical_network:
            msg = _("physical_network required for ND provider network")
            raise exc.InvalidInput(error_message=msg)

        for key, value in segment.items():
            if value and key not in [api.NETWORK_TYPE,
                                     api.PHYSICAL_NETWORK,
                                     api.MTU]:
                msg = _('%s prohibited for ND provider network') % key
                raise exc.InvalidInput(error_message=msg)

    def reserve_provider_segment(self, session, segment, filters=None):
        segment[api.MTU] = self.get_mtu(segment[api.PHYSICAL_NETWORK])
        return segment

    def allocate_tenant_segment(self, session, filters=None):
        physnet = self.default_nd_network
        return {
            api.NETWORK_TYPE: const.TYPE_ND,
            api.PHYSICAL_NETWORK: physnet,
            api.MTU: self.get_mtu(physnet),
        }

    def release_segment(self, session, segment):
        pass

    def get_mtu(self, physical_network):
        seg_mtu = super(NdfcNdTypeDriver, self).get_mtu()
        mtu = []
        if seg_mtu > 0:
            mtu.append(seg_mtu)
        if physical_network in self.physnet_mtus:
            mtu.append(int(self.physnet_mtus[physical_network]))
        return min(mtu) if mtu else 0
