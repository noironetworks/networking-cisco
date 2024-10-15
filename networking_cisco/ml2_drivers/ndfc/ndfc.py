# Copyright 2024 Cisco Systems, Inc.
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

from oslo_log import log

LOG = log.getLogger(__name__)

glob_nwk_map = {}


class Ndfc(object):
    '''
    NDFC class.
    '''
    def __init__(self, ndfc_ip, user, pwd, fabric):
        pass

    def create_vrf(self, vrf_name):
        return 1

    def delete_vrf(self, vrf_name):
        return 1

    def create_network(self, vrf_name, network_name, vlan, physnet):
        return 1

    def update_network(self, vrf_name, network_name, vlan, gw, physnet):
        return 1

    def delete_network(self, network_name, vlan, physnet):
        return 1

    def attach_network(self, vrf_name, network_name,
            vlan_id, topology_result):
        return 1

    def detach_network(self, vrf_name, network_name,
            vlan_id, topology_result):
        return 1
