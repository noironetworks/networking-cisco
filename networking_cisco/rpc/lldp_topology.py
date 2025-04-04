# Copyright (c) 2024 Cisco Systems Inc.
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

import oslo_messaging

from neutron_lib import rpc

TOPIC_LLDP_TOPOLOGY_SERVICE = 'lldp-topology-service'
VERSION = '1.0'


class LldpTopologyServiceApi(object):
    """Client side API for topology notifications

    This implements the client neutron RPC calls for topology
    updates from agents.
    """

    def __init__(self):
        target = oslo_messaging.Target(topic=TOPIC_LLDP_TOPOLOGY_SERVICE,
                                       version=VERSION)
        self.client = rpc.get_client(target)

    def update_link(self, context, host, interface, mac, switch, module, port,
                    pod_id, port_description='', serial_number=''):
        cctxt = self.client.prepare(version=VERSION)
        return cctxt.call(context, 'update_link', host=host,
                          interface=interface,
                          mac=mac, switch=switch, module=module, port=port,
                          pod_id=pod_id, port_description=port_description,
                          serial_number=serial_number)

    def delete_link(self, context, host, interface):
        cctxt = self.client.prepare(version=VERSION)
        return cctxt.call(context, 'delete_link', host=host,
                          interface=interface,
                          mac=None, switch=0, module=0, port=0)
