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

from networking_cisco.agent import lldp_topology

NXOS_STRING = 'Cisco Nexus Operating System'


class NxosTopologyHandler(lldp_topology.LldpTopologyHandler):
    """NXOS LLDP Topology Handler

    For ND/NxOS, peers are identified with the following fields:
    * host
    * receiving interface
    * switch IP
    * switch MAC
    * switch name
    * switch_port

    Where:
    * The switch IP comes from the chassis.mgmt-ip
    * The switch MAC comes from the chassis.mac
    * The switch name comes from the chassis.name
    * The switch port comes from port.descr
    """

    def __init__(self):
        super(NxosTopologyHandler, self).__init__()

    def _get_serial_number(self, interface_dict):
        value = interface_dict.get('unknown-tlvs', {}).get(
                'unknown-tlv', {}).get('oui', {}).get(
                '00,01,42', {}).get('subtype', {}).get('8', {}).get('value')
        if not value:
            return None
        sn_string = ''
        for hex_char in value.split(','):
            byte_char = bytes.fromhex(hex_char)
            sn_string += byte_char.decode('ASCII')
        return sn_string

    def extract_peers(self, topo_dict):
        peers = {}
        interfaces = {}
        lldp_dict = topo_dict.get('lldp')
        for key, value in lldp_dict.items():
            if_dict = interfaces.setdefault(key, {})
            if_dict.update(value)

        for interface in interfaces:
            # Only include peers that are NxOS
            chassis_dict = interfaces[interface].get('chassis')
            if NXOS_STRING not in chassis_dict.get('descr', ''):
                continue
            sys_name = chassis_dict.get('name')
            mgmt_ip = chassis_dict.get('mgmt-ip')
            mac = chassis_dict.get('mac')
            port_dict = interfaces[interface].get('port')
            port = port_dict.get('ifname')
            sn = self._get_serial_number(interfaces[interface])
            peer = (self.host, interface, mac,
                    mgmt_ip, sys_name, port, 0, 0, sn)
            peer_list = peers.setdefault(interface, [])
            peer_list.append(peer)
        return peers
