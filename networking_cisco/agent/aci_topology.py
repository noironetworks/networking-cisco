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

import re

from oslo_config import cfg

from networking_cisco.agent import lldp_topology


ACI_CHASSIS_DESCR_FORMAT = 'topology/pod-(\d+)/node-(\d+)'
ACI_PORT_DESCR_FORMATS = [
    'topology/pod-(\d+)/node-(\d+)/sys/conng/path-\[eth(\d+)/(\d+(\/\d+)*)\]',
    'topology/pod-(\d+)/paths-(\d+)/pathep-\[eth(\d+)/(\d+(\/\d+)*)\]',
]
ACI_PORT_LOCAL_FORMAT = 'Eth(\d+)/(\d+(\/\d+)*)'
ACI_VPCPORT_DESCR_FORMAT = ('topology/pod-(\d+)/protpaths-(\d+)-(\d+)/pathep-'
                            '\[(.*)\]')
VPCMODULE_NAME = 'vpc-%s-%s'


class AciTopologyHandler(lldp_topology.LldpTopologyHandler):
    """ACI LLDP Topology Handler

    For ACI, peers are identified with the following fields:
    * host
    * receiving interface
    * mac of receiving interface
    * switch
    * module
    * port
    * POD ID
    * port description

    Or:
    * host
    * receiving interface
    * mac of receiving interface
    * switch
    * VPC module
    * bundle
    * POD ID
    * port description

    Where:
    * The switch is extracted from the port.descr field for non-VPC
      configurations, and from the chassis.descr for VPC configurations
    * The module is extracted from the contents of the port.descr field
    * The bundle is extraced from the port.descr field (the part in brackets)
    * The VPC module is extracted from the contents of the port.local field,
      (only present when the connection is a VPC)
    * The POD ID is extracted from the port.descr field
    * The port description is from the port.descr field
    """
    def __init__(self):
        super(AciTopologyHandler, self).__init__()

        self.conf = cfg.CONF.lldp_topology_agent
        self.port_desc_re = list(map(re.compile, ACI_PORT_DESCR_FORMATS))
        self.port_local_re = re.compile(ACI_PORT_LOCAL_FORMAT)
        self.vpcport_desc_re = re.compile(ACI_VPCPORT_DESCR_FORMAT)
        self.chassis_desc_re = re.compile(ACI_CHASSIS_DESCR_FORMAT)

    def _get_serial_number(self, interface_dict):
        value = interface_dict.get('unknown-tlvs', {}).get(
                'unknown-tlv', {}).get('oui', {}).get(
                '00,01,42', {}).get('subtype', {}).get('212', {}).get('value')
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
            sn = self._get_serial_number(interfaces[interface])
            port_dict = interfaces[interface].get('port')
            if port_dict and port_dict.get('descr'):
                value = port_dict['descr']
                port_desc = value
                # First check for single-link formats
                for regexp in self.port_desc_re:
                    match = regexp.match(value)
                    if match:
                        mac = self._get_mac(interface)
                        pod_id, switch, module, port = match.group(1, 2, 3, 4)
                        peer = (self.host, interface, mac,
                                switch, module, port, pod_id, port_desc, sn)
                        peer_list = peers.setdefault(interface, [])
                        peer_list.append(peer)
                # Now check for (virtual) port channel format
                match = self.vpcport_desc_re.match(value)
                if match:
                    mac = self._get_mac(interface)
                    pod_id, switch1, switch2, bundle = match.group(1, 2, 3, 4)
                    switch, module, port = None, None, None
                    chassis = interfaces[interface].get('chassis')
                    if bundle is not None and chassis.get('descr'):
                        value = chassis['descr']
                        match = self.chassis_desc_re.match(value)
                        if match:
                            switch = match.group(2)
                        if (switch is not None and port_dict.get('local')):
                            value = port_dict['local']
                            match = self.port_local_re.match(value)
                            if match:
                                module, port = match.group(1, 2)
                            if module is not None and port is not None:
                                vpcmodule = VPCMODULE_NAME % (
                                    module, port)
                                peer = (self.host, interface, mac,
                                        switch, vpcmodule, bundle,
                                        pod_id, port_desc, sn)
                                peer_list = peers.setdefault(interface, [])
                                peer_list.append(peer)
        return peers
