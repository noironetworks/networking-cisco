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

import os
import re

from neutron.agent.linux import utils as linux_utils
from neutron_lib.utils import helpers as lib_helpers
from oslo_config import cfg
from oslo_log import log as logging

from networking_cisco.agent import lldp_topology

NXOS_STRING = 'Cisco Nexus Operating System'
LOG = logging.getLogger(__name__)


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
        self.bridge_to_interfaces = {}
        self.bridge_mappings_cache = None

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
        if not lldp_dict:
            return peers
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
            if not sn:
                continue
            peer = (self.host, interface, mac,
                    mgmt_ip, sys_name, port, 0, 0, sn)
            peer_list = peers.setdefault(interface, [])
            peer_list.append(peer)
        return peers

    def _get_bridge_mappings_from_ovsdb(self):
        if self.bridge_mappings_cache is not None:
            return self.bridge_mappings_cache

        try:
            output = linux_utils.execute(
                ['ovs-vsctl', 'get', 'Open_vSwitch', '.',
                 'external_ids:ovn-bridge-mappings'],
                run_as_root=True)
            bridge_mappings = output.strip().strip('"')
            self.bridge_mappings_cache = bridge_mappings
            LOG.info("Retrieved bridge mappings from OVSDB: %s",
                    bridge_mappings)
            return bridge_mappings
        except Exception as e:
            LOG.warning("Failed to get bridge mappings from OVSDB: %s", e)
            return None

    def _discover_ovs_bridge_ports(self):
        bridge_ports = {}
        excluded_bridges = (
            cfg.CONF.lldp_topology_agent.topology_excluded_bridges)
        excluded_port_pattern = (
            cfg.CONF.lldp_topology_agent.topology_excluded_port_types_regex)

        try:
            excluded_regex = re.compile(excluded_port_pattern)
        except re.error as e:
            LOG.warning("Invalid port type exclusion regex '%s': %s, "
                        "using default", excluded_port_pattern, e)
            excluded_regex = re.compile('^(patch|internal)$')

        try:
            output = linux_utils.execute(
                ['ovs-vsctl', 'list-br'], run_as_root=True)
            bridges = output.strip().split('\n') if output.strip() else []

            for bridge in bridges:
                if not bridge:
                    continue
                if bridge in excluded_bridges:
                    LOG.debug("Skipping excluded bridge: %s", bridge)
                    continue

                output = linux_utils.execute(
                    ['ovs-vsctl', 'list-ports', bridge], run_as_root=True)
                ports = [p.strip() for p in output.strip().split('\n')
                        if p.strip()]

                physical_ports = []
                for port in ports:
                    port_type = self._get_port_type(port)
                    if excluded_regex.match(port_type):
                        LOG.debug("Skipping port %s (type: %s) on bridge %s",
                                port, port_type, bridge)
                        continue
                    physical_ports.append(port)

                if physical_ports:
                    bridge_ports[bridge] = physical_ports
                    LOG.debug(
                        "Discovered OVS bridge %s with physical ports: %s",
                        bridge, physical_ports)
        except Exception as e:
            LOG.warning("Failed to discover OVS bridge ports: %s", e)

        return bridge_ports

    def _get_port_type(self, port_name):
        try:
            output = linux_utils.execute(
                ['ovs-vsctl', 'get', 'Interface', port_name, 'type'],
                run_as_root=True)
            port_type = output.strip().strip('"')
            return port_type if port_type else 'system'
        except Exception:
            return 'system'

    def _is_bond_interface(self, interface):
        bonding_path = '/sys/class/net/{}/bonding'.format(interface)
        return os.path.isdir(bonding_path)

    def _get_bond_slaves(self, bond_interface):
        try:
            slaves_path = '/sys/class/net/{}/bonding/slaves'.format(
                bond_interface)
            with open(slaves_path, 'r') as f:
                slaves = f.read().strip().split()
            LOG.debug("Bond %s has slaves: %s", bond_interface, slaves)
            return slaves
        except Exception:
            LOG.debug("Failed to read bond slaves for %s", bond_interface)
            return []

    def get_network_labels(self):
        bridge_mappings_str = self._get_bridge_mappings_from_ovsdb()
        if not bridge_mappings_str:
            LOG.debug("No bridge mappings found in OVSDB")
            return []

        try:
            bridge_mappings = lib_helpers.parse_mappings(
                bridge_mappings_str.split(','))
        except ValueError as exc:
            LOG.warning("Invalid bridge_mappings '%s': %s",
                        bridge_mappings_str, exc)
            return []

        if not bridge_mappings:
            LOG.debug("No valid bridge mappings after parsing")
            return []

        self.bridge_to_interfaces = self._discover_ovs_bridge_ports()

        network_labels = []
        for physnet, bridge in bridge_mappings.items():
            interfaces = self.bridge_to_interfaces.get(bridge, [])
            if not interfaces:
                LOG.debug("No interfaces found for bridge %s (physnet %s)",
                        bridge, physnet)
                continue

            for interface in interfaces:
                if self._is_bond_interface(interface):
                    slaves = self._get_bond_slaves(interface)
                    if slaves:
                        for slave in slaves:
                            network_labels.append((physnet, slave))
                            LOG.info(
                                "Network label mapping: %s -> %s "
                                "(bond %s, bridge %s)",
                                physnet, slave, interface, bridge)
                    else:
                        LOG.warning(
                            "Bond interface %s has no slaves, skipping",
                            interface)
                else:
                    network_labels.append((physnet, interface))
                    LOG.info("Network label mapping: %s -> %s (bridge %s)",
                            physnet, interface, bridge)

        return network_labels
