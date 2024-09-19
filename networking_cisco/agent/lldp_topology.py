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

from oslo_config import cfg
from oslo_log import log as logging
from oslo_service import periodic_task
from oslo_utils import importutils

from neutron.agent.linux import ip_lib
from neutron.agent.linux import utils
from neutron import manager
from neutron_lib.utils import net as net_utils

from networking_cisco.rpc import lldp_topology

AGENT_FORCE_UPDATE_COUNT = 5
BINARY_LLDP_TOPOLOGY_AGENT = 'neutron-lldp_topology-agent'
TYPE_LLDP_TOPOLOGY_AGENT = 'cisco-lldp-topology-agent'
TOPIC_LLDP_SERVICE = 'lldp-service'

LOG = logging.getLogger(__name__)

lldp_topology_opts = [
    cfg.ListOpt('topology_uplink_ports',
                default=[],
                help=_('The uplink ports to check for connectivity')),
    cfg.FloatOpt('topology_agent_poll_interval',
                 default=60,
                 help=_('Interval between agent poll for topology (in sec)')),
    cfg.FloatOpt('topology_agent_report_interval',
                 default=60,
                 help=_('Interval between agent status updates (in sec)')),
    cfg.ListOpt('topology_handlers',
                default=[],
                help=_("An ordered list of topology handlers to be loaded.")),
]

cfg.CONF.register_opts(lldp_topology_opts, "lldp_topology_agent")


class LldpTopologyAgent(manager.Manager):
    """LLDP Topology Agent

    The agent provides the LLDP information for the host. It uses the
    contents of the LLDP packets received, as well as the interface that
    they were received on, and uses that to report topology between the
    host running this agent and the peer interface that it's cconnected
    to.

    The agent will automatically send the current topology after a fixed
    number of iterations, regardless of whether the topology changed or
    not, in order to ensure that the server doesn't get out of sync with
    the agents.

    The agent keeps a dictionary of local interfaces, where the key is
    the name of the interface on the host, and the value is the MAC address
    of the interface.
    """
    def __init__(self, host=None):
        if host is None:
            host = net_utils.get_hostname()
        super(LldpTopologyAgent, self).__init__(host=host)

        self.host = host
        self.conf = cfg.CONF.lldp_topology_agent
        self.count_current = 0
        self.count_force_send = AGENT_FORCE_UPDATE_COUNT
        self.peers = {}
        self.handlers = []
        self.uplink_ports = []
        self.invalid_peers = []
        self._vlan = None
        self.state = None
        self.lldpcmd = None
        self.state_agent = None
        self._unknown_tlv = None

        self.topic = TOPIC_LLDP_SERVICE
        self.service_agent = lldp_topology.LldpTopologyServiceApi()

    def init_host(self):
        LOG.info("LLDP topology agent: agent starting on %s", self.host)
        self.state = {
            'binary': BINARY_LLDP_TOPOLOGY_AGENT,
            'host': self.host,
            'topic': self.topic,
            'configurations': {},
            'start_flag': True,
            'agent_type': TYPE_LLDP_TOPOLOGY_AGENT,
        }
        for handler in cfg.CONF.lldp_topology_agent.topology_handlers:
            handler_obj = importutils.import_object(handler)
            handler_obj.initialize(self.host)
            self.handlers.append(handler_obj)

        self.uplink_ports = []
        for inf in self.conf.topology_uplink_ports:
            if ip_lib.device_exists(inf):
                self.uplink_ports.append(inf)
            else:
                # ignore unknown interfaces
                LOG.error("No such interface (ignored): %s", inf)
        self.lldpcmd = ['lldpctl', '-f', 'keyvalue'] + self.uplink_ports

    def after_start(self):
        LOG.info("LLDP topology agent: started on %s", self.host)

    def _handle_unknown_tlv(self, curr_dict, key_hierarchy, key, value):
        # If we're parsing a new unknown TLV, create a dict for it
        if not self._unknown_tlv:
            self._unknown_tlv = {}
        # continue navigation if not the final key
        if key != key_hierarchy[-1]:
            key = key_hierarchy[-1]
        if key == 'unknown-tlv':
            self._unknown_tlv['value'] = value
        else:
            self._unknown_tlv[key] = value

        # If this is the last element for a full object, add
        # it to our dictionary
        if ('oui' in self._unknown_tlv and
                'len' in self._unknown_tlv and
                'subtype' in self._unknown_tlv and
                'value' in self._unknown_tlv):
            curr_dict = curr_dict.setdefault('unknown-tlvs', {})
            curr_dict = curr_dict.setdefault('unknown-tlv', {})
            curr_dict = curr_dict.setdefault('oui', {})
            curr_dict = curr_dict.setdefault(self._unknown_tlv['oui'], {})
            curr_dict = curr_dict.setdefault('subtype', {})
            curr_dict = curr_dict.setdefault(self._unknown_tlv['subtype'], {})
            curr_dict.update({'len': self._unknown_tlv['len'],
                              'value': self._unknown_tlv['value']})
            self._unknown_tlv = None

    def _handle_vlan(self, curr_dict, key_hierarchy, key, value):
        if not self._vlan:
            self._vlan = {}
        key = key_hierarchy[-1]
        self._vlan[key] = value

        # If this is the last element for a full object, add
        # it to our dictionary
        if 'vlan-id' in self._vlan and 'pvid' in self._vlan:
            vlan_id = self._vlan['vlan-id']
            curr_dict = curr_dict.setdefault('vlan', {})
            curr_dict = curr_dict.setdefault(vlan_id, {})
            curr_dict.update(self._vlan)
            self._vlan = None

    def _parse_topology_data(self, topo_data):
        """Handle formatted LLDPd output

        The organizatgion of the LLDP daemon's "lldpctl" formatted  output is
        terrible.  Its kind enough to provide things in a hierarchical format,
        which lends itself to dictionary formatting, but then gives you things
        like this:

        lldp.enp7s0.unknown-tlvs.unknown-tlv.oui=00,01,42
        lldp.enp7s0.unknown-tlvs.unknown-tlv.subtype=1
        lldp.enp7s0.unknown-tlvs.unknown-tlv.len=1
        lldp.enp7s0.unknown-tlvs.unknown-tlv=01
        lldp.enp7s0.unknown-tlvs.unknown-tlv.oui=00,01,42
        lldp.enp7s0.unknown-tlvs.unknown-tlv.subtype=8
        lldp.enp7s0.unknown-tlvs.unknown-tlv.len=11
        lldp.enp7s0.unknown-tlvs.unknown-tlv=46,4C,4D,32,36,31,36,30,39,32,47

        This might be tolerable, as you could special-case the unknown-tlv
        elements, but then you get things like this:

        lldp.enp8s0.vlan.vlan-id=814
        lldp.enp8s0.vlan.pvid=no
        lldp.enp8s0.vlan=VLAN0814
        lldp.enp8s0.vlan.vlan-id=1
        lldp.enp8s0.vlan.pvid=yes

        The intent of the above is a list of two VLAN entries:
        * VLAN 1, pvid is yes
        * VLAN 814, pvid is no

        But then there is just "VLAN0814", which makes it hard to know for sure
        which element it belongs to (other than matching the VLAN).
        """

        topo_dict = {}
        for line in topo_data.splitlines():
            if '=' not in line or not line.startswith('lldp'):
                continue
            # Split line into period-delimited key and the value
            key, value = line.split('=', 1)
            # Split key
            key_hierarchy = key.split('.')
            curr_dict = topo_dict
            special_case = False
            for key in key_hierarchy[:-1]:
                if key == 'unknown-tlv' or (key == 'unknown-tlvs' and
                        key_hierarchy[-1] == 'unknown-tlv'):
                    # Special case handling for unknown TLVs
                    self._handle_unknown_tlv(curr_dict,
                                             key_hierarchy, key, value)
                    special_case = True
                    break
                elif (key_hierarchy[-1] == 'vlan' and
                        key == key_hierarchy[-2]):
                    # Special case: ignore non-keyed VLAN fields
                    special_case = True
                    continue
                elif (key == 'vlan' and 'lldp-med' not in key_hierarchy):
                    self._handle_vlan(curr_dict,
                                      key_hierarchy, key, value)
                    special_case = True
                    break
                else:
                    curr_dict = curr_dict.setdefault(key, {})
            # If there is already a value, see if we need to turn it
            # into a list of values
            final_key = key_hierarchy[-1]
            if special_case:
                continue
            if curr_dict.get(final_key):
                if not isinstance(curr_dict[final_key], list):
                    curr_dict[final_key] = [curr_dict[final_key], value]
                # If it's already a list, just append this item
                elif isinstance(curr_dict, list):
                    curr_dict[final_key].append(value)
            # Else its brand new, so just add the key-value pair
            else:
                curr_dict[final_key] = value
        return topo_dict

    def _get_peers(self):
        topo_data = utils.execute(self.lldpcmd, run_as_root=True)
        topo_dict = self._parse_topology_data(topo_data)
        all_peers = {}
        for handler in self.handlers:
            peers = handler.extract_peers(topo_dict)
            if peers:
                all_peers.update(peers)
        return all_peers

    def _valid_peers(self, peers):
        # Reduce the peers array to one valid peer per interface
        # NOTE:
        # There is a bug in lldpd daemon that it keeps reporting
        # old peers even after their updates have stopped
        # we keep track of that report remove them from peers

        valid_peers = {}
        invalid_peers = []
        for interface in peers:
            curr_peer = None
            for peer in peers[interface]:
                if peer in self.invalid_peers or curr_peer:
                    invalid_peers.append(peer)
                else:
                    curr_peer = peer
            if curr_peer is not None:
                valid_peers[interface] = curr_peer

        self.invalid_peers = invalid_peers
        return valid_peers

    @periodic_task.periodic_task(
        spacing=cfg.CONF.lldp_topology_agent.topology_agent_poll_interval,
        run_immediately=True)
    def _check_for_new_peers(self, context):
        LOG.debug("LLDP topology agent: _check_for_new_peers")

        if not self.lldpcmd:
            return
        try:
            # Check if we must send update even if there is no change
            force_send = False
            self.count_current += 1
            if self.count_current >= self.count_force_send:
                force_send = True

            # Check for new peers
            new_peers = self._get_peers()
            new_peers = self._valid_peers(new_peers)

            # Keep a copy of current peers
            curr_peers = dict(self.peers)
            # Based on curr -> new updates, add the new interfaces
            self.peers = {}
            for interface, peer in new_peers.items():
                # Add or update the peer
                self.peers[interface] = peer
                # If the contents of a known peer have changed,
                # send a peer update with no topology, which acts
                # like a removal/delete.
                if (interface in curr_peers and
                        curr_peers[interface] != peer):
                    LOG.info('reporting peer removal: %s', peer)
                    self.service_agent.update_link(
                        context, peer[0], peer[1], None, 0, 0, 0, 0, '')
                    self.count_current = 0
                # If the it's a new peer, or the peer changed, or if we're
                # forced to send, provide the current peer connectivity
                if (interface not in curr_peers or
                        curr_peers[interface] != peer or
                        force_send):
                    LOG.info('reporting new peer: %s', peer)
                    self.service_agent.update_link(context, *peer)
                    self.count_current = 0
                # If the interface from the new peeris already in our list of
                # current peers, then we flag it as processed by removing it
                # from the list of current peers
                if interface in curr_peers:
                    curr_peers.pop(interface)

            # Any interface still in curr_peers means that it wasn't found in
            # new peers, which means it needs to be deleted
            for peer in list(curr_peers.values()):
                LOG.info('reporting peer removal: %s', peer)
                self.service_agent.update_link(
                    context, peer[0], peer[1], None, 0, 0, 0, 0, '')
                self.count_current = 0

        except Exception:
            LOG.exception("LLDP topology agent: exception in LLDP parsing")
            # Force update
            self.count_current = float('inf')

    def report_send(self, context):
        if not self.state_agent:
            return
        LOG.debug("LLDP topology agent: sending report state")

        try:
            self.state_agent.report_state(context, self.state)
            self.state.pop('start_flag', None)
        except AttributeError:
            # This means the server does not support report_state
            # ignore it
            return
        except Exception:
            LOG.exception("LLDP topology agent: failed in reporting state")


class LldpTopologyHandler(object):
    """Topology hander base class

    Base class that can be specialized to parse LLDP data
    for switches. The specialization should implement the
    extract_peers method to process the dictionary of
    topology data that was collected by the agent.
    """

    def __init__(self):
        super(LldpTopologyHandler, self).__init__()
        self.interfaces = {}

    def initialize(self, host):
        self.host = host

    def _get_mac(self, interface):
        if interface in self.interfaces:
            return self.interfaces[interface]
        try:
            mac = ip_lib.IPDevice(interface).link.address
            self.interfaces[interface] = mac
            return mac
        except Exception:
            # we can safely ignore it, it is only needed for debugging
            LOG.exception(
                "LLDP topology agent: can not get MACaddr for %s",
                interface)

    def extract_peers(self, topo_dict):
        pass
