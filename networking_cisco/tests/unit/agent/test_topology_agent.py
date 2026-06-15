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

from unittest import mock

from neutron.tests import base

from networking_cisco.agent import aci_topology
from networking_cisco.agent import lldp_topology
from networking_cisco.agent import nxos_topology
from networking_cisco.tests.unit.agent import topology_agent_data as tad

LLDP_CMD = ['lldpctl', '-f', 'keyvalue']
UPLINK_PORTS = ['uplink_port']


class TestTopologyAgent(base.BaseTestCase):

    @mock.patch('networking_cisco.rpc.lldp_topology.LldpTopologyServiceApi')
    def setUp(self, mock_notify):
        super(TestTopologyAgent, self).setUp()

        self.agent = lldp_topology.LldpTopologyAgent(host='host1')
        self.agent.host = 'host1'
        self.agent.lldpcmd = LLDP_CMD
        self.agent.service_agent = mock.Mock()

    def test_parse_topology(self):
        topo_test_data = (tad.TOPOLOGY_DATA_1_BYTES, tad.TOPOLOGY_DATA_2_BYTES)
        topo_interfaces = (('ens3', 'ens9', 'ens10'),
                           ('enp1s0', 'enp7s0', 'enp8s0'))
        for topo_run, topo_data in enumerate(topo_test_data):
            # Parse the topology data into nested dictionaries
            topo_dict = self.agent._parse_topology_data(topo_data)

            # Top level should be LLDP
            lldp_dict = topo_dict.get('lldp')
            self.assertIsNotNone(lldp_dict)

            interfaces = topo_interfaces[topo_run]
            for interface in interfaces:
                # Second level dict is the interface.
                interface_dict = lldp_dict.get(interface)
                self.assertIsNotNone(interface_dict)
                # Third level is where we care about specific keys:
                # * chassis
                # * port
                chassis_dict = interface_dict.get('chassis')
                self.assertIsNotNone(chassis_dict)
                port_dict = interface_dict.get('port')
                self.assertIsNotNone(port_dict)

                # Validate any chassis-level parameters
                self.assertIsNotNone(chassis_dict.get('mac'))
                self.assertIsNotNone(chassis_dict.get('name'))
                self.assertIsNotNone(chassis_dict.get('descr'))

                # Validate any port-level parameters
                #self.assertIsNotNone(port_dict.get('mac'))
                self.assertIsNotNone(port_dict.get('descr'))


class TestAciTopologyHandler(base.BaseTestCase):
    @mock.patch('networking_cisco.rpc.lldp_topology.LldpTopologyServiceApi')
    def setUp(self, mock_notify):
        super(TestAciTopologyHandler, self).setUp()

        self.agent = lldp_topology.LldpTopologyAgent(host='host1')
        self.agent.host = 'host1'
        self.agent.lldpcmd = LLDP_CMD
        self.agent.service_agent = mock.Mock()
        handler = aci_topology.AciTopologyHandler()
        handler.initialize('host1')
        self.agent.handlers = [handler]

    @mock.patch('neutron.agent.linux.ip_lib.IPDevice')
    @mock.patch('neutron.agent.linux.ip_lib.device_exists')
    def test_aci_extract_values(self, mock_exists, mock_ip_dev):
        self.ipdev = mock.Mock()
        self.mock_ip_dev = mock_ip_dev
        self.mock_ip_dev.return_value = self.ipdev
        self.mock_exists = mock_exists
        topo_dict = self.agent._parse_topology_data(tad.TOPOLOGY_DATA_1_BYTES)
        peers = self.agent.handlers[0].extract_peers(topo_dict)
        self.assertEqual(
            ('host1', 'ens9', mock.ANY, '101', 'vpc-1-39',
             'sauto_vpc_pg_2021_39', '1',
             'topology/pod-1/protpaths-101-102/pathep-[sauto_vpc_pg_2021_39]',
             'FDO232713WL'),
            peers['ens9'][0])
        self.assertEqual(
            ('host1', 'ens10', mock.ANY, '102', 'vpc-1-39',
             'sauto_vpc_pg_2021_39', '1',
             'topology/pod-1/protpaths-101-102/pathep-[sauto_vpc_pg_2021_39]',
             'FDO232716G5'),
            peers['ens10'][0])
        topo_dict = self.agent._parse_topology_data(
                tad.BAD_TOPOLOGY_DATA_1_BYTES)
        peers = self.agent.handlers[0].extract_peers(topo_dict)
        self.assertEqual(
            ('host1', 'ens9', mock.ANY, '101', 'vpc-1-39',
             'sauto_vpc_pg_2021_39', '1',
             'topology/pod-1/protpaths-101-102/pathep-[sauto_vpc_pg_2021_39]',
             'FDO232713WL'),
            peers['ens9'][0])
        self.assertIsNone(peers.get('ens10'))

    @mock.patch('neutron.agent.linux.utils.execute')
    @mock.patch('neutron.agent.linux.ip_lib.IPDevice')
    @mock.patch('neutron.agent.linux.ip_lib.device_exists')
    def test_aci_peer_update(self, mock_exists, mock_ip_dev, mock_execute):
        self.mock_execute = mock_execute
        self.mock_execute.return_value = tad.TOPOLOGY_DATA_1_BYTES
        self.ipdev = mock.Mock()
        self.mock_ip_dev = mock_ip_dev
        self.mock_ip_dev.return_value = self.ipdev
        self.mock_exists = mock_exists
        context = mock.Mock()

        # Run once to add the peers
        self.agent._check_for_new_peers(context)
        self.mock_execute.assert_called_once_with(mock.ANY, run_as_root=True)
        TS = 'topology/pod-1/protpaths-101-102/pathep-[sauto_vpc_pg_2021_39]'
        expected_calls = [
             mock.call(context, 'host1', 'ens9', mock.ANY,
                 '101', 'vpc-1-39', 'sauto_vpc_pg_2021_39', '1', TS,
                 'FDO232713WL'),
             mock.call(context, 'host1', 'ens10', mock.ANY,
                 '102', 'vpc-1-39', 'sauto_vpc_pg_2021_39', '1', TS,
                 'FDO232716G5')]

        self.agent.service_agent.update_link.assert_has_calls(
                expected_calls, any_order=False)

        # Get ready for next run
        self.mock_execute.reset_mock()
        self.agent.service_agent.update_link.reset_mock()
        # Drop one of the links in the VPC (ens10), and put
        # the other link on a new port.
        topo_data = tad.TOPOLOGY_DATA_1
        new_topo_data = []
        for line in topo_data.splitlines():
            # skip the ens10 interfacew
            if 'ens10' in line:
                continue
            if 'sauto_vpc_pg_2021_39' in line:
                new_line = line.replace('sauto_vpc_pg_2021_39',
                                        'sauto_vpc_pg_2021_40')
            elif 'Eth1/39' in line:
                new_line = line.replace('Eth1/39', 'Eth1/40')
            else:
                new_line = line
            new_topo_data.append(new_line)
        topo_data = '\n'.join(new_topo_data)
        self.mock_execute.return_value = topo_data

        self.agent._check_for_new_peers(context)
        self.mock_execute.assert_called_once_with(mock.ANY, run_as_root=True)
        TS = 'topology/pod-1/protpaths-101-102/pathep-[sauto_vpc_pg_2021_40]'
        expected_calls = [
             mock.call(context, 'host1', 'ens9', mock.ANY, 0, 0, 0, 0, ''),
             mock.call(context, 'host1', 'ens9', mock.ANY,
                 '101', 'vpc-1-40', 'sauto_vpc_pg_2021_40', '1', TS,
                 'FDO232713WL'),
             mock.call(context, 'host1', 'ens10', mock.ANY, 0, 0, 0, 0, '')]

        self.agent.service_agent.update_link.assert_has_calls(
                expected_calls, any_order=False)


class TestNxosTopologyHandler(base.BaseTestCase):
    @mock.patch('networking_cisco.rpc.lldp_topology.LldpTopologyServiceApi')
    def setUp(self, mock_notify):
        super(TestNxosTopologyHandler, self).setUp()

        self.agent = lldp_topology.LldpTopologyAgent('host1')
        self.agent.host = 'host1'
        self.agent.lldpcmd = LLDP_CMD
        self.agent.service_agent = mock.Mock()
        handler = nxos_topology.NxosTopologyHandler()
        handler.initialize('host1')
        self.agent.handlers = [handler]

    @mock.patch('neutron.agent.linux.ip_lib.IPDevice')
    @mock.patch('neutron.agent.linux.ip_lib.device_exists')
    def test_nxos_extract_values(self, mock_exists, mock_ip_dev):
        self.ipdev = mock.Mock()
        self.mock_ip_dev = mock_ip_dev
        self.mock_ip_dev.return_value = self.ipdev
        self.mock_exists = mock_exists
        topo_dict = self.agent._parse_topology_data(tad.TOPOLOGY_DATA_2_BYTES)
        peers = self.agent.handlers[0].extract_peers(topo_dict)
        self.assertEqual(
            ('host1', 'enp7s0', '80:6a:00:73:41:54', '172.28.9.26',
             'padkrish-9-26', 'Ethernet1/5', 0, 0, 'FLM2616092G'),
            peers['enp7s0'][0])
        self.assertEqual(
            ('host1', 'enp8s0', 'cc:d3:42:d3:fa:4a', '172.28.9.244',
             'padkrish-9-244', 'Ethernet1/34', 0, 0, 'FLM2738011Z'),
            peers['enp8s0'][0])
        topo_dict = self.agent._parse_topology_data(
                tad.BAD_TOPOLOGY_DATA_2_BYTES)
        peers = self.agent.handlers[0].extract_peers(topo_dict)
        self.assertEqual(
            ('host1', 'enp7s0', '80:6a:00:73:41:54', '172.28.9.26',
             'padkrish-9-26', 'Ethernet1/5', 0, 0, 'FLM2616092G'),
            peers['enp7s0'][0])
        self.assertIsNone(peers.get('enp8s0'))

    @mock.patch('neutron.agent.linux.utils.execute')
    @mock.patch('neutron.agent.linux.ip_lib.IPDevice')
    @mock.patch('neutron.agent.linux.ip_lib.device_exists')
    def test_nxospeer_update(self, mock_exists, mock_ip_dev, mock_execute):
        self.mock_execute = mock_execute
        self.mock_execute.return_value = tad.TOPOLOGY_DATA_2_BYTES
        self.ipdev = mock.Mock()
        self.mock_ip_dev = mock_ip_dev
        self.mock_ip_dev.return_value = self.ipdev
        self.mock_exists = mock_exists
        context = mock.Mock()

        # Run once to add the peers
        self.agent._check_for_new_peers(context)
        self.mock_execute.assert_called_once_with(mock.ANY, run_as_root=True)
        expected_calls = [
             mock.call(context, 'host1', 'enp7s0', '80:6a:00:73:41:54',
                       '172.28.9.26', 'padkrish-9-26', 'Ethernet1/5', 0, 0,
                       'FLM2616092G'),
             mock.call(context, 'host1', 'enp8s0', 'cc:d3:42:d3:fa:4a',
                       '172.28.9.244', 'padkrish-9-244', 'Ethernet1/34', 0, 0,
                       'FLM2738011Z')]

        self.agent.service_agent.update_link.assert_has_calls(
                expected_calls, any_order=False)

        # Get ready for next run
        self.mock_execute.reset_mock()
        self.agent.service_agent.update_link.reset_mock()

        # Drop one of the links in the VPC, and put the other on a new port.
        topo_data = tad.TOPOLOGY_DATA_2
        new_topo_data = []
        for line in topo_data.splitlines():
            # skip the ens10 interfacew
            if 'enp8s0' in line:
                continue
            if 'Ethernet1/5' in line:
                new_line = line.replace('Ethernet1/5', 'Ethernet1/6')
            else:
                new_line = line
            new_topo_data.append(new_line)
        topo_data = '\n'.join(new_topo_data)
        self.mock_execute.return_value = topo_data
        # This should look like
        self.agent._check_for_new_peers(context)
        self.mock_execute.assert_called_once_with(mock.ANY, run_as_root=True)
        expected_calls = [
             mock.call(context, 'host1', 'enp7s0', None, 0, 0, 0, 0, ''),
             mock.call(context, 'host1', 'enp7s0', '80:6a:00:73:41:54',
                       '172.28.9.26', 'padkrish-9-26', 'Ethernet1/6', 0, 0,
                       'FLM2616092G'),
             mock.call(context, 'host1', 'enp8s0', None, 0, 0, 0, 0, '')]

        self.agent.service_agent.update_link.assert_has_calls(
                expected_calls, any_order=False)


class TestNxosNetworkLabelDiscovery(base.BaseTestCase):

    def setUp(self):
        super(TestNxosNetworkLabelDiscovery, self).setUp()
        self.handler = nxos_topology.NxosTopologyHandler()
        self.handler.host = 'compute5'

    @mock.patch('neutron.agent.linux.utils.execute')
    def test_get_bridge_mappings_from_ovsdb(self, mock_execute):
        mock_execute.return_value = 'physnet1:br-ex,physnet3:br-nfs'

        result = self.handler._get_bridge_mappings_from_ovsdb()

        self.assertEqual('physnet1:br-ex,physnet3:br-nfs', result)
        mock_execute.assert_called_once_with(
            ['ovs-vsctl', 'get', 'Open_vSwitch', '.',
                'external_ids:ovn-bridge-mappings'],
            run_as_root=True)

    @mock.patch('neutron.agent.linux.utils.execute')
    def test_get_bridge_mappings_from_ovsdb_cached(self, mock_execute):
        self.handler.bridge_mappings_cache = 'cached_value'

        result = self.handler._get_bridge_mappings_from_ovsdb()

        self.assertEqual('cached_value', result)
        mock_execute.assert_not_called()

    @mock.patch('neutron.agent.linux.utils.execute')
    def test_get_bridge_mappings_from_ovsdb_error(self, mock_execute):
        mock_execute.side_effect = Exception('OVSDB error')

        result = self.handler._get_bridge_mappings_from_ovsdb()

        self.assertIsNone(result)

    @mock.patch.object(nxos_topology.NxosTopologyHandler, '_get_port_type')
    @mock.patch('neutron.agent.linux.utils.execute')
    def test_discover_ovs_bridge_ports(self, mock_execute, mock_get_port_type):
        mock_execute.side_effect = [
            'br-ex\nbr-nfs',
            'bond0',
            'bond1'
        ]
        mock_get_port_type.return_value = 'system'

        result = self.handler._discover_ovs_bridge_ports()

        self.assertEqual(2, len(result))
        self.assertEqual(['bond0'], result['br-ex'])
        self.assertEqual(['bond1'], result['br-nfs'])

    @mock.patch('neutron.agent.linux.utils.execute')
    def test_discover_ovs_bridge_ports_no_bridges(self, mock_execute):
        mock_execute.return_value = ''

        result = self.handler._discover_ovs_bridge_ports()

        self.assertEqual({}, result)

    @mock.patch.object(nxos_topology.NxosTopologyHandler, '_get_port_type')
    @mock.patch('neutron.agent.linux.utils.execute')
    def test_get_network_labels_full_flow(self, mock_execute,
            mock_get_port_type):
        mock_execute.side_effect = [
            'physnet1:br-ex,physnet3:br-nfs',
            'br-ex\nbr-nfs',
            'bond0',
            'bond1'
        ]
        mock_get_port_type.return_value = 'system'

        result = self.handler.get_network_labels()

        self.assertEqual(2, len(result))
        self.assertIn(('physnet1', 'bond0'), result)
        self.assertIn(('physnet3', 'bond1'), result)

    @mock.patch('neutron.agent.linux.utils.execute')
    def test_get_network_labels_no_ovsdb_mappings(self, mock_execute):
        mock_execute.return_value = ''

        result = self.handler.get_network_labels()

        self.assertEqual([], result)

    @mock.patch.object(nxos_topology.NxosTopologyHandler, '_get_port_type')
    @mock.patch('neutron.agent.linux.utils.execute')
    def test_get_network_labels_multiple_interfaces_per_bridge(
            self, mock_execute, mock_get_port_type):
        mock_execute.side_effect = [
            'physnet1:br-ex',
            'br-ex',
            'bond0\nbond1'
        ]
        mock_get_port_type.return_value = 'system'

        result = self.handler.get_network_labels()

        self.assertEqual(2, len(result))
        self.assertIn(('physnet1', 'bond0'), result)
        self.assertIn(('physnet1', 'bond1'), result)

    @mock.patch.object(nxos_topology.NxosTopologyHandler, '_get_port_type')
    @mock.patch('neutron.agent.linux.utils.execute')
    def test_get_network_labels_bridge_not_found(self, mock_execute,
            mock_get_port_type):
        mock_execute.side_effect = [
            'physnet1:br-nonexistent',
            'br-ex',
            'bond0'
        ]
        mock_get_port_type.return_value = 'system'

        result = self.handler.get_network_labels()

        self.assertEqual([], result)

    @mock.patch.object(nxos_topology.NxosTopologyHandler, '_get_port_type')
    @mock.patch('neutron.agent.linux.utils.execute')
    def test_discover_ovs_bridge_ports_excludes_br_int(
            self, mock_execute, mock_get_port_type):
        mock_execute.side_effect = [
            'br-ex\nbr-int\nbr-nfs',
            'bond0',
            'bond1'
        ]
        mock_get_port_type.return_value = 'system'

        result = self.handler._discover_ovs_bridge_ports()

        self.assertEqual(2, len(result))
        self.assertIn('br-ex', result)
        self.assertIn('br-nfs', result)
        self.assertNotIn('br-int', result)

    @mock.patch.object(nxos_topology.NxosTopologyHandler, '_get_port_type')
    @mock.patch('neutron.agent.linux.utils.execute')
    def test_discover_ovs_bridge_ports_filters_patch_ports(
            self, mock_execute, mock_get_port_type):
        mock_execute.side_effect = [
            'br-ex',
            'bond0\npatch-provnet-to-br-int'
        ]
        mock_get_port_type.side_effect = ['system', 'patch']

        result = self.handler._discover_ovs_bridge_ports()

        self.assertEqual(1, len(result))
        self.assertEqual(['bond0'], result['br-ex'])

    @mock.patch.object(nxos_topology.NxosTopologyHandler, '_get_port_type')
    @mock.patch('neutron.agent.linux.utils.execute')
    def test_discover_ovs_bridge_ports_filters_internal_ports(
            self, mock_execute, mock_get_port_type):
        mock_execute.side_effect = [
            'br-ex',
            'bond0\novn-comput-0'
        ]
        mock_get_port_type.side_effect = ['system', 'internal']

        result = self.handler._discover_ovs_bridge_ports()

        self.assertEqual(1, len(result))
        self.assertEqual(['bond0'], result['br-ex'])

    @mock.patch('neutron.agent.linux.utils.execute')
    def test_get_port_type_system(self, mock_execute):
        mock_execute.return_value = ''

        result = self.handler._get_port_type('bond0')

        self.assertEqual('system', result)
        mock_execute.assert_called_once_with(
            ['ovs-vsctl', 'get', 'Interface', 'bond0', 'type'],
            run_as_root=True)

    @mock.patch('neutron.agent.linux.utils.execute')
    def test_get_port_type_patch(self, mock_execute):
        mock_execute.return_value = '"patch"'

        result = self.handler._get_port_type('patch-port')

        self.assertEqual('patch', result)

    @mock.patch('neutron.agent.linux.utils.execute')
    def test_get_port_type_internal(self, mock_execute):
        mock_execute.return_value = 'internal'

        result = self.handler._get_port_type('ovn-port')

        self.assertEqual('internal', result)

    @mock.patch('neutron.agent.linux.utils.execute')
    def test_get_port_type_error_defaults_to_system(self, mock_execute):
        mock_execute.side_effect = Exception('Port not found')

        result = self.handler._get_port_type('unknown-port')

        self.assertEqual('system', result)

    @mock.patch('os.path.isdir')
    def test_is_bond_interface_true(self, mock_isdir):
        mock_isdir.return_value = True

        result = self.handler._is_bond_interface('bond0')

        self.assertTrue(result)
        mock_isdir.assert_called_once_with('/sys/class/net/bond0/bonding')

    @mock.patch('os.path.isdir')
    def test_is_bond_interface_false(self, mock_isdir):
        mock_isdir.return_value = False

        result = self.handler._is_bond_interface('enp1s0f0')

        self.assertFalse(result)

    @mock.patch('builtins.open', new_callable=mock.mock_open,
                read_data='enp4s0f0 enp4s0f1')
    def test_get_bond_slaves(self, mock_file):
        result = self.handler._get_bond_slaves('bond0')

        self.assertEqual(['enp4s0f0', 'enp4s0f1'], result)
        mock_file.assert_called_once_with(
            '/sys/class/net/bond0/bonding/slaves', 'r')

    @mock.patch('builtins.open')
    def test_get_bond_slaves_error_returns_empty_list(self, mock_file):
        mock_file.side_effect = Exception('File not found')

        result = self.handler._get_bond_slaves('bond0')

        self.assertEqual([], result)

    @mock.patch.object(nxos_topology.NxosTopologyHandler,
            '_is_bond_interface')
    @mock.patch.object(nxos_topology.NxosTopologyHandler,
            '_get_bond_slaves')
    @mock.patch.object(nxos_topology.NxosTopologyHandler, '_get_port_type')
    @mock.patch('neutron.agent.linux.utils.execute')
    def test_get_network_labels_expands_bond_interfaces(
            self, mock_execute, mock_get_port_type, mock_get_bond_slaves,
            mock_is_bond):
        mock_execute.side_effect = [
            'physnet1:br-ex',
            'br-ex',
            'bond0'
        ]
        mock_get_port_type.return_value = 'system'
        mock_is_bond.return_value = True
        mock_get_bond_slaves.return_value = ['enp4s0f0', 'enp4s0f1']

        result = self.handler.get_network_labels()

        self.assertEqual(2, len(result))
        self.assertIn(('physnet1', 'enp4s0f0'), result)
        self.assertIn(('physnet1', 'enp4s0f1'), result)
        mock_get_bond_slaves.assert_called_once_with('bond0')

    @mock.patch.object(nxos_topology.NxosTopologyHandler,
            '_is_bond_interface')
    @mock.patch.object(nxos_topology.NxosTopologyHandler, '_get_port_type')
    @mock.patch('neutron.agent.linux.utils.execute')
    def test_get_network_labels_non_bond_interface(
            self, mock_execute, mock_get_port_type, mock_is_bond):
        mock_execute.side_effect = [
            'physnet1:br-ex',
            'br-ex',
            'enp1s0f0'
        ]
        mock_get_port_type.return_value = 'system'
        mock_is_bond.return_value = False

        result = self.handler.get_network_labels()

        self.assertEqual(1, len(result))
        self.assertIn(('physnet1', 'enp1s0f0'), result)

    @mock.patch.object(nxos_topology.NxosTopologyHandler, '_get_port_type')
    @mock.patch('neutron.agent.linux.utils.execute')
    def test_discover_ovs_bridge_ports_custom_exclusion_regex(
            self, mock_execute, mock_get_port_type):
        mock_execute.side_effect = [
            'br-ex',
            'bond0\nmy-tunnel-port'
        ]
        mock_get_port_type.side_effect = ['system', 'tunnel']

        with mock.patch('oslo_config.cfg.CONF') as mock_conf:
            mock_conf.lldp_topology_agent.topology_excluded_bridges = []
            regex_pattern = '^(patch|internal|tunnel)$'
            mock_lldp = mock_conf.lldp_topology_agent
            mock_lldp.topology_excluded_port_types_regex = regex_pattern

            result = self.handler._discover_ovs_bridge_ports()

        self.assertEqual(1, len(result))
        self.assertEqual(['bond0'], result['br-ex'])
