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
