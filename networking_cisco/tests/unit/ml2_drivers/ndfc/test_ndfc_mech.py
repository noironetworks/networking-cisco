# Copyright 2025 Cisco Systems, Inc.
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

import abc
import os
from unittest import mock

from keystoneclient.v3 import client as ksc_client
from neutron.tests.unit.db import test_db_base_plugin_v2 as test_pluginV2
from neutron_lib.api.definitions import portbindings
from neutron_lib.api.definitions import segment
from neutron_lib import constants
from neutron_lib.plugins import directory

from networking_cisco.ml2_drivers.ndfc.cache import ProjectDetailsCache
from networking_cisco.ml2_drivers.ndfc import config as ndfc_conf
from networking_cisco.ml2_drivers.ndfc import db as nc_ml2_db
from networking_cisco.ml2_drivers.ndfc import mech_ndfc
from networking_cisco.ml2_drivers.ndfc import ndfc
from neutron.common import config
from neutron.tests.unit import fake_resources as fakes
from neutron.tests.unit.plugins.ml2 import test_plugin


class MechDriverSetupBase(abc.ABC):
    def setUp(self):
        config.register_common_config_options()
        super(MechDriverSetupBase, self).setUp()


TEST_TENANT_NAMES = {
    'another_tenant': 'AnotherTenantName',
    'bad_tenant_id': 'BadTenantIdName',
    'not_admin': 'NotAdminName',
    'some_tenant': 'SomeTenantName',
    'somebody_else': 'SomebodyElseName',
    't1': 'T1Name',
    'tenant1': 'Tenant1Name',
    'tenant_1': 'Tenant1Name',
    'tenant_2': 'Tenant2Name',
    'test-tenant': 'TestTenantName',
    'ten_1': 'prj_ten_1',
    'ten_2': 'prj_ten_2',
    test_pluginV2.TEST_TENANT_ID: test_pluginV2.TEST_TENANT_ID,
}


TEST_LEAF_ATTACHMENTS = {
    'FDO24170Q2T':
    {
        'tor_sw_intf_map':
        {
            'FDO24230D5G': {
                'tor_interfaces': ['Port-channel11'],
                'tor_name': '65-N9336FX2'},
            'FDO24230DAX': {'tor_interfaces':
                ['Port-channel11'], 'tor_name': '66-N9332FX2'}
        }
    },
    'FDO24170TNU':
    {
        'tor_sw_intf_map':
        {
            'FDO24230D5G': {
                'tor_interfaces': ['Port-channel11'],
                'tor_name': '65-N9336FX2'},
            'FDO24230DAX': {
                'tor_interfaces': ['Port-channel11'],
                'tor_name': '66-N9332FX2'}}
    }
}


current_directory = os.getcwd()
tenants_file = os.path.join(current_directory, 'tenants.json')


class FakeProject(object):
    def __init__(self, id, name, description='bad\"\'descr'):
        self.id = id
        self.name = name
        self.description = description


class FakeProjectManager(object):
    _instance = None

    def __init__(self):
        self._projects = {k: FakeProject(k, v)
                          for k, v in list(TEST_TENANT_NAMES.items())}

    def list(self):
        return list(self._projects.values())

    def get(self, project_id):
        return self._projects.get(project_id)

    @classmethod
    def reset(cls):
        cls._instance = None

    @classmethod
    def get_instance(cls):
        if not cls._instance:
            cls._instance = FakeProjectManager()
        return cls._instance

    @classmethod
    def set(cls, project_id, name, description=''):
        cls.get_instance()._projects[project_id] = FakeProject(
            project_id, name, description)


class FakeKeystoneClient(object):
    def __init__(self, **kwargs):
        self.projects = FakeProjectManager.get_instance()


class TestNDFCMechanismDriverBase(MechDriverSetupBase,
        test_plugin.Ml2PluginV2TestCase):

    _mechanism_drivers = ['ndfc']


class TestNDFCMechanismDriver(TestNDFCMechanismDriverBase):
    def setUp(self):
        ndfc_conf.register_opts()
        ndfc_conf.cfg.CONF.set_override('fabric_name',
                'SgmScale', group='ndfc')
        ndfc_conf.cfg.CONF.set_override('ndfc_ip', '172.28.9.19',
                group='ndfc')
        self.mock_keystone_auth = mock.patch.object(
            ProjectDetailsCache, 'get_auth', return_value=None).start()
        super(TestNDFCMechanismDriver, self).setUp()
        mm = directory.get_plugin().mechanism_manager
        self.ndfc_mech = mm.mech_drivers['ndfc'].obj
        self.context = mock.MagicMock()
        self.ndfc_mech.ndfc.ndfc_obj.get_po = mock.MagicMock(return_value='10')
        self.ndfc_mech.ndfc.ndfc_obj.get_switches = mock.MagicMock(
            return_value={
                '192.168.1.1':
                {
                    'serial': '123',
                    'ip': '192.168.1.1',
                    'role': 'tor',
                    'name': 'Switch1',
                    'tor_leaf_nodes': {'leaf1': 'sn1'},
                    'tor_leaf_intf': {'leaf1': 'intf1'}
                }
            }
        )
        FakeProjectManager.reset()
        self.saved_keystone_client = ksc_client.Client
        ksc_client.Client = FakeKeystoneClient

    def _create_fake_network_context(self,
                                     network_type,
                                     physical_network=None,
                                     segmentation_id=None):
        network_attrs = {'provider:network_type': network_type,
                         'provider:physical_network': physical_network,
                         'provider:segmentation_id': segmentation_id}
        segment_attrs = {'network_type': network_type,
                         'physical_network': physical_network,
                         'segmentation_id': segmentation_id}
        fake_network = \
            fakes.FakeNetwork.create_one_network(attrs=network_attrs).info()
        fake_segments = \
            [fakes.FakeSegment.create_one_segment(attrs=segment_attrs).info()]
        return fakes.FakeNetworkContext(fake_network, fake_segments)

    def _create_fake_subnet_context(self,
                                    network_id,
                                    cidr,
                                    old_network_id=None,
                                    old_cidr=None):
        subnet_attrs = {'network_id': network_id,
                        'gateway_ip': cidr}
        fake_subnet = \
            fakes.FakeSubnet.create_one_subnet(attrs=subnet_attrs).info()
        if old_network_id:
            old_subnet_attrs = {'network_id': old_network_id,
                                'gateway_ip': old_cidr}
            fake_old_subnet = fakes.FakeSubnet.create_one_subnet(
                    attrs=old_subnet_attrs).info()
            return fakes.FakeSubnetContext(fake_subnet, fake_old_subnet)
        return fakes.FakeSubnetContext(fake_subnet)

    @mock.patch.object(directory, 'get_plugin')
    def test_get_network(self, mock_get_plugin):
        fake_network_id = 'fake-network-id'
        expected_network = fakes.FakeNetwork.create_one_network(
                {'id': fake_network_id}).info()

        mock_plugin = mock.Mock()
        mock_plugin.get_network.return_value = expected_network
        mock_get_plugin.return_value = mock_plugin

        network = self.ndfc_mech.get_network(self.context, fake_network_id)

        self.assertEqual(network, expected_network)
        mock_plugin.get_network.assert_called_once_with(
                self.context._plugin_context, fake_network_id)

    @mock.patch.object(mech_ndfc.NDFCMechanismDriver, 'get_network')
    @mock.patch.object(ProjectDetailsCache, 'get_project_details',
            return_value=['mock_vrf_name'])
    @mock.patch.object(ndfc.Ndfc, 'create_network')
    @mock.patch.object(ndfc.Ndfc, 'update_network')
    @mock.patch.object(ndfc.Ndfc, 'delete_network')
    def test_network_postcommit(self, *args):
        # Test create and delete network postcommit methods
        fake_network_context = self._create_fake_network_context('local')
        self.ndfc_mech.create_network_postcommit(fake_network_context)
        self.ndfc_mech.delete_network_postcommit(fake_network_context)

        # Test create and delete network with physical network
        fake_network_context = self._create_fake_network_context('local',
                'physnet1')
        self.ndfc_mech.create_network_postcommit(fake_network_context)
        self.ndfc_mech.delete_network_postcommit(fake_network_context)

        # Test create, update and delete subnet postcommit methods
        self.mock_get_network = fake_network_context.current
        fake_subnet_context = self._create_fake_subnet_context(
                'fake-network-id', '10.10.10.0/24')
        self.ndfc_mech.create_subnet_postcommit(fake_subnet_context)
        fake_subnet_context = self._create_fake_subnet_context(
                'fake-network-id', '20.20.20.0/24',
                'fake-network-id', '10.10.10.0/24')
        self.ndfc_mech.update_subnet_postcommit(fake_subnet_context)
        self.ndfc_mech.delete_subnet_postcommit(fake_subnet_context)

    @mock.patch.object(mech_ndfc.NDFCMechanismDriver, 'get_topology')
    @mock.patch.object(ndfc.Ndfc, 'attach_network')
    @mock.patch.object(ndfc.Ndfc, 'detach_network')
    @mock.patch.object(ndfc.Ndfc, 'get_vrf_vlan')
    def test_port_postcommit(self, mock_get_vrf_vlan, mock_detach_network,
            mock_attach_network, mock_get_topology):
        # Test update and delete port postcommit methods
        self.mock_get_topology = TEST_LEAF_ATTACHMENTS
        mock_attach_network.return_value = True
        mock_detach_network.return_value = True
        mock_get_vrf_vlan.return_value = '100'

        fake_network_context = self._create_fake_network_context('vlan',
                'physnet1', '10')
        original_port = fakes.FakePort.create_one_port(
            attrs={'binding:vif_type': portbindings.VIF_TYPE_UNBOUND}).info()
        current_port = fakes.FakePort.create_one_port(
            attrs={'binding:vif_type': portbindings.VIF_TYPE_OVS}).info()
        fake_port_context = mock.Mock(current=current_port,
                original=original_port)
        fake_port_context.network = fake_network_context
        fake_port_context.host = 'current-host'
        fake_port_context.original_host = 'original-host'

        self.ndfc_mech.update_port_postcommit(fake_port_context)
        mock_attach_network.assert_called_once()
        mock_detach_network.reset_mock()
        self.ndfc_mech.delete_port_postcommit(fake_port_context)
        mock_detach_network.assert_called_once()

    @mock.patch.object(ndfc.Ndfc, 'create_vrf')
    @mock.patch.object(ndfc.Ndfc, 'delete_vrf')
    def test_keystone_notification_endpoint(self, *args):
        payload = {}

        payload['resource_info'] = 'test-tenant'
        keystone_ep = mech_ndfc.KeystoneNotificationEndpoint(self.ndfc_mech)

        # Test with project.created event.
        FakeProjectManager.set('test-tenant',
            'tenant1', 'bad\"\'descr')
        keystone_ep.info(None, None, 'identity.project.created', payload, None)

        # Test with project.deleted event.
        keystone_ep.info(None, None, 'identity.project.deleted', payload, None)

        payload['resource_info'] = 'test-tenant2'
        FakeProjectManager.set('test-tenant2',
            'tenant2', 'bad\"\'descr')
        keystone_ep.info(None, None, 'identity.project.created', payload, None)

    @mock.patch('neutron_lib.db.api.CONTEXT_WRITER.using')
    def test_update_link_no_switch(self, mock_db_writer):
        self.ndfc_mech.update_link(self.context, 'host1', 'intf1',
                'mac1', '', '', '', '', '', 'serial1')
        mock_db_writer.assert_not_called()

    @mock.patch('neutron_lib.db.api.CONTEXT_WRITER.using')
    def test_update_link_existing_host_link(self, mock_db_writer):
        mock_hlink = {
            'serial_number': 'serial1',
            'switch_ip': '192.168.1.1',
            'switch_mac': 'mac1',
            'switch_port': 'port1'
        }
        session = mock_db_writer.return_value.__enter__.return_value
        session.query.return_value.filter.return_value.filter.return_value \
            .one_or_none.return_value = mock_hlink

        self.ndfc_mech.update_link(self.context, 'host1', 'intf1',
                'mac1', '192.168.1.1', '', '', 'port1', '', 'serial1')
        session = mock_db_writer.return_value.__enter__.return_value
        session.add.assert_not_called()

    @mock.patch('neutron_lib.db.api.CONTEXT_WRITER.using')
    def test_update_link_add_tor_entries(self, mock_db_writer):
        session = mock_db_writer.return_value.__enter__.return_value
        mock_hlink_query = mock.Mock()
        mock_hlink_query.filter.return_value.filter.return_value \
            .one_or_none.return_value = None
        mock_tor_query = mock.Mock()
        mock_tor_query.filter.return_value.filter.return_value \
            .one_or_none.return_value = None
        session.query.side_effect = lambda model: {
            nc_ml2_db.NxosHostLink: mock_hlink_query,
            nc_ml2_db.NxosTors: mock_tor_query,
        }.get(model)

        self.ndfc_mech.switch_map = {
            '192.168.1.1': {
                'serial': 'sn1',
                'role': 'tor',
                'tor_leaf_nodes': {'leaf1': 'sn1_leaf'}
            }
        }
        self.ndfc_mech.ndfc.ndfc_obj.get_po = mock.Mock(return_value="")

        self.ndfc_mech.update_link(self.context, 'host1', 'intf1',
            'mac1', '192.168.1.1', 'module1', 'pod1', 'port1',
            'desc1', 'serial1')

        # Capture the call arguments for session.add
        add_call_args = session.add.call_args_list

        # Check if the expected NxosTors was added by comparing attributes
        found_match = any(
            (call_args[0][0].tor_serial_number == 'serial1' and
             call_args[0][0].leaf_serial_number == 'sn1_leaf' and
             call_args[0][0].tor_name == 'module1')
            for call_args in add_call_args
        )

        self.assertTrue(found_match,
            "Expected NxosTors entry not found in session.add calls")

    @mock.patch('neutron_lib.db.api.CONTEXT_WRITER.using')
    def test_update_link_add_host_entry(self, mock_db_writer):
        session = mock_db_writer.return_value.__enter__.return_value
        mock_hlink_query = mock.Mock()
        mock_hlink_query.filter.return_value.filter.return_value \
            .one_or_none.return_value = None
        mock_tor_query = mock.Mock()
        mock_tor_query.filter.return_value.filter.return_value \
            .one_or_none.return_value = None
        mock_tor_query.filter_by.return_value.all.return_value = []
        session.query.side_effect = lambda model: {
            nc_ml2_db.NxosHostLink: mock_hlink_query,
            nc_ml2_db.NxosTors: mock_tor_query,
        }.get(model)

        self.ndfc_mech.switch_map = {
            '192.168.1.1': {
                'serial': 'sn1',
                'role': 'leaf'
            }
        }
        self.ndfc_mech.ndfc.ndfc_obj.get_po = mock.Mock(return_value="10")

        self.ndfc_mech.update_link(self.context, 'host1', 'intf1',
                'mac1', '192.168.1.1', '', '', 'Ethernet1/51', '', 'serial1')

        add_call_args = session.add.call_args_list

        expected_host_link_attrs = {
            'host_name': 'host1',
            'interface_name': 'intf1',
            'serial_number': 'serial1',
            'switch_ip': '192.168.1.1',
            'switch_mac': 'mac1',
            'switch_port': 'Port-channel10'
        }
        found_match = any(
            isinstance(call_args[0][0], nc_ml2_db.NxosHostLink) and
            all(getattr(call_args[0][0], attr) == value for attr,
                value in expected_host_link_attrs.items())
            for call_args in add_call_args
        )

        self.assertTrue(found_match,
            "Expected NxosHostLink entry not found in session.add calls")

    @mock.patch('neutron_lib.db.api.CONTEXT_WRITER.using')
    def test_update_link_update_host_entry(self, mock_db_writer):
        session = mock_db_writer.return_value.__enter__.return_value
        mock_hlink = {
            'serial_number': 'old_serial',
            'switch_ip': 'old_ip',
            'switch_mac': 'old_mac',
            'switch_port': 'old_port'
        }
        session.query.return_value.filter.return_value.filter.return_value \
            .one_or_none.return_value = mock_hlink

        self.ndfc_mech.switch_map = {
            '192.168.1.1': {
                'serial': 'sn1',
                'role': 'leaf'
            }
        }
        self.ndfc_mech.ndfc.ndfc_obj.get_po = mock.Mock(return_value="10")

        self.ndfc_mech.update_link(self.context, 'host1', 'intf1',
                'mac1', '192.168.1.1', '', '', 'port1', '', 'serial1')

        self.assertEqual(mock_hlink['serial_number'], 'serial1')
        self.assertEqual(mock_hlink['switch_ip'], '192.168.1.1')
        self.assertEqual(mock_hlink['switch_mac'], 'mac1')
        self.assertEqual(mock_hlink['switch_port'], 'Port-channel10')

    def test_get_topology_attach(self):
        fake_network_context = self._create_fake_network_context(
                'local', 'physnet1', '10')
        topology = self.ndfc_mech.get_topology(self.context,
                fake_network_context.current, 'host1')
        self.assertIsNotNone(topology)

    @mock.patch.object(mech_ndfc.NDFCMechanismDriver,
            '_get_topology', return_value={'host': 'host1'})
    def test_get_topology_detach(self, mock_get_topology):
        fake_network_context = self._create_fake_network_context(
                'local', 'physnet1', '10')
        topology = self.ndfc_mech.get_topology(self.context,
                fake_network_context.current, 'host1', detach=True)
        self.assertEqual(topology, {'host': 'host1'})

    @mock.patch.object(ndfc.Ndfc, 'get_vrf_vlan')
    @mock.patch(
        'networking_cisco.ml2_drivers.ndfc.mech_ndfc.plugin_utils.'
        'parse_network_vlan_ranges')
    def test_allocate_vrf_segment(
            self, mock_parse_vlan_ranges, mock_get_vrf_vlan):
        vrf_name = 'test_vrf'
        expected_vlan_id = "150"
        mock_allocated_segment = {
                'id': 'segment-id-123', 'segmentation_id': expected_vlan_id}
        mock_ml2_plugin = mock.MagicMock()
        mock_type_manager = mock.MagicMock()
        mock_vlan_driver_obj = mock.MagicMock()
        mock_ml2_plugin.type_manager = mock_type_manager
        mock_type_manager.drivers.get.return_value.obj = mock_vlan_driver_obj
        mock_vlan_driver_obj.allocate_fully_specified_segment.\
            return_value = mock_allocated_segment
        self.context._plugin = mock_ml2_plugin
        self.context._plugin_context = mock.MagicMock()
        ndfc_conf.cfg.CONF.set_override(
                'network_vlan_ranges',
                'physnet1:100:200',
                group='ml2_type_vlan')

        mock_get_vrf_vlan.return_value = expected_vlan_id
        mock_parse_vlan_ranges.return_value = {'physnet1': [(100, 200)]}

        self.ndfc_mech.allocate_vrf_segment(self.context, vrf_name)

        mock_get_vrf_vlan.assert_called_once_with(vrf_name)
        mock_parse_vlan_ranges.assert_called_once_with(
            ndfc_conf.cfg.CONF.ml2_type_vlan.network_vlan_ranges)
        mock_type_manager.drivers.get.assert_called_once_with(
                constants.TYPE_VLAN)
        mock_vlan_driver_obj.allocate_fully_specified_segment.\
            assert_called_once_with(
                self.context._plugin_context,
                **{segment.PHYSICAL_NETWORK: 'physnet1',
                    'vlan_id': expected_vlan_id})

    @mock.patch(
        'networking_cisco.ml2_drivers.ndfc.mech_ndfc.'
        'loopingcall.FixedIntervalLoopingCall'
    )
    @mock.patch('random.uniform', return_value=5)
    @mock.patch('time.time')
    @mock.patch.object(mech_ndfc.NDFCMechanismDriver, '_cleanup_stale_tors')
    def test_initialize_starts_periodic_sync(
        self, mock_cleanup, mock_time, mock_random, mock_looping_call_cls):
        mock_time.return_value = 1000
        mock_looping_call = mock.Mock()
        mock_looping_call_cls.return_value = mock_looping_call

        self.ndfc_mech = mech_ndfc.NDFCMechanismDriver()
        self.ndfc_mech.ndfc = mock.Mock()
        self.ndfc_mech.ndfc.ndfc_obj.get_switches.return_value = {}
        self.ndfc_mech.switch_sync_interval = 1800

        self.ndfc_mech.initialize()

        mock_looping_call_cls.assert_called_once()
        mock_looping_call.start.assert_called_once_with(
            interval=1800, initial_delay=5, stop_on_exception=False)
        self.assertEqual(self.ndfc_mech.switch_map, {})

    @mock.patch('time.time')
    @mock.patch.object(mech_ndfc.NDFCMechanismDriver, '_cleanup_stale_tors')
    def test_switches_property_returns_cached_data(
            self, mock_cleanup, mock_time):
        self.ndfc_mech.switch_map = {
                '192.168.1.1': {'serial': 'sn1', 'role': 'leaf'}}
        self.ndfc_mech._last_switch_sync = 1000

        mock_time.return_value = 1500
        switches = self.ndfc_mech.switches

        self.assertEqual(switches,
                {'192.168.1.1': {'serial': 'sn1', 'role': 'leaf'}})
        mock_cleanup.assert_not_called()

    @mock.patch('time.time')
    @mock.patch.object(mech_ndfc.NDFCMechanismDriver, '_cleanup_stale_tors')
    def test_periodic_refresh_switch_list_updates_switch_map(
            self, mock_cleanup, mock_time):
        self.ndfc_mech.ndfc = mock.Mock()
        initial_switch_data = {
            '192.168.1.1': {
                'serial': 'sn1', 'role': 'tor',
                'tor_leaf_nodes': {'leaf1': 'lsn1'}
            }
        }
        updated_switch_data = {
            '192.168.1.1': {'serial': 'sn1', 'role': 'leaf'}
        }
        self.ndfc_mech.switch_map = initial_switch_data
        self.ndfc_mech.fabric_name = 'fabric1'

        self.ndfc_mech.ndfc.ndfc_obj.get_switches.return_value = \
            updated_switch_data
        self.ndfc_mech._refresh_switch_list()

        self.assertEqual(self.ndfc_mech.switch_map, updated_switch_data)
        mock_cleanup.assert_called_once_with(['sn1'])

    @mock.patch('neutron_lib.db.api.CONTEXT_WRITER.using')
    def test_cleanup_stale_tors_no_stale_sns(self, mock_db_writer):
        self.ndfc_mech._cleanup_stale_tors([])

        mock_db_writer.assert_not_called()

    @mock.patch('neutron_lib.db.api.CONTEXT_WRITER.using')
    def test_cleanup_stale_tors_matching_entries(self, mock_db_writer):
        session = mock_db_writer.return_value.__enter__.return_value

        mock_query = mock.Mock()
        session.query.return_value = mock_query
        mock_query.filter.return_value.delete.return_value = 2

        stale_sns = ['stale_sn1', 'stale_sn2']
        self.ndfc_mech._cleanup_stale_tors(stale_sns)

        mock_db_writer.assert_called_once()
        session.query.assert_called_once_with(nc_ml2_db.NxosTors)
        mock_query.filter.assert_called_once()
        mock_query.filter.return_value.delete.assert_called_once_with(
            synchronize_session='fetch')

    @mock.patch('neutron_lib.db.api.CONTEXT_WRITER.using')
    def test_cleanup_stale_leaf_nodes(self, mock_db_writer):
        session_mock = mock.Mock()
        mock_db_writer.return_value.__enter__.return_value = session_mock
        mock_query_leaf_sn = mock.Mock()
        mock_query_leaf_sn.filter.return_value.all.return_value = [
                ('leaf_sn_stale',), ('leaf_sn_active',)]
        mock_query_delete = mock.Mock()

        session_mock.query.side_effect = lambda model: {
            nc_ml2_db.NxosTors.leaf_serial_number: mock_query_leaf_sn,
            nc_ml2_db.NxosTors: mock_query_delete,
        }.get(model)

        cleanup_list = [
            ('tor_sn_1', {'leaf_sn_active'})
        ]

        self.ndfc_mech._cleanup_stale_leaf_nodes(cleanup_list)

        mock_query_leaf_sn.filter.assert_called_once()
        mock_query_delete.filter.assert_called_once()
        mock_query_delete.filter.return_value.delete.assert_called_once_with(
            synchronize_session='fetch'
        )
