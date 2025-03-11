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
                'tor_interfaces': ['Port-Channel11'],
                'tor_name': '65-N9336FX2'},
            'FDO24230DAX': {'tor_interfaces':
                ['Port-Channel11'], 'tor_name': '66-N9332FX2'}
        }
    },
    'FDO24170TNU':
    {
        'tor_sw_intf_map':
        {
            'FDO24230D5G': {
                'tor_interfaces': ['Port-Channel11'],
                'tor_name': '65-N9336FX2'},
            'FDO24230DAX': {
                'tor_interfaces': ['Port-Channel11'],
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
        self.mock_get_network = mock.patch.object(
                mech_ndfc.NDFCMechanismDriver,
                'get_network', return_value=None).start()
        self.mock_get_topology = mock.patch.object(
                mech_ndfc.NDFCMechanismDriver,
                'get_topology', return_value=None).start()
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
                                    cidr):
        subnet_attrs = {'network_id': network_id,
                        'gateway_ip': cidr}
        fake_subnet = \
            fakes.FakeSubnet.create_one_subnet(attrs=subnet_attrs).info()
        return fakes.FakeSubnetContext(fake_subnet)

    @mock.patch.object(mech_ndfc.NDFCMechanismDriver, 'get_network')
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

        # Test create and delete subnet postcommit methods
        self.mock_get_network = fake_network_context.current
        fake_subnet_context = self._create_fake_subnet_context(
                'fake-network-id', '10.10.10.0/824')
        self.ndfc_mech.create_subnet_postcommit(fake_subnet_context)
        self.ndfc_mech.delete_subnet_postcommit(fake_subnet_context)

    @mock.patch.object(mech_ndfc.NDFCMechanismDriver, 'get_topology')
    @mock.patch.object(ndfc.Ndfc, 'attach_network')
    @mock.patch.object(ndfc.Ndfc, 'detach_network')
    def test_port_postcommit(self, *args):
        # Test update and delete port postcommit methods
        self.mock_get_topology = TEST_LEAF_ATTACHMENTS
        fake_network_context = self._create_fake_network_context('vlan',
                'physnet1', '10')
        fake_port = fakes.FakePort.create_one_port(
            attrs={'binding:vnic_type': 'virtio-forwarder'}).info()
        fake_port_context = mock.Mock(current=fake_port, original=fake_port)
        fake_port_context.network = fake_network_context
        fake_port_context.host = 'current-host'
        fake_port_context.original_host = 'original-host'
        self.ndfc_mech.update_port_postcommit(fake_port_context)
        self.ndfc_mech.delete_port_postcommit(fake_port_context)

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

    @mock.patch.object(mech_ndfc.NDFCMechanismDriver, '_get_tor_entry')
    @mock.patch('neutron_lib.db.api.CONTEXT_WRITER.using')
    def test_update_link_add_tor_entries(self, mock_db_writer,
            mock_get_tor_entry):
        mock_get_tor_entry.return_value = []
        session = mock_db_writer.return_value.__enter__.return_value
        self.ndfc_mech.update_link(self.context, 'host1', 'intf1',
            'mac1', '192.168.1.1', 'module1', 'pod1', 'port1',
            'desc1', 'serial1')

        # Capture the call arguments for session.add
        add_call_args = session.add.call_args_list

        # Check if the expected NxosTors was added by comparing attributes
        found_match = any(
            (call_args[0][0].tor_serial_number == 'serial1' and
             call_args[0][0].leaf_serial_number == 'sn1' and
             call_args[0][0].tor_name == 'module1')
            for call_args in add_call_args
        )

        self.assertTrue(found_match,
            "Expected NxosTors entry not found in session.add calls")

    @mock.patch.object(mech_ndfc.NDFCMechanismDriver, '_get_tor_entry')
    @mock.patch('neutron_lib.db.api.CONTEXT_WRITER.using')
    def test_update_link_add_host_entry(self, mock_db_writer,
            mock_get_tor_entry):
        session = mock_db_writer.return_value.__enter__.return_value
        session.query.return_value.filter.return_value.filter.return_value \
            .one_or_none.return_value = None

        self.ndfc_mech.update_link(self.context, 'host1', 'intf1',
                'mac1', '192.168.1.1', '', '', 'Ethernet1/51', '', 'serial1')

        # Capture the call arguments for session.add
        add_call_args = session.add.call_args_list

        # Check if the expected NxosHostLink was added
        added_host_link = nc_ml2_db.NxosHostLink(
            host_name='host1',
            interface_name='intf1',
            serial_number='serial1',
            switch_ip='192.168.1.1',
            switch_mac='mac1',
            switch_port='Port-Channel10'
        )

        # Compare attributes instead of object identity
        found_match = any(
            (call_args[0][0].host_name == added_host_link.host_name and
             call_args[0][0].interface_name ==
             added_host_link.interface_name and
             call_args[0][0].serial_number == added_host_link.serial_number and
             call_args[0][0].switch_ip == added_host_link.switch_ip and
             call_args[0][0].switch_mac == added_host_link.switch_mac and
             call_args[0][0].switch_port == added_host_link.switch_port)
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

        self.ndfc_mech.update_link(self.context, 'host1', 'intf1',
                'mac1', '192.168.1.1', '', '', 'port1', '', 'serial1')

        self.assertEqual(mock_hlink['serial_number'], 'serial1')
        self.assertEqual(mock_hlink['switch_ip'], '192.168.1.1')
        self.assertEqual(mock_hlink['switch_mac'], 'mac1')
        self.assertEqual(mock_hlink['switch_port'], 'Port-Channel10')
