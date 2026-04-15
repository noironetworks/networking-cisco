# Copyright 2026 Cisco Systems
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

from unittest import mock

from neutron.common.ovn import constants as ovn_const
from neutron.tests import base as neutron_base

from networking_cisco.ml2_drivers.ovn_hpb import mech_ovn_hpb


class TestOVNHPBHelpers(neutron_base.BaseTestCase):

    def test_is_provider_segment_supported(self):
        self.assertTrue(mech_ovn_hpb.is_provider_segment_supported(
            {'network_type': 'flat'}))
        self.assertTrue(mech_ovn_hpb.is_provider_segment_supported(
            {'network_type': 'vlan'}))
        self.assertFalse(mech_ovn_hpb.is_provider_segment_supported(
            {'network_type': 'geneve'}))

    @mock.patch.object(mech_ovn_hpb.db_rev, 'bump_revision')
    @mock.patch.object(mech_ovn_hpb.segments_db, 'get_network_segments')
    def test_hpb_create_network_adds_provnet_ports_for_supported_segments(
            self, mock_get_segments, mock_bump_revision):
        context = mock.Mock()
        network = {'id': 'net-id'}
        driver = mock.MagicMock()
        txn = mock.MagicMock()
        driver._nb_idl.transaction.return_value.__enter__.return_value = txn
        driver._gen_network_parameters.return_value = {'neutron:foo': 'bar'}
        mock_get_segments.return_value = [
            {'id': 'seg-flat', 'physical_network': 'physnet1',
             'network_type': 'flat'},
            {'id': 'seg-geneve', 'physical_network': 'physnet2',
             'network_type': 'geneve'},
            {'id': 'seg-vlan-no-physnet', 'network_type': 'vlan'},
        ]

        result = mech_ovn_hpb.hpb_create_network(driver, context, network)

        self.assertEqual(network, result)
        driver._nb_idl.ls_add.assert_called_once_with(
            network_id='net-id', may_exist=True, **{'neutron:foo': 'bar'})
        driver.create_provnet_port.assert_called_once_with(
            context, 'net-id', mock_get_segments.return_value[0],
            txn=txn, network=network)
        mock_bump_revision.assert_called_once_with(
            context, network, ovn_const.TYPE_NETWORKS)
        driver.create_metadata_port.assert_called_once_with(context, network)

    @mock.patch.object(mech_ovn_hpb.db_rev, 'bump_revision')
    def test_hpb_update_network_returns_when_lswitch_missing(
            self, mock_bump_revision):
        context = mock.Mock()
        network = {'id': 'net-id', 'mtu': 1500}
        driver = mock.MagicMock()
        txn = mock.MagicMock()
        check_rev_cmd = mock.Mock(result=ovn_const.TXN_COMMITTED)
        driver._nb_idl.transaction.return_value.__enter__.return_value = txn
        driver._nb_idl.check_revision_number.return_value = check_rev_cmd
        driver._gen_network_parameters.return_value = {'neutron:foo': 'bar'}
        driver._nb_idl.get_lswitch.return_value = None

        mech_ovn_hpb.hpb_update_network(driver, context, network)

        txn.add.assert_called_once_with(check_rev_cmd)
        driver._nb_idl.db_set.assert_not_called()
        mock_bump_revision.assert_not_called()

    @mock.patch.object(mech_ovn_hpb.db_rev, 'bump_revision')
    @mock.patch.object(mech_ovn_hpb.segments_db, 'get_network_segments')
    @mock.patch.object(mech_ovn_hpb.utils, 'is_external_network',
                       return_value=False)
    def test_hpb_update_network_updates_supported_segment_tags(
            self, mock_is_external, mock_get_segments, mock_bump_revision):
        context = mock.Mock()
        network = {'id': 'net-id', 'mtu': 1550}
        original_network = {'id': 'net-id', 'mtu': 1500}
        driver = mock.MagicMock()
        txn = mock.MagicMock()
        check_rev_cmd = mock.Mock(result=ovn_const.TXN_COMMITTED)
        lswitch = mock.Mock(external_ids={})
        driver._nb_idl.transaction.return_value.__enter__.return_value = txn
        driver._nb_idl.check_revision_number.return_value = check_rev_cmd
        driver._gen_network_parameters.return_value = {'neutron:foo': 'bar'}
        driver._nb_idl.get_lswitch.return_value = lswitch
        driver._plugin.get_subnets_by_network.return_value = [
            {'id': 'subnet-1'}
        ]
        mock_get_segments.return_value = [
            {'id': 'seg-vlan', 'network_type': 'vlan',
             'physical_network': 'physnet1', 'segmentation_id': 101},
            {'id': 'seg-flat', 'network_type': 'flat',
             'physical_network': 'physnet2', 'segmentation_id': None},
            {'id': 'seg-geneve', 'network_type': 'geneve',
             'physical_network': 'physnet3', 'segmentation_id': 102},
        ]

        mech_ovn_hpb.hpb_update_network(
            driver, context, network, original_network=original_network)

        driver._plugin.get_subnets_by_network.assert_called_once_with(
            context, 'net-id')
        driver.update_subnet.assert_called_once_with(
            context, {'id': 'subnet-1'}, network, txn)
        driver._nb_idl.set_lswitch_port.assert_has_calls([
            mock.call(
                lport_name=mech_ovn_hpb.utils.ovn_provnet_port_name(
                    'seg-vlan'),
                tag=101, if_exists=True),
            mock.call(
                lport_name=mech_ovn_hpb.utils.ovn_provnet_port_name(
                    'seg-flat'),
                tag=[], if_exists=True),
        ])
        self.assertEqual(
            2, driver._nb_idl.set_lswitch_port.call_count)
        driver._qos_driver.update_network.assert_called_once_with(
            context, txn, network, original_network)
        mock_bump_revision.assert_called_once_with(
            context, network, ovn_const.TYPE_NETWORKS)
        mock_is_external.assert_called_once_with(network)

    @mock.patch.object(mech_ovn_hpb.registry, 'publish')
    @mock.patch.object(mech_ovn_hpb.uuidutils, 'generate_uuid',
                       return_value='generated-segment-id')
    @mock.patch.object(mech_ovn_hpb.nw, 'NetworkSegment')
    def test_new_add_network_segment_creates_and_publishes(
            self, mock_network_segment, mock_generate_uuid, mock_publish):
        context = mock.Mock()
        network_segment = mock.Mock(
            id='generated-segment-id',
            network_id='net-id',
            network_type='vlan')
        mock_network_segment.return_value = network_segment
        writer = mock.MagicMock()
        writer.__enter__.return_value = None
        writer.__exit__.return_value = None
        with mock.patch.object(
                mech_ovn_hpb.db_api.CONTEXT_WRITER, 'using',
                return_value=writer):
            segment = {
                'network_type': 'vlan',
                'physical_network': 'physnet1',
                'segmentation_id': 101,
            }

            mech_ovn_hpb.new_add_network_segment(context, 'net-id', segment)

        mock_generate_uuid.assert_called_once_with()
        mock_network_segment.assert_called_once_with(
            context, id='generated-segment-id', network_id='net-id',
            network_type='vlan', physical_network='physnet1',
            segmentation_id=101, segment_index=0, is_dynamic=False)
        network_segment.create.assert_called_once_with()
        self.assertEqual('generated-segment-id', segment['id'])
        self.assertEqual(2, mock_publish.call_count)

    @mock.patch.object(mech_ovn_hpb.nw, 'SegmentHostMapping')
    def test_new_map_segment_to_hosts_adds_only_new_hosts(
            self, mock_segment_host_mapping):
        context = mock.Mock()
        existing_mapping = mock.Mock(host='host-a')
        mock_segment_host_mapping.get_objects.return_value = [existing_mapping]
        new_mapping = mock.Mock()
        mock_segment_host_mapping.return_value = new_mapping
        writer = mock.MagicMock()
        writer.__enter__.return_value = None
        writer.__exit__.return_value = None
        with mock.patch.object(
                mech_ovn_hpb.db_api.CONTEXT_WRITER, 'using',
                return_value=writer):
            mech_ovn_hpb.new_map_segment_to_hosts(
                context, 'segment-id', ['host-a', 'host-b'])

        mock_segment_host_mapping.get_objects.assert_called_once_with(
            context, segment_id='segment-id')
        mock_segment_host_mapping.assert_called_once_with(
            context, segment_id='segment-id', host='host-b')
        new_mapping.create.assert_called_once_with()


class TestOVNHPBMechanismDriver(neutron_base.BaseTestCase):

    def setUp(self):
        super().setUp()
        self.driver = object.__new__(mech_ovn_hpb.OVNHPBMechanismDriver)
        self.ovn_client = mock.Mock()
        self.ovn_client_p = mock.patch.object(
            mech_ovn_hpb.OVNHPBMechanismDriver, '_ovn_client',
            new_callable=mock.PropertyMock, return_value=self.ovn_client)
        self.ovn_client_p.start()
        self.addCleanup(self.ovn_client_p.stop)

    def test_create_segment_provnet_port_ignores_unsupported_segments(self):
        payload = mock.Mock(
            context=mock.sentinel.context,
            latest_state={'id': 'seg-id', 'network_id': 'net-id',
                          'network_type': 'geneve',
                          'physical_network': 'physnet1'})

        self.driver.create_segment_provnet_port(None, None, None, payload)

        self.ovn_client.create_provnet_port.assert_not_called()

    def test_create_segment_provnet_port_creates_supported_segments(self):
        segment = {'id': 'seg-id', 'network_id': 'net-id',
                   'network_type': 'vlan', 'physical_network': 'physnet1'}
        payload = mock.Mock(
            context=mock.sentinel.context, latest_state=segment)

        self.driver.create_segment_provnet_port(None, None, None, payload)

        self.ovn_client.create_provnet_port.assert_called_once_with(
            mock.sentinel.context, 'net-id', segment)

    def test_delete_segment_provnet_port_ignores_missing_physnet(self):
        payload = mock.Mock(states=[{'id': 'seg-id', 'network_id': 'net-id',
                                     'network_type': 'vlan'}])

        self.driver.delete_segment_provnet_port(None, None, None, payload)

        self.ovn_client.delete_provnet_port.assert_not_called()

    def test_delete_segment_provnet_port_deletes_supported_segments(self):
        segment = {'id': 'seg-id', 'network_id': 'net-id',
                   'network_type': 'flat', 'physical_network': 'physnet1'}
        payload = mock.Mock(states=[segment])

        self.driver.delete_segment_provnet_port(None, None, None, payload)

        self.ovn_client.delete_provnet_port.assert_called_once_with(
            'net-id', segment)
