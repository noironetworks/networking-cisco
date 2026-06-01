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
import uuid

from neutron.common import _constants as n_const
from neutron.common.ovn import constants as ovn_const
from neutron.plugins.ml2.drivers.ovn.agent import neutron_agent
from neutron.tests import base as neutron_base
from neutron.tests.unit import fake_resources as fakes

from networking_cisco.ml2_drivers.ndfc import constants as ndfc_const
from networking_cisco.ml2_drivers.ovn_hpb import mech_ovn_hpb

from oslo_utils import timeutils


DEFAULT_DP_TYPE = 'system'  # For testing, we define "system" as default.


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
            'neutron-net-id', may_exist=True, **{'neutron:foo': 'bar'})
        driver.create_provnet_port.assert_called_once_with(
            'net-id', mock_get_segments.return_value[0],
            txn=txn)
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
            txn, network, original_network)
        mock_bump_revision.assert_called_once_with(
            context, network, ovn_const.TYPE_NETWORKS)
        mock_is_external.assert_called_once_with(network)

    @mock.patch.object(mech_ovn_hpb.registry, 'publish')
    @mock.patch.object(mech_ovn_hpb.uuidutils, 'generate_uuid',
                       return_value='generated-segment-id')
    @mock.patch.object(mech_ovn_hpb.nw, 'NetworkSegment')
    def test_new_add_network_segment_creates_and_publishes_precommit(
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
        mock_publish.assert_called_once()
        resource, event, trigger = mock_publish.call_args[0]
        payload = mock_publish.call_args[1]['payload']
        self.assertEqual(mech_ovn_hpb.resources.SEGMENT, resource)
        self.assertEqual(mech_ovn_hpb.events.PRECOMMIT_CREATE, event)
        self.assertEqual(mech_ovn_hpb.new_add_network_segment, trigger)
        self.assertEqual(context, payload.context)
        self.assertEqual('generated-segment-id', payload.resource_id)
        self.assertEqual((network_segment,), payload.states)

    @mock.patch.object(mech_ovn_hpb.registry, 'publish')
    @mock.patch.object(mech_ovn_hpb.uuidutils, 'generate_uuid',
                       return_value='generated-segment-id')
    @mock.patch.object(mech_ovn_hpb.nw, 'NetworkSegment')
    def test_new_add_network_segment_publishes_after_create_for_dynamic(
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

            mech_ovn_hpb.new_add_network_segment(
                context, 'net-id', segment, is_dynamic=True)

        mock_generate_uuid.assert_called_once_with()
        mock_network_segment.assert_called_once_with(
            context, id='generated-segment-id', network_id='net-id',
            network_type='vlan', physical_network='physnet1',
            segmentation_id=101, segment_index=0, is_dynamic=True)
        network_segment.create.assert_called_once_with()
        self.assertEqual('generated-segment-id', segment['id'])
        self.assertEqual(2, mock_publish.call_count)
        self.assertEqual(
            mech_ovn_hpb.events.PRECOMMIT_CREATE,
            mock_publish.call_args_list[0][0][1])
        self.assertEqual(
            mech_ovn_hpb.events.AFTER_CREATE,
            mock_publish.call_args_list[1][0][1])

    @mock.patch.object(mech_ovn_hpb.nw, 'SegmentHostMapping')
    def test_new_map_segment_to_hosts_adds_only_new_hosts(
            self, mock_segment_host_mapping):
        context = mock.Mock()
        context.session.no_autoflush = mock.MagicMock()
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

        context.session.no_autoflush.__enter__.assert_called_once_with()
        context.session.no_autoflush.__exit__.assert_called_once_with(
            None, None, None)
        mock_segment_host_mapping.get_objects.assert_called_once_with(
            context, segment_id='segment-id')
        mock_segment_host_mapping.assert_called_once_with(
            context, segment_id='segment-id', host='host-b')
        new_mapping.create.assert_called_once_with()

    @mock.patch.object(mech_ovn_hpb.registry, 'publish')
    def test_publish_segment_after_delete_uses_segment_payload(
            self, mock_publish):
        context = mock.Mock()
        segment = {'id': 'seg-id', 'network_id': 'net-id'}

        mech_ovn_hpb.publish_segment_after_delete(context, segment)

        mock_publish.assert_called_once()
        resource, event, trigger = mock_publish.call_args[0]
        payload = mock_publish.call_args[1]['payload']
        self.assertEqual(mech_ovn_hpb.resources.SEGMENT, resource)
        self.assertEqual(mech_ovn_hpb.events.AFTER_DELETE, event)
        self.assertEqual(mech_ovn_hpb.publish_segment_after_delete, trigger)
        self.assertEqual(context, payload.context)
        self.assertEqual('seg-id', payload.resource_id)
        self.assertEqual((segment,), payload.states)

    @mock.patch.object(mech_ovn_hpb, 'publish_segment_after_delete')
    @mock.patch.object(mech_ovn_hpb.segments_db, 'get_segment_by_id')
    def test_hpb_release_dynamic_segment_publishes_after_successful_delete(
            self, mock_get_segment, mock_publish):
        context = mock.Mock()
        type_manager = mock.Mock()
        segment = {'id': 'seg-id', 'network_type': 'vlan'}
        mock_get_segment.side_effect = [segment, None]

        with mock.patch.object(
                mech_ovn_hpb, '_real_release_dynamic_seg') as mock_real:
            mech_ovn_hpb.hpb_release_dynamic_segment(
                type_manager, context, 'seg-id')

        mock_real.assert_called_once_with(type_manager, context, 'seg-id')
        mock_publish.assert_called_once_with(context, segment)

    @mock.patch.object(mech_ovn_hpb, 'publish_segment_after_delete')
    @mock.patch.object(mech_ovn_hpb.segments_db, 'get_segment_by_id')
    def test_hpb_release_dynamic_segment_skips_notify_when_not_deleted(
            self, mock_get_segment, mock_publish):
        context = mock.Mock()
        type_manager = mock.Mock()
        segment = {'id': 'seg-id', 'network_type': 'vlan'}
        mock_get_segment.side_effect = [segment, segment]

        with mock.patch.object(
                mech_ovn_hpb, '_real_release_dynamic_seg') as mock_real:
            mech_ovn_hpb.hpb_release_dynamic_segment(
                type_manager, context, 'seg-id')

        mock_real.assert_called_once_with(type_manager, context, 'seg-id')
        mock_publish.assert_not_called()


class TestOVNHPBMechanismDriver(neutron_base.BaseTestCase):

    def setUp(self):
        super().setUp()
        self.driver = object.__new__(mech_ovn_hpb.OVNHPBMechanismDriver)
        self.driver.sg_enabled = False
        self.driver._nb_ovn = fakes.FakeOvsdbNbOvnIdl()
        self.driver._sb_ovn = fakes.FakeOvsdbSbOvnIdl()
        self.driver._post_fork_event = mock.Mock()
        self.driver._agent_cache = neutron_agent.AgentCache(self.driver)
        agent1 = self._add_agent('agent1')
        neutron_agent.AgentCache().get_agents = mock.Mock()
        neutron_agent.AgentCache().get_agents.return_value = [agent1]
        self.driver._setup_vif_port_bindings()
        self.ovn_client = mock.Mock()
        self.ovn_client_p = mock.patch.object(
            mech_ovn_hpb.OVNHPBMechanismDriver, '_ovn_client',
            new_callable=mock.PropertyMock, return_value=self.ovn_client)
        self.ovn_client_p.start()
        self.addCleanup(self.ovn_client_p.stop)

    def _add_chassis_private(self, nb_cfg, name=None):
        chassis_private = mock.Mock()
        chassis_private.nb_cfg = nb_cfg
        chassis_private.uuid = uuid.uuid4()
        chassis_private.name = name if name else str(uuid.uuid4())
        chassis_private.nb_cfg_timestamp = timeutils.utcnow_ts() * 1000
        return chassis_private

    def _add_chassis(self, name, hostname, external_ids=None,
                     other_config=None):
        external_ids = external_ids or {}
        other_config = other_config or {}
        return mock.Mock(name=name, hostname=hostname,
                         external_ids=external_ids, other_config=other_config)

    def _add_chassis_agent(self, nb_cfg, agent_type, chassis_private=None,
                           hostname=None):
        chassis_private = chassis_private or self._add_chassis_private(nb_cfg)
        hostname = hostname or chassis_private.name + '_host'
        if hasattr(chassis_private, 'nb_cfg_timestamp') and isinstance(
                chassis_private.nb_cfg_timestamp, mock.Mock):
            del chassis_private.nb_cfg_timestamp
        chassis_private.external_ids = {
            ovn_const.OVN_AGENT_OVN_BRIDGE: n_const.DEFAULT_BR_INT,
            ovn_const.OVN_DATAPATH_TYPE: DEFAULT_DP_TYPE,
        }
        if agent_type == ovn_const.OVN_METADATA_AGENT:
            chassis_private.external_ids.update({
                ovn_const.OVN_AGENT_METADATA_SB_CFG_KEY: nb_cfg,
                ovn_const.OVN_AGENT_METADATA_ID_KEY: str(uuid.uuid4())})
        chassis_private.chassis = [self._add_chassis(chassis_private.name,
                                                     hostname)]
        return neutron_agent.AgentCache().update(agent_type, chassis_private)

    def _add_agent(self, name, nb_cfg_offset=0, hostname=None):
        hostname = hostname or name + '_host'
        nb_cfg = 5
        self.driver.nb_ovn.nb_global.nb_cfg = nb_cfg + nb_cfg_offset
        chassis_private = self._add_chassis_private(nb_cfg, name=name)
        return self._add_chassis_agent(
            nb_cfg, ovn_const.OVN_CONTROLLER_AGENT,
            chassis_private=chassis_private, hostname=hostname)

    def test_validate_network_segments_filters_nd_segments(self):
        super_driver = mech_ovn_hpb.OVNHPBMechanismDriver.__mro__[1]
        with mock.patch.object(
                super_driver, '_validate_network_segments') as mock_super:
            self.driver._validate_network_segments([
                {'network_type': ndfc_const.TYPE_ND},
                {'network_type': 'vlan'},
                {'network_type': 'flat'},
            ])

        mock_super.assert_called_once_with([
            {'network_type': 'vlan'},
            {'network_type': 'flat'},
        ])

    def test_validate_network_segments_skips_super_for_nd_only(self):
        super_driver = mech_ovn_hpb.OVNHPBMechanismDriver.__mro__[1]
        with mock.patch.object(
                super_driver, '_validate_network_segments') as mock_super:
            self.driver._validate_network_segments([
                {'network_type': ndfc_const.TYPE_ND},
            ])

        mock_super.assert_not_called()

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
            'net-id', segment)

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

    def test_bind_nd_segment_fail(self):
        segment_attrs = {'network_type': 'nd',
                         'physical_network': 'unknown-physnet',
                         'segmentation_id': None}
        fake_segments = [fakes.FakeSegment.create_one_segment(
                attrs=segment_attrs).info()]
        fake_port = fakes.FakePort.create_one_port(
            attrs={'binding:vnic_type': 'normal'}).info()
        fake_port_context = fakes.FakePortContext(fake_port,
                                                  'host', fake_segments)
        self.driver.bind_port(fake_port_context)
        fake_port_context.set_binding.assert_not_called()
