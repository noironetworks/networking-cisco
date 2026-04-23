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
#
# OVN mechanism driver specialization for NDFC HPB use cases.
# This driver subclasses the upstream OVNMechanismDriver but skips
# validation for NDFC-specific ND networks, allowing them to coexist
# with OVN in ML2.

from contextlib import nullcontext
from datetime import datetime
from neutron_lib.api.definitions import segment as segment_def
from neutron_lib.callbacks import events
from neutron_lib.callbacks import registry
from neutron_lib.callbacks import resources
from neutron_lib import constants as const
from neutron_lib import context as n_context
from neutron_lib.db import api as db_api
from neutron_lib import exceptions as n_exc

from neutron.common.ovn import constants as ovn_const
from neutron.common.ovn import utils
from neutron.db import ovn_revision_numbers_db as db_rev
from neutron.db import segments_db
from neutron.objects import network as nw
from neutron.plugins.ml2.drivers.ovn.mech_driver import mech_driver as ovn_mech
from neutron.plugins.ml2.drivers.ovn.mech_driver.ovsdb import ovn_client as oc
from neutron.plugins.ml2.drivers.ovn.mech_driver.ovsdb import ovn_db_sync as od
from neutron.plugins.ml2 import managers as ml2_managers
from neutron.services.segments import db

from networking_cisco.ml2_drivers.ndfc import constants as ndfc_const

from oslo_log import log
from oslo_utils import uuidutils


LOG = log.getLogger(__name__)

NETWORK_TYPE = segment_def.NETWORK_TYPE
PHYSICAL_NETWORK = segment_def.PHYSICAL_NETWORK
SEGMENTATION_ID = segment_def.SEGMENTATION_ID
NETWORK_ID = 'network_id'


def is_provider_segment_supported(segment):
    return segment.get(segment_def.NETWORK_TYPE) in (
        const.TYPE_FLAT, const.TYPE_VLAN)


_real_create_network = oc.OVNClient.create_network


def hpb_create_network(self, context, network):
    # Create a logical switch with a name equal to the Neutron network
    # UUID.  This provides an easy way to refer to the logical switch
    # without having to track what UUID OVN assigned to it.
    lswitch_params = self._gen_network_parameters(network)
    lswitch_name = utils.ovn_name(network['id'])
    # NOTE(mjozefcz): Remove this workaround when bug
    # 1869877 will be fixed.
    segments = segments_db.get_network_segments(
        context, network['id'])
    with self._nb_idl.transaction(check_error=True) as txn:
        txn.add(self._nb_idl.ls_add(lswitch_name, **lswitch_params,
                                    may_exist=True))
        for segment in segments:
            if (segment.get(segment_def.PHYSICAL_NETWORK) and
                    is_provider_segment_supported(segment)):
                self.create_provnet_port(network['id'], segment, txn=txn,
                                         network=network)
    db_rev.bump_revision(context, network, ovn_const.TYPE_NETWORKS)
    self.create_metadata_port(context, network)
    return network


oc.OVNClient.create_network = hpb_create_network

_real_update_network = oc.OVNClient.update_network


def hpb_update_network(self, context, network, original_network=None):
    lswitch_name = utils.ovn_name(network['id'])
    check_rev_cmd = self._nb_idl.check_revision_number(
        lswitch_name, network, ovn_const.TYPE_NETWORKS)

    # TODO(numans) - When a network's dns domain name is updated, we need
    # to update the DNS records for this network in DNS OVN NB DB table.
    # (https://bugs.launchpad.net/networking-ovn/+bug/1777978)
    # Eg. if the network n1's dns domain name was "test1" and if it has
    # 2 bound ports - p1 and p2, we would have created the below dns
    # records
    # ===========================
    # p1 = P1_IP
    # p1.test1 = P1_IP
    # p1.default_domain = P1_IP
    # p2 = P2_IP
    # p2.test1 = P2_IP
    # p2.default_domain = P2_IP
    # ===========================
    # if the network n1's dns domain name is updated to test2, then we need
    # to delete the below DNS records
    # ===========================
    # p1.test1 = P1_IP
    # p2.test1 = P2_IP
    # ===========================
    # and add the new ones
    # ===========================
    # p1.test2 = P1_IP
    # p2.test2 = P2_IP
    # ===========================
    # in the DNS row for this network.

    with self._nb_idl.transaction(check_error=True) as txn:
        txn.add(check_rev_cmd)
        lswitch_params = self._gen_network_parameters(network)
        lswitch = self._nb_idl.get_lswitch(lswitch_name)
        if not lswitch:
            LOG.debug('Logical switch %s not found while updating '
                      'network %s', lswitch_name, network['id'])
            return
        txn.add(self._nb_idl.db_set(
            'Logical_Switch', lswitch_name, *lswitch_params.items()))
        # Check if previous mtu is different than current one,
        # checking will help reduce number of operations
        if (not lswitch or
                lswitch.external_ids.get(
                    ovn_const.OVN_NETWORK_MTU_EXT_ID_KEY) !=
                str(network['mtu'])):
            subnets = self._plugin.get_subnets_by_network(
                context, network['id'])
            for subnet in subnets:
                self.update_subnet(context, subnet, network, txn)

            if utils.is_external_network(network):
                # make sure to use admin context as this is a external
                # network
                self.set_gateway_mtu(n_context.get_admin_context(),
                                     network, txn=txn)

        self._check_network_changes_in_ha_chassis_groups(
            context, lswitch, lswitch_params, txn)

        # Update the segment tags, if any
        segments = segments_db.get_network_segments(context, network['id'])
        for segment in segments:
            if not is_provider_segment_supported(segment):
                continue
            tag = segment.get(segment_def.SEGMENTATION_ID)
            tag = [] if tag is None else tag
            lport_name = utils.ovn_provnet_port_name(segment['id'])
            txn.add(self._nb_idl.set_lswitch_port(lport_name=lport_name,
                                                  tag=tag, if_exists=True))

        self._qos_driver.update_network(txn, network, original_network)

    if check_rev_cmd.result == ovn_const.TXN_COMMITTED:
        db_rev.bump_revision(context, network, ovn_const.TYPE_NETWORKS)


oc.OVNClient.update_network = hpb_update_network

_real_sync = od.OvnNbSynchronizer.sync_networks_ports_and_dhcp_opts


def hpb_sync_n_p_and_opts(self, ctx):
    LOG.debug('OVN-NB Sync networks, ports and DHCP options started @ %s',
              str(datetime.now()))
    db_networks = {}
    for net in self.core_plugin.get_networks(ctx):
        db_networks[utils.ovn_name(net['id'])] = net

    # Ignore the floating ip ports with device_owner set to
    # const.DEVICE_OWNER_FLOATINGIP
    db_ports = {port['id']: port for port in
                self.core_plugin.get_ports(ctx) if not
                utils.is_lsp_ignored(port)}

    ovn_all_dhcp_options = self.ovn_api.get_all_dhcp_options()
    db_network_cache = dict(db_networks)

    ports_need_sync_dhcp_opts = []
    lswitches = self.ovn_api.get_all_logical_switches_with_ports()
    del_lswitchs_list = []
    del_lports_list = []
    add_provnet_ports_list = []
    del_provnet_ports_list = []
    for lswitch in lswitches:
        if lswitch['name'] in db_networks:
            for lport in lswitch['ports']:
                if lport in db_ports:
                    port = db_ports.pop(lport)
                    if not utils.is_network_device_port(port):
                        ports_need_sync_dhcp_opts.append(port)
                else:
                    del_lports_list.append({'port': lport,
                                            'lswitch': lswitch['name']})
            db_network = db_networks[lswitch['name']]
            db_segments = self.segments_plugin.get_segments(
                ctx, filters={'network_id': [db_network['id']]})
            segments_provnet_port_names = []
            for db_segment in db_segments:
                physnet = db_segment.get(segment_def.PHYSICAL_NETWORK)
                if not is_provider_segment_supported(
                        db_segment):
                    continue
                pname = utils.ovn_provnet_port_name(db_segment['id'])
                segments_provnet_port_names.append(pname)
                if physnet and pname not in lswitch['provnet_ports']:
                    add_provnet_ports_list.append(
                        {'network': db_network,
                         'segment': db_segment,
                         'lswitch': lswitch['name']})
            # Delete orphaned provnet ports
            for provnet_port in lswitch['provnet_ports']:
                if provnet_port in segments_provnet_port_names:
                    continue
                if provnet_port not in [
                        utils.ovn_provnet_port_name(v['segment'])
                        for v in add_provnet_ports_list]:
                    del_provnet_ports_list.append(
                        {'network': db_network,
                         'lport': provnet_port,
                         'lswitch': lswitch['name']})

            del db_networks[lswitch['name']]
        else:
            del_lswitchs_list.append(lswitch)

    for network in db_networks.values():
        LOG.warning("Network found in Neutron but not in "
                    "OVN NB DB, network_id=%s", network['id'])
        if self.mode == ovn_const.OVN_DB_SYNC_MODE_REPAIR:
            try:
                LOG.warning('Creating network %s in OVN NB DB',
                            network['id'])
                self._ovn_client.create_network(ctx, network)
            except RuntimeError:
                LOG.warning("Create network in OVN NB DB failed for "
                            "network %s", network['id'])
            except n_exc.IpAddressGenerationFailure:
                LOG.warning("No more IP addresses available during "
                            "implicit port creation while creating "
                            "network %s", network['id'])

    self._sync_metadata_ports(ctx, db_ports)

    self._sync_subnet_dhcp_options(
        ctx, db_network_cache, ovn_all_dhcp_options['subnets'])

    for port_id, port in db_ports.items():
        LOG.warning("Port found in Neutron but not in OVN NB "
                    "DB, port_id=%s", port['id'])
        if self.mode == ovn_const.OVN_DB_SYNC_MODE_REPAIR:
            try:
                LOG.warning('Creating the port %s in OVN NB DB',
                            port['id'])
                self._create_port_in_ovn(ctx, port)
                if port_id in ovn_all_dhcp_options['ports_v4']:
                    __, lsp_opts = utils.get_lsp_dhcp_opts(
                        port, const.IP_VERSION_4)
                    if lsp_opts:
                        ovn_all_dhcp_options['ports_v4'].pop(port_id)
                if port_id in ovn_all_dhcp_options['ports_v6']:
                    __, lsp_opts = utils.get_lsp_dhcp_opts(
                        port, const.IP_VERSION_6)
                    if lsp_opts:
                        ovn_all_dhcp_options['ports_v6'].pop(port_id)
            except RuntimeError:
                LOG.warning("Create port in OVN NB DB failed for"
                            " port %s", port['id'])

    with self.ovn_api.transaction(check_error=True) as txn:
        for lswitch in del_lswitchs_list:
            LOG.warning("Network found in OVN NB DB but not in "
                        "Neutron, network_id=%s", lswitch['name'])
            if self.mode == ovn_const.OVN_DB_SYNC_MODE_REPAIR:
                LOG.warning('Deleting network %s from OVN NB DB',
                            lswitch['name'])
                txn.add(self.ovn_api.ls_del(lswitch['name']))

        for provnet_port_info in add_provnet_ports_list:
            network = provnet_port_info['network']
            segment = provnet_port_info['segment']
            LOG.warning("Provider network found in Neutron but "
                        "provider network port not found in OVN NB DB, "
                        "network_id=%(net)s segment_id=%(seg)s",
                        {'net': network['id'],
                         'seg': segment['id']})
            if self.mode == ovn_const.OVN_DB_SYNC_MODE_REPAIR:
                LOG.warning('Creating provider network port %s in '
                            'OVN NB DB',
                            utils.ovn_provnet_port_name(segment['id']))
                self._ovn_client.create_provnet_port(
                    network['id'], segment, txn=txn, network=network)

        for provnet_port_info in del_provnet_ports_list:
            network = provnet_port_info['network']
            lport = provnet_port_info['lport']
            lswitch = provnet_port_info['lswitch']
            LOG.warning("Provider network port found in OVN NB DB, "
                        "but not in Neutron network_id=%(net)s "
                        "port_name=%(lport)s",
                        {'net': network,
                         'seg': lport})
            if self.mode == ovn_const.OVN_DB_SYNC_MODE_REPAIR:
                LOG.warning('Deleting provider network port %s from '
                            'OVN NB DB', lport)
                txn.add(self.ovn_api.delete_lswitch_port(
                    lport_name=lport,
                    lswitch_name=lswitch))

        for lport_info in del_lports_list:
            LOG.warning("Port found in OVN NB DB but not in "
                        "Neutron, port_id=%s", lport_info['port'])
            if self.mode == ovn_const.OVN_DB_SYNC_MODE_REPAIR:
                LOG.warning('Deleting port %s from OVN NB DB',
                            lport_info['port'])
                txn.add(self.ovn_api.delete_lswitch_port(
                    lport_name=lport_info['port'],
                    lswitch_name=lport_info['lswitch']))
                if lport_info['port'] in ovn_all_dhcp_options['ports_v4']:
                    LOG.warning('Deleting port DHCPv4 options for '
                                '(port %s)', lport_info['port'])
                    txn.add(self.ovn_api.delete_dhcp_options(
                        ovn_all_dhcp_options['ports_v4'].pop(
                            lport_info['port'])['uuid']))
                if lport_info['port'] in ovn_all_dhcp_options['ports_v6']:
                    LOG.warning('Deleting port DHCPv6 options for '
                                '(port %s)', lport_info['port'])
                    txn.add(self.ovn_api.delete_dhcp_options(
                        ovn_all_dhcp_options['ports_v6'].pop(
                            lport_info['port'])['uuid']))

    self._sync_port_dhcp_options(ports_need_sync_dhcp_opts,
                                 ovn_all_dhcp_options['ports_v4'],
                                 ovn_all_dhcp_options['ports_v6'])
    LOG.debug('OVN-NB Sync networks, ports and DHCP options completed @ '
              '%s', str(datetime.now()))


od.OvnNbSynchronizer.sync_networks_ports_and_dhcp_opts = hpb_sync_n_p_and_opts

_real_add_network_segment = segments_db.add_network_segment


def new_add_network_segment(context, network_id, segment, segment_index=0,
                        is_dynamic=False):
    with db_api.CONTEXT_WRITER.using(context):
        netseg_obj = nw.NetworkSegment(
            context, id=uuidutils.generate_uuid(), network_id=network_id,
            network_type=segment.get(NETWORK_TYPE),
            physical_network=segment.get(PHYSICAL_NETWORK),
            segmentation_id=segment.get(SEGMENTATION_ID),
            segment_index=segment_index, is_dynamic=is_dynamic)
        netseg_obj.create()
        registry.publish(resources.SEGMENT,
                         events.PRECOMMIT_CREATE,
                         new_add_network_segment,
                         payload=events.DBEventPayload(
                             context, resource_id=netseg_obj.id,
                             states=(netseg_obj,)))
        segment['id'] = netseg_obj.id
    registry.publish(resources.SEGMENT,
                     events.AFTER_CREATE,
                     new_add_network_segment,
                     payload=events.DBEventPayload(
                         context, resource_id=netseg_obj.id,
                         states=(netseg_obj,)))
    LOG.info("Added segment %(id)s of type %(network_type)s for network "
             "%(network_id)s",
             {'id': netseg_obj.id,
              'network_type': netseg_obj.network_type,
              'network_id': netseg_obj.network_id})


def publish_segment_after_delete(context, segment):
    registry.publish(resources.SEGMENT,
                     events.AFTER_DELETE,
                     publish_segment_after_delete,
                     payload=events.DBEventPayload(
                         context, resource_id=segment['id'],
                         states=(segment,)))


_real_release_dynamic_seg = ml2_managers.TypeManager.release_dynamic_segment


def hpb_release_dynamic_segment(self, context, segment_id):
    segment = segments_db.get_segment_by_id(context, segment_id)
    _real_release_dynamic_seg(self, context, segment_id)
    if segment and not segments_db.get_segment_by_id(context, segment_id):
        publish_segment_after_delete(context, segment)


ml2_managers.TypeManager.release_dynamic_segment = hpb_release_dynamic_segment


_real_map_segment_to_hosts = db.map_segment_to_hosts

segments_db.add_network_segment = new_add_network_segment


def new_map_segment_to_hosts(context, segment_id, hosts):
    """Map segment to a collection of hosts."""
    with db_api.CONTEXT_WRITER.using(context):
        no_autoflush = (context.session.no_autoflush
                        if getattr(context, 'session', None)
                        else nullcontext())
        with no_autoflush:
            existing_hosts = {
                mapping.host for mapping in nw.SegmentHostMapping.get_objects(
                    context, segment_id=segment_id)
            }
        hosts_to_add = set(hosts) - existing_hosts
        for host in hosts_to_add:
            nw.SegmentHostMapping(
                context, segment_id=segment_id, host=host).create()
    LOG.debug('Segment %s mapped to the hosts %s', segment_id, hosts_to_add)


db.map_segment_to_hosts = new_map_segment_to_hosts


class OVNHPBMechanismDriver(ovn_mech.OVNMechanismDriver):

    def _validate_network_segments(self, network_segments):
        # Filter out NDFC-specific ND segments from validation.
        filtered_segments = [
            s for s in network_segments
            if s.get('network_type') != ndfc_const.TYPE_ND
        ]

        if not filtered_segments:
            return

        super(OVNHPBMechanismDriver, self)._validate_network_segments(
            filtered_segments)

    # FIXME: until this gets addressed upstream, we need to
    # specialize this method to support hierarchical port binding.
    def create_segment_provnet_port(self, resource, event, trigger,
                                    payload=None):
        segment = payload.latest_state
        if (not segment.get(segment_def.PHYSICAL_NETWORK) or
                not is_provider_segment_supported(segment)):
            return
        self._ovn_client.create_provnet_port(segment['network_id'], segment)

    # FIXME: until this gets addressed upstream, we need to
    # specialize this method to support hierarchical port binding.
    def delete_segment_provnet_port(self, resource, event, trigger,
                                    payload):
        # NOTE(mjozefcz): Get the last state of segment resource.
        segment = payload.states[-1]
        if (segment.get(segment_def.PHYSICAL_NETWORK) and
                is_provider_segment_supported(segment)):
            self._ovn_client.delete_provnet_port(
                segment['network_id'], segment)
