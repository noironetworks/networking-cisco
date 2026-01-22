# Copyright 2024 Cisco Systems, Inc.
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

import ipaddress
import os
import random
import time

from networking_cisco.ml2_drivers.ndfc import cache
from networking_cisco.ml2_drivers.ndfc import config
from networking_cisco.ml2_drivers.ndfc import db as nc_ml2_db
from networking_cisco.ml2_drivers.ndfc.ndfc import Ndfc
from networking_cisco.rpc import topo_rpc_handler
from neutron.db import models_v2
from neutron.plugins.ml2 import models
from neutron_lib.api.definitions import portbindings
from neutron_lib import constants
from neutron_lib import context as n_context
from neutron_lib.db import api as db_api
from neutron_lib.plugins import directory
from neutron_lib.plugins.ml2 import api
from neutron_lib.plugins import utils as plugin_utils
from neutron_lib import rpc as n_rpc
from oslo_config import cfg
from oslo_log import log
import oslo_messaging
from oslo_serialization import jsonutils
from oslo_service import loopingcall
from oslo_utils import fileutils
import sqlalchemy as sa
from sqlalchemy.ext import baked
from sqlalchemy import func


LOG = log.getLogger(__name__)

BAKERY = baked.bakery(500, _size_alert=lambda c: LOG.warning(
    "sqlalchemy baked query cache size exceeded in %s", __name__))


class KeystoneNotificationEndpoint(object):
    filter_rule = oslo_messaging.NotificationFilter(
        event_type='^identity.project.[created|deleted]')

    def __init__(self, mechanism_driver):
        self._driver = mechanism_driver

    def info(self, ctxt, publisher_id, event_type, payload, metadata):
        tenant_id = payload.get('resource_info')
        # malformed notification?
        if not tenant_id:
            return None

        LOG.debug("Keystone notification %(event_type)s received for "
                 "tenant %(tenant_id)s",
                 {'event_type': event_type,
                  'tenant_id': tenant_id})

        if event_type == 'identity.project.created':
            self._driver.create_vrf(tenant_id)
            return oslo_messaging.NotificationResult.HANDLED

        if event_type == 'identity.project.deleted':
            #self._driver.purge_resources(tenant_id)
            self._driver.delete_vrf(tenant_id)
            return oslo_messaging.NotificationResult.HANDLED


class NDFCMechanismDriver(api.MechanismDriver,
        topo_rpc_handler.TopologyRpcHandlerMixin):
    def __init__(self):
        super(NDFCMechanismDriver, self).__init__()
        self._last_switch_sync = 0
        self.switch_map = {}

    def initialize(self):
        config.register_opts()
        self.keystone_notification_exchange = (cfg.CONF.ndfc.
                keystone_notification_exchange)
        self.keystone_notification_topic = (cfg.CONF.ndfc.
                                            keystone_notification_topic)
        self.keystone_notification_pool = (cfg.CONF.ndfc.
                                           keystone_notification_pool)
        self._setup_keystone_notification_listeners()
        self.ndfc_ip = (cfg.CONF.ndfc.ndfc_ip)
        self.user = (cfg.CONF.ndfc.user)
        self.pwd = (cfg.CONF.ndfc.pwd)
        self.fabric_name = (cfg.CONF.ndfc.fabric_name)
        self.switch_sync_interval = (cfg.CONF.ndfc.switch_sync_interval)
        self.force_old_api = (cfg.CONF.ndfc.force_old_api)
        self.ndfc = Ndfc(self.ndfc_ip, self.user, self.pwd, self.fabric_name,
                         self.force_old_api)
        self._core_plugin = None
        self.project_details_cache = cache.ProjectDetailsCache()
        self.tenants_file = 'tenants.json'
        self.load_tenants()
        self.start_rpc_listeners()

    def _start_switch_sync_loop(self):
        # Add jitter up to 10% of interval as initial delay
        interval = self.switch_sync_interval
        jitter = random.uniform(0, interval * 0.1)
        _switch_sync_loop = loopingcall.FixedIntervalLoopingCall(
            self._refresh_switch_list)
        _switch_sync_loop.start(interval=interval,
                                initial_delay=jitter,
                                stop_on_exception=False)
        LOG.debug(
            "Started periodic switch sync loop with interval %.2f seconds "
            "and initial delay %.2f seconds", interval, jitter)

    def _refresh_switch_list(self):
        LOG.debug("Refreshing switch list from NDFC...")
        try:
            previous_switch_map = self.switch_map
            latest_switch_map = self.ndfc.ndfc_obj.get_switches(
                    self.fabric_name, previous_switch_map)
            stale_tor_sns = []
            for switch_ip, switch_info in previous_switch_map.items():
                if switch_info and switch_info.get('role') == 'tor':
                    sn = switch_info.get('serial')
                    latest_info = latest_switch_map.get(switch_ip)
                    if not latest_info or latest_info.get('role') != 'tor':
                        stale_tor_sns.append(sn)
                        LOG.debug("Identified stale ToR serial number: %s", sn)
            # Update the in-memory switch map to the latest data
            self.switch_map = latest_switch_map
            self._last_switch_sync = time.time()
            LOG.debug("Switch list refreshed successfully.")
            # Clean up stale NxosTors entries identified
            if stale_tor_sns:
                self._cleanup_stale_tors(stale_tor_sns)

            # Identify and delete stale leaf entries
            cleanup_list = []
            for switch_ip, switch_info in self.switch_map.items():
                if switch_info and switch_info.get('role') == 'tor':
                    tor_serial_number = switch_info.get('serial')
                    current_leaf_sns = set(switch_info.get(
                        'tor_leaf_nodes', {}).values())
                    cleanup_list.append((tor_serial_number, current_leaf_sns))
            if cleanup_list:
                self._cleanup_stale_leaf_nodes(cleanup_list)

        except Exception as e:
            LOG.error("Failed to refresh switch list from NDFC: %s", e)

    @property
    def switches(self):
        return self.switch_map

    def _cleanup_stale_tors(self, stale_tor_serial_numbers):
        if not stale_tor_serial_numbers:
            LOG.debug("No stale ToR serial numbers provided for cleanup.")
            return

        try:
            admin_context = n_context.get_admin_context()
            with db_api.CONTEXT_WRITER.using(admin_context) as session:
                session.query(nc_ml2_db.NxosTors).filter(
                    nc_ml2_db.NxosTors.tor_serial_number.in_(
                        stale_tor_serial_numbers)
                ).delete(synchronize_session='fetch')
            LOG.debug("Stale NxosTors entries cleanup complete.")

        except Exception as e:
            LOG.error("An error occurred during stale NxosTors cleanup: %s", e)

    def _cleanup_stale_leaf_nodes(self, cleanup_list):
        try:
            admin_context = n_context.get_admin_context()
            with db_api.CONTEXT_WRITER.using(admin_context) as session:
                for tor_sn, current_leaf_sns in cleanup_list:
                    existing_leaf_sns = {
                        row[0] for row in session.query(
                            nc_ml2_db.NxosTors.leaf_serial_number).filter(
                                nc_ml2_db.NxosTors.tor_serial_number == tor_sn
                        ).all()
                    }

                    stale_leaf_sns = existing_leaf_sns - current_leaf_sns
                    if stale_leaf_sns:
                        session.query(nc_ml2_db.NxosTors).filter(
                            nc_ml2_db.NxosTors.tor_serial_number == tor_sn,
                            nc_ml2_db.NxosTors.leaf_serial_number.in_(
                                stale_leaf_sns)
                        ).delete(synchronize_session='fetch')
                        LOG.debug("Deleted stale leaf entries for ToR %s "
                                  "(Leaf SNs: %s)", tor_sn,
                                  ', '.join(stale_leaf_sns))

        except Exception as e:
            LOG.error("An error occurred during stale NxosTors leaf cleanup: "
                      "%s", e)

    def start_rpc_listeners(self):
        LOG.debug("NDFC MD starting RPC listeners")
        self._start_switch_sync_loop()
        return self._start_rpc_listeners()

    @property
    def plugin(self):
        if not self._core_plugin:
            self._core_plugin = directory.get_plugin()
        return self._core_plugin

    # TODO(sanaval): use db instead of file to look for existing tenants
    def load_tenants(self):
        if not os.path.exists(self.tenants_file):
            temp_path = fileutils.write_to_tempfile(
                    jsonutils.dumps({}).encode('utf-8'),
                    suffix='.json', prefix='tenants_')
            os.rename(temp_path, self.tenants_file)
        with open(self.tenants_file, 'rb') as file:
            self.tenants = jsonutils.load(file)

    def update_tenants(self):
        temp_path = fileutils.write_to_tempfile(
                jsonutils.dumps(self.tenants).encode('utf-8'),
                suffix='.json', prefix='tenants_')
        os.rename(temp_path, self.tenants_file)

    def get_network(self, context, network_id):
        network_db = self.plugin.get_network(context._plugin_context,
                network_id)
        return network_db

    def _get_topology(self, session, host):
        topology = {}
        query = BAKERY(lambda s: s.query(
            nc_ml2_db.NxosHostLink,
            nc_ml2_db.NxosTors))
        query += lambda q: q.outerjoin(
            nc_ml2_db.NxosTors,
            nc_ml2_db.NxosTors.tor_serial_number ==
            nc_ml2_db.NxosHostLink.serial_number)
        query += lambda q: q.filter(
            nc_ml2_db.NxosHostLink.host_name == sa.bindparam('host'))
        leaf_table = query(session).params(
            host=host).all()

        if not leaf_table:
            LOG.error("No matching host name found for host %s "
                    "Please check nxos_host_links table", host)

        for host_link, tor in leaf_table:
            interface_name = host_link.switch_port
            if tor:
                leaf_serial_number = tor.leaf_serial_number
                tor_serial_number = tor.tor_serial_number
                tor_name = tor.tor_name
                leaf_map = topology.setdefault(
                        leaf_serial_number, {'tor_sw_intf_map': {}})
                tor_map = leaf_map['tor_sw_intf_map'].setdefault(
                        tor_serial_number, {'tor_interfaces': [],
                            'tor_name': tor_name})
                if interface_name not in tor_map['tor_interfaces']:
                    tor_map['tor_interfaces'].append(interface_name)
            else:
                leaf_map = topology.setdefault(host_link.serial_number,
                        {'interfaces': []})
                if interface_name not in leaf_map['interfaces']:
                    leaf_map['interfaces'].append(interface_name)
        return topology

    def get_topology(self, context, network, host, detach=False):
        LOG.debug("Get topology for network %s, host %s", network, host)
        with db_api.CONTEXT_READER.using(
            context._plugin_context) as session:
            query = BAKERY(lambda s: s.query(
                func.count(sa.distinct(models.PortBindingLevel.port_id))))
            query += lambda q: q.outerjoin(
                models_v2.Port,
                models_v2.Port.id == models.PortBindingLevel.port_id)
            query += lambda q: q.filter(
                models_v2.Port.network_id == sa.bindparam('network_id'))
            query += lambda q: q.filter(
                models.PortBindingLevel.host == sa.bindparam('host'))
            count = query(session).params(
                network_id=network['id'],
                host=host).scalar() or 0

            if not detach and count > 1:
                LOG.debug("More hosts attached to network %s, "
                        "no network detach required", network)
                return
            if detach and count > 0:
                LOG.debug("Some host already attached to network %s, "
                        "No attach network required", network)
                return
            return self._get_topology(session, host)

    def allocate_vrf_segment(self, context, vrf_name):
        vrf_vlan_id = self.ndfc.get_vrf_vlan(vrf_name)
        if not vrf_vlan_id:
            LOG.warning("No vlan id found for vrf %s", vrf_name)
        else:
            LOG.debug("Vlan id for vrf %s is %s", vrf_name, vrf_vlan_id)
            network_vlan_ranges = plugin_utils.parse_network_vlan_ranges(
                cfg.CONF.ml2_type_vlan.network_vlan_ranges)
            LOG.debug("Network VLAN ranges: %s", network_vlan_ranges)
            physical_networks = list(network_vlan_ranges.keys())
            LOG.debug("physical networks: %s", physical_networks)
            for physical_network in physical_networks:
                seg_args = {
                    api.PHYSICAL_NETWORK: physical_network,
                    'vlan_id': vrf_vlan_id
                }
                LOG.debug("Segment args %s", seg_args)
                ml2_plugin = context._plugin
                type_manager = ml2_plugin.type_manager
                vlan_obj = type_manager.drivers.get(
                    constants.TYPE_VLAN).obj
                allocated_segment = vlan_obj.allocate_fully_specified_segment(
                    context._plugin_context, **seg_args)
                if allocated_segment:
                    LOG.debug("Dynamic segment %s allocated successfully",
                        allocated_segment)

    def _is_port_bound(self, port):
        return port.get(portbindings.VIF_TYPE) not in [
            portbindings.VIF_TYPE_UNBOUND,
            portbindings.VIF_TYPE_BINDING_FAILED]

    def purge_resources(self, tenant_id):
        ctx = n_context.get_admin_context()
        networks = self.plugin.get_networks(ctx)
        LOG.debug("NDFC Network DBs %s", networks)
        for network in networks:
            if (network['project_id'] == tenant_id):
                LOG.debug("NDFC purge network: %s", network)
                self.plugin.delete_network(ctx,
                        network['id'])

    def _setup_keystone_notification_listeners(self):
        targets = [oslo_messaging.Target(
                    exchange=self.keystone_notification_exchange,
                    topic=self.keystone_notification_topic, fanout=True)]
        endpoints = [KeystoneNotificationEndpoint(self)]
        server = oslo_messaging.get_notification_listener(
            n_rpc.NOTIFICATION_TRANSPORT, targets, endpoints,
            executor='eventlet', pool=self.keystone_notification_pool)
        server.start()

    def create_vrf(self, tenant_id):
        self.project_details_cache.ensure_project(tenant_id)
        prj_details = self.project_details_cache.get_project_details(tenant_id)
        vrf_name = prj_details[0]
        self.tenants[tenant_id] = vrf_name
        self.update_tenants()

        LOG.debug("Create NDFC VRF with vrf name: %s", vrf_name)
        res = self.ndfc.create_vrf(vrf_name)
        if res:
            LOG.info("NDFC VRF %s created successfully", vrf_name)
        else:
            LOG.error("NDFC VRF %s failed to create", vrf_name)

    def delete_vrf(self, tenant_id):
        vrf_name = self.tenants.pop(tenant_id, None)
        if vrf_name:
            self.update_tenants()
            LOG.debug("Delete NDFC VRF with vrf name: %s", vrf_name)
            res = self.ndfc.delete_vrf(vrf_name)
            if res:
                LOG.info("NDFC VRF %s deleted successfully", vrf_name)
            else:
                LOG.error("NDFC VRF %s failed to delete", vrf_name)
        else:
            LOG.debug("VRF name for tenant %s not found", tenant_id)

    def create_network(self, tenant_id, network_name,
            vlan_id, physical_network):
        self.project_details_cache.ensure_project(tenant_id)
        prj_details = self.project_details_cache.get_project_details(tenant_id)
        vrf_name = prj_details[0]
        if vrf_name:
            LOG.debug("Create NDFC network with network name: %s "
                    "vrf name: %s vlan id: %s physical network: %s",
                    network_name, vrf_name, vlan_id, physical_network)
            res = self.ndfc.create_network(vrf_name, network_name,
                    vlan_id, physical_network)
            if res:
                LOG.info("NDFC Network %s created successfully", network_name)
            else:
                LOG.error("NDFC Network %s failed to create", network_name)
        else:
            LOG.debug("VRF name for tenant %s not found", tenant_id)

    def attach_network(self, context, host):
        network = context.network.current

        topology_result = self.get_topology(context, network, host)
        if topology_result:
            self.project_details_cache.ensure_project(network['tenant_id'])
            prj_details = self.project_details_cache.get_project_details(
                network['tenant_id'])
            vrf_name = prj_details[0]
            if network['provider:network_type'] == constants.TYPE_VLAN:
                vlan_id = network['provider:segmentation_id']
                res = self.ndfc.attach_network(vrf_name, network['name'],
                    vlan_id, topology_result)
                if res:
                    self.allocate_vrf_segment(context, vrf_name)
                    LOG.info("NDFC Network %s attached successfully",
                        network['name'])
                else:
                    LOG.error("NDFC Network %s failed to attach",
                        network['name'])

    def detach_network(self, context, host):
        network = context.network.current

        topology_result = self.get_topology(context, network,
                host, detach=True)
        if topology_result:
            self.project_details_cache.ensure_project(network['tenant_id'])
            prj_details = self.project_details_cache.get_project_details(
                network['tenant_id'])
            vrf_name = prj_details[0]
            if network['provider:network_type'] == constants.TYPE_VLAN:
                vlan_id = network['provider:segmentation_id']
                res = self.ndfc.detach_network(vrf_name, network['name'],
                    vlan_id, topology_result)
                if res:
                    LOG.info("NDFC Network %s detached successfully",
                        network['name'])
                else:
                    LOG.error("NDFC Network %s failed to detach",
                        network['name'])

    def update_network(self, tenant_id, network_name, vlan_id,
            gateway_ip, physical_network):
        self.project_details_cache.ensure_project(tenant_id)
        prj_details = self.project_details_cache.get_project_details(tenant_id)
        vrf_name = prj_details[0]
        if vrf_name:
            LOG.debug("Update NDFC network with network name: %s "
                    "vrf name: %s vlan id: %s physical network %s "
                    "with gateway ip: %s",
                    network_name, vrf_name, vlan_id,
                    physical_network, gateway_ip)
            res = self.ndfc.update_network(vrf_name, network_name,
                    vlan_id, gateway_ip, physical_network)
            if res:
                LOG.info("NDFC Network %s updated successfully", network_name)
            else:
                LOG.error("NDFC Network %s failed to update", network_name)
        else:
            LOG.debug("VRF name for tenant %s not found", tenant_id)

    def delete_network(self, network_name, vlan_id, physical_network):
        LOG.debug("Delete NDFC network with network name: %s", network_name)
        res = self.ndfc.delete_network(network_name,
                vlan_id, physical_network)
        if res:
            LOG.info("NDFC Network %s deleted successfully", network_name)
        else:
            LOG.error("NDFC Network %s failed to delete", network_name)

    def create_network_postcommit(self, context):
        network = context.current

        network_name = network['name']
        tenant_id = network['tenant_id']
        vlan_id = network['provider:segmentation_id']
        physical_network = network['provider:physical_network']
        LOG.info("create_network_postcommit: %s", network)

        if physical_network:
            self.create_network(tenant_id, network_name,
                    vlan_id, physical_network)

    def delete_network_postcommit(self, context):
        network = context.current

        network_name = network['name']
        vlan_id = network['provider:segmentation_id']
        physical_network = network['provider:physical_network']
        LOG.debug("delete_network_postcommit: %s", network)

        if physical_network:
            self.delete_network(network_name, vlan_id, physical_network)

    def create_subnet_postcommit(self, context):
        subnet = context.current

        LOG.debug("create_subnet_postcommit: %s", subnet)

        network_id = subnet['network_id']
        network_db = self.get_network(context, network_id)
        tenant_id = network_db['project_id']
        network_name = network_db['name']
        vlan_id = network_db['provider:segmentation_id']
        physical_network = network_db['provider:physical_network']
        gateway_ip = subnet['gateway_ip']
        prefix_len = ipaddress.ip_network(subnet['cidr']).prefixlen
        gateway = str(gateway_ip) + "/" + str(prefix_len)

        if physical_network:
            self.update_network(tenant_id, network_name,
                    vlan_id, gateway, physical_network)

    def update_subnet_postcommit(self, context):
        subnet = context.current
        orig_subnet = context.original

        LOG.debug("update_subnet_postcommit: %s", subnet)

        if subnet['gateway_ip'] != orig_subnet['gateway_ip']:
            network_id = subnet['network_id']
            network_db = self.get_network(context, network_id)
            tenant_id = network_db['project_id']
            network_name = network_db['name']
            vlan_id = network_db['provider:segmentation_id']
            physical_network = network_db['provider:physical_network']
            gateway_ip = subnet['gateway_ip']
            prefix_len = ipaddress.ip_network(subnet['cidr']).prefixlen
            gateway = str(gateway_ip) + "/" + str(prefix_len)

            if physical_network:
                self.update_network(tenant_id, network_name,
                        vlan_id, gateway, physical_network)

    def delete_subnet_postcommit(self, context):
        subnet = context.current

        LOG.debug("delete_subnet_postcommit: %s", subnet)

        network_id = subnet['network_id']
        network_db = self.get_network(context, network_id)
        tenant_id = network_db['project_id']
        network_name = network_db['name']
        vlan_id = network_db['provider:segmentation_id']
        physical_network = network_db['provider:physical_network']
        gateway = ''

        if physical_network:
            self.update_network(tenant_id, network_name,
                    vlan_id, gateway, physical_network)

    def update_port_postcommit(self, context):
        old_port = context.original
        port = context.current

        if context.original_host and context.original_host != context.host:
            self.detach_network(context, context.original_host)

        if (old_port.get(
            portbindings.VIF_TYPE) == portbindings.VIF_TYPE_UNBOUND and
                self._is_port_bound(port)):
            self.attach_network(context, context.host)

    def delete_port_postcommit(self, context):
        port = context.current

        if self._is_port_bound(port):
            self.detach_network(context, context.host)

    # Topology RPC method handler
    def update_link(self, context, host, interface, mac,
                    switch, module, pod_id, port,
                    port_description, serial_number):
        LOG.debug('Topology RPC: update_link: %s',
                  ', '.join([str(p) for p in
                             (host, interface, mac, switch, module, port,
                              pod_id, port_description, serial_number)]))
        # FIXME(This only creates the link - doesn't update it)
        if not switch:
            return
        switch_interface = port
        switch_info = self.switches.get(switch)
        with db_api.CONTEXT_WRITER.using(context) as session:
            # See if we need to add entries to the ToR table
            if switch_info and switch_info.get('role') == 'tor':
                leaf_map = switch_info.get('tor_leaf_nodes')
                for leaf_name, leaf_sn in leaf_map.items():
                    tor = session.query(nc_ml2_db.NxosTors).filter(
                        nc_ml2_db.NxosTors.tor_serial_number == serial_number
                    ).filter(
                            nc_ml2_db.NxosTors.leaf_serial_number == leaf_sn).\
                        one_or_none()
                    if tor:
                        continue
                    LOG.debug("Adding NxosTors entry for ToR serial %s, "
                              "Leaf serial %s", serial_number, leaf_sn)
                    session.add(nc_ml2_db.NxosTors(
                        tor_serial_number=serial_number,
                        leaf_serial_number=leaf_sn, tor_name=module))

            if switch_info and switch_info.get('role') != 'tor':
                stale_tors_to_delete = session.query(
                    nc_ml2_db.NxosTors).filter_by(
                    tor_serial_number=serial_number).all()
                for tor_entry in stale_tors_to_delete:
                    session.delete(tor_entry)

            po = ""
            if switch_info:
                po = self.ndfc.ndfc_obj.get_po(self.fabric_name,
                    switch_info.get('serial'), switch_interface)
            if po != "":
                switch_interface = "Port-Channel" + po

            hlink = session.query(
                nc_ml2_db.NxosHostLink).filter(
                    nc_ml2_db.NxosHostLink.host_name == host).filter(
                        nc_ml2_db.NxosHostLink.interface_name ==
                        interface).one_or_none()
            if (hlink and
                hlink['serial_number'] == serial_number and
                hlink['switch_ip'] == switch and
                hlink['switch_mac'] == mac and
                hlink['switch_port'] == switch_interface):
                # There was neither a change nor a refresh required.
                return

            if hlink:
                hlink['serial_number'] = serial_number
                hlink['switch_ip'] = switch
                hlink['switch_mac'] = mac
                hlink['switch_port'] = switch_interface
            else:
                session.add(nc_ml2_db.NxosHostLink(host_name=host,
                    interface_name=interface, serial_number=serial_number,
                    switch_ip=switch, switch_mac=mac,
                    switch_port=switch_interface))
                LOG.debug("Added NxosHostLink for host %s interface %s",
                        host, interface)
