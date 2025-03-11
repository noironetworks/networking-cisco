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
import json
import os

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
from neutron_lib import rpc as n_rpc
from oslo_config import cfg
from oslo_log import log
import oslo_messaging
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
                  'project name': tenant_id})

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
        LOG.debug("NDFC config details: ndfc_ip: %s user: %s "
                  "pwd: %s fabric_name %s",
                  self.ndfc_ip, self.user, self.pwd, self.fabric_name)
        self.ndfc = Ndfc(self.ndfc_ip, self.user, self.pwd, self.fabric_name)
        self._core_plugin = None
        self.project_details_cache = cache.ProjectDetailsCache()
        self.tenants_file = 'tenants.json'
        self.load_tenants()
        self.start_rpc_listeners()
        self.switch_map = {}

    @property
    def switches(self):
        # TODO(sanaval): add synchronization with NDFC for the switches
        if not self.switch_map:
            self.switch_map = self.ndfc.ndfc_obj.get_switches(self.fabric_name)
        return self.switch_map

    def start_rpc_listeners(self):
        LOG.info("NDFC MD starting RPC listeners")
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
                    json.dumps({}).encode('utf-8'),
                    suffix='.json', prefix='tenants_')
            os.rename(temp_path, self.tenants_file)
        with open(self.tenants_file, 'r') as file:
            self.tenants = json.load(file)

    def update_tenants(self):
        temp_path = fileutils.write_to_tempfile(
                json.dumps(self.tenants).encode('utf-8'),
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
                return
            if detach and count > 0:
                return
            return self._get_topology(session, host)

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
            LOG.debug("NDFC VRF %s created successfully", vrf_name)
        else:
            LOG.debug("NDFC VRF %s failed to create", vrf_name)

    def delete_vrf(self, tenant_id):
        vrf_name = self.tenants.pop(tenant_id, None)
        if vrf_name:
            self.update_tenants()
            LOG.debug("Delete NDFC VRF with vrf name: %s", vrf_name)
            res = self.ndfc.delete_vrf(vrf_name)
            if res:
                LOG.debug("NDFC VRF %s deleted successfully", vrf_name)
            else:
                LOG.debug("NDFC VRF %s failed to delete", vrf_name)
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
                LOG.debug("NDFC Network %s created successfully", network_name)
            else:
                LOG.debug("NDFC Network %s failed to create", network_name)
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
                    LOG.debug("NDFC Network %s attached successfully",
                        network['name'])
                else:
                    LOG.debug("NDFC Network %s failed to attach",
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
                    LOG.debug("NDFC Network %s detached successfully",
                        network['name'])
                else:
                    LOG.debug("NDFC Network %s failed to detach",
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
                LOG.debug("NDFC Network %s updated successfully", network_name)
            else:
                LOG.debug("NDFC Network %s failed to update", network_name)
        else:
            LOG.debug("VRF name for tenant %s not found", tenant_id)

    def delete_network(self, network_name, vlan_id, physical_network):
        LOG.debug("Delete NDFC network with network name: %s", network_name)
        res = self.ndfc.delete_network(network_name,
                vlan_id, physical_network)
        if res:
            LOG.debug("NDFC Network %s deleted successfully", network_name)
        else:
            LOG.debug("NDFC Network %s failed to delete", network_name)

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
        port = context.current

        if context.original_host and context.original_host != context.host:
            self.detach_network(context, context.original_host)

        if self._is_port_bound(port):
            self.attach_network(context, context.host)

    def delete_port_postcommit(self, context):
        port = context.current

        if self._is_port_bound(port):
            self.detach_network(context, context.host)

    def _get_tor_entry(self, context, tor_sn, leaf_sn):
        with db_api.CONTEXT_READER.using(context) as session:
            return session.query(
                nc_ml2_db.NxosTors).filter(
                    nc_ml2_db.NxosTors.tor_serial_number == tor_sn).filter(
                            nc_ml2_db.NxosTors.leaf_serial_number ==
                            leaf_sn).one_or_none()

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
        with db_api.CONTEXT_WRITER.using(context) as session:
            hlink = session.query(
                nc_ml2_db.NxosHostLink).filter(
                    nc_ml2_db.NxosHostLink.host_name == host).filter(
                        nc_ml2_db.NxosHostLink.interface_name ==
                        interface).one_or_none()
            if (hlink and
                hlink['serial_number'] == serial_number and
                hlink['switch_ip'] == switch and
                hlink['switch_mac'] == mac and
                hlink['switch_port'] == port):
                # There was neither a change nor a refresh required.
                return
            # Now see if we need to add entries to the ToR table as well
            switch_info = self.switches.get(switch)
            if switch_info and switch_info.get('role') == 'tor':
                leaf_map = switch_info.get('tor_leaf_nodes')
                for leaf_name, leaf_sn in leaf_map.items():
                    tor = self._get_tor_entry(context, serial_number, leaf_sn)
                    if tor:
                        continue
                    with db_api.CONTEXT_WRITER.using(context) as session:
                        session.add(nc_ml2_db.NxosTors(
                            tor_serial_number=serial_number,
                            leaf_serial_number=leaf_sn, tor_name=module))
            po = self.ndfc.ndfc_obj.get_po(
                switch_info.get('serial'), switch_interface)
            if po != "":
                switch_interface = "Port-Channel" + po
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
