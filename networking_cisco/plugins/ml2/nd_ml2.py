# Copyright 2026 Cisco Systems, Inc.
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

from neutron.plugins.ml2 import driver_context
from neutron.plugins.ml2 import plugin as ml2_plugin
from neutron_lib.api.definitions import address_scope as as_def
from neutron_lib.callbacks import events
from neutron_lib.callbacks import registry
from neutron_lib.callbacks import resources
from neutron_lib import context as n_context
from neutron_lib.db import api as db_api
from neutron_lib import exceptions as n_exc
from oslo_log import log as logging
from oslo_utils import excutils

from networking_cisco.ml2_drivers.ndfc import constants as ndfc_const
from networking_cisco.ml2_drivers.ndfc import extension_db
from networking_cisco.ml2_drivers.ndfc.extensions import (
    ndfc_network_deploy as nd_net_ext
)
from networking_cisco.plugins.ml2.nd_extension_manager import (
    NdExtensionManager
)
from networking_cisco.plugins.ml2.nd_manager import NdManager


LOG = logging.getLogger(__name__)


class RouterNotCompatibleWithNetworkType(n_exc.BadRequest):
    message = ("RouterNotCompatibleWithNetworkType: Router interface "
               "cannot be added to a network of type '%(network_type)s'.")


class NdMl2Plugin(ml2_plugin.Ml2Plugin):

    def __init__(self):
        if hasattr(ml2_plugin.Ml2Plugin, '_supported_extension_aliases'):
            if (nd_net_ext.ALIAS not in
                    ml2_plugin.Ml2Plugin._supported_extension_aliases):
                ml2_plugin.Ml2Plugin._supported_extension_aliases.append(
                    nd_net_ext.ALIAS)

        super(NdMl2Plugin, self).__init__()
        self._nd_manager = NdManager()
        self.nd_extension_manager = NdExtensionManager(self._nd_manager)
        registry.subscribe(
            self._check_router_interface_network_type,
            resources.ROUTER_INTERFACE,
            events.BEFORE_CREATE)

    @property
    def supported_extension_aliases(self):
        aliases = list(super(NdMl2Plugin, self).supported_extension_aliases)
        if nd_net_ext.ALIAS not in aliases:
            aliases.append(nd_net_ext.ALIAS)
        return aliases

    def create_address_scope(self, context, address_scope):
        mech_context = None
        with db_api.CONTEXT_WRITER.using(context):
            result = super(NdMl2Plugin, self).create_address_scope(
                context, address_scope)

            body = address_scope.get(as_def.ADDRESS_SCOPE, {})
            self.nd_extension_manager.handle_address_scope_create(
                context, body, result)

            if hasattr(driver_context, 'AddressScopeContext'):
                mech_context = driver_context.AddressScopeContext(
                    self, context, result)
                self.mechanism_manager.create_address_scope_precommit(
                    mech_context)

        if mech_context is not None:
            try:
                self.mechanism_manager.create_address_scope_postcommit(
                    mech_context)
            except Exception:
                with excutils.save_and_reraise_exception():
                    LOG.error("mechanism_manager.create_address_scope_"
                              "postcommit failed, deleting address_scope "
                              "'%s'", result['id'])
                    self.delete_address_scope(context, result['id'])

        LOG.debug("NdMl2Plugin.create_address_scope: body=%s result=%s",
                  address_scope, result)
        return result

    def get_address_scope(self, context, id, fields=None):
        res = super(NdMl2Plugin, self).get_address_scope(context, id, fields)
        if not res:
            return res
        try:
            with db_api.CONTEXT_READER.using(context):
                session = context.session
                base_model = self._get_address_scope(context, id)
                self.nd_extension_manager.extend_address_scope_dict(
                    session, base_model, res
                )
        except Exception:
            LOG.exception("Failed to extend address_scope %s with nd-name", id)
        return res

    def get_address_scopes(self, context, filters=None, fields=None):
        res_list = super(NdMl2Plugin, self).get_address_scopes(
            context, filters, fields)
        if not res_list:
            return res_list
        for res in res_list:
            addr_id = res.get("id")
            if not addr_id:
                continue
            try:
                with db_api.CONTEXT_READER.using(context):
                    session = context.session
                    base_model = self._get_address_scope(context, addr_id)
                    self.nd_extension_manager.extend_address_scope_dict(
                        session, base_model, res
                    )
            except Exception:
                LOG.exception("Failed to extend address_scope %s with "
                        "nd-vrf-name", addr_id)
        return res_list

    def delete_address_scope(self, context, id):
        session = getattr(context, 'session', None)
        if session is None:
            admin_ctx = n_context.get_admin_context()
            session = admin_ctx.session
        nd_vrf_name = None
        delete_vrf = False
        try:
            ext_row = (session.query(extension_db.NdAddressScopeExtension)
                       .filter_by(address_scope_id=id)
                       .first())
            if ext_row is not None:
                nd_vrf_name = ext_row.nd_vrf_name
        except Exception:
            LOG.exception("Failed to load NdAddressScopeExtension for %s", id)

        super(NdMl2Plugin, self).delete_address_scope(context, id)

        if nd_vrf_name:
            try:
                others = (session.query(extension_db.NdAddressScopeExtension)
                          .filter(extension_db.NdAddressScopeExtension.
                                  nd_vrf_name == nd_vrf_name,
                                  extension_db.NdAddressScopeExtension.
                                  address_scope_id != id)
                          .count())
                delete_vrf = (others == 0)
            except Exception:
                LOG.exception(
                    "Failed to check other NdAddressScopeExtension rows for "
                    "VRF %s", nd_vrf_name)

        if nd_vrf_name and delete_vrf:
            self.nd_extension_manager.delete_vrf_for_address_scope(nd_vrf_name)

    def get_network(self, context, id, fields=None, net_db=None):
        res = super(NdMl2Plugin, self).get_network(context, id, fields)
        if not res:
            return res
        try:
            with db_api.CONTEXT_READER.using(context):
                session = context.session
                base_model = type('obj', (), {'id': id})()
                self.nd_extension_manager.extend_network_dict(
                    session, base_model, res
                )
        except Exception:
            LOG.exception("Failed to extend network %s with nd-status", id)
        return res

    def get_networks(self, context, filters=None, fields=None, sorts=None,
                     limit=None, marker=None, page_reverse=False):
        res_list = super(NdMl2Plugin, self).get_networks(
            context, filters, fields, sorts, limit, marker, page_reverse)
        if not res_list:
            return res_list
        for res in res_list:
            net_id = res.get("id")
            if not net_id:
                continue
            try:
                with db_api.CONTEXT_READER.using(context):
                    session = context.session
                    base_model = type('obj', (), {'id': net_id})()
                    self.nd_extension_manager.extend_network_dict(
                        session, base_model, res
                    )
            except Exception:
                LOG.exception(
                    "Failed to extend network %s with nd-status", net_id)
        return res_list

    def update_network(self, context, id, network):
        original = super(NdMl2Plugin, self).get_network(context, id)

        result = super(NdMl2Plugin, self).update_network(context, id, network)
        LOG.debug("update_network: network id: %s; network type: %s",
                  result.get('id'), result.get('provider:network_type'))

        body = network.get('network', {}) or {}
        nd_status = body.get(nd_net_ext.ND_STATUS)
        if not nd_status:
            return result

        if result.get('provider:network_type') != ndfc_const.TYPE_ND:
            return result

        mech_context = driver_context.NetworkContext(
            self, context, result, original)
        self.mechanism_manager.update_network_postcommit(mech_context)

        return result

    def _check_router_interface_network_type(self, resource, event,
            trigger, payload=None):
        if payload is None:
            return
        context = payload.context
        metadata = payload.metadata or {}
        network_id = metadata.get('network_id')
        if not network_id:
            return
        try:
            network = super(NdMl2Plugin, self).get_network(context, network_id)
        except Exception:
            LOG.debug("_check_router_interface_network_type: could not "
                      "fetch network %s", network_id)
            return
        network_type = network.get('provider:network_type')
        if network_type == ndfc_const.TYPE_ND:
            raise RouterNotCompatibleWithNetworkType(
                network_type=network_type)
