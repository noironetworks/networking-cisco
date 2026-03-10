# Copyright 2026 Cisco Systems, Inc.
# All rights reserved.
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

"""ML2 extension driver for ND-specific attributes.

This driver is intentionally minimal. It exists primarily so that
deployments can enable an ND-specific ML2 extension driver via the
``[ml2] extension_drivers`` configuration option. Once enabled, it wires
in the ND API extension package so that attributes like ``nd-name``
are exposed through Neutron's API layer.
"""

from networking_cisco.ml2_drivers.ndfc import constants as ndfc_const
from networking_cisco.ml2_drivers.ndfc import extension_db
from networking_cisco.ml2_drivers.ndfc import extensions as nd_ext_pkg
from networking_cisco.ml2_drivers.ndfc.ndfc import get_ndfc_conf
from neutron.api import extensions as old_extensions
from neutron.db.models import address_scope as as_db
from neutron_lib.db import api as db_api
from neutron_lib import exceptions as n_exc
from neutron_lib.plugins.ml2 import api
from oslo_log import log as logging


LOG = logging.getLogger(__name__)


class NdExtensionDriver(api.ExtensionDriver):

    @property
    def extension_alias(self):
        return "nd_extension_driver"

    def initialize(self):
        ext_paths = list(getattr(nd_ext_pkg, "__path__", []))
        if ext_paths:
            ext_path = ext_paths[0]
            LOG.debug("NdExtensionDriver.initialize: adding API extension "
                      "path %s", ext_path)
            old_extensions.append_api_extensions_path([ext_path])
        else:
            LOG.warning("NdExtensionDriver.initialize: nd_ext_pkg has no "
                        "__path__; skipping append_api_extensions_path")
        LOG.debug("NdExtensionDriver.initialize: completed")

    def _is_nd_network(self, result):
        return result.get('provider:network_type') == ndfc_const.TYPE_ND

    def _set_nd_network_status(self, plugin_context, network_id, nd_status):
        if nd_status is None:
            return
        with db_api.CONTEXT_WRITER.using(plugin_context):
            session = plugin_context.session
            ext = (session.query(extension_db.NdNetworkExtension)
                   .filter_by(network_id=network_id)
                   .first())
            if ext is None:
                ext = extension_db.NdNetworkExtension(
                    network_id=network_id,
                    nd_status=nd_status,
                )
                session.add(ext)
            else:
                ext.nd_status = nd_status

    def process_create_network(self, plugin_context, data, result):
        nd_status = data.get('nd-status') or data.get('nd_status')
        if not nd_status:
            return
        if not self._is_nd_network(result):
            return
        self._set_nd_network_status(plugin_context, result['id'], nd_status)

    def process_update_network(self, plugin_context, data, result):
        nd_status = data.get('nd-status') or data.get('nd_status')
        if nd_status is None:
            return
        if not self._is_nd_network(result):
            return
        self._set_nd_network_status(plugin_context, result['id'], nd_status)

    def extend_network_dict(self, session, base_model, result):
        if not self._is_nd_network(result):
            return
        ext = (session.query(extension_db.NdNetworkExtension)
               .filter_by(network_id=base_model.id)
               .first())
        if ext is not None:
            result['nd-status'] = ext.nd_status

    def extend_network_dict_bulk(self, session, results):
        for result in results:
            base_model = result.get('db_obj')
            if base_model is None:
                # Fallback: rely on extend_network_dict to resolve by id.
                network_id = result.get('id')
                if not network_id:
                    continue
                base_model = type('obj', (), {'id': network_id})()  # shim
            self.extend_network_dict(session, base_model, result)

    def process_create_subnet(self, plugin_context, data, result):
        return

    def process_update_subnet(self, plugin_context, data, result):
        return

    def extend_subnet_dict(self, session, base_model, result):
        return

    def extend_subnet_dict_bulk(self, session, results):
        return

    def process_create_port(self, plugin_context, data, result):
        return

    def process_update_port(self, plugin_context, data, result):
        return

    def extend_port_dict(self, session, base_model, result):
        return

    def extend_port_dict_bulk(self, session, results):
        return

    def process_create_address_scope(self, plugin_context, data, result):
        LOG.debug("NdExtensionDriver.process_create_address_scope: "
                  "data=%s result=%s", data, result)
        nd_vrf_name = data.get('nd-vrf-name') or data.get('nd_vrf_name')
        if not nd_vrf_name:
            LOG.debug("NdExtensionDriver: no nd-vrf-name in request, skipping")
            return

        ip_version = data.get('ip_version')
        if ip_version is not None:
            session = plugin_context.session
            mappings = (session.query(as_db.AddressScope)
                .join(extension_db.NdAddressScopeExtension,
                    extension_db.NdAddressScopeExtension.
                    address_scope_id == as_db.AddressScope.id)
                .filter(extension_db.NdAddressScopeExtension.nd_vrf_name ==
                    nd_vrf_name).all())
            for scope in mappings:
                if scope.ip_version == ip_version:
                    raise n_exc.InvalidInput(
                        error_message=(
                            'VRF %s is already in use by address-scope %s' %
                            (nd_vrf_name, scope.id)))

        ndfc = get_ndfc_conf()
        try:
            created = ndfc.create_vrf(nd_vrf_name)
            if not created:
                LOG.error("ND create_vrf failed for address scope nd-vrf-name "
                          "%s (address_scope_id=%s)",
                          nd_vrf_name, result['id'])
            else:
                LOG.debug(
                    "ND create_vrf succeeded for address scope nd-vrf-name "
                    "%s (address_scope_id=%s)", nd_vrf_name, result['id'])
        except Exception as exc:
            LOG.error("Failed to create VRF %(vrf)s in ND: %(exc)s",
                      {"vrf": nd_vrf_name, "exc": exc})

        with db_api.CONTEXT_WRITER.using(plugin_context):
            session = plugin_context.session
            ext = extension_db.NdAddressScopeExtension(
                address_scope_id=result['id'],
                nd_vrf_name=nd_vrf_name,
            )
            session.add(ext)
            LOG.debug("NdExtensionDriver: inserted extension row for %s",
                      result['id'])

    def extend_address_scope_dict(self, session, base_model, result):
        LOG.debug("NdExtensionDriver.extend_address_scope_dict: id=%s",
                  base_model.id)
        ext = (session.query(extension_db.NdAddressScopeExtension)
               .filter_by(address_scope_id=base_model.id)
               .first())
        LOG.debug("NdExtensionDriver: extension row=%s", ext)
        if ext:
            result['nd-vrf-name'] = ext.nd_vrf_name
