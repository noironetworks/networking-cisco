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

from openstack.network.v2 import network as network_sdk
from openstack import resource
from openstackclient.network.v2 import network as osc_network
from osc_lib import exceptions as osc_exc

from cliff import hooks
from oslo_log import log as logging

from openstackclient.i18n import _

ND_STATUS = 'nd-status'

_get_attrs_orig = getattr(osc_network, '_get_attrs', None)


LOG = logging.getLogger(__name__)


def _get_attrs_nd(client_manager, parsed_args):
    if _get_attrs_orig is not None:
        attrs = _get_attrs_orig(client_manager, parsed_args)
    else:
        attrs = {}
    nd_status = getattr(parsed_args, 'nd_status', None)
    if nd_status:
        if nd_status != 'SYNC':
            raise osc_exc.CommandError(
                "Only nd-status=SYNC is allowed; SUCCESS/FAILED are "
                "managed by NDFC and the Neutron ND poller.")
        attrs[ND_STATUS] = nd_status
    return attrs


if hasattr(osc_network, '_get_attrs'):
    osc_network._get_attrs = _get_attrs_nd

network_sdk.Network.nd_status = resource.Body(ND_STATUS)


class SetNetworkNdStatus(hooks.CommandHook):

    def get_parser(self, parser):
        parser.add_argument(
            '--nd-status',
            metavar='<nd-status>',
            dest='nd_status',
            choices=['SYNC'],
            help=_('Trigger ND redeploy (nd-status=SYNC) for an ND network. '
                   'The nd_status field may be SUCCESS, FAILED, or SYNC; '
                   'only SYNC may be set via this command.'),
        )
        return parser

    def get_epilog(self):
        return ''

    def before(self, parsed_args):
        nd_status = getattr(parsed_args, 'nd_status', None)
        if not nd_status:
            return parsed_args

        cmd = getattr(self, 'cmd', None)
        app = getattr(cmd, 'app', None) if cmd is not None else None
        client_manager = getattr(app, 'client_manager', None) if app else None
        network_proxy = getattr(
                client_manager, 'network', None) if client_manager else None
        if network_proxy is None:
            return parsed_args

        net_name_or_id = getattr(parsed_args, 'network', None)
        if not net_name_or_id:
            return parsed_args

        net = network_proxy.find_network(net_name_or_id, ignore_missing=True)
        if not net:
            return parsed_args

        net_type = getattr(net, 'provider_network_type', None)

        LOG.debug("SetNetworkNdStatus.before: resolved network %r with "
                  "provider_network_type=%r", net, net_type)

        if net_type and net_type != 'nd':
            raise osc_exc.CommandError(
                "nd-status can only be set on ND networks "
                "(provider:network_type=nd).")

        return parsed_args

    def after(self, parsed_args, return_code):
        if return_code != 0:
            return return_code

        nd_status = getattr(parsed_args, 'nd_status', None)
        if not nd_status:
            return return_code

        cmd = getattr(self, 'cmd', None)
        app = getattr(cmd, 'app', None) if cmd is not None else None
        client_manager = getattr(
                app, 'client_manager', None) if app else None
        network_proxy = getattr(
                client_manager, 'network', None) if client_manager else None
        if network_proxy is None:
            return return_code

        net_name_or_id = getattr(parsed_args, 'network', None)
        if not net_name_or_id:
            return return_code

        try:
            net = network_proxy.find_network(net_name_or_id,
                                             ignore_missing=True)
        except Exception:
            return return_code

        if not net:
            return return_code

        try:
            network_proxy.update_network(net, nd_status=nd_status)
        except Exception:
            return return_code

        return return_code


class ShowNetworkNdStatus(hooks.CommandHook):

    def get_parser(self, parser):
        return parser

    def get_epilog(self):
        return ''

    def before(self, parsed_args):
        return parsed_args

    def after(self, parsed_args, return_code):
        return return_code
