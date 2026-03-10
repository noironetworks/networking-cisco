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

from cliff import hooks

from openstackclient.i18n import _

ND_STATUS = 'nd-status'

_get_attrs_orig = getattr(osc_network, '_get_attrs', None)


def _get_attrs_nd(client_manager, parsed_args):
    if _get_attrs_orig is not None:
        attrs = _get_attrs_orig(client_manager, parsed_args)
    else:
        attrs = {}
    nd_status = getattr(parsed_args, 'nd_status', None)
    if nd_status:
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
            choices=['SUCCESS', 'FAILED', 'SYNC'],
            help=_('Set ND deploy status or trigger SYNC for an ND '
                   'network.'),
        )
        return parser

    def get_epilog(self):
        return ''

    def before(self, parsed_args):
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
