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

from openstack.network.v2 import address_scope as address_scope_sdk
from openstack import resource
from openstackclient.network.v2 import address_scope as osc_address_scope
from osc_lib import exceptions

from cliff import hooks

from openstackclient.i18n import _


ND_VRF_NAME = 'nd-vrf-name'


_get_attrs_orig = osc_address_scope._get_attrs


def _get_attrs_nd(client_manager, parsed_args):
    attrs = _get_attrs_orig(client_manager, parsed_args)
    nd_vrf_name = getattr(parsed_args, 'nd_vrf_name', None)
    if nd_vrf_name:
        attrs[ND_VRF_NAME] = nd_vrf_name
    return attrs


osc_address_scope._get_attrs = _get_attrs_nd

address_scope_sdk.AddressScope.nd_vrf_name = resource.Body(ND_VRF_NAME)


class CreateAddressScopeNd(hooks.CommandHook):

    def get_parser(self, parser):
        parser.add_argument(
            '--nd-vrf-name',
            metavar='<nd-vrf-name>',
            dest='nd_vrf_name',
            help=_('ND VRF name for this address scope.'),
        )
        return parser

    def get_epilog(self):
        return ''

    def before(self, parsed_args):
        if getattr(parsed_args, 'nd_vrf_name', None) and \
                getattr(parsed_args, 'share', False):
            raise exceptions.CommandError(
                _('--nd-vrf-name cannot be combined with --share; '))
        return parsed_args

    def after(self, parsed_args, return_code):
        return return_code


class ShowAddressScopeNd(hooks.CommandHook):

    def get_parser(self, parser):
        return parser

    def get_epilog(self):
        return ''

    def before(self, parsed_args):
        return parsed_args

    def after(self, parsed_args, return_code):
        return return_code
