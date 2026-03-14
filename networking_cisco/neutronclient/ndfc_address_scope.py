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

from __future__ import print_function

from networking_cisco._i18n import _

from neutronclient.common import extension
from neutronclient.neutron import v2_0 as neutronV20


ADDRESS_SCOPE = 'address_scope'


class NdAddressScope(extension.NeutronClientExtension):
    resource = ADDRESS_SCOPE
    resource_plural = 'address_scopes'
    object_path = '/address-scopes'
    resource_path = '/address-scopes/%s'
    versions = ['2.0']
    allow_names = True


class NdAddressScopeCreate(extension.ClientExtensionCreate,
                           NdAddressScope):
    shell_command = 'nd-address-scope-create'

    def add_known_arguments(self, parser):
        parser.add_argument(
            '--nd-vrf-name',
            dest='nd_vrf_name',
            help=_('ND VRF name for this address scope.')
        )
        parser.add_argument(
            '--ip-version',
            dest='ip_version',
            type=int,
            choices=[4, 6],
            required=True,
            help=_('IP version of this address scope (4 or 6).')
        )
        parser.add_argument(
            '--share',
            dest='shared',
            action='store_true',
            default=False,
            help=_('Make the address scope shared.')
        )
        parser.add_argument(
            'name',
            help=_('Name of the address scope.')
        )

    def args2body(self, parsed_args):
        if getattr(parsed_args, 'nd_vrf_name', None) and getattr(
                parsed_args, 'shared', False):
            raise SystemExit(_(
                'nd-vrf-name cannot be combined with shared address ') + _(
                    'scopes'))

        body = {self.resource: {
            'name': parsed_args.name,
            'ip_version': parsed_args.ip_version,
            'shared': parsed_args.shared,
        }}

        if getattr(parsed_args, 'nd_vrf_name', None):
            body[self.resource]['nd-vrf-name'] = parsed_args.nd_vrf_name

        neutronV20.update_dict(parsed_args, body[self.resource], [])
        return body
