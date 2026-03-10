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


NETWORK = 'network'


class NdNetworkDeploy(extension.NeutronClientExtension):
    resource = NETWORK
    resource_plural = 'networks'
    object_path = '/networks'
    resource_path = '/networks/%s'
    versions = ['2.0']
    allow_names = True


class NdNetworkDeployUpdate(extension.ClientExtensionUpdate,
                            NdNetworkDeploy):
    shell_command = 'nd-network-deploy-update'

    def add_known_arguments(self, parser):
        parser.add_argument(
            '--nd-status',
            dest='nd_status',
            choices=['SUCCESS', 'FAILED', 'SYNC'],
            help=_('Set ND deploy status or trigger SYNC for this '
                   'network (ND only).'),
        )

    def args2body(self, parsed_args):
        body = {self.resource: {}}
        if getattr(parsed_args, 'nd_status', None):
            body[self.resource]['nd-status'] = parsed_args.nd_status
        neutronV20.update_dict(parsed_args, body[self.resource], [])
        return body
