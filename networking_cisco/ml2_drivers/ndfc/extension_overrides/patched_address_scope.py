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

from neutron.extensions import address_scope
from neutron_lib.api.definitions import address_scope as apidef


ND_VRF_NAME = 'nd-vrf-name'


class Patched_address_scope(address_scope.Address_scope):

    def update_attributes_map(self, attributes):
        super(Patched_address_scope, self).update_attributes_map(
            attributes,
            extension_attrs_map=apidef.RESOURCE_ATTRIBUTE_MAP)

        addr_attrs = attributes.setdefault('address_scopes', {})
        if ND_VRF_NAME not in addr_attrs:
            addr_attrs[ND_VRF_NAME] = {
                'allow_post': True,
                'allow_put': False,
                'is_visible': True,
                'default': None,
            }

    @classmethod
    def get_extended_resources(cls, version):
        """Return extended resources with nd-name injected.

        We delegate to the base address_scope extension to build the
        standard attribute map, and then add nd-name as an additional
        attribute on the address_scopes resource.
        """
        extended = super(Patched_address_scope, cls).get_extended_resources(
            version)
        if version != '2.0':
            return extended

        addr_attrs = extended.setdefault('address_scopes', {})
        if ND_VRF_NAME not in addr_attrs:
            addr_attrs[ND_VRF_NAME] = {
                'allow_post': True,
                'allow_put': False,
                'is_visible': True,
                'default': None,
            }

        return extended
