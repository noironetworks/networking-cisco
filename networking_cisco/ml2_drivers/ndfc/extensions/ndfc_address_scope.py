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

from neutron_lib.api import extensions


ALIAS = 'nd-address-scope'
ND_VRF_NAME = 'nd-vrf-name'


EXTENDED_ATTRIBUTES_2_0 = {
    'address_scopes': {
        ND_VRF_NAME: {
            'allow_post': True,
            'allow_put': False,
            'is_visible': True,
            'default': None,
        },
    },
}


class Nd_address_scope(extensions.ExtensionDescriptor):

    @classmethod
    def get_name(cls):
        return "ND Address Scope extension"

    @classmethod
    def get_alias(cls):
        return ALIAS

    @classmethod
    def get_description(cls):
        return (
            "Adds nd-vrf-name to address scopes so ND fabrics can map them "
            "to specific VRFs."
        )

    @classmethod
    def get_updated(cls):
        # ISO 8601 formatted timestamp
        return "2026-03-13T00:00:00-00:00"

    @classmethod
    def get_extended_resources(cls, version):
        if version == "2.0":
            return EXTENDED_ATTRIBUTES_2_0
        return {}
