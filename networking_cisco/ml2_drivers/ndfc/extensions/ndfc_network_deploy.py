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
from neutron_lib import constants as n_const

ALIAS = 'nd-network-deploy'
ND_STATUS = 'nd-status'

ND_STATUS_VALUES = ('SUCCESS', 'FAILED', 'SYNC')


EXTENDED_ATTRIBUTES_2_0 = {
    'networks': {
        ND_STATUS: {
            'allow_post': True,
            'allow_put': True,
            'is_visible': True,
            # Optional attribute; remains unset unless explicitly used.
            'default': n_const.ATTR_NOT_SPECIFIED,
            'validate': {'type:values': ND_STATUS_VALUES},
        },
    },
}


class Ndfc_network_deploy(extensions.ExtensionDescriptor):

    @classmethod
    def get_name(cls):
        return 'ND network deploy extension'

    @classmethod
    def get_alias(cls):
        return ALIAS

    @classmethod
    def get_description(cls):
        return (
            'Adds nd-status to ND (type=nd) networks so the NDFC mechanism '
            'driver can expose the status of the last ND deploy operation '
            'and accept a SYNC trigger from operators.'
        )

    @classmethod
    def get_updated(cls):
        # ISO 8601 formatted timestamp
        return '2026-03-30T00:00:00-00:00'

    @classmethod
    def get_extended_resources(cls, version):
        if version == '2.0':
            return EXTENDED_ATTRIBUTES_2_0
        return {}
