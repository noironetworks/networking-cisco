# Copyright 2026 Cisco Systems, Inc.
# All Rights Reserved
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
#

import abc

import fixtures
from neutron.api import extensions as neutron_ext
from neutron.common import config


class NdfcMl2Base(abc.ABC):
    def setUp(self):
        config.register_common_config_options()

        self.useFixture(fixtures.MockPatchObject(
            neutron_ext.PluginAwareExtensionManager,
            'check_if_plugin_extensions_loaded',
            return_value=None))

        super().setUp()
