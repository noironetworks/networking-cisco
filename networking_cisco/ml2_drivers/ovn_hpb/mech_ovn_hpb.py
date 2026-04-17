# Copyright 2026 Cisco Systems
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
# OVN mechanism driver specialization for NDFC HPB use cases.
# This driver subclasses the upstream OVNMechanismDriver but skips
# validation for NDFC-specific ND networks, allowing them to coexist
# with OVN in ML2.

from neutron.plugins.ml2.drivers.ovn.mech_driver import mech_driver as ovn_mech

from networking_cisco.ml2_drivers.ndfc import constants as ndfc_const


class OVNHPBMechanismDriver(ovn_mech.OVNMechanismDriver):

    def _validate_network_segments(self, network_segments):
        # Filter out NDFC-specific ND segments from validation.
        filtered_segments = [
            s for s in network_segments
            if s.get('network_type') != ndfc_const.TYPE_ND
        ]

        if not filtered_segments:
            return

        super(OVNHPBMechanismDriver, self)._validate_network_segments(
            filtered_segments)
