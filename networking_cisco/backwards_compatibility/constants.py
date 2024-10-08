# Copyright 2018 Cisco Systems, Inc.  All rights reserved.
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

# NOTE(sambetts) F401 is the flake8 code for the "X imported but not used"
# error we only ignore that so that other errors like import order still get
# caught.

from networking_cisco.backwards_compatibility \
        import neutron_version as nv  # noqa

# Pull in all the neutron_lib constants
from neutron_lib.constants import *  # noqa

from neutron_lib.plugins.constants import *  # noqa

# Additional things that haven't moved to neutron_lib yet
from neutron.plugins.common.constants import \
        EXT_TO_SERVICE_MAPPING  # noqa: F401
