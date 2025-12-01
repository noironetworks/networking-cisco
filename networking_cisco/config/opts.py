# Licensed under the Apache License, Version 2.0 (the "License"); you may not
# use this file except in compliance with the License. You may obtain a copy
# of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from networking_cisco.plugins.cisco.device_manager import (
    config as asrcfg)


def list_asr_conf_opts():
    return [
        ('cisco_hosting_device_credential:<uuid>', asrcfg.credentials_subopts),
        ('cisco_hosting_device_template:<uuid>', asrcfg.template_subopts),
        ('cisco_hosting_device:<uuid>', asrcfg.hosting_device_subopts),
        ('cisco_router_type:<uuid>', asrcfg.router_type_subopts)
    ]
