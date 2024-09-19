# Copyright (c) 2024 Cisco Systems Inc.
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

import sys

from neutron.common import config as common_cfg
from neutron.conf.agent import common as config
from neutron import service
from oslo_config import cfg
from oslo_service import service as svc

from networking_cisco.agent import lldp_topology


def launch(binary, manager, topic=None,
           root_helper=False, report_interval=None, periodic_interval=None):
    common_cfg.register_common_config_options()
    config.register_root_helper(cfg.CONF)
    common_cfg.init(sys.argv[1:])
    config.setup_logging()
    config.setup_privsep()
    report = cfg.CONF.lldp_topology_agent.topology_agent_report_interval
    periodic = cfg.CONF.lldp_topology_agent.topology_agent_poll_interval
    server = service.Service.create(
        binary=binary, manager=manager, topic=topic,
        report_interval=report, periodic_interval=periodic)
    svc.launch(cfg.CONF, server).wait()


def main():
    launch(
        lldp_topology.BINARY_LLDP_TOPOLOGY_AGENT,
        'networking_cisco.agent.lldp_topology.LldpTopologyAgent')
