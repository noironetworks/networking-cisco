# Copyright (c) 2017 Cisco Systems, Inc.
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

import mock

from networking_cisco import backwards_compatibility as bc


PORT_ID = 'fake_port_id'
TRUNK_ID = 'fake_trunk_id'
DNS_NAME = 'test_dns_name'
VM_NAME = 'test_vm_name'
SEGMENTATION_VLAN = 'vlan'
SEGMENTATION_ID1 = 101
SEGMENTATION_ID2 = 102

SUBPORTS = [
    {'segmentation_type': SEGMENTATION_VLAN, 'port_id': PORT_ID,
     'segmentation_id': SEGMENTATION_ID1},
    {'segmentation_type': SEGMENTATION_VLAN, 'port_id': PORT_ID,
     'segmentation_id': SEGMENTATION_ID2}]

TRUNK = {
    'status': bc.constants.PORT_STATUS_ACTIVE,
    'sub_ports': SUBPORTS,
    'name': 'trunk0',
    'admin_state_up': 'true',
    'tenant_id': 'fake_tenant_id',
    'project_id': 'fake_project_id',
    'port_id': PORT_ID,
    'id': TRUNK_ID,
    'description': 'fake trunk port'}

PROFILE_BAREMETAL = [{"switch_info": "test_value"}]

SUBPORT = {
    'status': bc.constants.PORT_STATUS_ACTIVE,
    'port_id': PORT_ID,
    'segmentation_id': SEGMENTATION_ID1}

PORT_BAREMETAL = {
    'status': bc.constants.PORT_STATUS_ACTIVE,
    'id': PORT_ID,
    bc.portbindings.VNIC_TYPE: bc.portbindings.VNIC_BAREMETAL,
    bc.dns.DNSNAME: DNS_NAME,
    bc.portbindings.PROFILE: {"local_link_information": PROFILE_BAREMETAL},
    'trunk_details': {'trunk_id': TRUNK_ID, 'sub_ports': SUBPORTS}}

PORT_VM = {
    'status': bc.constants.PORT_STATUS_ACTIVE,
    'id': PORT_ID,
    bc.portbindings.VNIC_TYPE: bc.portbindings.VNIC_NORMAL,
    bc.portbindings.HOST_ID: VM_NAME,
    bc.portbindings.PROFILE: {},
    'trunk_details': {'trunk_id': TRUNK_ID, 'sub_ports': SUBPORTS}}


class TestSubPort(object):
    port_id = PORT_ID
    trunk_id = TRUNK_ID
    segmentation_type = SEGMENTATION_VLAN
    segmentation_id = SEGMENTATION_ID1


class TestTrunk(object):
    admin_state_up = 'test_admin_state'
    id = TRUNK_ID
    tenant_id = 'test_tenant_id'
    name = 'test_trunk_name'
    port_id = PORT_ID
    status = bc.constants.PORT_STATUS_ACTIVE
    sub_ports = SUBPORTS
    update = mock.Mock()
