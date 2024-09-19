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


RAW_TOPOLOGY_DATA_1 = [
    "lldp.ens9.via=LLDP"
    "lldp.ens9.rid=2",
    "lldp.ens9.age=24 days, 18:08:04",
    "lldp.ens9.chassis.mac=a4:53:0e:a5:e1:db",
    "lldp.ens9.chassis.name=ostack-pt-1-leaf-1",
    "lldp.ens9.chassis.descr=topology/pod-1/node-101",
    "lldp.ens9.chassis.mgmt-ip=10.30.120.191",
    "lldp.ens9.chassis.Bridge.enabled=on",
    "lldp.ens9.chassis.Router.enabled=on",
    "lldp.ens9.port.local=Eth1/39",
    "lldp.ens9.port.descr=%(TS1)s",
    "lldp.ens9.port.ttl=120",
    "lldp.ens9.lldp-med.device-type=Network Connectivity Device",
    "lldp.ens9.lldp-med.Capabilities.available=yes",
    "lldp.ens9.lldp-med.Policy.available=yes",
    "lldp.ens9.lldp-med.MDI/PSE.available=yes",
    "lldp.ens9.lldp-med.policy.apptype=Voice",
    "lldp.ens9.lldp-med.policy.defined=yes",
    "lldp.ens9.lldp-med.policy.vlan.vid=priority",
    "lldp.ens9.lldp-med.policy.priority=Best effort",
    "lldp.ens9.lldp-med.policy.pcp=0",
    "lldp.ens9.lldp-med.policy.dscp=0",
    "lldp.ens9.unknown-tlvs.unknown-tlv.oui=00,01,42",
    "lldp.ens9.unknown-tlvs.unknown-tlv.subtype=1",
    "lldp.ens9.unknown-tlvs.unknown-tlv.len=1",
    "lldp.ens9.unknown-tlvs.unknown-tlv=01",
    "lldp.ens9.unknown-tlvs.unknown-tlv.oui=00,01,42",
    "lldp.ens9.unknown-tlvs.unknown-tlv.subtype=209",
    "lldp.ens9.unknown-tlvs.unknown-tlv.len=1",
    "lldp.ens9.unknown-tlvs.unknown-tlv=04",
    "lldp.ens9.unknown-tlvs.unknown-tlv.oui=00,01,42",
    "lldp.ens9.unknown-tlvs.unknown-tlv.subtype=216",
    "lldp.ens9.unknown-tlvs.unknown-tlv.len=2",
    "lldp.ens9.unknown-tlvs.unknown-tlv=00,00",
    "lldp.ens9.unknown-tlvs.unknown-tlv.oui=00,01,42",
    "lldp.ens9.unknown-tlvs.unknown-tlv.subtype=201",
    "lldp.ens9.unknown-tlvs.unknown-tlv.len=1",
    "lldp.ens9.unknown-tlvs.unknown-tlv=01",
    "lldp.ens9.unknown-tlvs.unknown-tlv.oui=00,01,42",
    "lldp.ens9.unknown-tlvs.unknown-tlv.subtype=212",
    "lldp.ens9.unknown-tlvs.unknown-tlv.len=11",
    "lldp.ens9.unknown-tlvs.unknown-tlv=46,44,4F,32,33,32,37,31,33,57,4C",
    "lldp.ens9.unknown-tlvs.unknown-tlv.oui=00,01,42",
    "lldp.ens9.unknown-tlvs.unknown-tlv.subtype=214",
    "lldp.ens9.unknown-tlvs.unknown-tlv.len=15",
    "lldp.ens9.unknown-tlvs.unknown-tlv=%(TLV3)s",
    "lldp.ens9.unknown-tlvs.unknown-tlv.oui=00,01,42",
    "lldp.ens9.unknown-tlvs.unknown-tlv.subtype=210",
    "lldp.ens9.unknown-tlvs.unknown-tlv.len=14",
    "lldp.ens9.unknown-tlvs.unknown-tlv=%(TLV4)s",
    "lldp.ens9.unknown-tlvs.unknown-tlv.oui=00,01,42",
    "lldp.ens9.unknown-tlvs.unknown-tlv.subtype=202",
    "lldp.ens9.unknown-tlvs.unknown-tlv.len=1",
    "lldp.ens9.unknown-tlvs.unknown-tlv=01",
    "lldp.ens9.unknown-tlvs.unknown-tlv.oui=00,01,42",
    "lldp.ens9.unknown-tlvs.unknown-tlv.subtype=211",
    "lldp.ens9.unknown-tlvs.unknown-tlv.len=2",
    "lldp.ens9.unknown-tlvs.unknown-tlv=0E,75",
    "lldp.ens9.unknown-tlvs.unknown-tlv.oui=00,01,42",
    "lldp.ens9.unknown-tlvs.unknown-tlv.subtype=215",
    "lldp.ens9.unknown-tlvs.unknown-tlv.len=18",
    "lldp.ens9.unknown-tlvs.unknown-tlv=%(TLV1)s",
    "lldp.ens9.unknown-tlvs.unknown-tlv.oui=00,01,42",
    "lldp.ens9.unknown-tlvs.unknown-tlv.subtype=206",
    "lldp.ens9.unknown-tlvs.unknown-tlv.len=11",
    "lldp.ens9.unknown-tlvs.unknown-tlv=6F,73,74,61,63,6B,2D,70,74,2D,31",
    "lldp.ens9.unknown-tlvs.unknown-tlv.oui=00,01,42",
    "lldp.ens9.unknown-tlvs.unknown-tlv.subtype=208",
    "lldp.ens9.unknown-tlvs.unknown-tlv.len=4",
    "lldp.ens9.unknown-tlvs.unknown-tlv=0A,00,48,40",
    "lldp.ens9.unknown-tlvs.unknown-tlv.oui=00,01,42",
    "lldp.ens9.unknown-tlvs.unknown-tlv.subtype=203",
    "lldp.ens9.unknown-tlvs.unknown-tlv.len=4",
    "lldp.ens9.unknown-tlvs.unknown-tlv=00,00,00,65",
    "lldp.ens9.unknown-tlvs.unknown-tlv.oui=00,01,42",
    "lldp.ens9.unknown-tlvs.unknown-tlv.subtype=205",
    "lldp.ens9.unknown-tlvs.unknown-tlv.len=2",
    "lldp.ens9.unknown-tlvs.unknown-tlv=00,01",
    "lldp.ens9.unknown-tlvs.unknown-tlv.oui=00,01,42",
    "lldp.ens9.unknown-tlvs.unknown-tlv.subtype=207",
    "lldp.ens9.unknown-tlvs.unknown-tlv.len=41",
    "lldp.ens9.unknown-tlvs.unknown-tlv=%(TLV2)s",
    "lldp.ens10.via=LLDP",
    "lldp.ens10.rid=3",
    "lldp.ens10.age=24 days, 18:07:58",
    "lldp.ens10.chassis.mac=a4:53:0e:9d:6d:87",
    "lldp.ens10.chassis.name=ostack-pt-1-leaf-2",
    "lldp.ens10.chassis.descr=topology/pod-1/node-102",
    "lldp.ens10.chassis.mgmt-ip=10.30.120.192",
    "lldp.ens10.chassis.Bridge.enabled=on",
    "lldp.ens10.chassis.Router.enabled=on",
    "lldp.ens10.port.local=Eth1/39",
    "lldp.ens10.port.descr=%(TS1)s",
    "lldp.ens10.port.ttl=120",
    "lldp.ens10.lldp-med.device-type=Network Connectivity Device",
    "lldp.ens10.lldp-med.Capabilities.available=yes",
    "lldp.ens10.lldp-med.Policy.available=yes",
    "lldp.ens10.lldp-med.MDI/PSE.available=yes",
    "lldp.ens10.lldp-med.policy.apptype=Voice",
    "lldp.ens10.lldp-med.policy.defined=yes",
    "lldp.ens10.lldp-med.policy.vlan.vid=priority",
    "lldp.ens10.lldp-med.policy.priority=Best effort",
    "lldp.ens10.lldp-med.policy.pcp=0",
    "lldp.ens10.lldp-med.policy.dscp=0",
    "lldp.ens10.unknown-tlvs.unknown-tlv.oui=00,01,42",
    "lldp.ens10.unknown-tlvs.unknown-tlv.subtype=1",
    "lldp.ens10.unknown-tlvs.unknown-tlv.len=1",
    "lldp.ens10.unknown-tlvs.unknown-tlv=01",
    "lldp.ens10.unknown-tlvs.unknown-tlv.oui=00,01,42",
    "lldp.ens10.unknown-tlvs.unknown-tlv.subtype=209",
    "lldp.ens10.unknown-tlvs.unknown-tlv.len=1",
    "lldp.ens10.unknown-tlvs.unknown-tlv=04",
    "lldp.ens10.unknown-tlvs.unknown-tlv.oui=00,01,42",
    "lldp.ens10.unknown-tlvs.unknown-tlv.subtype=216",
    "lldp.ens10.unknown-tlvs.unknown-tlv.len=2",
    "lldp.ens10.unknown-tlvs.unknown-tlv=00,00",
    "lldp.ens10.unknown-tlvs.unknown-tlv.oui=00,01,42",
    "lldp.ens10.unknown-tlvs.unknown-tlv.subtype=201",
    "lldp.ens10.unknown-tlvs.unknown-tlv.len=1",
    "lldp.ens10.unknown-tlvs.unknown-tlv=01",
    "lldp.ens10.unknown-tlvs.unknown-tlv.oui=00,01,42",
    "lldp.ens10.unknown-tlvs.unknown-tlv.subtype=212",
    "lldp.ens10.unknown-tlvs.unknown-tlv.len=11",
    "lldp.ens10.unknown-tlvs.unknown-tlv=46,44,4F,32,33,32,37,31,36,47,35",
    "lldp.ens10.unknown-tlvs.unknown-tlv.oui=00,01,42",
    "lldp.ens10.unknown-tlvs.unknown-tlv.subtype=214",
    "lldp.ens10.unknown-tlvs.unknown-tlv.len=15",
    "lldp.ens10.unknown-tlvs.unknown-tlv=%(TLV3)s",
    "lldp.ens10.unknown-tlvs.unknown-tlv.oui=00,01,42",
    "lldp.ens10.unknown-tlvs.unknown-tlv.subtype=210",
    "lldp.ens10.unknown-tlvs.unknown-tlv.len=14",
    "lldp.ens10.unknown-tlvs.unknown-tlv=%(TLV4)s",
    "lldp.ens10.unknown-tlvs.unknown-tlv.oui=00,01,42",
    "lldp.ens10.unknown-tlvs.unknown-tlv.subtype=202",
    "lldp.ens10.unknown-tlvs.unknown-tlv.len=1",
    "lldp.ens10.unknown-tlvs.unknown-tlv=01",
    "lldp.ens10.unknown-tlvs.unknown-tlv.oui=00,01,42",
    "lldp.ens10.unknown-tlvs.unknown-tlv.subtype=211",
    "lldp.ens10.unknown-tlvs.unknown-tlv.len=2",
    "lldp.ens10.unknown-tlvs.unknown-tlv=0E,75",
    "lldp.ens10.unknown-tlvs.unknown-tlv.oui=00,01,42",
    "lldp.ens10.unknown-tlvs.unknown-tlv.subtype=215",
    "lldp.ens10.unknown-tlvs.unknown-tlv.len=18",
    "lldp.ens10.unknown-tlvs.unknown-tlv=%(TLV5)s",
    "lldp.ens10.unknown-tlvs.unknown-tlv.oui=00,01,42",
    "lldp.ens10.unknown-tlvs.unknown-tlv.subtype=206",
    "lldp.ens10.unknown-tlvs.unknown-tlv.len=11",
    "lldp.ens10.unknown-tlvs.unknown-tlv=6F,73,74,61,63,6B,2D,70,74,2D,31",
    "lldp.ens10.unknown-tlvs.unknown-tlv.oui=00,01,42",
    "lldp.ens10.unknown-tlvs.unknown-tlv.subtype=208",
    "lldp.ens10.unknown-tlvs.unknown-tlv.len=4",
    "lldp.ens10.unknown-tlvs.unknown-tlv=0A,00,48,42",
    "lldp.ens10.unknown-tlvs.unknown-tlv.oui=00,01,42",
    "lldp.ens10.unknown-tlvs.unknown-tlv.subtype=203",
    "lldp.ens10.unknown-tlvs.unknown-tlv.len=4",
    "lldp.ens10.unknown-tlvs.unknown-tlv=00,00,00,66",
    "lldp.ens10.unknown-tlvs.unknown-tlv.oui=00,01,42",
    "lldp.ens10.unknown-tlvs.unknown-tlv.subtype=205",
    "lldp.ens10.unknown-tlvs.unknown-tlv.len=2",
    "lldp.ens10.unknown-tlvs.unknown-tlv=00,01",
    "lldp.ens10.unknown-tlvs.unknown-tlv.oui=00,01,42",
    "lldp.ens10.unknown-tlvs.unknown-tlv.subtype=207",
    "lldp.ens10.unknown-tlvs.unknown-tlv.len=41",
    "lldp.ens10.unknown-tlvs.unknown-tlv=%(TLV6)s",
    "lldp.ens3.via=LLDP",
    "lldp.ens3.rid=1",
    "lldp.ens3.age=24 days, 18:08:04",
    "lldp.ens3.chassis.mac=34:ed:1b:a3:cf:84",
    "lldp.ens3.chassis.name=ostack-pt-1-s1-kvm",
    "lldp.ens3.chassis.descr=%(DESC1)s",
    "lldp.ens3.chassis.mgmt-ip=10.30.120.31",
    "lldp.ens3.chassis.mgmt-ip=fe80::2ef8:9bff:fe2e:a89b",
    "lldp.ens3.chassis.Bridge.enabled=on",
    "lldp.ens3.chassis.Router.enabled=on",
    "lldp.ens3.chassis.Wlan.enabled=off",
    "lldp.ens3.chassis.Station.enabled=off",
    "lldp.ens3.port.mac=fe:54:00:30:f8:19",
    "lldp.ens3.port.descr=vnet0",
    "lldp.ens3.port.ttl=120",
    "lldp.ens3.port.auto-negotiation.supported=no",
    "lldp.ens3.port.auto-negotiation.enabled=no",
    "lldp.ens3.port.auto-negotiation.current=%(AUTO)s"]

# Ugly: We have to create strings using variables in order
#       to keep PEP8 checks happy.
TS1 = 'topology/pod-1/protpaths-101-102/pathep-[sauto_vpc_pg_2021_39]'
TLV1 = '6F,73,74,61,63,6B,2D,70,74,2D,31,2D,6C,65,61,66,2D,31'
TLV2_P1 = '01,0A,00,00,01,39,63,35,62,62,62,36,32,2D,'
TLV2_P2 = '63,64,64,61,2D,31,31,65,61,2D,39,30,37,39,'
TLV2_P3 = '2D,38,37,38,32,32,37,33,35,34,33,34,32'
TLV2 = TLV2_P1 + TLV2_P2 + TLV2_P3
TLV3 = '4E,39,4B,2D,43,39,33,31,38,30,59,43,2D,45,58'
TLV4 = "6E,39,30,30,30,2D,31,36,2E,30,28,37,62,29"
TLV5 = '6F,73,74,61,63,6B,2D,70,74,2D,31,2D,6C,65,61,66,2D,32'
TLV6_P1 = '01,0A,00,00,01,39,63,35,62,62,62,36,32,2D,63,64,64,61,2D,'
TLV6_P2 = '31,31,65,61,2D,39,30,37,39,2D,38,37,38,32,32,37,33,35,34,33,34,32'
TLV6 = TLV6_P1 + TLV6_P2
DESC1_P1 = 'Ubuntu 18.04.6 LTS Linux 4.15.0-184-generic '
DESC1_P2 = '#194-Ubuntu SMP Thu Jun 2 18:54:48 UTC 2022 x86_64'
DESC1 = DESC1_P1 + DESC1_P2
AUTO = "10BaseTFD - UTP MAU, full duplex mode"


TOPOLOGY_STRING_1 = '\n'.join(RAW_TOPOLOGY_DATA_1)

TOPOLOGY_DATA_1_DICT = {
    'TS1': TS1, 'TLV1': TLV1, 'TLV2': TLV2, 'TLV3': TLV3,
    'TLV4': TLV4, 'TLV5': TLV5, 'TLV6': TLV6, 'DESC1': DESC1, 'AUTO': AUTO}

TOPOLOGY_DATA_1 = TOPOLOGY_STRING_1 % TOPOLOGY_DATA_1_DICT
TOPOLOGY_DATA_1_BYTES = TOPOLOGY_DATA_1

RAW_TOPOLOGY_DATA_2 = [
    "lldp.enp1s0.via=LLDP",
    "lldp.enp1s0.rid=3",
    "lldp.enp1s0.age=9 days, 16:37:51",
    "lldp.enp1s0.chassis.mac=40:f0:78:11:b4:0c",
    "lldp.enp1s0.chassis.name=openstack2",
    "lldp.enp1s0.chassis.descr=%(DESC2)s",
    "lldp.enp1s0.chassis.mgmt-ip=172.28.9.35",
    "lldp.enp1s0.chassis.mgmt-iface=6",
    "lldp.enp1s0.chassis.mgmt-ip=fe80::a688:73ff:fe5b:c3a",
    "lldp.enp1s0.chassis.mgmt-iface=6",
    "lldp.enp1s0.chassis.Bridge.enabled=on",
    "lldp.enp1s0.chassis.Router.enabled=on",
    "lldp.enp1s0.chassis.Wlan.enabled=off",
    "lldp.enp1s0.chassis.Station.enabled=off",
    "lldp.enp1s0.port.mac=fe:54:00:08:ce:7f",
    "lldp.enp1s0.port.descr=vnet5",
    "lldp.enp1s0.port.ttl=120",
    "lldp.enp1s0.port.auto-negotiation.supported=no",
    "lldp.enp1s0.port.auto-negotiation.enabled=no",
    "lldp.enp1s0.port.auto-negotiation.current=%(AUTO)s",
    "lldp.enp7s0.via=LLDP",
    "lldp.enp7s0.rid=2",
    "lldp.enp7s0.age=9 days, 16:38:06",
    "lldp.enp7s0.chassis.mac=80:6a:00:73:41:54",
    "lldp.enp7s0.chassis.name=padkrish-9-26",
    "lldp.enp7s0.chassis.descr=%(DESC3)s",
    "lldp.enp7s0.chassis.mgmt-ip=172.28.9.26",
    "lldp.enp7s0.chassis.mgmt-iface=83886080",
    "lldp.enp7s0.chassis.Bridge.enabled=on",
    "lldp.enp7s0.chassis.Router.enabled=on",
    "lldp.enp7s0.port.ifname=Ethernet1/5",
    "lldp.enp7s0.port.descr=Ethernet1/5",
    "lldp.enp7s0.port.ttl=120",
    "lldp.enp7s0.port.mfs=9216",
    "lldp.enp7s0.vlan.vlan-id=1",
    "lldp.enp7s0.vlan.pvid=yes",
    "lldp.enp7s0.unknown-tlvs.unknown-tlv.oui=00,01,42",
    "lldp.enp7s0.unknown-tlvs.unknown-tlv.subtype=1",
    "lldp.enp7s0.unknown-tlvs.unknown-tlv.len=1",
    "lldp.enp7s0.unknown-tlvs.unknown-tlv=01",
    "lldp.enp7s0.unknown-tlvs.unknown-tlv.oui=00,01,42",
    "lldp.enp7s0.unknown-tlvs.unknown-tlv.subtype=8",
    "lldp.enp7s0.unknown-tlvs.unknown-tlv.len=11",
    "lldp.enp7s0.unknown-tlvs.unknown-tlv=46,4C,4D,32,36,31,36,30,39,32,47",
    "lldp.enp8s0.via=LLDP",
    "lldp.enp8s0.rid=1",
    "lldp.enp8s0.age=9 days, 16:38:06",
    "lldp.enp8s0.chassis.mac=cc:d3:42:d3:fa:4a",
    "lldp.enp8s0.chassis.name=padkrish-9-244",
    "lldp.enp8s0.chassis.descr=%(DESC3)s",
    "lldp.enp8s0.chassis.mgmt-ip=172.28.9.244",
    "lldp.enp8s0.chassis.mgmt-iface=83886080",
    "lldp.enp8s0.chassis.Bridge.enabled=on",
    "lldp.enp8s0.chassis.Router.enabled=on",
    "lldp.enp8s0.port.ifname=Ethernet1/34",
    "lldp.enp8s0.port.descr=Ethernet1/34",
    "lldp.enp8s0.port.ttl=120",
    "lldp.enp8s0.port.mfs=9216",
    "lldp.enp8s0.vlan.vlan-id=814",
    "lldp.enp8s0.vlan.pvid=no",
    "lldp.enp8s0.vlan=VLAN0814",
    "lldp.enp8s0.vlan.vlan-id=1",
    "lldp.enp8s0.vlan.pvid=yes",
    "lldp.enp8s0.unknown-tlvs.unknown-tlv.oui=00,01,42",
    "lldp.enp8s0.unknown-tlvs.unknown-tlv.subtype=1",
    "lldp.enp8s0.unknown-tlvs.unknown-tlv.len=1",
    "lldp.enp8s0.unknown-tlvs.unknown-tlv=01",
    "lldp.enp8s0.unknown-tlvs.unknown-tlv.oui=00,01,42",
    "lldp.enp8s0.unknown-tlvs.unknown-tlv.subtype=8",
    "lldp.enp8s0.unknown-tlvs.unknown-tlv.len=11",
    "lldp.enp8s0.unknown-tlvs.unknown-tlv=46,4C,4D,32,37,33,38,30,31,31,5A"]

TOPOLOGY_STRING_2 = '\n'.join(RAW_TOPOLOGY_DATA_2)

DESC2_P1 = 'Ubuntu 22.04.4 LTS Linux 5.15.0-106-generic '
DESC2_P2 = '#116-Ubuntu SMP Wed Apr 17 09:17:56 UTC 2024 x86_64'
DESC2 = DESC2_P1 + DESC2_P2

DESC3_P1 = 'Cisco Nexus Operating System (NX-OS) Software '
DESC3_P2 = '10.4(3) TAC support: http://www.cisco.com/tac Copyright (c) '
DESC3_P3 = '2002-2024, Cisco Systems, Inc. All rights reserved.'
DESC3 = DESC3_P1 + DESC3_P2 + DESC3_P3

AUTO = "10BaseTFD - UTP MAU, full duplex mode"

TOPOLOGY_DATA_2_DICT = {'DESC2': DESC2, 'DESC3': DESC3, 'AUTO': AUTO}

TOPOLOGY_DATA_2 = TOPOLOGY_STRING_2 % TOPOLOGY_DATA_2_DICT
TOPOLOGY_DATA_2_BYTES = TOPOLOGY_DATA_2
