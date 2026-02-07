# Copyright 2025 Cisco Systems, Inc.
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

from networking_cisco.ml2_drivers.ndfc import constants
from networking_cisco.ml2_drivers.ndfc.ndfc_helper import NdfcHelper
from oslo_log import log
from oslo_serialization import jsonutils

LOG = log.getLogger(__name__)

glob_nwk_map = {}


class Ndfc:
    '''
    NDFC class.
    '''
    def __init__(self, ndfc_ip, user, pwd, fabric, force_old_api):
        '''
        Init routine.
        '''
        self.ip = ndfc_ip
        # TODO(sanaval): add support for other auth types
        self.user = user
        self.pwd = pwd
        self.fabric = fabric
        self.ndfc_obj = NdfcHelper(ip=self.ip, user=self.user, pwd=self.pwd,
                                   force_old_api=force_old_api)

    def _get_create_vrf_payload(self, vrf_name):
        fabric = self.fabric
        tag = constants.TAG
        template_config_vrf = {'routeTarget': 'auto', 'vrfName': vrf_name,
                'vrfVlanName': '', 'vrfIntfDescription': '',
                'vrfDescription': '', 'trmEnabled': 'false',
                'isRPExternal': 'false', 'advertiseHostRouteFlag': 'false',
                'advertiseDefaultRouteFlag': 'true',
                'configureStaticDefaultRouteFlag': 'true', 'tag': tag,
                'vrfRouteMap': 'FABRIC-RMAP-REDIST-SUBNET', 'maxBgpPaths': '1',
                'maxIbgpPaths': '2', 'rpAddress': '', 'loopbackNumber': '',
                'L3VniMcastGroup': '', 'multicastGroup': ''}
        dct = {"fabric": fabric, "vrfName": vrf_name,
               "vrfTemplate": "Default_VRF_Universal",
               "vrfTemplateConfig": template_config_vrf,
               "vrfTemplateParams": "{}",
               "vrfExtensionTemplate": "Default_VRF_Extension_Universal"}
        return dct

    def _get_create_vrf_payload_v2(self, vrf_name):
        fabric = self.fabric
        tag = constants.TAG
        vrf_config = {
            "fabricName": fabric,
            "vrfName": vrf_name,
            "vrfType": "vxlan"
        }
        additional_data = {}
        additional_data['trmEnabled'] = False
        additional_data['advertiseHostRoute'] = False
        additional_data['advertiseDefaultRoute'] = True
        additional_data['configureStaticDefaultRoute'] = True
        additional_data['tag'] = int(tag)
        additional_data['maxBgpPaths'] = 1
        additional_data['maxIbgpPaths'] = 2
        additional_data['vrfRouteMap'] = 'FABRIC-RMAP-REDIST-SUBNET'
        additional_data['rtAuto'] = True
        if additional_data:
            vrf_config['additionalData'] = additional_data
        final_payload = {"vrfs": [vrf_config]}
        return final_payload

    def create_vrf(self, vrf_name):
        if self.ndfc_obj.nd_new_version:
            payload = self._get_create_vrf_payload_v2(vrf_name)
        else:
            payload = self._get_create_vrf_payload(vrf_name)
        ret = self.ndfc_obj.create_vrf(self.fabric, payload)
        LOG.debug("create vrf payload is %s", payload)
        LOG.info("For fabric %s, vrf %s, create vrf returned %s", self.fabric,
                vrf_name, ret)
        return ret

    def _get_deploy_payload(self, network):
        data = self.ndfc_obj.get_network_switch_map(self.fabric, network)
        return data

    def _get_deploy_payload_attach(self, leaf_attachments, network):
        dct = {}
        for snum in leaf_attachments:
            dct[snum] = network
        return dct

    def _get_deploy_payload_attach_v2(self, leaf_attachments, network):
        switch_ids_list = list(leaf_attachments.keys())
        deploy_payload = {
            "networkNames": [network],
            "switchIds": switch_ids_list
        }
        return deploy_payload

    def _get_create_network_payload(self, vrf_name, network_name, vlan):
        gw = ""
        tag = constants.TAG
        mtu = constants.MTU
        nve_id = constants.NVE_ID
        template_type = constants.TEMPLATE_TYPE
        template_config_network = {'gatewayIpAddress': gw,
                'gatewayIpV6Address': '', 'intfDescription': '',
                'suppressArp': False, 'dhcpServerAddr1': '',
                'dhcpServerAddr2': '', 'loopbackId': '', 'vrfDhcp': '',
                'mtu': mtu, 'vrfName': vrf_name, 'networkName': network_name,
                'isLayer2Only': False, 'nveId': nve_id, 'vlanId': vlan,
                'vlanName': '', 'secondaryGW1': '', 'secondaryGW2': '',
                'trmEnabled': '', 'rtBothAuto': '', 'enableL3OnBorder': '',
                'tag': tag}
        dct = {'fabric': self.fabric, 'vrf': vrf_name,
               'networkName': network_name,
               'networkTemplateConfig': template_config_network,
               'networkTemplate': template_type}
        return dct

    def _get_create_network_payload_v2(self, vrf_name, network_name, vlan):
        gw = ""
        tag = constants.TAG
        mtu = constants.MTU
        template_type = constants.TEMPLATE_TYPE
        network_id = vlan * 10
        network_config = {
            "displayName": network_name,
            "fabricName": self.fabric,
            "networkName": network_name,
            "vlanId": vlan,
            "vrfName": vrf_name,
            "networkId": network_id,
        }
        network_config['networkType'] = 'vxlan'
        l2_data = {}
        l2_data['vlanName'] = ""
        l2_data['rtAuto'] = False
        network_config['l2Data'] = l2_data
        l3_data = {}
        l3_data['gatewayIp'] = gw
        l3_data['vlanInterfaceDescription'] = ""
        l3_data['arp'] = True
        if mtu is not None:
            l3_data['mtu'] = {'protocol': {'layer2': mtu}}
        l3_data['ipv4Trm'] = False
        l3_data['ipv6Trm'] = False
        l3_data['gatewayOnBorder'] = False
        if tag is not None:
            l3_data['tag'] = int(tag)
        l3_data['netflow'] = False
        l3_data['igmpVersion'] = 2
        network_config['l3Data'] = l3_data
        if template_type:
            network_config['networkTemplateName'] = template_type
        return {"networks": [network_config]}

    def create_network(self, vrf_name, network_name, vlan, physnet):
        LOG.debug("Create network called for vrf %s network %s vlan %s and "
            "physnet %s", vrf_name, network_name, vlan, physnet)
        if self.ndfc_obj.nd_new_version:
            payload = self._get_create_network_payload_v2(
                    vrf_name, network_name, vlan)
        else:
            payload = self._get_create_network_payload(
                    vrf_name, network_name, vlan)
        LOG.debug("create network payload is %s", payload)
        ret = self.ndfc_obj.create_network(self.fabric, payload)
        LOG.info("For %s:%s Create Network returned %s", vrf_name,
                network_name, ret)
        return ret

    def _get_update_network_payload(self, fabric, network_name, gw):
        payload = self.ndfc_obj.get_network_info(fabric, network_name)
        # TODO(padkrish) do return check for None
        LOG.debug("Get network object %s wih GW %s", payload, gw)
        if payload is not None:
            if self.ndfc_obj.nd_new_version:
                template_data = payload.get("l3Data")
                template_data["gatewayIpv4Address"] = gw
            else:
                template_data = payload.get("networkTemplateConfig")
                template_data_json = jsonutils.loads(template_data)
                template_data_json["gatewayIpAddress"] = gw
                payload["networkTemplateConfig"] = template_data_json
            return payload

    def update_network(self, vrf_name, network_name, vlan, gw, physnet):
        LOG.debug("Update network called for %s:%s:%s with GW %s",
                vrf_name, network_name, vlan, gw)
        fabric = self.fabric
        payload = self._get_update_network_payload(fabric, network_name, gw)
        LOG.debug("Payload for update network is %s", payload)
        deploy_payload = self._get_deploy_payload(network_name)
        LOG.debug("Deploy payload is %s", deploy_payload)
        if len(deploy_payload) == 0:
            LOG.debug("No switches found, only doing an update network, "
                "payload %s", payload)
            ret = self.ndfc_obj.update_network(fabric, network_name, payload)
        else:
            LOG.debug("Doing an update and deploy on the network")
            ret = self.ndfc_obj.update_deploy_network(fabric, network_name,
                    payload, deploy_payload)
        LOG.info("For %s:%s update network returned %s", fabric, network_name,
                ret)
        return ret

    def _get_common_attach_payload(self, fabric, network_name, vlan, leaf_snum,
                                   leaf_info):
        flag = False
        attach_snum = {"fabric": fabric, "networkName": network_name,
                "serialNumber": leaf_snum, "detachSwitchPorts": "",
                "vlan": vlan, "dot1QVlan": constants.DOT1Q_VLAN,
                "untagged": "false", "freeformConfig": "",
                "deployment": "true", "extensionValues": "",
                "instanceValues": ""}
        tor_complete_intf = ""
        if leaf_info.get('tor_sw_intf_map') is not None and len(leaf_info.get(
            'tor_sw_intf_map')) > 0:
            # ToR Case
            leaf_tor_info = leaf_info['tor_sw_intf_map']
            for tor_snum, tor_info in leaf_tor_info.items():
                tor_name = tor_info['tor_name']
                tor_interfaces = tor_info['tor_interfaces']
                if len(tor_interfaces) == 0:
                    continue
                tor_intf_str = ",".join(tor_interfaces)
                tor_intf = tor_name + "(" + tor_intf_str + ")"
                if tor_complete_intf == "":
                    tor_complete_intf = tor_intf
                else:
                    tor_complete_intf = tor_complete_intf + " " + tor_intf
            if len(tor_complete_intf) > 0:
                attach_snum["torPorts"] = tor_complete_intf
            flag = True
        if 'interfaces' in leaf_info:
            leaf_intf_str = ",".join(leaf_info['interfaces'])
            attach_snum["switchPorts"] = leaf_intf_str
            flag = True
        if not flag:
            return None
        return attach_snum

    def _get_common_attach_payload_v2(self, fabric, network_name,
            vlan, leaf_snum, leaf_info):
        interfaces = []
        if leaf_info.get('tor_sw_intf_map'):
            for tor_snum, tor_info in leaf_info['tor_sw_intf_map'].items():
                tor_interfaces = tor_info.get('tor_interfaces', [])
                for intf_name in tor_interfaces:
                    interfaces.append({
                        "interfaceRange": intf_name,
                    })

        if 'interfaces' in leaf_info:
            for intf_name in leaf_info['interfaces']:
                interfaces.append({
                    "interfaceRange": intf_name,
                })
        return interfaces

    def _create_attach_payload(self, collated_attach, vrf_name, network_name,
                               vlan):
        fabric = self.fabric
        attach_list = []
        for leaf_snum, leaf_info in collated_attach.items():
            attach_snum = self._get_common_attach_payload(fabric, network_name,
                    vlan, leaf_snum, leaf_info)
            LOG.debug("attach snum is %s", attach_snum)
            if attach_snum is None or (attach_snum.get(
                'switchPorts') is None and attach_snum.get(
                    'torPorts') is None):
                LOG.error("Leaf %s has no regular or ToR interfaces",
                        leaf_snum)
                continue
            attach_list.append(attach_snum)
            peer_serial = leaf_info.get('peer_serial')
            if peer_serial and peer_serial not in collated_attach:
                LOG.debug("Adding vPC peer attachment for leaf %s peer %s",
                        leaf_snum, peer_serial)
                peer_attach = {
                    'fabric': fabric,
                    'networkName': network_name,
                    'serialNumber': peer_serial,
                    'detachSwitchPorts': '',
                    'vlan': vlan,
                    'dot1QVlan': constants.DOT1Q_VLAN,
                    'untagged': 'false',
                    'freeformConfig': '',
                    'deployment': 'true',
                    'extensionValues': '',
                    'instanceValues': ''
                }
                attach_list.append(peer_attach)
        attach_dct = [{"networkName": network_name,
            "lanAttachList": attach_list}]
        return attach_dct

    def _create_attach_payload_v2(self, collated_attach,
            vrf_name, network_name, vlan):
        attach_list = []
        for leaf_snum, leaf_info in collated_attach.items():
            interfaces = self._get_common_attach_payload_v2(
                self.fabric, network_name, vlan, leaf_snum, leaf_info
            )
            LOG.debug("Attach interfaces: %s", interfaces)
            if not interfaces:
                LOG.error(
                    "Leaf %s has no regular or ToR interfaces to attach.",
                    leaf_snum)
                continue
            attachment_entry = {
                "attach": True,
                "interfaces": interfaces,
                "networkName": network_name,
                "switchId": leaf_snum,
                "vlanId": vlan
            }
            attach_list.append(attachment_entry)
            peer_serial = leaf_info.get('peer_serial')
            if peer_serial and peer_serial not in collated_attach:
                LOG.debug("Adding vPC peer attachment for leaf %s peer %s",
                          leaf_snum, peer_serial)
                peer_attachment_entry = {
                    "attach": True,
                    "interfaces": [],
                    "networkName": network_name,
                    "switchId": peer_serial,
                    "vlanId": vlan
                }
                attach_list.append(peer_attachment_entry)
        return {"attachments": attach_list}

    def _create_detach_payload(self, leaf_attachments, collated_attach,
                               vrf_name, network_name, vlan):
        fabric = self.fabric
        attach_list = []
        for leaf_snum, leaf_info in collated_attach.items():
            attach_snum = self._get_common_attach_payload(fabric, network_name,
                    vlan, leaf_snum, leaf_info)
            LOG.debug("attach snum is %s", attach_snum)
            if attach_snum is None:
                LOG.error("Leaf %s has no regular or ToR interfaces")
                continue
            if not attach_snum.get("switchPorts") and not attach_snum.get(
                    "torPorts"):
                attach_snum["deployment"] = False
            if leaf_snum in leaf_attachments:
                if leaf_attachments[leaf_snum].get("interfaces") is not None:
                    interfaces = leaf_attachments[leaf_snum].get("interfaces")
                    attach_snum["detachSwitchPorts"] = ','.join(interfaces)
            attach_list.append(attach_snum)

            peer_serial = leaf_info.get('peer_serial')
            if peer_serial and peer_serial not in collated_attach:
                LOG.debug(
                    "Adding vPC peer detach entry for leaf %s peer %s",
                    leaf_snum, peer_serial)
                peer_attach = {
                    'fabric': fabric,
                    'networkName': network_name,
                    'serialNumber': peer_serial,
                    'detachSwitchPorts': '',
                    'vlan': vlan,
                    'dot1QVlan': constants.DOT1Q_VLAN,
                    'untagged': 'false',
                    'freeformConfig': '',
                    'deployment': False,
                    'extensionValues': '',
                    'instanceValues': ''
                }
                attach_list.append(peer_attach)
        attach_dct = [{"networkName": network_name,
            "lanAttachList": attach_list}]
        return attach_dct

    def _create_detach_payload_v2(self, leaf_attachments, collated_attach,
                                  vrf_name, network_name, vlan):
        attach_list = []
        for leaf_snum, leaf_info_to_detach in leaf_attachments.items():
            interfaces_to_detach = self._get_common_attach_payload_v2(
                self.fabric, network_name, vlan, leaf_snum, leaf_info_to_detach
            )
            if interfaces_to_detach:
                attachment_entry = {
                    "attach": False,
                    "interfaces": [],
                    "networkName": network_name,
                    "switchId": leaf_snum,
                    "vlanId": vlan
                }
                attach_list.append(attachment_entry)

                leaf_info_full = collated_attach.get(leaf_snum, {})
                peer_serial = leaf_info_full.get('peer_serial') or (
                    leaf_info_to_detach.get('peer_serial'))
                if peer_serial and peer_serial not in leaf_attachments:
                    LOG.debug(
                        "Adding vPC peer detach entry for leaf %s peer %s",
                        leaf_snum, peer_serial)
                    peer_attachment_entry = {
                        "attach": False,
                        "interfaces": [],
                        "networkName": network_name,
                        "switchId": peer_serial,
                        "vlanId": vlan
                    }
                    attach_list.append(peer_attachment_entry)
            else:
                LOG.warning(
                    "Leaf %s has no interfaces specified for detachment. "
                    "Skipping.", leaf_snum)
        return {"attachments": attach_list}

    def _get_exist_attach_copy(self, exist_attach, new_attach):
        exist_attach_copy = {}
        for snum, info in exist_attach.items():
            if snum in new_attach:
                exist_attach_copy[snum] = info
        return exist_attach_copy

    def _merge_attachments(self, exist_attach, new_attach):
        exist_attach_copy = self._get_exist_attach_copy(
                exist_attach, new_attach)
        LOG.debug("exist attach copy %s new attach %s",
                  exist_attach_copy, new_attach)

        for leaf_snum, leaf_info in new_attach.items():
            if leaf_snum not in exist_attach_copy:
                exist_attach_copy[leaf_snum] = leaf_info
                continue
            exist_leaf_info = exist_attach_copy[leaf_snum]

            peer_serial = leaf_info.get('peer_serial')
            if peer_serial:
                exist_leaf_info['peer_serial'] = peer_serial

            if 'interfaces' in leaf_info:
                if exist_leaf_info.get('interfaces') is None:
                    exist_attach_copy[leaf_snum]['interfaces'] = leaf_info.get(
                        'interfaces')
                else:
                    if leaf_info.get('interfaces') is not None:
                        exist_leaf_intf = exist_leaf_info.get('interfaces')
                        for intf in leaf_info.get('interfaces'):
                            if intf not in exist_leaf_intf:
                                exist_attach_copy[leaf_snum][
                                    'interfaces'].append(intf)
            if 'tor_sw_intf_map' not in leaf_info:
                continue
            if 'tor_sw_intf_map' not in exist_leaf_info:
                exist_attach_copy[leaf_snum]['tor_sw_intf_map'] = (
                        leaf_info.get('tor_sw_intf_map'))
                continue
            exist_tor_info_map = exist_leaf_info.get('tor_sw_intf_map')
            for tor_snum, tor_info in leaf_info.get('tor_sw_intf_map').items():
                tor_key = "SN_" + tor_info.get('tor_name')
                if tor_key not in exist_tor_info_map:
                    exist_attach_copy[leaf_snum][
                            'tor_sw_intf_map'][
                                    tor_key] = tor_info
                else:
                    exist_tor_info = exist_tor_info_map.get(tor_key)
                    if 'tor_interfaces' not in exist_tor_info:
                        exist_attach_copy[leaf_snum]['tor_sw_intf_map'][
                                tor_key]['tor_interfaces'] = tor_info.get(
                                        'tor_interfaces')
                    else:
                        exist_tor_intfs = exist_tor_info.get('tor_interfaces')
                        for tor_intf in tor_info.get('tor_interfaces'):
                            if tor_intf not in exist_tor_intfs:
                                exist_attach_copy[leaf_snum][
                                        'tor_sw_intf_map'][tor_key][
                                                'tor_interfaces'].append(
                                                        tor_intf)
        return exist_attach_copy

    def _remove_attachments(self, exist_attach, new_attach):
        exist_attach_copy = self._get_exist_attach_copy(
                exist_attach, new_attach)
        LOG.debug("exist attach copy %s new attach %s",
                  exist_attach_copy, new_attach)

        for leaf_snum, leaf_info in new_attach.items():
            if leaf_snum not in exist_attach_copy:
                LOG.error("Leaf %s not in existing attachment", leaf_snum)
                continue
            exist_leaf_info = exist_attach_copy[leaf_snum]

            peer_serial = leaf_info.get('peer_serial')
            if peer_serial:
                exist_leaf_info['peer_serial'] = peer_serial

            if exist_leaf_info.get('interfaces') is not None and (
                    leaf_info.get('interfaces') is not None):
                exist_leaf_intf = exist_leaf_info.get('interfaces')
                for intf in leaf_info.get('interfaces'):
                    if intf not in exist_leaf_intf:
                        LOG.error(
                            "For switch %s interface %s not found", leaf_snum,
                            intf)
                    else:
                        exist_attach_copy[leaf_snum]['interfaces'].remove(intf)
            if 'tor_sw_intf_map' not in leaf_info:
                continue
            if 'tor_sw_intf_map' not in exist_leaf_info:
                LOG.error(
                    "For %s, TOR switch map not found for existing attachment",
                    leaf_snum)
                continue
            exist_tor_info_map = exist_leaf_info.get('tor_sw_intf_map')
            for tor_snum, tor_info in leaf_info.get('tor_sw_intf_map').items():
                tor_key = "SN_" + tor_info.get('tor_name')
                if tor_key not in exist_tor_info_map:
                    LOG.error(
                        "For %s, TOR %s not found for existing attachment",
                        leaf_snum, tor_key)
                else:
                    exist_tor_info = exist_tor_info_map.get(tor_key)
                    if 'tor_interfaces' not in exist_tor_info:
                        LOG.error("For %s, TOR %s, interfaces not found for "
                            "existing attachment", leaf_snum, tor_key)
                    else:
                        exist_tor_intfs = exist_tor_info.get('tor_interfaces')
                        for tor_intf in tor_info.get('tor_interfaces'):
                            if tor_intf not in exist_tor_intfs:
                                LOG.error("For %s, TOR %s, interface %s not "
                                    "found for existing attachment", leaf_snum,
                                    tor_key, tor_intf)
                            else:
                                exist_attach_copy[leaf_snum][
                                        'tor_sw_intf_map'][tor_key][
                                                'tor_interfaces'].remove(
                                                        tor_intf)
        return exist_attach_copy

    def get_vrf_vlan(self, vrf_name):
        fabric = self.fabric
        vrf_attachments = self.ndfc_obj.get_vrf_attachments(fabric, vrf_name)
        vlan_id = None
        if self.ndfc_obj.nd_new_version:
            if vrf_attachments and "attachments" in vrf_attachments:
                attachments = vrf_attachments.get("attachments", [])
                for item in attachments:
                    if item.get("vlanId") is not None:
                        return item["vlanId"]
        else:
            if vrf_attachments and "lanAttachList" in vrf_attachments[0]:
                for item in vrf_attachments[0]["lanAttachList"]:
                    if item.get("vlanId") is not None:
                        return item["vlanId"]
        return vlan_id

    def attach_network(self, vrf_name, network_name, vlan, leaf_attachments):
        # leaf_attachments is a map of snums
        # map[leaf_snums] -> {leaf_name, interface, map[tors]}
        # map[tors] -> {tor_name, tor_interface}
        LOG.debug("attach network called for vrf %s network %s vlan %s with "
                  "new attachment %s", vrf_name, network_name, vlan,
                  leaf_attachments)
        exist_attach = self.ndfc_obj.get_network_switch_interface_map(
            self.fabric, network_name)
        LOG.debug("existing attachments %s", exist_attach)
        collated_attach = self._merge_attachments(
            exist_attach, leaf_attachments)
        LOG.debug("collated attachments %s", collated_attach)
        if self.ndfc_obj.nd_new_version:
            attach_payload = self._create_attach_payload_v2(
                collated_attach, vrf_name, network_name, vlan)
            deploy_payload = self._get_deploy_payload_attach_v2(
                leaf_attachments, network_name)
        else:
            attach_payload = self._create_attach_payload(
                collated_attach, vrf_name, network_name, vlan)
            deploy_payload = self._get_deploy_payload_attach(
                leaf_attachments, network_name)
        LOG.debug("attach payload is %s", attach_payload)
        LOG.debug("deploy payload %s", deploy_payload)
        ret = self.ndfc_obj.attach_deploy_network(
            self.fabric, attach_payload, deploy_payload)
        if not ret:
            LOG.error("Attach network failed for fabric %s, vrf %s "
                      "network %s", self.fabric, vrf_name, network_name)
        LOG.info("Network Attachment for %s:%s:%s ret %s",
                 self.fabric, vrf_name, network_name, ret)
        return ret

    def detach_network(self, vrf_name, network_name, vlan, leaf_attachments):
        # leaf_attachments is a map of snums
        # map[leaf_snums] -> {leaf_name, interface, map[tors]}
        # map[tors] -> {tor_name, tor_interface}
        LOG.debug("detach network called for vrf %s network %s vlan %s with "
                  "new attachment %s", vrf_name, network_name, vlan,
                  leaf_attachments)
        exist_attach = self.ndfc_obj.get_network_switch_interface_map(
            self.fabric, network_name)
        LOG.debug("existing attachments %s", exist_attach)
        removed_attach = self._remove_attachments(
            exist_attach, leaf_attachments)
        LOG.debug("removed attachments %s", removed_attach)
        if self.ndfc_obj.nd_new_version:
            detach_payload = self._create_detach_payload_v2(
                leaf_attachments, removed_attach, vrf_name, network_name, vlan)
            deploy_payload = self._get_deploy_payload_attach_v2(
                leaf_attachments, network_name)
        else:
            detach_payload = self._create_detach_payload(
                leaf_attachments, removed_attach, vrf_name, network_name, vlan)
            deploy_payload = self._get_deploy_payload_attach(
                leaf_attachments, network_name)
        LOG.debug("detach payload is %s", detach_payload)
        LOG.debug("deploy payload %s", deploy_payload)
        ret = self.ndfc_obj.attach_deploy_network(
            self.fabric, detach_payload, deploy_payload)
        if not ret:
            LOG.error("Detach network failed for fabric %s, vrf %s "
                      "network %s", self.fabric, vrf_name, network_name)
        LOG.info("Network Detachment for %s:%s:%s ret %s",
                 self.fabric, vrf_name, network_name, ret)
        return ret

    def delete_network(self, network_name, vlan, physnet):
        LOG.debug("Delete network called with %s", network_name)
        fabric = self.fabric
        ret = self.ndfc_obj.delete_network(fabric, network_name)
        LOG.info("For %s:%s delete network returned %s",
                 fabric, network_name, ret)
        return ret

    def delete_vrf(self, vrf_name):
        LOG.debug("Delete vrf called with %s", vrf_name)
        fabric = self.fabric
        ret = self.ndfc_obj.delete_vrf(fabric, vrf_name)
        LOG.info("For %s:%s delete vrf returned %s", fabric, vrf_name, ret)
        return ret
