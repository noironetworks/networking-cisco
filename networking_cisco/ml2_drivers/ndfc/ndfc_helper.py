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

# pylint: disable=no-member
'''
NDFC helper module. This module interacts with NDFC.
'''

from functools import wraps
import json
from oslo_log import log
import requests
from requests.exceptions import HTTPError

ADD = "ADD"
DELETE_ADD = "DELETE_ADD"
NOOP = "NOOP"

LOG = log.getLogger(__name__)


def _find_fail_recursively(data):
    '''
    Recursively searches for 'fail' (case-insensitive) in any string
    value within a nested Python object (dictionary or list).
    '''
    if isinstance(data, dict):
        return any(_find_fail_recursively(value) for value in data.values())
    if isinstance(data, list):
        return any(_find_fail_recursively(item) for item in data)
    if isinstance(data, str):
        return 'fail' in data.lower()
    return False


class NdfcHelper:
    '''
    NDFC helper class.
    '''

    def __init__(self, **kwargs):
        '''
        Init routine that initializes the URL's, user, pws etc.
        '''
        self._base_url = "appcenter/cisco/ndfc/api/v1/security/fabrics/"
        self._get_attach_url = "appcenter/cisco/ndfc/api/v1/lan-fabric/" + (
            "rest/top-down/fabrics/%s/networks/attachments?network-names=%s")
        self._vrf_url = "appcenter/cisco/ndfc/api/v1/lan-fabric/rest/" + (
            "top-down/v2/fabrics/")
        self._network_url = "appcenter/cisco/ndfc/api/v1/lan-fabric/rest/" + (
            "top-down/v2/fabrics/")
        self._get_network_url = "appcenter/cisco/ndfc/api/v1/lan-fabric/" + (
            "rest/top-down/fabrics/%s/networks/%s")
        self._config_save_url = "appcenter/cisco/ndfc/api/v1/lan-fabric/" + (
            "rest/control/fabrics/")
        self._deploy_save_url = "appcenter/cisco/ndfc/api/v1/lan-fabric/" + (
            "rest/control/fabrics/")
        self._network_deploy_url = "appcenter/cisco/ndfc/api/v1/" + (
            "lan-fabric/rest/top-down/v2/networks/deploy/")
        self._inventory_url = "appcenter/cisco/ndfc/api/v1/lan-fabric/" + (
            "rest/control/fabrics/")
        self._interface_url = "appcenter/cisco/ndfc/api/v1/lan-fabric/" + (
            "rest/interface/detail/filter?serialNumber=")
        self._topology_url = "appcenter/cisco/ndfc/api/v1/lan-fabric/" + (
            "rest/topology/topologydataforvmm?serialNumbers=")
        self._smart_license_status_new = "api/v1/infra" + (
            "/license/smartLicenseStatus")
        self.nd_new_version = False

        self._ip = kwargs['ip']
        # TODO(sanaval): add support for other auth types
        self._user = kwargs['user']
        self._pwd = kwargs['pwd']
        self._timeout_resp = 100
        self._req_headers = {'Accept': 'application/json',
                             'Content-Type': 'application/json; charset=UTF-8'}
        self._resp_ok = (requests.codes.ok, requests.codes.created,
                         requests.codes.accepted)
        self._expiration_time = 100000
        self._protocol_host_url = "https://" + self._ip + "/"
        self.determine_nd_api_version()

    def _build_url(self, remaining_url):
        '''
        Appends the base URL with the passing URL.
        '''
        return self._protocol_host_url + remaining_url

    def _response_body_indicates_failure(self, res, func_name, payload=None):
        '''
        Checks a successful (200 OK) response body for "fail" keywords.
        Returns True if a failure message is found, False otherwise.
        '''
        try:
            data = res.json()
            if _find_fail_recursively(data):
                LOG.error("API call '%(func)s' succeeded with status %(code)s "
                    "but the response body indicates a failure."
                    "Payload: %(payload)s, Response: %(res)s",
                    {
                        'func': func_name,
                        'code': res.status_code,
                        'payload': payload,
                        'res': data
                    }
                )
                return True
        except ValueError:
            LOG.debug("Response for '%s' was not JSON, cannot check for "
                      "failure keywords.", func_name)
        return False

    def http_exc_handler(http_func):
        '''
        Decorator function for catching exceptions.
        '''
        @wraps(http_func)
        def exc_handler_int(*args):
            try:
                fn_name = http_func.__name__
                return http_func(*args)
            except HTTPError as http_err:
                LOG.error("HTTP error during call to %(func)s, %(err)s",
                          {'func': fn_name, 'err': http_err})
        return exc_handler_int

    @http_exc_handler
    def get_jwt_token(self):
        '''
        Function to get jwt token
        '''
        login_url = self._build_url('login')
        payload = {'userName': self._user, 'userPasswd': self._pwd,
                   'domain': 'DefaultAuth',
                   'expirationTime': self._expiration_time}
        res = requests.post(login_url, data=json.dumps(payload),
                            headers=self._req_headers,
                            #auth=(self._user, self._pwd),
                            timeout=self._timeout_resp, verify=False)
        session_id = ""
        if res and res.status_code in self._resp_ok:
            session_id = res.json().get('jwttoken')
            return session_id

    @http_exc_handler
    def login(self):
        '''
        Function for login to NDFC.
        '''
        session_id = self.get_jwt_token()
        if session_id is not None:
            self._req_headers.update({'Authorization': 'Bearer ' + session_id})
            return True, session_id
        return False, ""

    @http_exc_handler
    def logout(self):
        '''
        Function for logoff from NDFC.
        '''
        logout_url = self._build_url('rest/logout')
        requests.post(logout_url, headers=self._req_headers,
                      timeout=self._timeout_resp, verify=False)

    @http_exc_handler
    def _determine_nd_api_version(self):
        '''
        Function to determine if we have support for new APIs
        '''
        url = self._build_url(self._smart_license_status_new)
        res = requests.get(url, headers=self._req_headers,
                           timeout=self._timeout_resp, verify=False)
        if res and (res.status_code in self._resp_ok):
            self.nd_new_version = True
        else:
            self.nd_new_version = False

    def determine_nd_api_version(self):
        '''
        Function to determine new API support
        '''
        try:
            ret = self.login()
            if not ret:
                LOG.error("Failed to login to NDFC")
                return
            ret = self._determine_nd_api_version()
            LOG.debug("Determined access to new APIs to be %s"
                      % (self.nd_new_version))
            self.logout()
        except Exception as exc:
            LOG.error("determine nd api version failed with "
                      "exception %(exc)s", {'exc': exc})

    def _get_leaf_switch_map(self, ret):
        dct = {}
        if ret is None:
            return dct
        for nwk_data in ret:
            for lan_attach in nwk_data.get('lanAttachList'):
                if lan_attach.get('portNames') and (
                        lan_attach.get('switchRole') == 'leaf'):
                    dct[lan_attach.get('switchSerialNo')] = lan_attach.get(
                            'networkName')
                    if lan_attach.get('peerSerialNo') != '':
                        dct[lan_attach.get('peerSerialNo')] = lan_attach.get(
                                'networkName')
        return dct

    def _get_new_intf_name(self, tor_intf):
        if "Port-channel" in tor_intf:
            val = tor_intf.split("Port-channel")[1]
            return "Port-Channel" + val
        return tor_intf

    def _parse_tor_interface_map(self, portnames):
        tor_map = {}
        for tor_intf in portnames.split():
            tor_str = tor_intf.split("(")
            if len(tor_str) < 2:
                LOG.error("Incorrect tor interface format %s", tor_intf)
                return tor_map
            tor_name = tor_str[0]
            tor_intfs_str = tor_str[1].split(")")
            if len(tor_intfs_str) < 1:
                LOG.error("incorrect tor interface format for %s, %s",
                          tor_intf, tor_str)
                return tor_map
            tor_list = []
            for tor_intf in tor_intfs_str[0].split(","):
                new_intf = self._get_new_intf_name(tor_intf)
                LOG.debug("get_intf_name called with %s and new intf is %s",
                          tor_intf, new_intf)
                tor_list.append(new_intf)
            # Hack as of now, TODO(padkrish) wo make it consistent with
            # topology discovery
            tor_snum = "SN_" + tor_name
            tor_map[tor_snum] = {}
            tor_map[tor_snum]['tor_interfaces'] = tor_list
            tor_map[tor_snum]['tor_name'] = tor_name
        return tor_map

    def _get_switch_interface_map(self, ret):
        switch_map = {}
        for nwk_data in ret:
            for lan_attach in nwk_data.get('lanAttachList'):
                if lan_attach.get('portNames') and (
                        lan_attach.get('switchRole') == 'leaf'):
                    snum = lan_attach.get('switchSerialNo')
                    switch_map[snum] = {}
                    if "(" in lan_attach.get('portNames'):
                        tor_sw_intf_map = self._parse_tor_interface_map(
                                lan_attach.get('portNames'))
                        switch_map[snum]["tor_sw_intf_map"] = tor_sw_intf_map
                    else:
                        new_intf_list = []
                        for intf in lan_attach.get('portNames').split(","):
                            new_intf = self._get_new_intf_name(intf)
                            new_intf_list.append(new_intf)
                        switch_map[snum]["interfaces"] = new_intf_list
                    switch_map[snum]["switch_name"] = lan_attach.get(
                            'switchName')
        return switch_map

    @http_exc_handler
    def _get_attachments(self, fabric, network):
        '''
        Retrieve the network attachment given the fabric and network.
        '''
        attach_url = self._get_attach_url % (fabric, network)
        url = self._build_url(attach_url)
        res = requests.get(url, headers=self._req_headers,
                           timeout=self._timeout_resp, verify=False)
        LOG.debug("Get attachments URL %s", url)
        if not res or res.status_code not in self._resp_ok:
            LOG.error("Invalid res for _get_attachments for fabric %s nwk %s",
                   fabric, network)
            return None

        if self._response_body_indicates_failure(res, '_get_attachments'):
            return None

        data = res.json()
        return data

    def get_network_switch_map(self, fabric, network):
        '''
        Return the map of leaf switch to network
        '''
        dct = {}
        try:
            ret = self.login()
            if not ret:
                LOG.error("Failed to login to NDFC")
                return dct
            ret = self._get_attachments(fabric, network)
            LOG.debug("Get attachments returned %s", ret)
            dct = self._get_leaf_switch_map(ret)
            self.logout()
            return dct
        except Exception as exc:
            LOG.error("Exception raised in get_network_switch_map %s", exc)
            return dct

    def get_network_switch_interface_map(self, fabric, network):
        '''
        Return the map of leaf switch to network
        '''
        try:
            ret = self.login()
            if not ret:
                LOG.error("Failed to login to NDFC")
                return False
            sw_attachments = self._get_attachments(fabric, network)
            dct = self._get_switch_interface_map(sw_attachments)
            self.logout()
            return dct
        except Exception as exc:
            LOG.error("Exception raised in get_network_switch_interface_map "
                      "%s", exc)
            return None

    @http_exc_handler
    def _get_network_info(self, fabric, nwk):
        '''
        Function that returns if the network for the fabric exists
        in NDFC.
        '''
        network_url = self._get_network_url % (fabric, nwk)
        url = self._build_url(network_url)
        res = requests.get(url, headers=self._req_headers,
                           timeout=self._timeout_resp, verify=False)

        LOG.debug("Get network url is %s", url)
        if not res or res.status_code not in self._resp_ok:
            LOG.error("Invalid res for _get_network_info for fabric %s nwk %s",
                      fabric, nwk)
            return None

        if self._response_body_indicates_failure(res, '_get_network_info'):
            return None

        data = res.json()
        return data

    def get_network_info(self, fabric, nwk):
        '''
        Function that returns the network information in NDFC
        '''
        try:
            ret = self.login()
            if not ret:
                LOG.error("Failed to login to NDFC")
                return False
            ret = self._get_network_info(fabric, nwk)
            self.logout()
            return ret
        except Exception as exc:
            LOG.error("Exception raised in get_network_info %s", exc)
            return None

    @http_exc_handler
    def _create_network(self, fabric, payload):
        '''
        Function to create the Network in NDFC.
        '''
        url = self._build_url(self._network_url) + fabric + "/networks"
        res = requests.post(url, headers=self._req_headers,
                            data=json.dumps(payload),
                            timeout=self._timeout_resp, verify=False)
        if not res or res.status_code not in self._resp_ok:
            LOG.error(
                "create network failed with status code: %s, "
                "reason: %s, response body: %s, payload: %s",
                res.status_code, res.reason, res.text, json.dumps(payload)
            )
            return False
        if self._response_body_indicates_failure(
            res, '_create_network', payload=json.dumps(payload)):
            return False

        LOG.debug("create network successful")
        return True

    def create_network(self, fabric, payload):
        '''
        Top level function to create the Network.
        '''
        try:
            ret = self.login()
            if not ret:
                LOG.error("Failed to login to NDFC")
                return False
            ret = self._create_network(fabric, payload)
            if not ret:
                return False
            self.logout()
        except Exception as exc:
            LOG.error("create network failed with exception %(exc)s",
                      {'exc': exc})
            return False
        return True

    @http_exc_handler
    def _update_network(self, fabric, network_name, payload):
        '''
        Function to update the Network in NDFC.
        '''
        url = self._build_url(self._network_url) + fabric + (
                "/networks/" + network_name)
        res = requests.put(url, headers=self._req_headers,
                           data=json.dumps(payload),
                           timeout=self._timeout_resp, verify=False)
        if not res or res.status_code not in self._resp_ok:
            LOG.error(
                "update network failed with status code: %s, "
                "reason: %s, response body: %s, payload: %s",
                res.status_code, res.reason, res.text, json.dumps(payload)
            )
            return False
        if self._response_body_indicates_failure(
            res, '_update_network', payload=json.dumps(payload)):
            return False

        LOG.debug("update network successful")
        return True

    def update_network(self, fabric, network_name, payload):
        '''
        Top level function to update the Network.
        '''
        try:
            ret = self.login()
            if not ret:
                LOG.error("Failed to login to NDFC")
                return False
            ret = self._update_network(fabric, network_name, payload)
            if not ret:
                return False
            self.logout()
        except Exception as exc:
            LOG.error("update network failed with exception %(exc)s",
                      {'exc': exc})
            return False
        return True

    def update_deploy_network(self, fabric, network_name, update_payload,
                              deploy_payload):
        '''
        Function to create, attach and deploy the network.
        '''
        try:
            ret = self.login()
            if not ret:
                LOG.error("Failed to login to NDFC")
                return False
            ret = self._update_network(fabric, network_name, update_payload)
            if not ret:
                return False
            ret = self._config_deploy_save(fabric, deploy_payload)
            if not ret:
                return False
            self.logout()
        except Exception as exc:
            LOG.error("create, attach and deploy network failed with "
                      "exception %(exc)s", {'exc': exc})
            return False
        return True

    @http_exc_handler
    def _attach_network(self, fabric, payload):
        '''
        Function to attach the network in NDFC.
        '''
        url = self._build_url(self._network_url) + fabric + (
                "/networks/attachments")
        res = requests.post(url, headers=self._req_headers,
                data=json.dumps(payload), timeout=self._timeout_resp,
                verify=False)
        LOG.debug("attach/detach network url %s payload %s", url,
            json.dumps(payload))

        if not res or res.status_code not in self._resp_ok:
            LOG.error(
                "attach/detach network failed with status code: %s, "
                "reason: %s, response body: %s, payload: %s",
                res.status_code, res.reason, res.text, json.dumps(payload)
            )
            return False

        if self._response_body_indicates_failure(
            res, '_attach_network', payload=json.dumps(payload)):
            return False

        LOG.debug("attach/detach network successful")
        return True

    def attach_deploy_network(self, fabric, payload, deploy_payload):
        '''
        Top level function to attach the Network.
        '''
        try:
            ret = self.login()
            if not ret:
                LOG.error("Failed to login to NDFC")
                return False
            try:
                ret = self._attach_network(fabric, payload)
                if not ret:
                    LOG.error("Failed to attach/detach network")
                    return False
                ret = self._config_deploy_save(fabric, deploy_payload)
                if not ret:
                    LOG.error("Failed to deploy")
                    return False
            finally:
                self.logout()
        except Exception as exc:
            LOG.error("attach/detach network failed with exception %(exc)s",
                      {'exc': exc})
            return False
        return True

    @http_exc_handler
    def _delete_network(self, fabric, network):
        '''
        Function to create the Network in NDFC.
        '''
        url = self._build_url(self._network_url) + fabric + (
                "/bulk-delete/networks?network-names=" + network)
        res = requests.delete(url, headers=self._req_headers,
                timeout=self._timeout_resp, verify=False)
        if not res or res.status_code not in self._resp_ok:
            LOG.error(
                "delete network failed with status code: %s, "
                "reason: %s, response body: %s",
                res.status_code, res.reason, res.text
            )
            return False
        if self._response_body_indicates_failure(
            res, '_delete_network'):
            return False

        LOG.debug("delete network successful")
        return True

    def delete_network(self, fabric, network):
        '''
        Top level function to delete the Network.
        '''
        try:
            ret = self.login()
            if not ret:
                LOG.error("Failed to login to NDFC")
                return False
            ret = self._delete_network(fabric, network)
            if not ret:
                return False
            self.logout()
        except Exception as exc:
            LOG.error("delete network failed with exception %(exc)s",
                      {'exc': exc})
            return False
        return True

    @http_exc_handler
    def _config_deploy_save(self, fabric, deploy_payload):
        '''
        Function to create the VRF in NDFC.
        '''
        if len(deploy_payload) == 0:
            url = self._build_url(self._deploy_save_url) + fabric + (
                    "/config-deploy?forceShowRun=false")
            LOG.debug("Deploy called with url %s", url)
            res = requests.post(url, headers=self._req_headers,
                                timeout=self._timeout_resp, verify=False)
        else:
            url = self._build_url(self._network_deploy_url)
            LOG.debug("Deploy called with url %s and payload %s", url,
                    deploy_payload)
            res = requests.post(url, headers=self._req_headers,
                    data=json.dumps(deploy_payload),
                    timeout=self._timeout_resp, verify=False)
        if not res or res.status_code not in self._resp_ok:
            LOG.error(
                "deploy save failed with status code: %s, "
                "reason: %s, response body: %s",
                res.status_code, res.reason, res.text
            )
            return False
        if self._response_body_indicates_failure(
            res, '_config_deploy_save', payload=json.dumps(deploy_payload)):
            return False

        LOG.debug("deploy save successful")
        return True

    @http_exc_handler
    def _create_vrf(self, fabric, payload):
        '''
        Function to create the VRF in NDFC.
        '''
        url = self._build_url(self._vrf_url) + fabric + "/vrfs"
        res = requests.post(url, headers=self._req_headers,
                data=json.dumps(payload), timeout=self._timeout_resp,
                verify=False)
        if not res or res.status_code not in self._resp_ok:
            LOG.error(
                "create vrf failed with status code: %s, "
                "reason: %s, response body: %s, payload: %s",
                res.status_code, res.reason, res.text, json.dumps(payload)
            )
            return False
        if self._response_body_indicates_failure(
            res, '_create_vrf', payload=json.dumps(payload)):
            return False

        LOG.debug("create vrf successful")
        return True

    def create_vrf(self, fabric, payload):
        '''
        Top level function to create the VRF.
        '''
        try:
            ret = self.login()
            if not ret:
                LOG.error("Failed to login to NDFC")
                return False
            ret = self._create_vrf(fabric, payload)
            if not ret:
                return False
            self.logout()
        except Exception as exc:
            LOG.error("create vrf failed with exception %(exc)s",
                      {'exc': exc})
            return False
        return True

    @http_exc_handler
    def _delete_vrf(self, fabric, vrf):
        '''
        Function to create the Vrf in NDFC.
        '''
        url = self._build_url(self._vrf_url) + fabric + (
                "/bulk-delete/vrfs?vrf-names=" + vrf)
        res = requests.delete(url, headers=self._req_headers,
                              timeout=self._timeout_resp, verify=False)
        if not res or res.status_code not in self._resp_ok:
            LOG.error(
                "delete vrf failed with status code: %s, "
                "reason: %s, response body: %s",
                res.status_code, res.reason, res.text
            )
            return False
        if self._response_body_indicates_failure(res, '_delete_vrf'):
            return False

        LOG.debug("delete vrf successful")
        return True

    def delete_vrf(self, fabric, vrf):
        '''
        Top level function to delete the VRF.
        '''
        try:
            ret = self.login()
            if not ret:
                LOG.error("Failed to login to NDFC")
                return False
            ret = self._delete_vrf(fabric, vrf)
            if not ret:
                return False
            self.logout()
        except Exception as exc:
            LOG.error("delete vrf failed with exception %(exc)s",
                      {'exc': exc})
            self.logout()
            return False
        return True

    @http_exc_handler
    def _get_switches(self, fabric):
        '''
        Function for retrieving the switch list from NDFC, given the fabric.
        '''
        switches_map = {}
        url = self._build_url(self._inventory_url) + fabric + "/inventory/"
        res = requests.get(url, headers=self._req_headers,
                timeout=self._timeout_resp, verify=False)
        if not res or res.status_code not in self._resp_ok:
            LOG.error("invalid result for get_switches status %(status)s",
                      {'status': res.status_code})
            return switches_map
        if self._response_body_indicates_failure(res, '_get_switches'):
            return switches_map

        if res and res.status_code in self._resp_ok:
            data = res.json()
            for sw_info in data:
                snum = sw_info.get("serialNumber")
                ip = sw_info.get("ipAddress")
                role = sw_info.get("switchRole")
                name = sw_info.get("logicalName")
                sw_dct = {'serial': snum, 'ip': ip, 'role': role, 'name': name}
                # TODO(padkrish) Optimization to cache this info??
                if role == "tor":
                    topo_url = self._build_url(self._topology_url) + snum
                    res_topo = requests.get(topo_url,
                            headers=self._req_headers,
                            timeout=self._timeout_resp, verify=False)
                    topo_data = res_topo.json()
                    neighbor_leaf_map = {}
                    for node in topo_data.get('nodeList'):
                        node_data = node.get('data')
                        if node_data.get('logicalName') == name:
                            continue
                        if node_data.get('switchRole') != 'leaf':
                            continue
                        neighbor_leaf_map[node_data.get('logicalName')] = (
                                node_data.get('serialNumber'))
                    tor_leaf_intf_map = {}
                    for edge in topo_data.get('edgeList'):
                        edge_data = edge.get('data')
                        nbr_switch = edge_data.get('toSwitch')
                        nbr_interface = edge_data.get('toInterface')
                        if nbr_switch != name:
                            tor_leaf_intf_map[nbr_switch] = nbr_interface
                        else:
                            nbr_switch = edge_data.get('fromSwitch')
                            nbr_interface = edge_data.get('fromInterface')
                            # TODO(padkrish), need another check to omit ToR
                            # neighbors
                            tor_leaf_intf_map[nbr_switch] = nbr_interface
                    sw_dct['tor_leaf_nodes'] = neighbor_leaf_map
                    sw_dct['tor_leaf_intf'] = tor_leaf_intf_map
                switches_map[ip] = sw_dct
        LOG.debug("get_switches returned %s", switches_map)
        return switches_map

    def get_switches(self, fabric, previous_switch_map=None):
        '''
        Top level function for retrieving the switches.
        '''
        sw_info = []
        try:
            ret = self.login()
            if ret:
                sw_info = self._get_switches(fabric)
                self.logout()
        except Exception as exc:
            LOG.error("Exception in get_switches, %(exc)s", {'exc': exc})
        #If sw_info is empty and previous_switch_map is provided, use that
        if not sw_info and previous_switch_map is not None:
            LOG.debug("setting previous switch map, as sw_info was empty")
            sw_info = previous_switch_map
        return sw_info

    @http_exc_handler
    def _get_po(self, snum, ifname):
        url = self._build_url(self._interface_url) + snum + "&ifName=" + (
                ifname + "&ifTypes=INTERFACE_ETHERNET,INTERFACE_PORT_CHANNEL")
        res = requests.get(url, headers=self._req_headers,
                           timeout=self._timeout_resp, verify=False)
        LOG.debug("URL for get po is %s, res %s", url, res)
        if not res or res.status_code not in self._resp_ok:
            LOG.error("invalid result for get_po status %(status)s",
                      {'status': res.status_code})
            return ""
        if self._response_body_indicates_failure(res, '_get_po'):
            return ""

        data = res.json()
        for intf in data:
            # This needs to be fixed to only check for type port-channel
            if intf.get('ifName') == ifname and intf.get('ifType') == (
                    "INTERFACE_ETHERNET"):
                po = intf.get('channelIdStr')
                if po is None:
                    return ""
                return po

    def get_po(self, snum, ifname):
        '''
        Top level function for retrieving PO.
        '''
        po = ""
        try:
            ret = self.login()
            if ret:
                po = self._get_po(snum, ifname)
                self.logout()
        except Exception as exc:
            LOG.error("Exception in get_po, %(exc)s", {'exc': exc})
        return po
