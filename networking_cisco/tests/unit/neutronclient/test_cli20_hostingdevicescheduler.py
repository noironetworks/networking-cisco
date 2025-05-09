# Copyright 2015 Cisco Systems, Inc.
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

import mock
import sys

from mox3 import mox

from networking_cisco.neutronclient import hostingdevicescheduler as scheduler
from networking_cisco.tests.unit import test_cli20

AGENT_ID = 'agent_id1'
HOSTING_DEVICE_ID = 'hd_id1'


class CLITestV20L3HostingDeviceConfigAgentScheduler(test_cli20.CLITestV20Base):

    def _test_assoc_with_cfg_agent(self, resource, cmd, cmd_args, destination,
                                   body, result):
        path = ((scheduler.ConfigAgentHandlingHostingDevice.resource_path +
                 destination) % cmd_args[0])
        result_str = self.client.serialize(result)
        return_tup = (test_cli20.MyResp(200), result_str)
        cmd_parser = cmd.get_parser('test_' + resource)
        parsed_args = cmd_parser.parse_args(cmd_args)

        if getattr(self, 'mox', None):
            self.mox.StubOutWithMock(cmd, "get_client")
            self.mox.StubOutWithMock(self.client.httpclient, "request")
            cmd.get_client().MultipleTimes().AndReturn(self.client)

            self.client.httpclient.request(
                test_cli20.end_url(path), 'POST',
                body=test_cli20.MyComparator(body, self.client),
                headers=mox.ContainsKeyValue(
                    'X-Auth-Token', test_cli20.TOKEN)).AndReturn(return_tup)
            self.mox.ReplayAll()
            cmd.run(parsed_args)
            self.mox.VerifyAll()
            self.mox.UnsetStubs()
        else:
            mock_request_calls = [
                mock.call(
                    test_cli20.end_url(path), 'POST',
                    body=test_cli20.MyComparator(body, self.client),
                    headers=test_cli20.ContainsKeyValue(
                        {'X-Auth-Token': test_cli20.TOKEN}))
            ]

            with mock.patch.object(cmd, "get_client",
                    return_value=self.client) as mock_get_client:
                with mock.patch.object(self.client.httpclient, "request",
                        return_value=return_tup) as mock_request:
                    cmd.run(parsed_args)
                    mock_request.assert_has_calls(mock_request_calls)
                    self.assert_mock_multiple_calls_with_same_arguments(
                        mock_get_client, mock.call(), None)

    def _test_disassoc_with_cfg_agent(self, resource, cmd, cmd_args,
                                      destination):
        path = ((scheduler.ConfigAgentHandlingHostingDevice.resource_path +
                 destination + '/%s') % cmd_args)
        return_tup = (test_cli20.MyResp(204), None)
        cmd_parser = cmd.get_parser('test_' + resource)
        parsed_args = cmd_parser.parse_args(cmd_args)

        if getattr(self, 'mox', None):
            self.mox.StubOutWithMock(cmd, "get_client")
            self.mox.StubOutWithMock(self.client.httpclient, "request")
            cmd.get_client().MultipleTimes().AndReturn(self.client)

            self.client.httpclient.request(
                test_cli20.end_url(path), 'DELETE',
                body=None,
                headers=mox.ContainsKeyValue(
                    'X-Auth-Token', test_cli20.TOKEN)).AndReturn(return_tup)
            self.mox.ReplayAll()
            cmd.run(parsed_args)
            self.mox.VerifyAll()
            self.mox.UnsetStubs()
        else:
            mock_request_calls = [
                mock.call(
                    test_cli20.end_url(path), 'DELETE',
                    body=None,
                    headers=test_cli20.ContainsKeyValue(
                        {'X-Auth-Token': test_cli20.TOKEN}))
            ]

            with mock.patch.object(cmd, "get_client",
                    return_value=self.client) as mock_get_client:
                with mock.patch.object(self.client.httpclient, "request",
                        return_value=return_tup) as mock_request:
                    cmd.run(parsed_args)
                    mock_request.assert_has_calls(mock_request_calls)
                    self.assert_mock_multiple_calls_with_same_arguments(
                        mock_get_client, mock.call(), None)

    def test_associate_hosting_device_with_cfg_agent(self):
        resource = 'hosting_device'
        cmd = scheduler.HostingDeviceAssociateWithConfigAgent(
            test_cli20.MyApp(sys.stdout), None)
        args = (AGENT_ID, HOSTING_DEVICE_ID)
        body = {'hosting_device_id': HOSTING_DEVICE_ID}
        result = {}
        self._test_assoc_with_cfg_agent(
            resource, cmd, args, scheduler.CFG_AGENT_HOSTING_DEVICES, body,
            result)

    def test_disassociate_hosting_device_with_cfg_agent(self):
        resource = 'hosting_device'
        cmd = scheduler.HostingDeviceDisassociateFromConfigAgent(
            test_cli20.MyApp(sys.stdout), None)
        args = (AGENT_ID, HOSTING_DEVICE_ID)
        self._test_disassoc_with_cfg_agent(
            resource, cmd, args, scheduler.CFG_AGENT_HOSTING_DEVICES)

    def test_list_hosting_devices_handled_by_cfg_agent(self):
        resources = 'hosting_devices'
        cmd = scheduler.HostingDeviceHandledByConfigAgentList(
            test_cli20.MyApp(sys.stdout), None)
        hosting_device_id = HOSTING_DEVICE_ID
        path = ((scheduler.ConfigAgentHandlingHostingDevice.resource_path +
                 scheduler.CFG_AGENT_HOSTING_DEVICES) % hosting_device_id)
        contents = [{self.id_field: 'myid1', 'name': 'my_name',
                     'description': 'A fast one', 'admin_state_up': True,
                     'template_id': 'templateid',
                     'management_ip_address': '10.11.12.13'}]
        res = self._test_list_resources(
            resources, cmd, base_args=[hosting_device_id], path=path,
            response_contents=contents)
        self.assertIn('name', res)
        self.assertIn('admin_state_up', res)
        self.assertIn('template_id', res)
        self.assertNotIn('description', res)
        self.assertNotIn('management_ip_address', res)

    def test_list_cfg_agents_handling_hosting_device(self):
        resources = 'agents'
        cmd = scheduler.ConfigAgentHandlingHostingDeviceList(
            test_cli20.MyApp(sys.stdout), None)
        hosting_device_id = HOSTING_DEVICE_ID
        _resource_path = '/dev_mgr/hosting_devices/%s'
        path = ((_resource_path + scheduler.HOSTING_DEVICE_CFG_AGENTS) %
                hosting_device_id)
        contents = [{self.id_field: 'myid1', 'alive': ':-)', 'topic': 'L3Cfg',
                     'agent_type': 'Cisco_Config_agent', 'description': 'None',
                     'admin_state_up': True, 'host': 'Controller',
                     'management_ip_address': '10.11.12.13'}]
        res = self._test_list_resources(
            resources, cmd, base_args=[hosting_device_id], path=path,
            response_contents=contents)
        self.assertIn('alive', res)
        self.assertIn('agent_type', res)
        self.assertIn('admin_state_up', res)
        self.assertIn('host', res)
        self.assertNotIn('description', res)
        self.assertNotIn('topic', res)
