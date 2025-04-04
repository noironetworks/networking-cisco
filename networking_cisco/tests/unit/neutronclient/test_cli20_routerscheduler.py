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

from networking_cisco.neutronclient import hostingdevice
from networking_cisco.neutronclient import routerscheduler
from networking_cisco.tests.unit import test_cli20


HOSTING_DEVICE_ID = 'hd_id1'
ROUTER_ID = 'router_id1'


class CLITestV20L3RouterHostingDeviceScheduler(test_cli20.CLITestV20Base):

    def _test_add_to_hosting_device(self, resource, cmd, cmd_args, destination,
                                    body, result):
        path = ((hostingdevice.HostingDevice.resource_path + destination) %
                cmd_args[0])
        cmd_parser = cmd.get_parser('test_' + resource)
        parsed_args = cmd_parser.parse_args(cmd_args)
        result_str = self.client.serialize(result)
        return_tup = (test_cli20.MyResp(200), result_str)

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

    def _test_remove_from_hosting_device(self, resource, cmd, cmd_args,
                                         destination):
        path = ((hostingdevice.HostingDevice.resource_path + destination +
                 '/%s') % cmd_args)
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

    def test_add_router_to_hosting_device(self):
        resource = 'hosting_device'
        cmd = routerscheduler.AddRouterToHostingDevice(
            test_cli20.MyApp(sys.stdout), None)
        args = (HOSTING_DEVICE_ID, ROUTER_ID)
        body = {'router_id': ROUTER_ID}
        result = {}
        self._test_add_to_hosting_device(
            resource, cmd, args, routerscheduler.DEVICE_L3_ROUTERS, body,
            result)

    def test_remove_router_from_hosting_device(self):
        resource = 'hosting_device'
        cmd = routerscheduler.RemoveRouterFromHostingDevice(
            test_cli20.MyApp(sys.stdout), None)
        args = (HOSTING_DEVICE_ID, ROUTER_ID)
        self._test_remove_from_hosting_device(
            resource, cmd, args, routerscheduler.DEVICE_L3_ROUTERS)

    def test_list_routers_on_hosting_device(self):
        resources = 'routers'
        cmd = routerscheduler.RoutersOnHostingDeviceList(
            test_cli20.MyApp(sys.stdout), None)
        hosting_device_id = HOSTING_DEVICE_ID
        path = ((hostingdevice.HostingDevice.resource_path +
                 routerscheduler.DEVICE_L3_ROUTERS) % hosting_device_id)
        contents = [{self.id_field: 'myid1', 'name': 'my_name',
                     'admin_state_up': True,
                     'external_gateway_info': {'network_id': 'net-id'}}]
        res = self._test_list_resources(
            resources, cmd, base_args=[hosting_device_id], path=path,
            response_contents=contents)
        self.assertIn('external_gateway_info', res)
        self.assertIn('name', res)
        self.assertNotIn('admin_state_up', res)

    def test_list_hosting_devices_hosting_router(self):
        resources = 'hosting_devices'
        cmd = routerscheduler.HostingDeviceHostingRouterList(
            test_cli20.MyApp(sys.stdout), None)
        router_id = ROUTER_ID
        path = ((self.client.router_path + routerscheduler.L3_ROUTER_DEVICES) %
                router_id)
        contents = [{self.id_field: 'myid1', 'name': 'my_name',
                     'description': 'A fast one', 'status': 'ACTIVE',
                     'admin_state_up': True, 'template_id': 'templateid',
                     'management_ip_address': '10.11.12.13'}]
        res = self._test_list_resources(resources, cmd, base_args=[router_id],
                                        path=path, response_contents=contents)
        self.assertIn('name', res)
        self.assertIn('status', res)
        self.assertIn('admin_state_up', res)
        self.assertIn('template_id', res)
        self.assertNotIn('description', res)
        self.assertNotIn('management_ip_address', res)
