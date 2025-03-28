# Copyright 2015 Cisco Systems Inc.
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

import sys

import mock

from networking_cisco.neutronclient import networkprofile as np
from networking_cisco.tests.unit import test_cli20
from openstackclient import shell


class CLITestV20NetworkProfile(test_cli20.CLITestV20Base):

    def setUp(self):
        self._mock_extension_loading()
        self.register_non_admin_status_resource('network_profile')
        super(CLITestV20NetworkProfile, self).setUp()

    def _mock_extension_loading(self):
        ext_pkg = 'neutronclient.common.extension'
        ext = mock.patch(ext_pkg + '._discover_via_entry_points').start()
        ext.return_value = [("network_profile", np)]
        return ext

    def test_ext_cmd_loaded(self):
        shell.OpenStackShell('2.0')
        ext_cmd = {'cisco-network-profile-list': np.NetworkProfileList,
                   'cisco-network-profile-show': np.NetworkProfileShow,
                   'cisco-network-profile-create': np.NetworkProfileCreate,
                   'cisco-network-profile-delete': np.NetworkProfileDelete}
        self.assertDictContainsSubset(ext_cmd, shell.COMMANDS['2.0'])

    def test_create_networkprofile(self):
        """Create networkprofile: myid."""
        resource = 'network_profile'
        cmd = np.NetworkProfileCreate(test_cli20.MyApp(sys.stdout), None)
        name = 'myname'
        myid = 'myid'
        segment_type = 'vlan'
        args = [name, segment_type]
        position_names = ['name', 'segment_type']
        position_values = [name, segment_type]
        self._test_create_resource(resource, cmd, name, myid, args,
                                   position_names, position_values)

    def test_list_networkprofile_detail(self):
        """List networkprofile: -D."""
        resources = 'network_profiles'
        cmd = np.NetworkProfileList(test_cli20.MyApp(sys.stdout), None)
        contents = [{'name': 'myname', 'segment_type': 'vlan'}]
        self._test_list_resources(resources, cmd, True,
                                  response_contents=contents)

    def test_list_networkprofile_known_option_after_unknown(self):
        """List networkprofile: -- --tags a b --request-format xml."""
        resources = 'network_profiles'
        cmd = np.NetworkProfileList(test_cli20.MyApp(sys.stdout), None)
        contents = [{'name': 'myname', 'segment_type': 'vlan'}]
        self._test_list_resources(resources, cmd, tags=['a', 'b'],
                                  response_contents=contents)

    def test_list_networkprofile_fields(self):
        """List networkprofile: --fields a --fields b -- --fields c d."""
        resources = 'network_profiles'
        cmd = np.NetworkProfileList(test_cli20.MyApp(sys.stdout), None)
        contents = [{'name': 'myname', 'segment_type': 'vlan'}]
        self._test_list_resources(resources, cmd,
                                  fields_1=['a', 'b'], fields_2=['c', 'd'],
                                  response_contents=contents)

    def test_show_networkprofile(self):
        """Show networkprofile: --fields id --fields name myid."""
        resource = 'network_profile'
        cmd = np.NetworkProfileShow(test_cli20.MyApp(sys.stdout), None)
        args = ['--fields', 'id', '--fields', 'name', self.test_id]
        self._test_show_resource(resource, cmd, self.test_id, args,
                                 ['id', 'name'])

    def test_delete_networkprofile(self):
        """Delete networkprofile: myid."""
        resource = 'network_profile'
        cmd = np.NetworkProfileDelete(test_cli20.MyApp(sys.stdout), None)
        myid = 'myid'
        args = [myid]
        self._test_delete_resource(resource, cmd, myid, args)

    def test_create_networkprofile_overlay(self):
        """Create networkprofile: myid."""
        resource = 'network_profile'
        cmd = np.NetworkProfileCreate(test_cli20.MyApp(sys.stdout), None)
        name = 'myname'
        myid = 'myid'
        segment_type = 'overlay'
        args = [name, segment_type, '--sub_type', 'enhanced']
        position_names = ['name', 'segment_type', ]
        position_values = [name, segment_type, ]
        self._test_create_resource(resource, cmd, name, myid, args,
                                   position_names, position_values,
                                   sub_type='enhanced')

    def test_list_networkprofile_overlay_detail(self):
        """List networkprofile: -D."""
        resources = 'network_profiles'
        cmd = np.NetworkProfileList(test_cli20.MyApp(sys.stdout), None)
        contents = [{'name': 'myname', 'segment_type': 'overlay',
                    '--sub_type': 'enhanced'}]
        self._test_list_resources(resources, cmd, True,
                                  response_contents=contents)
