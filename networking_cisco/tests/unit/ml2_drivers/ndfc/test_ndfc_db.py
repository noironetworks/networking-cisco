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

from networking_cisco.ml2_drivers.ndfc import db as nc_ml2_db
from neutron.tests.unit import testlib_api
from neutron_lib import context
from neutron_lib.db import api as db_api


class TestCiscoNxosDb(testlib_api.SqlTestCase):
    """Unit tests for Cisco NDFC mechanism driver's topology database."""

    def setUp(self, *args, **kwargs):
        super(TestCiscoNxosDb, self).setUp(*args, **kwargs)
        self.ctx = context.get_admin_context()

    def _get_host_link(self, context, host, interface):
        with db_api.CONTEXT_READER.using(self.ctx) as session:
            return session.query(
                    nc_ml2_db.NxosHostLink).filter(
                    nc_ml2_db.NxosHostLink.host_name == host).filter(
                    nc_ml2_db.NxosHostLink.interface_name ==
                    interface).all()

    def test_port_query(self):
        # REVISIT(tbachmana: This is only for an example of how
        # the tables are populated, queried, and used. It will be
        # removed before merging.)

        # Create a Host Link
        with db_api.CONTEXT_WRITER.using(self.ctx) as session:
            # Create compute-01 host links
            session.add(nc_ml2_db.NxosHostLink(host_name='compute01.maas',
                interface_name='enp8s0', serial_number='FDO24230D5G',
                switch_ip='10.0.7.65', switch_mac='f8:6b:d9:fe:67:88',
                switch_port='Port-Channel11'))
            session.add(nc_ml2_db.NxosHostLink(host_name='compute01.maas',
                interface_name='enp9s0', serial_number='FDO24230DAX',
                switch_ip='10.0.7.66', switch_mac='f8:6b:d9:fe:6e:3c',
                switch_port='Port-Channel11'))
            session.add(nc_ml2_db.NxosHostLink(host_name='compute02.maas',
                interface_name='enp8s0', serial_number='FDO2738092V',
                switch_ip='10.0.7.67', switch_mac='68:79:09:13:52:98',
                switch_port='Port-Channel11'))
            session.add(nc_ml2_db.NxosHostLink(host_name='compute02.maas',
                interface_name='enp9s0', serial_number='FDO2738091G',
                switch_ip='10.0.7.68', switch_mac='68:79:09:13:59:78',
                switch_port='Port-Channel11'))
            session.add(nc_ml2_db.NxosHostLink(host_name='compute03.maas',
                interface_name='enp10s0', serial_number='FDO234704FQ',
                switch_ip='10.0.7.69', switch_mac='3c:51:0e:e0:32:b0',
                switch_port='Port-Channel11'))
            session.add(nc_ml2_db.NxosHostLink(host_name='compute03.maas',
                interface_name='enp9s0', serial_number='FDO23470XQ5',
                switch_ip='10.0.7.70', switch_mac='a0:b4:39:bd:4e:a0',
                switch_port='Port-Channel11'))
            session.add(nc_ml2_db.NxosHostLink(host_name='compute04.maas',
                interface_name='eno5', serial_number='FDO234704FQ',
                switch_ip='10.0.7.69', switch_mac='3c:51:0e:e0:32:b4',
                switch_port='Port-Channel12'))
            session.add(nc_ml2_db.NxosHostLink(host_name='compute04.maas',
                interface_name='eno6', serial_number='FDO23470XQ5',
                switch_ip='10.0.7.70', switch_mac='a0:b4:39:bd:4e:a4',
                switch_port='Port-Channel12'))

            # Add the corresponding ToRs
            session.add(nc_ml2_db.NxosTors(
                tor_serial_number='FDO234704FQ',
                leaf_serial_number='FDO244508KY',
                tor_name=' 69-N9332FX2'))
            session.add(nc_ml2_db.NxosTors(
                tor_serial_number='FDO234704FQ',
                leaf_serial_number='FDO244508LB',
                tor_name=' 69-N9332FX2'))
            session.add(nc_ml2_db.NxosTors(
                tor_serial_number='FDO23470XQ5',
                leaf_serial_number='FDO244508KY',
                tor_name=' 70-N9332FX2'))
            session.add(nc_ml2_db.NxosTors(
                tor_serial_number='FDO23470XQ5',
                leaf_serial_number='FDO244508LB',
                tor_name=' 70-N9332FX2'))
            session.add(nc_ml2_db.NxosTors(
                tor_serial_number='FDO24230D5G',
                leaf_serial_number='FDO24170Q2T',
                tor_name=' 65-N9336FX2'))
            session.add(nc_ml2_db.NxosTors(
                tor_serial_number='FDO24230D5G',
                leaf_serial_number='FDO24170TNU',
                tor_name=' 65-N9336FX2'))
            session.add(nc_ml2_db.NxosTors(
                tor_serial_number='FDO24230DAX',
                leaf_serial_number='FDO24170Q2T',
                tor_name=' 66-N9332FX2'))
            session.add(nc_ml2_db.NxosTors(
                tor_serial_number='FDO24230DAX',
                leaf_serial_number='FDO24170TNU',
                tor_name=' 66-N9332FX2'))
            session.add(nc_ml2_db.NxosTors(
                tor_serial_number='FDO2738091G',
                leaf_serial_number='FDO244508KY',
                tor_name=' 68-N93108FX3'))
            session.add(nc_ml2_db.NxosTors(
                tor_serial_number='FDO2738091G',
                leaf_serial_number='FDO244508LB',
                tor_name=' 68-N93108FX3'))
            session.add(nc_ml2_db.NxosTors(
                tor_serial_number='FDO2738092V',
                leaf_serial_number='FDO244508KY',
                tor_name=' 67-N93108FX3'))
            session.add(nc_ml2_db.NxosTors(
                tor_serial_number='FDO2738092V',
                leaf_serial_number='FDO244508LB',
                tor_name=' 67-N93108FX3'))

        result = self._get_host_link(context, 'compute01.maas', 'enp8s0')
        with db_api.CONTEXT_READER.using(self.ctx) as session:
            leaf_serial_number = result[0]['serial_number']
            result = session.query(nc_ml2_db.NxosHostLink,
                                   nc_ml2_db.NxosTors).outerjoin(
                    nc_ml2_db.NxosTors, nc_ml2_db.NxosTors.tor_serial_number ==
                    nc_ml2_db.NxosHostLink.serial_number).filter(
                            nc_ml2_db.NxosTors.tor_serial_number ==
                            leaf_serial_number).all()
            self.assertEqual(len(result), 2)
