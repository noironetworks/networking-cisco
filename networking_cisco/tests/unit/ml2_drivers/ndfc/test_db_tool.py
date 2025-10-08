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

import abc
import io
import sqlalchemy as sa
from unittest import mock

from networking_cisco.ml2_drivers.ndfc.db import NxosHostLink
from networking_cisco.ml2_drivers.ndfc.db import NxosTors
from networking_cisco.ml2_drivers.ndfc import db_tool
from neutron.common import config
from neutron.tests.unit.plugins.ml2 import test_plugin
from oslo_config import cfg
from oslo_log import log

LOG = log.getLogger('networking_cisco.ml2_drivers.ndfc.db_tool')


class TestDBToolBase(abc.ABC):
    def setUp(self):
        config.register_common_config_options()
        super().setUp()


class TestDBTool(TestDBToolBase, test_plugin.Ml2PluginV2TestCase):
    def setUp(self):
        super(TestDBTool, self).setUp()

    @mock.patch('sqlalchemy.orm.sessionmaker')
    @mock.patch('sqlalchemy.create_engine')
    def test_get_session(self, mock_create_engine, mock_sessionmaker):
        """Test creation of a SQLAlchemy session."""
        cfg.CONF.database.connection = \
            "mysql+pymysql://user:password@localhost/testdb"

        mock_engine = mock.MagicMock()
        mock_create_engine.return_value = mock_engine
        mock_session = mock.MagicMock()
        mock_sessionmaker.return_value = mock.MagicMock(
                return_value=mock_session)

        session = db_tool.get_session()

        self.assertEqual(session, mock_session)
        mock_create_engine.assert_called_once_with(
            "mysql+pymysql://user:password@localhost/testdb")
        mock_sessionmaker.assert_called_once_with(bind=mock_engine)

    @mock.patch('networking_cisco.ml2_drivers.ndfc.db_tool.get_session')
    @mock.patch('networking_cisco.ml2_drivers.ndfc.db_tool.setup')
    @mock.patch('sys.argv', ['db_tool.py',
        '--config-file', '/etc/neutron/neutron.conf', 'list-nxos-links'])
    @mock.patch('sys.exit')
    @mock.patch('sys.stdout', new_callable=io.StringIO)
    @mock.patch('networking_cisco.ml2_drivers.ndfc.db_tool.BAKERY')
    def test_list_nxos_links(self, mock_bakery, mock_stdout, mock_exit,
            mock_setup, mock_get_session):
        """Test the 'list-nxos-links' command."""
        mock_session = mock.MagicMock()
        mock_get_session.return_value.__enter__.return_value = mock_session
        mock_get_session.return_value.__exit__.return_value = None

        mock_link1 = mock.Mock(spec=NxosHostLink)
        mock_link1.__str__ = mock.MagicMock(
                return_value="MockHostLink(host1, eth0)")
        mock_link2 = mock.Mock(spec=NxosHostLink)
        mock_link2.__str__ = mock.MagicMock(
                return_value="MockHostLink(host2, eth1)")

        mock_baked_query_result_obj = mock.MagicMock()
        mock_baked_query_result_obj.all.return_value = [
                mock_link1, mock_link2]
        mock_bakery.return_value = mock.MagicMock(
                return_value=mock_baked_query_result_obj)

        db_tool.main()

        mock_bakery.assert_called_once()
        mock_bakery.return_value.assert_called_once_with(mock_session)
        mock_baked_query_result_obj.all.assert_called_once()
        self.assertEqual(mock_stdout.getvalue(),
            "MockHostLink(host1, eth0)\nMockHostLink(host2, eth1)\n")
        mock_exit.assert_not_called()

    @mock.patch('networking_cisco.ml2_drivers.ndfc.db_tool.get_session')
    @mock.patch('networking_cisco.ml2_drivers.ndfc.db_tool.setup')
    @mock.patch('sys.argv', ['db_tool.py',
        '--config-file', '/etc/neutron/neutron.conf', 'delete-nxos-links',
        '--condition', "hostname='compute01.maas'"])
    @mock.patch('sys.exit')
    @mock.patch.object(LOG, 'debug')
    def test_delete_nxos_links(self, mock_log_debug, mock_exit,
            mock_setup, mock_get_session):
        """Test the 'delete-nxos-links' command."""
        mock_session = mock.MagicMock()
        mock_get_session.return_value.__enter__.return_value = mock_session
        mock_get_session.return_value.__exit__.return_value = None

        mock_query_obj = mock.MagicMock()
        mock_session.query.return_value = mock_query_obj
        mock_query_obj.filter.return_value = mock_query_obj
        mock_query_obj.delete.return_value = 5

        db_tool.main()

        mock_session.query.assert_called_once_with(NxosHostLink)
        mock_query_obj.filter.assert_called_once()
        filter_arg = mock_query_obj.filter.call_args[0][0]
        self.assertIsInstance(filter_arg, sa.sql.elements.TextClause)
        self.assertEqual(str(filter_arg), "hostname='compute01.maas'")
        mock_query_obj.delete.assert_called_once_with(
                synchronize_session=False)
        mock_log_debug.assert_called_once_with(
            "Successfully deleted %d rows from table: %s",
            5, "nxos_host_links")
        mock_exit.assert_not_called()

    @mock.patch('networking_cisco.ml2_drivers.ndfc.db_tool.get_session')
    @mock.patch('networking_cisco.ml2_drivers.ndfc.db_tool.setup')
    @mock.patch('sys.argv', ['db_tool.py',
        '--config-file', '/etc/neutron/neutron.conf', 'list-nxos-tors'])
    @mock.patch('sys.exit')
    @mock.patch('sys.stdout', new_callable=io.StringIO)
    @mock.patch('networking_cisco.ml2_drivers.ndfc.db_tool.BAKERY')
    def test_list_nxos_tors(self, mock_bakery, mock_stdout, mock_exit,
                            mock_setup, mock_get_session):
        """Test the 'list-nxos-tors' command."""
        mock_session = mock.MagicMock()
        mock_get_session.return_value.__enter__.return_value = mock_session
        mock_get_session.return_value.__exit__.return_value = None

        mock_tor1 = mock.Mock(spec=NxosTors)
        mock_tor1.__str__ = mock.MagicMock(
                return_value="MockNxosTors(torA, SN1)")
        mock_tor2 = mock.Mock(spec=NxosTors)
        mock_tor2.__str__ = mock.MagicMock(
                return_value="MockNxosTors(torB, SN2)")

        mock_baked_query_result_obj = mock.MagicMock()
        mock_baked_query_result_obj.all.return_value = [mock_tor1, mock_tor2]
        mock_bakery.return_value = mock.MagicMock(
                return_value=mock_baked_query_result_obj)

        db_tool.main()

        mock_bakery.assert_called_once()
        mock_bakery.return_value.assert_called_once_with(mock_session)
        mock_baked_query_result_obj.all.assert_called_once()
        self.assertEqual(mock_stdout.getvalue(),
            "MockNxosTors(torA, SN1)\nMockNxosTors(torB, SN2)\n")
        mock_exit.assert_not_called()

    @mock.patch('networking_cisco.ml2_drivers.ndfc.db_tool.get_session')
    @mock.patch('networking_cisco.ml2_drivers.ndfc.db_tool.setup')
    @mock.patch('sys.argv', ['db_tool.py',
        '--config-file', '/etc/neutron/neutron.conf', 'delete-nxos-tors',
        '--condition', "tor_id=1"])
    @mock.patch('sys.exit')
    @mock.patch.object(LOG, 'debug')
    def test_delete_nxos_tors(self, mock_log_debug, mock_exit,
            mock_setup, mock_get_session):
        """Test the 'delete-nxos-tors' command."""
        mock_session = mock.MagicMock()
        mock_get_session.return_value.__enter__.return_value = mock_session
        mock_get_session.return_value.__exit__.return_value = None

        mock_query_obj = mock.MagicMock()
        mock_session.query.return_value = mock_query_obj
        mock_query_obj.filter.return_value = mock_query_obj
        mock_query_obj.delete.return_value = 1

        db_tool.main()

        mock_session.query.assert_called_once_with(NxosTors)
        mock_query_obj.filter.assert_called_once()
        filter_arg = mock_query_obj.filter.call_args[0][0]
        self.assertIsInstance(filter_arg, sa.sql.elements.TextClause)
        self.assertEqual(str(filter_arg), "tor_id=1")
        mock_query_obj.delete.assert_called_once_with(
                synchronize_session=False)
        mock_log_debug.assert_called_once_with(
            "Successfully deleted %d rows from table: %s", 1, "nxos_tors")
        mock_exit.assert_not_called()
