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
from unittest import mock

from networking_cisco.ml2_drivers.ndfc.db import NxosHostLink
from networking_cisco.ml2_drivers.ndfc.db import NxosTors
from networking_cisco.ml2_drivers.ndfc import db_tool
from neutron.common import config
from neutron.tests.unit.plugins.ml2 import test_plugin
from oslo_config import cfg


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
    def test_list_nxos_links(self, mock_setup, mock_get_session):
        """Test the 'list-nxos-links' command."""
        mock_session = mock.MagicMock()
        mock_get_session.return_value.__enter__.return_value = mock_session

        list_table = 'networking_cisco.ml2_drivers.ndfc.db_tool.list_table'

        with mock.patch(list_table) as mock_list_table:
            db_tool.main()
            mock_list_table.assert_called_once_with(
                    mock_session, NxosHostLink)

    @mock.patch('networking_cisco.ml2_drivers.ndfc.db_tool.get_session')
    @mock.patch('networking_cisco.ml2_drivers.ndfc.db_tool.setup')
    @mock.patch('sys.argv', ['db_tool.py',
        '--config-file', '/etc/neutron/neutron.conf', 'delete-nxos-links',
        '--condition', "hostname='compute01.maas'"])
    def test_delete_nxos_links(self, mock_setup, mock_get_session):
        """Test the 'delete-nxos-links' command."""
        mock_session = mock.MagicMock()
        mock_get_session.return_value.__enter__.return_value = mock_session

        delete_table = 'networking_cisco.ml2_drivers.ndfc.db_tool.delete_table'

        with mock.patch(delete_table) as mock_delete_table:
            db_tool.main()
            mock_delete_table.assert_called_once_with(
                    mock_session, NxosHostLink,
                    condition="hostname='compute01.maas'")

    @mock.patch('networking_cisco.ml2_drivers.ndfc.db_tool.get_session')
    @mock.patch('networking_cisco.ml2_drivers.ndfc.db_tool.setup')
    @mock.patch('sys.argv', ['db_tool.py',
        '--config-file', '/etc/neutron/neutron.conf', 'list-nxos-tors'])
    def test_list_nxos_tors(self, mock_setup, mock_get_session):
        """Test the 'list-nxos-tors' command."""
        mock_session = mock.MagicMock()
        mock_get_session.return_value.__enter__.return_value = mock_session

        list_table = 'networking_cisco.ml2_drivers.ndfc.db_tool.list_table'

        with mock.patch(list_table) as mock_list_table:
            db_tool.main()
            mock_list_table.assert_called_once_with(
                    mock_session, NxosTors)

    @mock.patch('networking_cisco.ml2_drivers.ndfc.db_tool.get_session')
    @mock.patch('networking_cisco.ml2_drivers.ndfc.db_tool.setup')
    @mock.patch('sys.argv', ['db_tool.py',
        '--config-file', '/etc/neutron/neutron.conf', 'delete-nxos-tors',
        '--condition', "tor_id=1"])
    def test_delete_nxos_tors(self, mock_setup, mock_get_session):
        """Test the 'delete-nxos-tors' command."""
        mock_session = mock.MagicMock()
        mock_get_session.return_value.__enter__.return_value = mock_session

        delete_table = 'networking_cisco.ml2_drivers.ndfc.db_tool.delete_table'

        with mock.patch(delete_table) as mock_delete_table:
            db_tool.main()
            mock_delete_table.assert_called_once_with(
                    mock_session, NxosTors, condition='tor_id=1')
