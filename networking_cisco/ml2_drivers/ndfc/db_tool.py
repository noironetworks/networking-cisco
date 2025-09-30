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

import argparse
import sys

from networking_cisco.ml2_drivers.ndfc.db import NxosHostLink
from networking_cisco.ml2_drivers.ndfc.db import NxosTors
from neutron.common import config as common_cfg
from oslo_config import cfg
from oslo_db import options as db_options
from oslo_log import log
import sqlalchemy as sa
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext import baked


LOG = log.getLogger(__name__)

BAKERY = baked.bakery(500, _size_alert=lambda c: LOG.warning(
    "sqlalchemy baked query cache size exceeded in %s", __name__)
)


def setup():
    """Initialize oslo_config."""
    # Register common OpenStack configuration options
    common_cfg.register_common_config_options()
    db_options.set_defaults(cfg.CONF)
    # Parse CLI arguments and config files
    common_cfg.init(sys.argv[1:])


def get_session():
    """Create a SQLAlchemy session."""
    db_connection = cfg.CONF.database.connection
    LOG.debug("Using database connection string: %s", db_connection)
    try:
        engine = sa.create_engine(db_connection)
        Session = sa.orm.sessionmaker(bind=engine)
        return Session()
    except Exception as e:
        LOG.error("Error connecting to the database: %s", e)
        sys.exit(1)


def list_table(session, model):
    """Generic function to list all rows from a table."""
    try:
        query = BAKERY(lambda s: s.query(model))
        results = query(session).all()
        for row in results:
            print(row)
    except SQLAlchemyError as e:
        LOG.error("Error querying table %s: %s", model.__tablename__, e)
        sys.exit(1)


def delete_table(session, model, condition=None):
    """Generic function to delete rows from a table."""
    try:
        query = session.query(model)
        if condition:
            query = query.filter(sa.text(condition))
        deleted_count = query.delete(synchronize_session=False)
        LOG.debug("Successfully deleted %d rows from table: %s",
                deleted_count, model.__tablename__)
    except SQLAlchemyError as e:
        LOG.error("Error deleting data from table %s: %s",
                model.__tablename__, e)
        sys.exit(1)


def main():
    """Main execution function."""
    parser = argparse.ArgumentParser(
        description="Database Tool for Cisco Networking"
    )
    parser.add_argument(
        '--config-file',
        required=True,
        help="Path to the neutron.conf configuration file"
    )
    subparsers = parser.add_subparsers(
            dest='command', help="Available commands")

    subparsers.add_parser(
        'list-nxos-links',
        help="List all NXOS host links"
    )

    delete_links_parser = subparsers.add_parser(
        'delete-nxos-links',
        help="Delete NXOS host links"
    )
    delete_links_parser.add_argument(
        '--condition',
        help="Condition to filter which links to delete (optional)"
    )

    subparsers.add_parser(
        'list-nxos-tors',
        help="List all NXOS ToRs"
    )

    delete_tors_parser = subparsers.add_parser(
        'delete-nxos-tors',
        help="Delete NXOS ToRs"
    )
    delete_tors_parser.add_argument(
        '--condition',
        help="Condition to filter which ToRs to delete (optional)"
    )

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(1)

    sys.argv = [sys.argv[0], "--config-file=%s" % args.config_file]

    setup()

    command_map = {
        'list-nxos-links': (NxosHostLink, list_table),
        'delete-nxos-links': (NxosHostLink, delete_table),
        'list-nxos-tors': (NxosTors, list_table),
        'delete-nxos-tors': (NxosTors, delete_table),
    }

    if args.command in command_map:
        with get_session() as session:
            model, func = command_map[args.command]
            if 'delete' in args.command:
                func(session, model, condition=args.condition)
            else:
                func(session, model)
    else:
        LOG.error("Invalid command. Use --help for a list of valid commands.")
        sys.exit(1)


if __name__ == '__main__':
    main()
