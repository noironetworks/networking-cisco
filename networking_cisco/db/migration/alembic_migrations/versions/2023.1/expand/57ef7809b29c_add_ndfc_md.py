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

from alembic import op
import sqlalchemy as sa


"""NxOS Topology DB

Revision ID: 57ef7809b29c
Revises: 6454463cea8b
Create Date: 2024-09-26 15:37:20.996070

"""

# revision identifiers, used by Alembic.
revision = '57ef7809b29c'
down_revision = '6454463cea8b'


def upgrade():
    op.create_table(
        'nxos_host_links',
        sa.Column('host_name', sa.String(128), primary_key=True),
        sa.Column('interface_name', sa.String(32), primary_key=True),
        sa.Column('serial_number', sa.String(length=16)),
        sa.Column('switch_ip', sa.String(128)),
        sa.Column('switch_mac', sa.String(24)),
        sa.Column('switch_port', sa.String(128)),
        sa.PrimaryKeyConstraint('host_name', 'interface_name'))

    op.create_table(
        'nxos_tors',
        sa.Column('tor_serial_number', sa.String(length=16),
                  primary_key=True),
        sa.Column('leaf_serial_number', sa.String(length=16),
                  primary_key=True),
        sa.Column('tor_name', sa.String(32)),
        sa.PrimaryKeyConstraint('tor_serial_number',
                                'leaf_serial_number'))


def downgrade():
    pass
