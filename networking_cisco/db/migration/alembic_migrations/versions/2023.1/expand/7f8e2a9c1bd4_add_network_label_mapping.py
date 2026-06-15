# Copyright (c) 2026 Cisco Systems Inc.
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


"""Add network label mapping table

Revision ID: 7f8e2a9c1bd4
Revises: 9abcd1234def
Create Date: 2026-06-15 14:10:00.000000

"""

revision = '7f8e2a9c1bd4'
down_revision = '9abcd1234def'


def upgrade():
    op.create_table(
        'nxos_host_network_labels',
        sa.Column('host_name', sa.String(128), nullable=False),
        sa.Column('network_label', sa.String(64), nullable=False),
        sa.Column('interface_name', sa.String(32), nullable=False),
        sa.PrimaryKeyConstraint('host_name', 'network_label',
                                'interface_name'))


def downgrade():
    pass
