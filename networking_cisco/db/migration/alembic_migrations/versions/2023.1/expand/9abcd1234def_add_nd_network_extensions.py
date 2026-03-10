# Copyright 2026 Cisco Systems, Inc.
# All rights reserved.
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

"""Create ND network extensions table

Revision ID: 9abcd1234def
Revises: 8a7b21c3f1a2
Create Date: 2026-03-30 00:00:00.000000
"""

# revision identifiers, used by Alembic.
revision = '9abcd1234def'
down_revision = '8a7b21c3f1a2'


def upgrade():
    op.create_table(
        'nd_network_extensions',
        sa.Column('network_id', sa.String(length=36), nullable=False),
        sa.Column('nd_status', sa.String(length=32), nullable=True),
        sa.ForeignKeyConstraint(
            ['network_id'], ['networks.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('network_id')
    )


def downgrade():
    op.drop_table('nd_network_extensions')
