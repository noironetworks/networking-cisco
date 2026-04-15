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

"""Create ND address-scope extensions table

Revision ID: 8a7b21c3f1a2
Revises: 57ef7809b29c
Create Date: 2026-03-13 00:00:00.000000
"""

# revision identifiers, used by Alembic.
revision = '8a7b21c3f1a2'
down_revision = '57ef7809b29c'


def upgrade():
    op.create_table(
        'nd_address_scope_extensions',
        sa.Column('address_scope_id', sa.String(36), nullable=False),
        sa.Column('nd_vrf_name', sa.String(255), nullable=True),
        sa.ForeignKeyConstraint(['address_scope_id'], ['address_scopes.id'],
                                name='nd_addr_scope_extn_fk_addr_scope',
                                ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('address_scope_id')
    )


def downgrade():
    op.drop_table('nd_address_scope_extensions')
