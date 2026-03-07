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

from neutron.db.models import address_scope as as_db
from neutron_lib.db import model_base
import sqlalchemy as sa
from sqlalchemy import orm


class NdAddressScopeExtension(model_base.BASEV2):
    """Extension table for ND address-scope attributes.

    Stores ND-specific data for Neutron address scopes, keyed by
    address_scope_id. This allows us to extend the upstream resource
    without modifying its core table schema.
    """

    __tablename__ = 'nd_address_scope_extensions'

    address_scope_id = sa.Column(
        sa.String(36),
        sa.ForeignKey('address_scopes.id', ondelete='CASCADE'),
        primary_key=True)

    address_scope = orm.relationship(
        as_db.AddressScope,
        backref=orm.backref(
            'nd_mapping', lazy='joined', uselist=False, cascade='delete'))

    nd_vrf_name = sa.Column(sa.String(255), nullable=True)
