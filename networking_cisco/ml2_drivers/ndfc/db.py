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

import sqlalchemy as sa

from neutron_lib.db import model_base


class NxosHostLink(model_base.BASEV2):
    """Represents a link between an NXOS switch and a host."""

    __tablename__ = 'nxos_host_links'

    host_name = sa.Column(sa.String(128), default='', server_default='',
                          nullable=False, primary_key=True)
    interface_name = sa.Column(sa.String(32), default='', server_default='',
                               nullable=False, primary_key=True)
    serial_number = sa.Column(sa.String(length=16),
                              default='', server_default='')
    switch_ip = sa.Column(sa.String(128), default='', server_default='')
    switch_mac = sa.Column(sa.String(24), default='', server_default='')
    switch_port = sa.Column(sa.String(128), default='', server_default='')


class NxosTors(model_base.BASEV2):
    """Represents a link between an NXOS switch and a host."""

    __tablename__ = 'nxos_tors'

    tor_serial_number = sa.Column(sa.String(length=16), default='',
                                  server_default='', primary_key=True)
    leaf_serial_number = sa.Column(sa.String(length=16), default='',
                                   server_default='', primary_key=True)
    tor_name = sa.Column(sa.String(32), default='', server_default='')
