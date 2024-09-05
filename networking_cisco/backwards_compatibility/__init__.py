# Copyright 2016 Cisco Systems, Inc.  All rights reserved.
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

from neutron.plugins.ml2.drivers import type_tunnel

from networking_cisco.backwards_compatibility \
        import neutron_version as nv  # noqa

# FIXME(sambetts) We should remove cases where people are using bc.<neutron
# version> so that we don't need to do this.
from networking_cisco.backwards_compatibility.neutron_version import *  # noqa

# FIXME(sambetts) We should remove cases where people are using bc.constants
# instead of importing constants properly so we don't need to do this.
from networking_cisco.backwards_compatibility import constants  # noqa

# FIXME(sambetts)
from networking_cisco.backwards_compatibility import extensions  # noqa


from neutron.agent.common import utils as agent_utils
from neutron.conf.agent import common as neutron_agent_conf  # noqa
from neutron.conf.agent import common as config  # noqa
from neutron.conf import common as base_config
from neutron.conf.plugins.ml2 import config as ml2_config  # noqa
from neutron.db.models import agent as agent_model
from neutron.db.models import l3 as l3_models
from neutron.db.models import l3agent as rb_model  # noqa
from neutron.db import segments_db  # noqa
from neutron.objects import trunk as trunk_objects  # noqa
from neutron.services.trunk.drivers import base as trunk_base  # noqa

from neutron_lib.agent import topics  # noqa
from neutron_lib.api.definitions import dns as dns_const
from neutron_lib.api.definitions import dns  # noqa
from neutron_lib.api.definitions import external_net as exnet_const  # noqa
from neutron_lib.api.definitions import extraroute as extraroute_const
from neutron_lib.api.definitions import l3 as l3_const  # noqa
from neutron_lib.api.definitions import portbindings  # noqa
from neutron_lib.api.definitions import provider_net as providernet  # noqa
from neutron_lib.api.definitions import provider_net  # noqa
from neutron_lib.api import faults as cb_faults  # noqa
from neutron_lib.api import validators
from neutron_lib.callbacks import events as cb_events  # noqa
from neutron_lib.callbacks import registry as cb_registry  # noqa
from neutron_lib.callbacks import resources as cb_resources  # noqa
from neutron_lib import context
from neutron_lib.db import api as db_api  # noqa
from neutron_lib.db import api as lib_db_api
from neutron_lib.db import model_base
from neutron_lib.db.resource_extend import extends  # noqa
from neutron_lib.db.resource_extend import get_funcs  # noqa
from neutron_lib.db.resource_extend import has_resource_extenders  # noqa
from neutron_lib.exceptions import agent as agent_exceptions  # noqa
from neutron_lib.exceptions import l3 as l3_exceptions  # noqa
from neutron_lib.plugins import directory
from neutron_lib.plugins.ml2 import api as ml2_api  # noqa
from neutron_lib.services import base as service_base  # noqa
from neutron_lib.services.trunk import constants as trunk_consts  # noqa
from neutron_lib.utils import helpers as common_utils  # noqa
from neutron_lib.utils import runtime as runtime_utils  # noqa


is_attr_set = validators.is_attr_set
validators = validators.validators
HasProject = model_base.HasProject

get_plugin = directory.get_plugin
VXLAN_TUNNEL_TYPE = type_tunnel.ML2TunnelTypeDriver
Agent = agent_model.Agent
RouterPort = l3_models.RouterPort
Router = l3_models.Router

is_agent_down = agent_utils.is_agent_down

extraroute_const.EXTENDED_ATTRIBUTES_2_0 = (
        extraroute_const.RESOURCE_ATTRIBUTE_MAP)
dns_const.EXTENDED_ATTRIBUTES_2_0 = dns_const.RESOURCE_ATTRIBUTE_MAP

core_opts = base_config.core_opts


def get_context():
    return context.Context()


def get_db_ref(context):
    return context


def get_tunnel_session(context):
    return context.session


def get_novaclient_images(nclient):
    return nclient.glance


def get_reader_session():
    return lib_db_api.get_reader_session()


def get_writer_session():
    return lib_db_api.get_writer_session()


def auto_schedule_routers(self, hosts, r_ids):
    self.l3_plugin.auto_schedule_routers(self.adminContext, hosts)


# Return the database object rather than oslo versioned object
def get_agent_db_obj(agent):
    return agent.db_obj
