# Copyright 2013 Metacloud, Inc.
# Copyright 2012 OpenStack Foundation
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

"""WSGI Routers for the Resource service."""

from keystone.common import json_home
from keystone.common import router
from keystone.common import wsgi
from keystone.resource import controllers


class Admin(wsgi.ComposableRouter):
    def add_routes(self, mapper):
        # Tenant Operations
        tenant_controller = controllers.Tenant()
        mapper.connect('/tenants',
                       controller=tenant_controller,
                       action='get_all_projects',
                       conditions=dict(method=['GET']))
        mapper.connect('/tenants/{tenant_id}',
                       controller=tenant_controller,
                       action='get_project',
                       conditions=dict(method=['GET']))


class Routers(wsgi.RoutersBase):

    def append_v3_routers(self, mapper, routers):
        routers.append(
            router.Router(controllers.AccountV3(),
                          'accounts', 'account',
                          resource_descriptions=self.v3_resources))

        config_controller = controllers.AccountConfigV3()

        self._add_resource(
            mapper, config_controller,
            path='/accounts/{account_id}/config',
            get_head_action='get_account_config',
            put_action='create_account_config',
            patch_action='update_account_config_only',
            delete_action='delete_account_config',
            rel=json_home.build_v3_resource_relation('account_config'),
            status=json_home.Status.EXPERIMENTAL,
            path_vars={
                'account_id': json_home.Parameters.ACCOUNT_ID
            })

        config_group_param = (
            json_home.build_v3_parameter_relation('config_group'))
        self._add_resource(
            mapper, config_controller,
            path='/accounts/{account_id}/config/{group}',
            get_head_action='get_account_config',
            patch_action='update_account_config_group',
            delete_action='delete_account_config',
            rel=json_home.build_v3_resource_relation('account_config_group'),
            status=json_home.Status.EXPERIMENTAL,
            path_vars={
                'account_id': json_home.Parameters.ACCOUNT_ID,
                'group': config_group_param
            })

        self._add_resource(
            mapper, config_controller,
            path='/accounts/{account_id}/config/{group}/{option}',
            get_head_action='get_account_config',
            patch_action='update_account_config',
            delete_action='delete_account_config',
            rel=json_home.build_v3_resource_relation('account_config_option'),
            status=json_home.Status.EXPERIMENTAL,
            path_vars={
                'account_id': json_home.Parameters.ACCOUNT_ID,
                'group': config_group_param,
                'option': json_home.build_v3_parameter_relation(
                    'config_option')
            })

        routers.append(
            router.Router(controllers.ProjectV3(),
                          'projects', 'project',
                          resource_descriptions=self.v3_resources))
