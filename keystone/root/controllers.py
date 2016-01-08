#Copyright 2012 OpenStack Foundation
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

from oslo_log import log

from keystone.common import controller
from keystone.common import dependency
from keystone import exception
from keystone.i18n import _, _LW
from keystone import notifications
from keystone import identity
from keystone import jio_policy
CONF = cfg.CONF
LOG = log.getLogger(__name__)


@dependency.requires('assignment_api', 'identity_api', 'resource_api','jio_policy_api')
class RootV3(controller.V3Controller):

    @controller.v2_deprecated
    def genericmapper(self, context):
        self.assert_admin(context)

        query_string = context.get('query_string', None)
        Action = query_string['Action']
        user_controller = identity.controllers.UserV3()
        group_controller = identity.controllers.GroupV3()
        credential_controller = cred.controllers.CredentialV3()

        if Action == 'CreateUser':
            user = {}
            if 'DefaultProjectId' in query_string:
                user['default_project_id'] = query_string['DefaultProjectId']
            if 'Description' in query_string:
                user['description'] = query_string['Description']
            if 'DomainId' in query_string:
                user['domain_id'] = query_string['DomainId']
            if 'Email' in query_string:
                user['email'] = query_string['Email']
            if 'Enabled' in query_string:
                user['enabled'] = (False, True) [query_string['Enabled'] == 'Yes']
            if 'Name' in query_string:
                user['name'] = query_string['Name']
            if 'Password' in query_string:
                user['password'] = query_string['Password']

            return user_controller.create_user(context,user)
        elif Action == 'GetUser':
            return user_controller.get_user(context,query_string['Id'])

        elif Action == 'UpdateUser':
            user = {}
            if 'Description' in query_string:
                user['description'] = query_string['Description']
            if 'Email' in query_string:
                user['email'] = query_string['Email']
            if 'Enabled' in query_string:
            	user['enabled'] = (False, True) [query_string['Enabled'] == 'Yes']
	        if 'Name' in query_string:
                user['name'] = query_string['Name']
            if 'Password' in query_string:
                user['password'] = query_string['Password']

            return user_controller.update_user(context,query_string['Id'],user)

        elif Action == 'DeleteUser':
            return user_controller.delete_user(context,query_string['Id'])

        elif Action == 'ListGroupsForUser':
            return group_controller.list_groups_for_user(context,query_string['Id'])

        elif Action == 'CreateGroup':
            group = {}
            if 'Description' in query_string:
                group['description'] = query_string['Description']
            if 'DomainId' in query_string:
                group['domain_id'] = query_string['DomainId']
            if 'Name' in query_string:
                group['name'] = query_string['Name']

            return group_controller.create_group(context,group)

        elif Action == 'GetGroup':
            return group_controller.get_group(context,query_string['Id'])

        elif Action == 'UpdateGroup':
            group = {}
            if 'Description' in query_string:
                group['description'] = query_string['Description']
            if 'Name' in query_string:
                group['name'] = query_string['Name']

            return group_controller.update_group(context,query_string['Id'],group)

        elif Action == 'DeleteGroup':
            return group_controller.delete_group(context,query_string['Id'])

        elif Action == 'ListUserInGroup':
            return user_controller.list_users_in_group(context,query_string['Id'])

        elif Action == 'AssignUserToGroup':
            return user_controller.add_user_to_group(context,query_string['UserId'],query_string['GroupId'])

        elif Action == 'RemoveUserFromGroup':
            return user_controller.remove_user_from_group(context,query_string['UserId'],query_string['GroupId'])

        elif Action == 'CheckUserInGroup':
            return user_controller.check_user_in_group(context,query_string['UserId'],query_string['GroupId'])

        elif Action == 'CreateCredential':
            credential = {}
            if 'Blob' in query_string:
                credential['blob'] = query_string['Blob']
            if 'ProjectId' in query_string:
                credential['project_id'] = query_string['ProjectId']
            if 'Type' in query_string:
                credential['type'] = query_string['Type']
            if 'UserId' in query_string:
                credential['user_id'] = query_string['UserId']
	    import pdb;pdb.set_trace()
            return credential_controller.create_credential(context,credential)

        elif Action == 'GetCredential':
            return credential_controller.get_credential(context,query_string['Id'])

        elif Action == 'UpdateCredential':
            credential = {}
            if 'Blob' in query_string:
                credential['blob'] = query_string['Blob']
            if 'ProjectId' in query_string:
                credential['project_id'] = query_string['ProjectId']
            if 'Type' in query_string:
                credential['type'] = query_string['Type']
            if 'UserId' in query_string:
                credential['user_id'] = query_string['UserId']

            return credential_controller.update_credential(context,query_string['Id'],credential)

        elif Action == 'DeleteCredential':
            return credential_controller.delete_credential(context,query_string['Id'])
	else:
            raise exception.ActionNotFound(action = Action)
