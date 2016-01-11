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

import logging
import uuid

import fixtures
from oslo_config import cfg
from testtools import matchers

from keystone.common import controller
from keystone import exception
from keystone.tests import unit as tests
from keystone.tests.unit import test_v3


CONF = cfg.CONF


class IdentityTestCase(test_v3.RestfulTestCase):
    """Test users and groups."""

    def setUp(self):
        super(IdentityTestCase, self).setUp()

        self.group = self.new_group_ref(
            domain_id=self.domain_id)
        self.group = self.identity_api.create_group(self.group)
        self.group_id = self.group['id']

        self.credential_id = uuid.uuid4().hex
        self.credential = self.new_credential_ref(
            user_id=self.user['id'],
            project_id=self.project_id)
        self.credential['id'] = self.credential_id
        self.credential_api.create_credential(
            self.credential_id,
            self.credential)

    # user crud tests

    def test_create_user(self):
        """Call ``POST /users``."""
        ref = self.new_user_ref(domain_id=self.domain_id)
	user = '/?Action=CreateUser' + '&Name=' + ref['name'] + '&Description=' + ref['description'] + '&Password='+ ref['password']+'&Email='+ ref['email'] + '&DomainId=' + ref['domain_id'] 
	r = self.get(
            user)
	return self.assertValidUserResponse(r, ref)

    def test_create_user_400(self):
        """Call ``POST /users``."""
        self.get('/?Action=CreateUser', expected_status=400)


    def test_list_users(self):
        """Call ``GET /users``."""
        resource_url = '/?Action=ListUsers'
        r = self.get(resource_url)
        self.assertValidUserListResponse(r, ref=self.user,
                                         resource_url=resource_url)

    def test_list_users_with_static_admin_token_and_multiple_backends(self):
        # domain-specific operations with the bootstrap ADMIN token is
        # disallowed when domain-specific drivers are enabled
        self.config_fixture.config(group='identity',
                                   domain_specific_drivers_enabled=True)
        self.get('/?Action=ListUsers', token=CONF.admin_token,
                 expected_status=exception.Unauthorized.code)

    def test_list_users_no_default_project(self):
        """Call ``GET /users`` making sure no default_project_id."""
        user = self.new_user_ref(self.domain_id)
        user = self.identity_api.create_user(user)
        resource_url = '/?Action=ListUsers'
        r = self.get(resource_url)
        self.assertValidUserListResponse(r, ref=user,
                                         resource_url=resource_url)

    def test_get_user(self):
        """Call ``GET /users/{user_id}``."""
        ref = '/?Action=GetUser' + '&Id=' + self.user['id']
        r = self.get(ref)
        self.assertValidUserResponse(r, self.user)

    def test_get_user_with_default_project(self):
        """Call ``GET /users/{user_id}`` making sure of default_project_id."""
        user = self.new_user_ref(domain_id=self.domain_id,
                                 project_id=self.project_id)
        user = self.identity_api.create_user(user)
        ref = '/?Action=GetUser' + '&Id=' + user['id']
        r = self.get(ref)
        self.assertValidUserResponse(r, user)

    def test_add_user_to_group(self):
        """Call ``PUT /groups/{group_id}/users/{user_id}``."""
        ref= '/?Action=AssignUserToGroup' + '&GroupId=' + self.group_id + '&UserId=' + self.user['id']
        self.get(ref,expected_status=204)

    def test_list_groups_for_user(self):
        """Call ``GET /users/{user_id}/groups``."""

        # Administrator is allowed to list others' groups
        ref= '/?Action=AssignUserToGroup' + '&GroupId=' + self.group_id + '&UserId=' + self.user['id']
        self.get(ref,expected_status=204)
	
        resource_url = '/?Action=ListGroupsForUser&Id=' + self.user['id']
        r = self.get(resource_url)
        self.assertValidGroupListResponse(r, ref=self.group,
                                          resource_url=resource_url)

    def test_check_user_in_group(self):
        """Call ``HEAD /groups/{group_id}/users/{user_id}``."""
        ref= '/?Action=AssignUserToGroup' + '&GroupId=' + self.group_id + '&UserId=' + self.user['id']
        self.get(ref,expected_status=204)

        ref= '/?Action=CheckUserInGroup' + '&GroupId=' + self.group_id + '&UserId=' + self.user['id']
        self.get(ref,expected_status=204)

    def test_list_users_in_group(self):
        """Call ``GET /groups/{group_id}/users``."""
        ref= '/?Action=AssignUserToGroup' + '&GroupId=' + self.group_id + '&UserId=' + self.user['id']
        self.get(ref,expected_status=204)

        resource_url= '/?Action=ListUserInGroup' + '&Id=' + self.group_id
        r = self.get(resource_url)

        self.assertValidUserListResponse(r, ref=self.user,
                                         resource_url=resource_url)

    def test_remove_user_from_group(self):
        """Call ``DELETE /groups/{group_id}/users/{user_id}``."""
        ref= '/?Action=AssignUserToGroup' + '&GroupId=' + self.group_id + '&UserId=' + self.user['id']
        self.get(ref,expected_status=204)

        ref= '/?Action=RemoveUserFromGroup' + '&GroupId=' + self.group_id + '&UserId=' + self.user['id']
        self.get(ref,expected_status=204)

    def test_update_user(self):
        """Call ``PATCH /users/{user_id}``."""
        ref = self.new_user_ref(domain_id=self.domain_id)
        del ref['id']
        user = '/?Action=UpdateUser' + '&Name=' + ref['name'] + '&Id=' + self.user['id'] + '&Description=' + ref['description'] +'&Email='+ ref['email'] + '&DomainId=' + ref['domain_id']
        r = self.get(user)
        print r
        self.assertValidUserResponse(r, ref)


    def test_delete_user(self):
        """Call ``DELETE /users/{user_id}``.

        As well as making sure the delete succeeds, we ensure
        that any credentials that reference this user are
        also deleted, while other credentials are unaffected.
        In addition, no tokens should remain valid for this user.

        """
        # First check the credential for this user is present
        r = self.credential_api.get_credential(self.credential['id'])
        self.assertDictEqual(r, self.credential)
        # Create a second credential with a different user
        self.user2 = self.new_user_ref(
            domain_id=self.domain['id'],
            project_id=self.project['id'])
        self.user2 = self.identity_api.create_user(self.user2)
        self.credential2 = self.new_credential_ref(
            user_id=self.user2['id'],
            project_id=self.project['id'])
        self.credential_api.create_credential(
            self.credential2['id'],
            self.credential2)
        # Create a token for this user which we can check later
        # gets deleted
        auth_data = self.build_authentication_request(
            user_id=self.user['id'],
            password=self.user['password'],
            project_id=self.project['id'])
        token = self.get_requested_token(auth_data)
        # Confirm token is valid for now
        self.head('/auth/tokens',
                  headers={'X-Subject-Token': token},
                  expected_status=200)

        # Now delete the user
        user = '/?Action=DeleteUser' + '&Id=' + self.user['id']
        self.get(user, expected_status=204)

        # Deleting the user should have deleted any credentials
        # that reference this project
        self.assertRaises(exception.CredentialNotFound,
                          self.credential_api.get_credential,
                          self.credential['id'])
        # And the no tokens we remain valid
        tokens = self.token_provider_api._persistence._list_tokens(
            self.user['id'])
        self.assertEqual(0, len(tokens))
        # But the credential for user2 is unaffected
        r = self.credential_api.get_credential(self.credential2['id'])
        self.assertDictEqual(r, self.credential2)

    # group crud tests

    def test_create_group(self):
        """Call ``POST /groups``."""
        ref = self.new_group_ref(domain_id=self.domain_id)
        group = '/?Action=CreateGroup' + '&Name=' + ref['name'] + '&Description=' + ref['description'] +'&DomainId=' + ref['domain_id'] 
        self.get(group, expected_status=200)
    
    def test_create_group_400(self):
        """Call ``POST /groups``."""
        self.get('/?Action=CreateGroup', expected_status=400)

        """Call ``DELETE /groups/{group_id}``."""
        self.delete('/groups/%(group_id)s' % {
            'group_id': self.group_id})

    def test_list_groups(self):
        """Call ``GET /groups``."""
        resource_url = '/?Action=ListGroups'
        r = self.get(resource_url)
        self.assertValidGroupListResponse(r, ref=self.group,
                                          resource_url=resource_url)

    def test_get_group(self):
        """Call ``GET /groups/{group_id}``."""
        ref = '/?Action=GetGroup' + '&Id=' + self.group_id
        r = self.get(ref)
        self.assertValidGroupResponse(r, self.group)

    def test_update_group(self):
        """Call ``PATCH /groups/{group_id}``."""
        ref = self.new_group_ref(domain_id=self.domain_id)
        del ref['id']
        group = '/?Action=UpdateGroup' + '&Name=' + ref['name'] + '&Id=' + self.group_id + '&Description=' + ref['description']
        r = self.get(group)
        print r
        self.assertValidGroupResponse(r, ref)

    def test_delete_group(self):
        """Call ``DELETE /groups/{group_id}``."""
        group = '/?Action=DeleteGroup' + '&Id=' + self.group_id
        self.get(group,expected_status=204)

    def test_create_user_password_not_logged(self):
        # When a user is created, the password isn't logged at any level.

        log_fix = self.useFixture(fixtures.FakeLogger(level=logging.DEBUG))

        ref = self.new_user_ref(domain_id=self.domain_id)
        self.post(
            '/users',
            body={'user': ref})

        self.assertNotIn(ref['password'], log_fix.output)

    def test_update_password_not_logged(self):
        # When admin modifies user password, the password isn't logged at any
        # level.

        log_fix = self.useFixture(fixtures.FakeLogger(level=logging.DEBUG))

        # bootstrap a user as admin
        user_ref = self.new_user_ref(domain_id=self.domain['id'])
        password = user_ref['password']
        user_ref = self.identity_api.create_user(user_ref)

        # administrative password reset
        new_password = uuid.uuid4().hex
        self.patch('/users/%s' % user_ref['id'],
                   body={'user': {'password': new_password}},
                   expected_status=200)

        self.assertNotIn(password, log_fix.output)
        self.assertNotIn(new_password, log_fix.output)


class IdentityV3toV2MethodsTestCase(tests.TestCase):
    """Test users V3 to V2 conversion methods."""

    def setUp(self):
        super(IdentityV3toV2MethodsTestCase, self).setUp()
        self.load_backends()
        self.user_id = uuid.uuid4().hex
        self.default_project_id = uuid.uuid4().hex
        self.tenant_id = uuid.uuid4().hex
        # User with only default_project_id in ref
        self.user1 = {'id': self.user_id,
                      'name': self.user_id,
                      'default_project_id': self.default_project_id,
                      'domain_id': CONF.identity.default_domain_id}
        # User without default_project_id or tenantId in ref
        self.user2 = {'id': self.user_id,
                      'name': self.user_id,
                      'domain_id': CONF.identity.default_domain_id}
        # User with both tenantId and default_project_id in ref
        self.user3 = {'id': self.user_id,
                      'name': self.user_id,
                      'default_project_id': self.default_project_id,
                      'tenantId': self.tenant_id,
                      'domain_id': CONF.identity.default_domain_id}
        # User with only tenantId in ref
        self.user4 = {'id': self.user_id,
                      'name': self.user_id,
                      'tenantId': self.tenant_id,
                      'domain_id': CONF.identity.default_domain_id}

        # Expected result if the user is meant to have a tenantId element
        self.expected_user = {'id': self.user_id,
                              'name': self.user_id,
                              'username': self.user_id,
                              'tenantId': self.default_project_id}

        # Expected result if the user is not meant to have a tenantId element
        self.expected_user_no_tenant_id = {'id': self.user_id,
                                           'name': self.user_id,
                                           'username': self.user_id}

    def test_v3_to_v2_user_method(self):

        updated_user1 = controller.V2Controller.v3_to_v2_user(self.user1)
        self.assertIs(self.user1, updated_user1)
        self.assertDictEqual(self.user1, self.expected_user)
        updated_user2 = controller.V2Controller.v3_to_v2_user(self.user2)
        self.assertIs(self.user2, updated_user2)
        self.assertDictEqual(self.user2, self.expected_user_no_tenant_id)
        updated_user3 = controller.V2Controller.v3_to_v2_user(self.user3)
        self.assertIs(self.user3, updated_user3)
        self.assertDictEqual(self.user3, self.expected_user)
        updated_user4 = controller.V2Controller.v3_to_v2_user(self.user4)
        self.assertIs(self.user4, updated_user4)
        self.assertDictEqual(self.user4, self.expected_user_no_tenant_id)

    def test_v3_to_v2_user_method_list(self):
        user_list = [self.user1, self.user2, self.user3, self.user4]
        updated_list = controller.V2Controller.v3_to_v2_user(user_list)

        self.assertEqual(len(updated_list), len(user_list))

        for i, ref in enumerate(updated_list):
            # Order should not change.
            self.assertIs(ref, user_list[i])

        self.assertDictEqual(self.user1, self.expected_user)
        self.assertDictEqual(self.user2, self.expected_user_no_tenant_id)
        self.assertDictEqual(self.user3, self.expected_user)
        self.assertDictEqual(self.user4, self.expected_user_no_tenant_id)


class UserSelfServiceChangingPasswordsTestCase(test_v3.RestfulTestCase):

    def setUp(self):
        super(UserSelfServiceChangingPasswordsTestCase, self).setUp()
        self.user_ref = self.new_user_ref(domain_id=self.domain['id'])
        password = self.user_ref['password']
        self.user_ref = self.identity_api.create_user(self.user_ref)
        # self.user_ref['password'] = password
        self.user_ref['old_password'] = password
        new_password = self.get_policy_password()
        context = {'environment': {'REMOTE_USER': self.user_ref,
                                   'AUTH_TYPE': 'Negotiate'}}
        self.identity_api.change_password(context, self.user_ref["id"], password, new_password)
        self.user_ref['password'] = new_password
        self.token = self.get_request_token(self.user_ref['password'], 201)

    def get_request_token(self, password, expected_status):
        auth_data = self.build_authentication_request(
            user_id=self.user_ref['id'],
            password=password)
        r = self.v3_authenticate_token(auth_data,
                                       expected_status=expected_status)
        return r.headers.get('X-Subject-Token')

    def change_password(self, expected_status, **kwargs):
        """Returns a test response for a change password request."""
        return self.post('/users/%s/password' % self.user_ref['id'],
                         body={'user': kwargs},
                         token=self.token,
                         expected_status=expected_status)

    def test_changing_password(self):
        # original password works
        token_id = self.get_request_token(self.user_ref['password'],
                                          expected_status=201)
        # original token works
        old_token_auth = self.build_authentication_request(token=token_id)
        self.v3_authenticate_token(old_token_auth, expected_status=201)

        # change password
        new_password = self.get_policy_password()
        self.change_password(password=new_password,
                             original_password=self.user_ref['password'],
                             expected_status=204)

        # old password fails
        self.get_request_token(self.user_ref['password'], expected_status=401)

        # old token fails
        self.v3_authenticate_token(old_token_auth, expected_status=404)

        # new password works
        self.get_request_token(new_password, expected_status=201)

    def test_changing_password_with_missing_original_password_fails(self):
        r = self.change_password(password=self.get_policy_password(),
                                 expected_status=400)
        self.assertThat(r.result['error']['message'],
                        matchers.Contains('original_password'))

    def test_changing_password_with_missing_password_fails(self):
        r = self.change_password(original_password=self.user_ref['password'],
                                 expected_status=400)
        self.assertThat(r.result['error']['message'],
                        matchers.Contains('password'))

    def test_changing_password_with_incorrect_password_fails(self):
        self.change_password(password=self.get_policy_password(),
                             original_password=self.get_policy_password(),
                             expected_status=401)

    def test_changing_password_with_disabled_user_fails(self):
        # disable the user account
        self.user_ref['enabled'] = False
        self.patch('/users/%s' % self.user_ref['id'],
                   body={'user': self.user_ref})

        self.change_password(password=self.get_policy_password(),
                             original_password=self.user_ref['password'],
                             expected_status=401)

    def test_changing_password_not_logged(self):
        # When a user changes their password, the password isn't logged at any
        # level.

        log_fix = self.useFixture(fixtures.FakeLogger(level=logging.DEBUG))

        # change password
        new_password = self.get_policy_password()
        self.change_password(password=new_password,
                             original_password=self.user_ref['password'],
                             expected_status=204)

        self.assertNotIn(self.user_ref['password'], log_fix.output)
        self.assertNotIn(new_password, log_fix.output)

    def test_changing_password_not_complying_policy_fails(self):
        password = "1234"
        r = self.change_password(password=password,
                                 original_password=self.user_ref['password'],
                                 expected_status=400)

        self.assertThat(r.result['error']['message'],
                        matchers.Contains('password'))

    def test_changing_password_with_same_password_fails(self):
        r = self.change_password(password=self.user_ref['password'],
                                 original_password=self.user_ref['password'],
                                 expected_status=400)

        self.assertThat(r.result['error']['message'],
                        matchers.Contains('password'))

    def test_changing_password_with_last_used_password_fails(self):
        #user previous password as the new password to change
        r = self.change_password(password=self.user_ref['old_password'],
                                original_password=self.user_ref['password'],
                                expected_status=400)

        self.assertThat(r.result['error']['message'],
                        matchers.Contains('Cannot use old passwords'))
