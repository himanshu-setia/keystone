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

"""Entry point into the Jio policy service."""

import abc

from oslo_config import cfg
import six

from keystone.common import dependency
from keystone.common import manager
from keystone import exception
from keystone import notifications


CONF = cfg.CONF


@dependency.requires('identity_api', 'resource_api')
@dependency.provider('jio_policy_api')
class Manager(manager.Manager):
    """Default pivot point for the Policy backend.

    See :mod:`keystone.common.manager.Manager` for more details on how this
    dynamically calls the backend.

    """

    _JIO_POLICY = 'jio_policy'

    def __init__(self):
        super(Manager, self).__init__(CONF.jio_policy.driver)

    def list_actions(self, hints=None):
        return self.driver.list_actions(hints)

    def create_policy(self, project_id, policy_id, policy):
        ref = self.driver.create_policy(project_id, policy_id, policy)
        return ref

    def list_policies(self, project_id):
        # TODO(ajayaa) Check whether the user has permission to list policies
        # in the project.
        project_ref = self.resource_api.get_project(project_id)
        return self.driver.list_policies(project_id)

    def get_policy(self, policy_id):
        # TODO(ajayaa) Check whether the user has permission to get a policy.
        return self.driver.get_policy(policy_id)

    def delete_policy(self, policy_id):
        ref = self.driver.delete_policy(policy_id)

    def update_policy(self, policy_id, policy):
        return self.driver.update_policy(policy_id, policy)

    def attach_policy_to_user(self, policy_id, user_id):
        self.identity_api.get_user(user_id)
        self.driver.attach_policy_to_user(policy_id, user_id)

    def detach_policy_from_user(self, policy_id, user_id):
        self.identity_api.get_user(user_id)
        self.driver.detach_policy_from_user(policy_id, user_id)

    def attach_policy_to_group(self, policy_id, group_id):
        self.identity_api.get_group(group_id)
        self.driver.attach_policy_to_group(policy_id, group_id)

    def detach_policy_from_group(self, policy_id, group_id):
        self.identity_api.get_group(group_id)
        self.driver.detach_policy_from_group(policy_id, group_id)

    def is_user_authorized(self, user_id, project_id, action, resource, is_implicit_allow):
        group_ids = self._get_group_ids_for_user_id(user_id)
        ref = self.driver.is_user_authorized(user_id,
                                             group_ids,
                                             project_id,
                                             action,
                                             resource,
                                             is_implicit_allow)
        return ref

    def list_policy_summary(self,policy_id):
	return self.driver.list_policy_summary(policy_id)

    def get_group_policies(self, groupid):
	return self.driver.get_group_policies(groupid)

    def get_user_policies(self, userid):
        return self.driver.get_user_policies(userid)

    def _get_group_ids_for_user_id(self, user_id):
        return [x['id'] for
                x in self.identity_api.list_groups_for_user(user_id)]

    def is_action_resource_type_allowed(self, action_name, resource_type):
        return self.driver.is_action_resource_type_allowed(self, action_name, resource_type)

    def create_action(self, action_id, action_name, service_type):
        return self.driver.create_action(action_id, action_name, service_type)

@six.add_metaclass(abc.ABCMeta)
class Driver(object):

    def list_actions(self):
        """" LISTS all the actions

        :raises: keystone.exception.ActionNotFound

        """
        raise exception.NotImplemented()

    @abc.abstractmethod
    def create_policy(self, project_id, policy_id, policy):
        """Store a policy blob.

        :raises: keystone.exception.Conflict

        """
        raise exception.NotImplemented()  # pragma: no cover

    @abc.abstractmethod
    def delete_policy(self, policy_id):
        """Deletes a policy and all associated actions and resources.

        :raises: keystone.exception.PolicyNotFound

        """
        raise exception.NotImplemented()

    @abc.abstractmethod
    def get_policy(self, policy_id):
        """Gets a policy blob.

        "raises: keystone.exception.PolicyNotFound

        """
        raise exception.NotImplemented()

    @abc.abstractmethod
    def update_policy(self, policy_id):
        """Updates a policy atomically.

        "raises: keystone.exception.PolicyNotFound

        """
        raise exception.NotImplemented()

    @abc.abstractmethod
    def attach_policy_to_user(self, policy_id, user_id):
        """Attaches a policy to a user.

        :raises: keystone.exception.PolicyNotFound
                 keystone.exception.UserNotFound
        """
        raise exception.NotImplemented()

    @abc.abstractmethod
    def detach_policy_from_user(self, policy_id, user_id):
        """Detach policy from a user.

        :raises: keystone.exception.PolicyNotFound
                 keystone.exception.UserNotFound
        """
        raise exception.NotImplemented()

    @abc.abstractmethod
    def attach_policy_to_group(self, policy_id, group_id):
        """Attaches a policy to a group.

        :raises: keystone.exception.PolicyNotFound
                 keystone.exception.GroupNotFound
        """
        raise exception.NotImplemented()

    @abc.abstractmethod
    def detach_policy_from_group(self, policy_id, group_id):
        """Detaches policy from a group.

        :raises: keystone.exception.PolicyNotFound
                 keystone.exception.UserNotFound
        """
        raise exception.NotImplemented()

    @abc.abstractmethod
    def is_user_authorized(self, user_id, group_id, project_id, action,
                           resource):
        """Checks if userid is allowed to do action on resource
        :raises: keystone.exception.ActionNotFound
                 keystone.exception.ResourceNotFound
        """
        raise exception.NotImplemented()

    @abc.abstractmethod
    def is_action_resource_type_allowed(self, action_name, resource_type):
        raise exception.NotImplemented()

