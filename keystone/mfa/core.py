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


@dependency.provider('mfa_api')
class Manager(manager.Manager):
    """Default pivot point for the Policy backend.

    See :mod:`keystone.common.manager.Manager` for more details on how this
    dynamically calls the backend.

    """
    _MFA = 'mfa'

    def __init__(self):
        super(Manager, self).__init__(CONF.mfa.driver)

    def create_virtual_mfa_device(self, device):
        ref = self.driver.create_virtual_mfa_device(device)
        return ref

    def enable_mfa_device(self, user, mfa_device, code1, code2, is_resync):
        return self.driver.enable_mfa_device(user, mfa_device, code1, code2, is_resync)

    def deactivate_mfa_device(self, user, mfa_device):
        return self.driver.deactivate_mfa_device(user, mfa_device)

    def delete_virtual_mfa_device(self, device):
        return self.driver.delete_virtual_mfa_device(device)

    def list_virtual_mfa_devices(self, assign_status, account_id):
        return self.driver.list_virtual_mfa_devices(assign_status, account_id)

    def validate_otp(self, user_id, otp):
        if '_' in otp:
            otp1 = otp.split('_')[0]
            otp2 = otp.split('_')[1]
            return self.driver.validate_two_otp(user_id, otp1, otp2)
        return self.driver.validate_otp(user_id, otp)

    def get_resync_info(self, user_id):
        return self.driver.get_resync_info(user_id)

    def get_session_token(context, mfa_name, duration_in_sec, code):
        #TODO(himanshu)
        return

@six.add_metaclass(abc.ABCMeta)
class Driver(object):
    def create_virtual_mfa_device(self, device):
        raise exception.NotImplemented()

    def enable_mfa_device(self, user, mfa_device, code1, code2, is_resync):
        raise exception.NotImplemented()

    def deactivate_mfa_device(self, user, mfa_device):
        raise exception.NotImplemented()

    def delete_virtual_mfa_device(self, mfa_device):
        raise exception.NotImplemented()

    def list_virtual_mfa_devices(self, assign_status, account_id):
        raise exception.NotImplemented()

    def validate_otp(self, user_id, otp):
        raise exception.NotImplemented()

    def get_resync_info(self, user_id):
        raise exception.NotImplemented()
