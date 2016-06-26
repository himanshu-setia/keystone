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

import uuid

from keystone.common import controller
from keystone.common import dependency
from keystone.common import validation
from keystone import notifications
#from keystone.mfa import schema
from keystone import exception

@dependency.requires('mfa_api','identity_api')
class MfaV3(controller.V3Controller):

    def create_virtual_mfa_device(self, context, device):
        # name and account_id exist in device dictionary
        device['id'] = uuid.uuid4().hex
        #device['jrn'] = "jrn:jcs:iam:" + account_id + ":mfa:" + device['name']
        mfa_device = self.mfa_api.create_virtual_mfa_device(device)
        #TODO(himanshu): add 'jrn'info in mfa_device
        return MfaV3.wrap_member(context, mfa_device)
    
    def enable_mfa_device(self, context, user, mfa_device, code1, code2, is_resync=False):
        self.mfa_api.enable_mfa_device(user, mfa_device, code1, code2, is_resync)
    
    def deactivate_mfa_device(self, context, user, mfa_device):
        self.mfa_api.deactivate_mfa_device(user, mfa_device)
    
    def delete_virtual_mfa_device(self, context, mfa_device):
        self.mfa_api.delete_virtual_mfa_device(mfa_device)
    
    def list_virtual_mfa_devices(self, context, assign_status, account_id):
        ref = self.mfa_api.list_virtual_mfa_devices(assign_status, account_id)
        return MfaV3.wrap_collection(context, ref)
    
    def get_session_token(self, context, mfa_name, duration_in_sec, code):
        #TODO(himanshu)
        return
