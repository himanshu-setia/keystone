# Copyright 2012 OpenStack LLC
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
import itertools
import copy
import datetime
from keystone.common import dependency
from keystone.common import sql
from keystone import exception
from keystone import mfa
from oslo_serialization import jsonutils
from sqlalchemy.orm import load_only
from sqlalchemy import or_
from sqlalchemy import and_
from sqlalchemy.orm import relationship
from keystone.identity.backends.sql import User
import pyotp
import uuid
import base64
import time

from oslo_config import cfg
from oslo_log import log

CONF = cfg.CONF
LOG = log.getLogger(__name__)

interval=30
def timecode(for_time):
    i = time.mktime(for_time.timetuple())
    return int(i / interval)
            

class MfaDeviceModel(sql.ModelBase, sql.DictBase):
    __tablename__ = 'mfa_device'
    attributes = ['id', 'name', 'seed', 'account_id', 'created_at']
    id = sql.Column(sql.String(64), primary_key=True)
    name = sql.Column(sql.String(length=255), nullable=False, index=True)
    seed = sql.Column(sql.String(length=64), nullable=False)
    account_id = sql.Column(sql.String(length=64), nullable=False)
    created_at = sql.Column(sql.DateTime, nullable=False, default=datetime.datetime.utcnow(), index=True)

class MfaDeviceUserMappingModel(sql.ModelBase, sql.DictBase):
    __tablename__ = 'mfa_device_user_mapping'
    attributes = ['mfa_device_id', 'user_id', 'enabled']
    mfa_device_id = sql.Column('mfa_device_id', sql.String(length=64), primary_key=True)
    user_id = sql.Column('user_id', sql.String(length=64), primary_key=True)
    enabled = sql.Column('enabled', sql.Boolean, default=False, nullable=False)

     

    
@dependency.requires('identity_api')
class Mfa(mfa.Driver):

    @sql.handle_conflicts(conflict_message='Mfa device already exists')
    def create_virtual_mfa_device(self, device):
        device['seed'] = uuid.uuid4().hex
        session = sql.get_session()
        with session.begin():
            session.add(MfaDeviceModel(id=device['id'],
                                       name=device['name'],
                                       seed=device['seed'],
                                       account_id=device['account_id']))
        #TODO(himanshu) return QR Code
        return device

    @sql.handle_conflicts(conflict_message='Mfa device is already enabled')
    def enable_mfa_device(self, user, mfa_device, code1, code2, is_resync=False):
        session = sql.get_session()

        if is_resync:
            user_ref = session.query(User).filter_by(id=user['id']).first()
            if not user_ref.mfa_enabled:
                raise exception.Forbidden('User is not MFA enabled') 

        ref = session.query(MfaDeviceModel).filter_by(name=mfa_device['name']).\
                              filter_by(account_id=mfa_device['account_id']).first()
        import pdb; pdb.set_trace()
        en_seed = base64.b32encode(ref.seed)
        totp = pyotp.TOTP(en_seed)
        server_code1 = totp.generate_otp(timecode(datetime.datetime.now() - 
                                                  datetime.timedelta(0,interval)))
        server_code2 = totp.generate_otp(timecode(datetime.datetime.now()))
        if code1!=server_code1 or code2!=server_code2:
            #TODO(himanshu) print debug log
            LOG.debug('User provided codes - code1: %s, code2: %s ', code1, code2)
            LOG.debug('System generated codes - code1: %s, code2: %s', 
                            server_code1, server_code2)
            raise exception.Forbidden('Invalid authentication code !')
       
        mfa_device['id'] = session.query(MfaDeviceModel).\
                             filter_by(name=mfa_device['name']).\
                             filter_by(account_id=mfa_device['account_id']).first().id
 
        #TODO(himanshu) print mfa authentication successful
        LOG.debug('MFA authentication successful')
        with session.begin():
            session.add(MfaDeviceUserMappingModel(user_id=user['id'],
	                mfa_device_id=mfa_device['id'],
			enabled=True))
            if not is_resync:
                session.query(User).filter_by(id=user['id']).update({'mfa_enabled': True})

    @sql.handle_conflicts(conflict_message='Mfa device is already disabled')
    def deactivate_mfa_device(self, user, mfa_device):
        session = sql.get_session()
        
        with session.begin():
            device_id = session.query(MfaDeviceModel).filter_by(name=mfa_device['name']).\
                            filter_by(account_id=mfa_device['account_id']).first().id
	    q = session.query(MfaDeviceUserMappingModel).filter_by(user_id=user['id']).\
	                         filter_by(mfa_device_id=device_id).first()
	    if q:
                session.delete(q)
	        session.query(User).filter_by(id=user['id']).update({'mfa_enabled': False})
            else:
                raise exception.ValidationError('mfa device is not enabled')

    def delete_virtual_mfa_device(self, mfa_device):
        session = sql.get_session()

	with session.begin():
            device_ref = session.query(MfaDeviceModel).filter_by(name=mfa_device['name']).\
                            filter_by(account_id=mfa_device['account_id']).first()
	    q = session.query(MfaDeviceUserMappingModel).\
	                 filter_by(mfa_device_id=device_ref.id).first()
	    if q:
	        session.query(User).filter_by(id=q.user_id).update({'mfa_enabled': False})
	        session.delete(q)
	    session.delete(device_ref)


    def list_virtual_mfa_devices(self, assign_status, account_id):
        session = sql.get_session()

        if assign_status == 'any':
            refs = session.query(MfaDeviceModel).filter_by(account_id=account_id).all()
        elif assign_status == 'enabled':
            refs = session.query(MfaDeviceModel).join(MfaDeviceUserMappingModel).\
                       filter(MfaDeviceUserMappingModel.enabled == True).\
                       filter(MfaDeviceModel.account_id == account_id).all()
        elif assign_status == 'disabled':
            refs = session.query(MfaDeviceModel).join(MfaDeviceUserMappingModel).\
                       filter(MfaDeviceUserMappingModel.enabled == False).\
                       filter(MfaDeviceModel.account_id == account_id).all()
        else:
            raise exception.ValidationError('Invalid AssignmentStatus')

        ret = []
        attrs_to_return = ['id', 'name', 'created_at']
        for ref in refs:
            new_ref = {}
            for index, value in enumerate(ref):
                if value[0] in attrs_to_return:
                    new_ref[value[0]] = value[1]
                #new_ref[attrs_to_return[index]] = value
            ret.append(new_ref)

        return ret

    #def get_session_token():
