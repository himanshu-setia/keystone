# Copyright 2016 Reliance Jio and its licensors. All Rights 
# Reserved  Reliance Jio Propreitary
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.
#
#        EDIT HISTORY FOR MODULE
#
# $Header:	 /keystone/mfa/backends/sql.py
# $Datetime:	2016/07/10
#
#  when		who	what, where, why
#------------------------------------------------------------------------
# 2016/07/10	hs	1st version of file
#
#



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
import qrcode

from oslo_config import cfg
from oslo_log import log

CONF = cfg.CONF
LOG = log.getLogger(__name__)

interval=30
MAX_ALLOWED_ATTEMPTS=3

def timecode(for_time):
    i = time.mktime(for_time.timetuple())
    return int(i / interval)


class MfaDeviceModel(sql.ModelBase, sql.DictBase):
    __tablename__ = 'mfa_device'
    attributes = ['id', 'name', 'seed', 'account_id', 'created_at', 'user_id', 'enabled']
    id = sql.Column(sql.String(64), primary_key=True)
    name = sql.Column(sql.String(length=255), nullable=False, index=True)
    seed = sql.Column(sql.String(length=64), nullable=False)
    account_id = sql.Column(sql.String(length=64), nullable=False)
    created_at = sql.Column(sql.DateTime, nullable=False, default=datetime.datetime.utcnow(), index=True)
    user_id = sql.Column('user_id', sql.String(length=64), nullable=True, unique=True, index=True)
    enabled = sql.Column('enabled', sql.Boolean, default=False, nullable=False)

class MfaAuthAttemptsModel(sql.ModelBase, sql.DictBase):
    __tablename__ = 'mfa_auth_attempts'
    attributes = ['user_id', 'wrong_attempt_cnt', 'last_wrong_attempt']
    user_id = sql.Column('user_id', sql.String(length=64), primary_key=True)
    wrong_attempt_cnt = sql.Column('wrong_attempt_cnt', sql.Integer, default=0, nullable=False)
    last_wrong_attempt = sql.Column(sql.DateTime, nullable=False, default=datetime.datetime.utcnow()) 



@dependency.requires('identity_api')
class Mfa(mfa.Driver):

    @sql.handle_conflicts(conflict_message='Mfa device already exists')
    def create_virtual_mfa_device(self, device):
#        device['seed'] = uuid.uuid4().hex
        device['seed'] = pyotp.random_base32()
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
        if ref.user_id and ref.enabled:
            raise exception.Forbidden('This MFA device is already enabled')

        #en_seed = base64.b32encode(ref.seed)
        en_seed = ref.seed
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

        mfa_device['id'] = ref.id

        #TODO(himanshu) print mfa authentication successful
        LOG.debug('MFA authentication successful')
        with session.begin():
            if not is_resync:
                session.query(User).filter_by(id=user['id']).update({'mfa_enabled': True})
                session.query(MfaDeviceModel).filter_by(id=mfa_device['id']).\
                    update({'user_id': user['id'], 'enabled': True})
                session.add(MfaAuthAttemptsModel(user_id=user['id'],
                                                 wrong_attempt_cnt=0,
                                                 last_wrong_attempt=datetime.datetime.now()))
            else:
                session.query(MfaDeviceModel).filter_by(id=mfa_device['id']).\
                    update({'enabled': True})
                session.query(MfaAuthAttemptsModel).filter_by(user_id=user['id']).\
                    update({'wrong_attempt_cnt': 0, 'last_wrong_attempt': datetime.datetime.now()})                

    @sql.handle_conflicts(conflict_message='Mfa device is already disabled')
    def deactivate_mfa_device(self, user, mfa_device):
        session = sql.get_session()
        
        with session.begin():
            ref = session.query(MfaDeviceModel).filter_by(name=mfa_device['name']).\
                            filter_by(account_id=mfa_device['account_id']).first()
            if ref.enabled:
               session.query(MfaDeviceModel).filter_by(id=ref.id).\
                                               update({'user_id': None, 'enabled': False})
               session.query(User).filter_by(id=user['id']).update({'mfa_enabled': False})
            else:
                raise exception.ValidationError('mfa device is not enabled')

    def delete_virtual_mfa_device(self, mfa_device):
        session = sql.get_session()

        with session.begin():
            device_ref = session.query(MfaDeviceModel).filter_by(name=mfa_device['name']).\
                            filter_by(account_id=mfa_device['account_id']).first()
            if device_ref.user_id:
                session.query(User).filter_by(id=device_ref.user_id).update({'mfa_enabled': False})
            session.delete(device_ref)


    def list_virtual_mfa_devices(self, assign_status, account_id):
        session = sql.get_session()

        if assign_status == 'any':
            refs = session.query(MfaDeviceModel).filter_by(account_id=account_id).all()
        elif assign_status == 'enabled':
            refs = session.query(MfaDeviceModel).filter(MfaDeviceModel.enabled == True).\
                       filter(MfaDeviceModel.account_id == account_id).all()
        elif assign_status == 'disabled':
            refs = session.query(MfaDeviceModel).filter(MfaDeviceModel.enabled == False).\
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

    def validate_otp(self, user_id, otp):
        session = sql.get_session() 
        ref = session.query(MfaDeviceModel).filter_by(user_id=user_id).first()
        if not ref.enabled:
            raise exception.MFAResyncExpected('mfa device needs resync') 
        en_seed = ref.seed
        totp = pyotp.TOTP(en_seed)
        server_code = totp.generate_otp(timecode(datetime.datetime.now()))      
        if otp!=server_code:
            refs = session.query(MfaAuthAttemptsModel).filter_by(user_id=user_id).first()
            if refs.wrong_attempt_cnt < MAX_ALLOWED_ATTEMPTS - 1:
                with session.begin():
                    session.query(MfaAuthAttemptsModel).filter_by(user_id=user_id).\
                       update({'wrong_attempt_cnt': refs.wrong_attempt_cnt + 1,\
                                'last_wrong_attempt': datetime.datetime.now()})
                raise exception.IncorrectOTPError()
            else:
                with session.begin():
                    session.query(MfaDeviceModel).filter_by(user_id=user_id).\
                        update({'enabled': False})
                    session.query(MfaAuthAttemptsModel).filter_by(user_id=user_id).\
                        update({'wrong_attempt_cnt': 0,\
                                'last_wrong_attempt': datetime.datetime.now()})
                raise exception.MFAResyncExpected()
        else:
            session.query(MfaAuthAttemptsModel).filter_by(user_id=user_id).\
                update({'wrong_attempt_cnt': 0})

    def validate_two_otp(self, user_id, otp1, otp2):
        session = sql.get_session()
        ref = session.query(MfaDeviceModel).filter_by(user_id=user_id).first()
        if ref.enabled:
            raise exception.ValidationError('mfa device already enabled') 
        en_seed = ref.seed
        totp = pyotp.TOTP(en_seed)
        server_code1 = totp.generate_otp(timecode(datetime.datetime.now() - 
                                                  datetime.timedelta(0,interval)))
        server_code2 = totp.generate_otp(timecode(datetime.datetime.now()))
        if otp1!=server_code1 or otp2!=server_code2:
            LOG.debug('User provided codes - code1: %s, code2: %s ', otp1, otp2)
            LOG.debug('System generated codes - code1: %s, code2: %s',
                            server_code1, server_code2)
            with session.begin():
                session.query(MfaAuthAttemptsModel).filter_by(user_id=user_id).\
                    update({'last_wrong_attempt': datetime.datetime.now()})
            
            raise exception.MFAResyncExpected()
        else:
            with session.begin():
                session.query(MfaAuthAttemptsModel).filter_by(user_id=user_id).\
                    update({'wrong_attempt_cnt': 0})
                session.query(MfaDeviceModel).filter_by(user_id=user_id).\
                    update({'enabled': True})

    def get_resync_info(self, user_id):
        session = sql.get_session()
        ref = session.query(MfaDeviceModel).filter_by(user_id=user_id).first()
        if not ref.enabled:
            return True
        return False

    #def get_session_token():
