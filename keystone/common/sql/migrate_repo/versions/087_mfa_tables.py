import migrate
import sqlalchemy as sql
from oslo_log import log
import datetime
from oslo_config import cfg

CONF = cfg.CONF
LOG = log.getLogger(__name__)

def upgrade(migrate_engine):
    meta = sql.MetaData()
    meta.bind = migrate_engine

    user_table = sql.Table('user', meta, autoload=True)
    account = sql.Table('account', meta, autoload=True)

    user_mfa_enabled_column = sql.Column('mfa_enabled', sql.Boolean, default=False, nullable=True)
    user_mfa_enabled_column.create(user_table)

    mfa_device = sql.Table(
              'mfa_device', meta,
              sql.Column('id', sql.String(length=64), primary_key=True),
              sql.Column('name', sql.String(length=255), nullable=False, index=True),
              sql.Column('seed', sql.String(length=64), nullable=False),
              sql.Column('account_id', sql.String(length=64), nullable=False, index=True),
              sql.Column('created_at', sql.DateTime, nullable=False, default=datetime.datetime.utcnow(), index=True),
              sql.Column('user_id', sql.String(length=64), unique=True, nullable=True, index=True),
              sql.Column('enabled', sql.Boolean, default=False, nullable=False),
              sql.UniqueConstraint('name', 'account_id', name='ixu_mfa_name_account_id'),
              sql.ForeignKeyConstraint(
                  ['account_id'], ['account.id'],
                  name='fk_mfa_device_account_id'
              ),
              mysql_engine='InnoDB',
              mysql_charset='utf8')
			 
    mfa_auth_attempts = sql.Table(
              'mfa_auth_attempts', meta,
              sql.Column('user_id', sql.String(length=64), primary_key=True, index=True),
              sql.Column('wrong_attempt_cnt', sql.Integer, default=0, nullable=False),
              sql.Column('last_wrong_attempt', sql.DateTime, nullable=False, default=datetime.datetime.utcnow()),
              sql.ForeignKeyConstraint(
                  ['user_id'], ['user.id'],
                  name='fk_mfa_auth_attempts_user_id'
              ),
              mysql_engine='InnoDB',
              mysql_charset='utf8')

    iam_keys = sql.Table(
            'iam_keys', meta,
            sql.Column('access_key', sql.String(64), primary_key=True),
            sql.Column('secret_key', sql.String(64), nullable=False),
            sql.Column('expiry', sql.DateTime, nullable=False, default=datetime.datetime.utcnow()\
                + datetime.timedelta(days=CONF.IntermediateToken.key_active_duration), index=True),
            mysql_engine='InnoDB',
            mysql_charset='utf8')

    # create mfa related tables
    tables = [iam_keys, mfa_device, mfa_auth_attempts]
	
    for table in tables:
        try:
            table.create()
        except Exception:
            LOG.exception('Exception while creating table: %r', table)
            raise		 

