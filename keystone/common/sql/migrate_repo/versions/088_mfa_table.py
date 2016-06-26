from oslo_log import log
import sqlalchemy as sql
from keystone.common import sql as key_sql
import datetime

LOG = log.getLogger(__name__)


def upgrade(migrate_engine):
    meta = sql.MetaData()
    meta.bind = migrate_engine

    user = sql.Table('user', meta, autoload=True)
    account = sql.Table('account', meta, autoload=True)
	
    mfa_device = sql.Table(
              'mfa_device', meta,
              sql.Column('id', sql.String(length=64), primary_key=True),
              sql.Column('name', sql.String(length=255), nullable=False, index=True),
              sql.Column('seed', sql.String(length=64), nullable=False),
              sql.Column('account_id', sql.String(length=64), nullable=False, index=True),
              sql.Column('created_at', sql.DateTime, nullable=False, default=datetime.datetime.utcnow(), index=True),
              sql.UniqueConstraint('name', 'account_id', name='ixu_mfa_name_account_id'),
              sql.ForeignKeyConstraint(
                  ['account_id'], ['account.id'],
                  name='fk_mfa_account_account_id'
              ),
              mysql_engine='InnoDB',
              mysql_charset='utf8')
			 
    mfa_device_user_mapping = sql.Table(
              'mfa_device_user_mapping', meta,
              sql.Column('mfa_device_id', sql.String(length=64), primary_key=True),
              sql.Column('user_id', sql.String(length=64), primary_key=True),
              sql.Column('enabled', sql.Boolean, default=False, nullable=False),
              sql.ForeignKeyConstraint(
                  ['mfa_device_id'], ['mfa_device.id'],
                  name='fk_mfa_device_device_id'
              ),
              sql.ForeignKeyConstraint(
                  ['user_id'], ['user.id'],
                  name='fk_mfa_device_user_user_id'
              ),
              mysql_engine='InnoDB',
              mysql_charset='utf8')
			  
    # create mfa related tables
    tables = [mfa_device, mfa_device_user_mapping]
	
    for table in tables:
        try:
            table.create()
        except Exception:
            LOG.exception('Exception while creating table: %r', table)
            raise		 
