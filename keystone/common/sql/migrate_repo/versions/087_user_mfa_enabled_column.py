import migrate
import sqlalchemy as sql
from oslo_log import log

def upgrade(migrate_engine):
    meta = sql.MetaData()
    meta.bind = migrate_engine
    user_table = sql.Table('user', meta, autoload=True)
    user_mfa_enabled_column = sql.Column('mfa_enabled', sql.Boolean, default=False, nullable=True)
    user_mfa_enabled_column.create(user_table)
