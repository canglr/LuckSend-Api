"""empty message

Revision ID: b044e7136f16
Revises: 
Create Date: 2019-07-18 23:50:12.783402

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'b044e7136f16'
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.create_table('admin_users',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('name', sa.String(), nullable=False),
    sa.Column('user_name', sa.String(), nullable=False),
    sa.Column('mail_address', sa.String(), nullable=False),
    sa.Column('password_hash', sa.String(), nullable=False),
    sa.Column('master', sa.Boolean(), nullable=False),
    sa.Column('is_active', sa.Boolean(), nullable=False),
    sa.Column('creation_date', sa.DateTime(), nullable=False),
    sa.Column('last_update', sa.DateTime(), nullable=False),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('mail_address'),
    sa.UniqueConstraint('user_name')
    )
    op.create_table('countries',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('country_code', sa.String(), nullable=False),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_table('countrymultilang',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('multi_code', sa.String(), nullable=True),
    sa.Column('country_code', sa.String(), nullable=False),
    sa.Column('country_name', sa.String(), nullable=False),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_table('deviceinformation',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('brand', sa.String(), nullable=False),
    sa.Column('model', sa.String(), nullable=False),
    sa.Column('release', sa.String(), nullable=False),
    sa.Column('creation_date', sa.DateTime(), nullable=False),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_table('tags',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('tag_name', sa.String(), nullable=False),
    sa.Column('creation_date', sa.DateTime(), nullable=False),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_table('users',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('mail_adress', sa.String(), nullable=False),
    sa.Column('name', sa.String(), nullable=False),
    sa.Column('profile_picture', sa.String(), nullable=False),
    sa.Column('local', sa.String(), nullable=False),
    sa.Column('provider_name', sa.String(), nullable=False),
    sa.Column('provider_id', sa.String(), nullable=False),
    sa.Column('id_share', sa.String(), nullable=False),
    sa.Column('is_active', sa.Boolean(), nullable=False),
    sa.Column('creation_date', sa.DateTime(), nullable=False),
    sa.Column('last_update', sa.DateTime(), nullable=False),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('id_share')
    )
    op.create_table('versions',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('versions_name', sa.String(), nullable=False),
    sa.Column('versions_description', sa.String(), nullable=True),
    sa.Column('versions_code', sa.String(), nullable=False),
    sa.Column('versions_secret_key', sa.String(), nullable=False),
    sa.Column('contact_secret_key', sa.String(), nullable=False),
    sa.Column('creation_date', sa.DateTime(), nullable=False),
    sa.Column('expiration', sa.DateTime(), nullable=False),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_table('feedbacks',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('user_id', sa.Integer(), nullable=False),
    sa.Column('description', sa.String(), nullable=False),
    sa.Column('read', sa.Boolean(), nullable=False),
    sa.Column('creation_date', sa.DateTime(), nullable=False),
    sa.Column('last_update', sa.DateTime(), nullable=False),
    sa.ForeignKeyConstraint(['user_id'], ['users.id'], ),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_table('keys',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('user_id', sa.Integer(), nullable=False),
    sa.Column('key', sa.String(), nullable=False),
    sa.Column('device_key', sa.String(), nullable=False),
    sa.Column('creation_date', sa.DateTime(), nullable=False),
    sa.Column('expiration', sa.DateTime(), nullable=False),
    sa.Column('device_information_id', sa.Integer(), nullable=False),
    sa.ForeignKeyConstraint(['device_information_id'], ['deviceinformation.id'], ),
    sa.ForeignKeyConstraint(['user_id'], ['users.id'], ),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_table('logs',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('user_id', sa.Integer(), nullable=False),
    sa.Column('ip_address', sa.String(), nullable=False),
    sa.Column('action', sa.String(), nullable=False),
    sa.Column('data', sa.JSON(), nullable=True),
    sa.Column('creation_date', sa.DateTime(), nullable=False),
    sa.ForeignKeyConstraint(['user_id'], ['users.id'], ),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_table('participants',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('user_id', sa.Integer(), nullable=False),
    sa.Column('raffle_id', sa.Integer(), nullable=False),
    sa.Column('date', sa.DateTime(), nullable=False),
    sa.Column('creation_date', sa.DateTime(), nullable=False),
    sa.ForeignKeyConstraint(['user_id'], ['users.id'], ),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_table('raffles',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('id_share', sa.String(), nullable=False),
    sa.Column('user_id', sa.Integer(), nullable=False),
    sa.Column('title', sa.String(), nullable=False),
    sa.Column('contact_information', sa.String(), nullable=False),
    sa.Column('description', sa.String(), nullable=False),
    sa.Column('expiration', sa.DateTime(), nullable=False),
    sa.Column('status', sa.Boolean(), nullable=False),
    sa.Column('processing', sa.Boolean(), nullable=False),
    sa.Column('completed', sa.Boolean(), nullable=False),
    sa.Column('delete', sa.Boolean(), nullable=False),
    sa.Column('disable', sa.Boolean(), nullable=False),
    sa.Column('winners', sa.Integer(), nullable=False),
    sa.Column('reserves', sa.Integer(), nullable=False),
    sa.Column('raffle_date', sa.DateTime(), nullable=False),
    sa.Column('creation_date', sa.DateTime(), nullable=False),
    sa.Column('last_update', sa.DateTime(), nullable=False),
    sa.ForeignKeyConstraint(['user_id'], ['users.id'], ),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('id_share')
    )
    op.create_table('countrytargets',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('country_id', sa.Integer(), nullable=False),
    sa.Column('raffle_id', sa.Integer(), nullable=False),
    sa.ForeignKeyConstraint(['country_id'], ['countries.id'], ),
    sa.ForeignKeyConstraint(['raffle_id'], ['raffles.id'], ),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_table('luckys',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('user_id', sa.Integer(), nullable=False),
    sa.Column('raffles_id', sa.Integer(), nullable=False),
    sa.Column('secret_key', sa.String(), nullable=False),
    sa.Column('status', sa.Boolean(), nullable=False),
    sa.Column('check_key', sa.Boolean(), nullable=False),
    sa.Column('creation_date', sa.DateTime(), nullable=False),
    sa.ForeignKeyConstraint(['raffles_id'], ['raffles.id'], ),
    sa.ForeignKeyConstraint(['user_id'], ['users.id'], ),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('secret_key')
    )
    op.create_table('tagtargets',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('tag_id', sa.Integer(), nullable=False),
    sa.Column('raffle_id', sa.Integer(), nullable=False),
    sa.Column('creation_date', sa.DateTime(), nullable=False),
    sa.ForeignKeyConstraint(['raffle_id'], ['raffles.id'], ),
    sa.ForeignKeyConstraint(['tag_id'], ['tags.id'], ),
    sa.PrimaryKeyConstraint('id')
    )
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_table('tagtargets')
    op.drop_table('luckys')
    op.drop_table('countrytargets')
    op.drop_table('raffles')
    op.drop_table('participants')
    op.drop_table('logs')
    op.drop_table('keys')
    op.drop_table('feedbacks')
    op.drop_table('versions')
    op.drop_table('users')
    op.drop_table('tags')
    op.drop_table('deviceinformation')
    op.drop_table('countrymultilang')
    op.drop_table('countries')
    op.drop_table('admin_users')
    # ### end Alembic commands ###
