"""empty message

Revision ID: d2eccecbd7d2
Revises: 0b3ba0d8a9c4
Create Date: 2019-09-28 21:21:40.676333

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'd2eccecbd7d2'
down_revision = '0b3ba0d8a9c4'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.add_column('socialreports', sa.Column('social_id', sa.Integer(), nullable=False))
    op.create_foreign_key(None, 'socialreports', 'socialmedia', ['social_id'], ['id'])
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_constraint(None, 'socialreports', type_='foreignkey')
    op.drop_column('socialreports', 'social_id')
    # ### end Alembic commands ###
