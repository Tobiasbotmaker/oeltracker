"""Replace favorite_beer with bio

Revision ID: bfd2c2e72c47
Revises: 6cf67669efda
Create Date: 2025-05-05 21:15:39.710155

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'bfd2c2e72c47'
down_revision = '6cf67669efda'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('users', schema=None) as batch_op:
        batch_op.add_column(sa.Column('bio', sa.Text(), nullable=True))
        batch_op.drop_column('favorite_beer')

    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('users', schema=None) as batch_op:
        batch_op.add_column(sa.Column('favorite_beer', sa.VARCHAR(length=255), autoincrement=False, nullable=True))
        batch_op.drop_column('bio')

    # ### end Alembic commands ###
