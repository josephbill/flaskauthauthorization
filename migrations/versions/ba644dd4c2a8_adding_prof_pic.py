"""adding prof. pic

Revision ID: ba644dd4c2a8
Revises: 7fbe1fcd3498
Create Date: 2023-10-05 12:39:42.762279

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'ba644dd4c2a8'
down_revision = '7fbe1fcd3498'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('user', schema=None) as batch_op:
        batch_op.add_column(sa.Column('profile_picture', sa.String(length=255), nullable=True))

    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('user', schema=None) as batch_op:
        batch_op.drop_column('profile_picture')

    # ### end Alembic commands ###