"""add cvss4 columns

Revision ID: 47e0c8f9856d
Revises: ad29e4bcf2cf
Create Date: 2024-08-17 21:43:12.666824+00:00

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '47e0c8f9856d'
down_revision = 'ad29e4bcf2cf'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.add_column('vulnerability', sa.Column('_cvss4_vector_string', sa.Text(), nullable=True))
    op.add_column('vulnerability', sa.Column('cvss4_base_score', sa.Float(), nullable=True))
    op.add_column('vulnerability', sa.Column('cvss4_base_severity', sa.Text(), nullable=True))
    op.add_column('vulnerability', sa.Column('cvss4_attack_vector', sa.Text(), nullable=True))
    op.add_column('vulnerability', sa.Column('cvss4_attack_complexity', sa.Text(), nullable=True))
    op.add_column('vulnerability', sa.Column('cvss4_attack_requirements', sa.Text(), nullable=True))
    op.add_column('vulnerability', sa.Column('cvss4_privileges_required', sa.Text(), nullable=True))
    op.add_column('vulnerability', sa.Column('cvss4_user_interaction', sa.Text(), nullable=True))
    op.add_column('vulnerability', sa.Column('cvss4_vulnerable_system_confidentiality_impact', sa.Text(), nullable=True))
    op.add_column('vulnerability', sa.Column('cvss4_subsequent_system_confidentiality_impact', sa.Text(), nullable=True))
    op.add_column('vulnerability', sa.Column('cvss4_vulnerable_system_integrity_impact', sa.Text(), nullable=True))
    op.add_column('vulnerability', sa.Column('cvss4_subsequent_system_integrity_impact', sa.Text(), nullable=True))
    op.add_column('vulnerability', sa.Column('cvss4_vulnerable_system_availability_impact', sa.Text(), nullable=True))
    op.add_column('vulnerability', sa.Column('cvss4_subsequent_system_availability_impact', sa.Text(), nullable=True))
    op.add_column('vulnerability', sa.Column('cvss4_safety', sa.Text(), nullable=True))
    op.add_column('vulnerability', sa.Column('cvss4_automatable', sa.Text(), nullable=True))
    op.add_column('vulnerability', sa.Column('cvss4_recovery', sa.Text(), nullable=True))
    op.add_column('vulnerability', sa.Column('cvss4_value_density', sa.Text(), nullable=True))
    op.add_column('vulnerability', sa.Column('cvss4_vulnerability_response_effort', sa.Text(), nullable=True))
    op.add_column('vulnerability', sa.Column('cvss4_provider_urgency', sa.Text(), nullable=True))
    op.add_column('vulnerability', sa.Column('cvss4_modified_attack_vector', sa.Text(), nullable=True))
    op.add_column('vulnerability', sa.Column('cvss4_modified_attack_complexity', sa.Text(), nullable=True))
    op.add_column('vulnerability', sa.Column('cvss4_modified_attack_requirements', sa.Text(), nullable=True))
    op.add_column('vulnerability', sa.Column('cvss4_modified_privileges_required', sa.Text(), nullable=True))
    op.add_column('vulnerability', sa.Column('cvss4_modified_user_interaction', sa.Text(), nullable=True))
    op.add_column('vulnerability', sa.Column('cvss4_modified_vulnerable_system_confidentiality_impact', sa.Text(), nullable=True))
    op.add_column('vulnerability', sa.Column('cvss4_modified_subsequent_system_confidentiality_impact', sa.Text(), nullable=True))
    op.add_column('vulnerability', sa.Column('cvss4_modified_vulnerable_system_integrity_impact', sa.Text(), nullable=True))
    op.add_column('vulnerability', sa.Column('cvss4_modified_subsequent_system_integrity_impact', sa.Text(), nullable=True))
    op.add_column('vulnerability', sa.Column('cvss4_modified_vulnerable_system_availability_impact', sa.Text(), nullable=True))
    op.add_column('vulnerability', sa.Column('cvss4_modified_subsequent_system_availability_impact', sa.Text(), nullable=True))
    op.add_column('vulnerability', sa.Column('cvss4_confidentiality_requirement', sa.Text(), nullable=True))
    op.add_column('vulnerability', sa.Column('cvss4_integrity_requirement', sa.Text(), nullable=True))
    op.add_column('vulnerability', sa.Column('cvss4_availability_requirement', sa.Text(), nullable=True))
    op.add_column('vulnerability', sa.Column('cvss4_exploit_maturity', sa.Text(), nullable=True))
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_column('vulnerability', 'cvss4_exploit_maturity')
    op.drop_column('vulnerability', 'cvss4_availability_requirement')
    op.drop_column('vulnerability', 'cvss4_integrity_requirement')
    op.drop_column('vulnerability', 'cvss4_confidentiality_requirement')
    op.drop_column('vulnerability', 'cvss4_modified_subsequent_system_availability_impact')
    op.drop_column('vulnerability', 'cvss4_modified_vulnerable_system_availability_impact')
    op.drop_column('vulnerability', 'cvss4_modified_subsequent_system_integrity_impact')
    op.drop_column('vulnerability', 'cvss4_modified_vulnerable_system_integrity_impact')
    op.drop_column('vulnerability', 'cvss4_modified_subsequent_system_confidentiality_impact')
    op.drop_column('vulnerability', 'cvss4_modified_vulnerable_system_confidentiality_impact')
    op.drop_column('vulnerability', 'cvss4_modified_user_interaction')
    op.drop_column('vulnerability', 'cvss4_modified_privileges_required')
    op.drop_column('vulnerability', 'cvss4_modified_attack_requirements')
    op.drop_column('vulnerability', 'cvss4_modified_attack_complexity')
    op.drop_column('vulnerability', 'cvss4_modified_attack_vector')
    op.drop_column('vulnerability', 'cvss4_provider_urgency')
    op.drop_column('vulnerability', 'cvss4_vulnerability_response_effort')
    op.drop_column('vulnerability', 'cvss4_value_density')
    op.drop_column('vulnerability', 'cvss4_recovery')
    op.drop_column('vulnerability', 'cvss4_automatable')
    op.drop_column('vulnerability', 'cvss4_safety')
    op.drop_column('vulnerability', 'cvss4_subsequent_system_availability_impact')
    op.drop_column('vulnerability', 'cvss4_vulnerable_system_availability_impact')
    op.drop_column('vulnerability', 'cvss4_subsequent_system_integrity_impact')
    op.drop_column('vulnerability', 'cvss4_vulnerable_system_integrity_impact')
    op.drop_column('vulnerability', 'cvss4_subsequent_system_confidentiality_impact')
    op.drop_column('vulnerability', 'cvss4_vulnerable_system_confidentiality_impact')
    op.drop_column('vulnerability', 'cvss4_user_interaction')
    op.drop_column('vulnerability', 'cvss4_privileges_required')
    op.drop_column('vulnerability', 'cvss4_attack_requirements')
    op.drop_column('vulnerability', 'cvss4_attack_complexity')
    op.drop_column('vulnerability', 'cvss4_attack_vector')
    op.drop_column('vulnerability', 'cvss4_base_severity')
    op.drop_column('vulnerability', 'cvss4_base_score')
    op.drop_column('vulnerability', '_cvss4_vector_string')
    # ### end Alembic commands ###
