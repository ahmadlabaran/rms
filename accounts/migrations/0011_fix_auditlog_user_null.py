# Generated manually to fix AuditLog user_id NOT NULL constraint

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('accounts', '0010_alter_academicsession_created_by_and_more'),
    ]

    operations = [
        # First, update any existing NULL values to avoid constraint issues
        migrations.RunSQL(
            "UPDATE accounts_auditlog SET user_id = NULL WHERE user_id NOT IN (SELECT id FROM auth_user);",
            reverse_sql="-- No reverse operation needed"
        ),
        
        # Then alter the field to allow NULL
        migrations.AlterField(
            model_name='auditlog',
            name='user',
            field=models.ForeignKey(null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='audit_logs', to='auth.user'),
        ),
    ]
