# Generated manually to add rejection fields to Result model

import django.db.models.deletion
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('accounts', '0016_add_grading_and_carryover_models'),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        # Add rejection tracking fields to Result model
        migrations.AddField(
            model_name='result',
            name='rejected_by',
            field=models.ForeignKey(blank=True, help_text='User who rejected this result', null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='results_rejected', to=settings.AUTH_USER_MODEL),
        ),
        migrations.AddField(
            model_name='result',
            name='rejection_reason',
            field=models.TextField(blank=True, help_text='Reason for rejection', null=True),
        ),
        migrations.AddField(
            model_name='result',
            name='rejection_date',
            field=models.DateTimeField(blank=True, help_text='When the result was rejected', null=True),
        ),
    ]
