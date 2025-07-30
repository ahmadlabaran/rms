# Generated manually to add grading and carry-over models

import django.db.models.deletion
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('accounts', '0015_coursethreshold'),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        # Create GradingThreshold model
        migrations.CreateModel(
            name='GradingThreshold',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('grade_letter', models.CharField(choices=[('A', 'A - Excellent'), ('B', 'B - Very Good'), ('C', 'C - Good'), ('D', 'D - Pass'), ('F', 'F - Fail')], max_length=1)),
                ('min_score', models.DecimalField(decimal_places=2, help_text='Minimum score for this grade', max_digits=5)),
                ('max_score', models.DecimalField(decimal_places=2, help_text='Maximum score for this grade', max_digits=5)),
                ('grade_points', models.DecimalField(decimal_places=2, default=0.0, help_text='Grade points for GPA calculation', max_digits=3)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
                ('created_by', models.ForeignKey(null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='grading_thresholds_created', to=settings.AUTH_USER_MODEL)),
                ('faculty', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='grading_thresholds', to='accounts.faculty')),
            ],
            options={
                'verbose_name': 'Grading Threshold',
                'verbose_name_plural': 'Grading Thresholds',
                'ordering': ['-min_score'],
                'unique_together': {('faculty', 'grade_letter')},
            },
        ),
        
        # Create CarryOverStudent model
        migrations.CreateModel(
            name='CarryOverStudent',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('failed_score', models.DecimalField(decimal_places=2, max_digits=5)),
                ('failed_grade', models.CharField(max_length=1)),
                ('passing_threshold', models.DecimalField(decimal_places=2, max_digits=5)),
                ('status', models.CharField(choices=[('IDENTIFIED', 'Identified'), ('NOTIFIED', 'Notified'), ('REGISTERED', 'Registered for Retake'), ('COMPLETED', 'Completed Retake')], default='IDENTIFIED', max_length=20)),
                ('identified_at', models.DateTimeField(auto_now_add=True)),
                ('notified_at', models.DateTimeField(blank=True, null=True)),
                ('notes', models.TextField(blank=True, help_text='Administrative notes')),
                ('course', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='accounts.course')),
                ('department', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='accounts.department')),
                ('faculty', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='accounts.faculty')),
                ('level', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='accounts.level')),
                ('result', models.OneToOneField(on_delete=django.db.models.deletion.CASCADE, related_name='carryover_record', to='accounts.result')),
                ('session', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='accounts.academicsession')),
                ('student', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='carryover_records', to='accounts.student')),
            ],
            options={
                'verbose_name': 'Carry-Over Student',
                'verbose_name_plural': 'Carry-Over Students',
                'ordering': ['level__name', 'department__name', 'student__matric_number'],
                'unique_together': {('student', 'course', 'session')},
            },
        ),
    ]
