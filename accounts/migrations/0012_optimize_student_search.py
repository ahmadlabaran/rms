# Generated migration for optimizing student search performance

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('accounts', '0011_fix_auditlog_user_null'),
    ]

    operations = [
        # Add database indexes for faster student searches
        migrations.RunSQL(
            # Create indexes for faster search queries
            [
                "CREATE INDEX IF NOT EXISTS idx_student_matric_number ON accounts_student (matric_number);",
                "CREATE INDEX IF NOT EXISTS idx_student_faculty_id ON accounts_student (faculty_id);",
                "CREATE INDEX IF NOT EXISTS idx_student_department_id ON accounts_student (department_id);",
                "CREATE INDEX IF NOT EXISTS idx_student_current_level_id ON accounts_student (current_level_id);",
                "CREATE INDEX IF NOT EXISTS idx_user_first_name ON auth_user (first_name);",
                "CREATE INDEX IF NOT EXISTS idx_user_last_name ON auth_user (last_name);",
                "CREATE INDEX IF NOT EXISTS idx_user_is_active ON auth_user (is_active);",
                "CREATE INDEX IF NOT EXISTS idx_courseenrollment_course_session ON accounts_courseenrollment (course_id, session_id);",
                "CREATE INDEX IF NOT EXISTS idx_course_departments ON accounts_course_departments (course_id, department_id);",
            ],
            # Reverse migration - drop indexes
            [
                "DROP INDEX IF EXISTS idx_student_matric_number;",
                "DROP INDEX IF EXISTS idx_student_faculty_id;",
                "DROP INDEX IF EXISTS idx_student_department_id;",
                "DROP INDEX IF EXISTS idx_student_current_level_id;",
                "DROP INDEX IF EXISTS idx_user_first_name;",
                "DROP INDEX IF EXISTS idx_user_last_name;",
                "DROP INDEX IF EXISTS idx_user_is_active;",
                "DROP INDEX IF EXISTS idx_courseenrollment_course_session;",
                "DROP INDEX IF EXISTS idx_course_departments;",
            ]
        ),
    ]
