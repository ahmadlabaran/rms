from django.core.management.base import BaseCommand
from django.contrib.auth.models import User
from accounts.models import (
    UserRole, Student, Faculty, Department, Course, Result, 
    CourseEnrollment, AcademicSession, AuditLog, Notification
)


class Command(BaseCommand):
    help = 'Clean database and keep only Super Admin user'

    def add_arguments(self, parser):
        parser.add_argument(
            '--confirm',
            action='store_true',
            help='Confirm that you want to delete all data except Super Admin',
        )

    def handle(self, *args, **options):
        if not options['confirm']:
            self.stdout.write(
                self.style.WARNING(
                    'This command will delete ALL data except the Super Admin user.\n'
                    'Run with --confirm to proceed.\n'
                    'Example: python manage.py clean_database --confirm'
                )
            )
            return

        try:
            # Get Super Admin users before deletion
            super_admin_users = User.objects.filter(
                rms_roles__role='SUPER_ADMIN'
            ).distinct()

            if not super_admin_users.exists():
                self.stdout.write(
                    self.style.ERROR('No Super Admin users found! Cannot proceed.')
                )
                return

            super_admin_count = super_admin_users.count()
            super_admin_names = [user.get_full_name() or user.username for user in super_admin_users]

            # Delete all data in order (respecting foreign key constraints)
            self.stdout.write('Cleaning database...')

            # Delete academic data
            deleted_counts = {}
            deleted_counts['Results'] = Result.objects.count()
            Result.objects.all().delete()

            deleted_counts['Course Enrollments'] = CourseEnrollment.objects.count()
            CourseEnrollment.objects.all().delete()

            deleted_counts['Courses'] = Course.objects.count()
            Course.objects.all().delete()

            deleted_counts['Students'] = Student.objects.count()
            Student.objects.all().delete()

            deleted_counts['Departments'] = Department.objects.count()
            Department.objects.all().delete()

            deleted_counts['Faculties'] = Faculty.objects.count()
            Faculty.objects.all().delete()

            # Delete notifications and audit logs
            deleted_counts['Notifications'] = Notification.objects.count()
            Notification.objects.all().delete()

            deleted_counts['Audit Logs'] = AuditLog.objects.exclude(
                user__in=super_admin_users
            ).count()
            AuditLog.objects.exclude(user__in=super_admin_users).delete()

            # Delete user roles except Super Admin
            deleted_counts['User Roles'] = UserRole.objects.exclude(
                role='SUPER_ADMIN'
            ).count()
            UserRole.objects.exclude(role='SUPER_ADMIN').delete()

            # Delete all users except Super Admin
            deleted_counts['Users'] = User.objects.exclude(
                id__in=super_admin_users.values_list('id', flat=True)
            ).count()
            User.objects.exclude(
                id__in=super_admin_users.values_list('id', flat=True)
            ).delete()

            # Create a fresh audit log entry
            for super_admin in super_admin_users:
                AuditLog.objects.create(
                    user=super_admin,
                    action='CREATE_USER',
                    description='Database cleaned - all data removed except Super Admin users',
                    level='INFO'
                )

            # Display results
            self.stdout.write(
                self.style.SUCCESS(
                    f'\nDatabase cleaned successfully!\n'
                    f'\nPreserved Super Admin users ({super_admin_count}):'
                )
            )
            
            for name in super_admin_names:
                self.stdout.write(f'  - {name}')

            self.stdout.write('\nDeleted data:')
            for item_type, count in deleted_counts.items():
                if count > 0:
                    self.stdout.write(f'  - {count} {item_type}')

            self.stdout.write(
                self.style.SUCCESS(
                    f'\n🎯 The system is now clean and ready for fresh setup!\n'
                    f'Super Admin can now create faculties and faculty deans.\n'
                )
            )

        except Exception as e:
            self.stdout.write(
                self.style.ERROR(f'Error cleaning database: {str(e)}')
            )
